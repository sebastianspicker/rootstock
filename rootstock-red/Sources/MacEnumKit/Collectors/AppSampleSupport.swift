import Foundation
import RootstockCore
import Security

/// Shared sampling of /Applications (+ optional extra paths) and codesign inspection.
enum AppSampleSupport {
    static let sampleLimit = 25

    /// Up to `sampleLimit` app bundle paths from /Applications, optionally unioned with extras.
    static func sampleAppBundlePaths(extraPaths: [String] = []) -> [String] {
        let fm = FileManager.default
        let appsRoot = URL(fileURLWithPath: "/Applications", isDirectory: true)
        var ordered: [String] = []
        var seen = Set<String>()

        func append(_ path: String) {
            let standardized = (path as NSString).standardizingPath
            guard !seen.contains(standardized) else { return }
            seen.insert(standardized)
            ordered.append(standardized)
        }

        if let contents = try? fm.contentsOfDirectory(
            at: appsRoot,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        ) {
            let apps = contents
                .filter { $0.pathExtension == "app" }
                .sorted { $0.lastPathComponent.localizedCaseInsensitiveCompare($1.lastPathComponent) == .orderedAscending }
            for app in apps {
                append(app.path)
                if ordered.count >= sampleLimit { break }
            }
        }

        for path in extraPaths where ordered.count < sampleLimit {
            let lower = path.lowercased()
            if lower.hasSuffix(".app") || lower.contains(".app/") {
                // Prefer the .app bundle root when given an inner path.
                if let range = path.range(of: ".app", options: [.caseInsensitive]) {
                    let bundle = String(path[..<range.upperBound])
                    append(bundle)
                } else {
                    append(path)
                }
            } else if fm.fileExists(atPath: path) {
                append(path)
            }
        }

        return Array(ordered.prefix(sampleLimit))
    }

    /// Main executable URL inside an .app, or the path itself for bare binaries.
    static func mainExecutablePath(for path: String) -> String? {
        let fm = FileManager.default
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: path, isDirectory: &isDir) else { return nil }

        if path.lowercased().hasSuffix(".app") || isDir.boolValue {
            if let bundle = Bundle(path: path), let exe = bundle.executableURL?.path {
                return exe
            }
            let macos = URL(fileURLWithPath: path)
                .appendingPathComponent("Contents/MacOS", isDirectory: true)
            if let items = try? fm.contentsOfDirectory(atPath: macos.path),
               let first = items.first(where: { !$0.hasPrefix(".") })
            {
                return macos.appendingPathComponent(first).path
            }
            return nil
        }
        return path
    }

    static func inspectCodesign(path: String) -> CodesignSample {
        var staticCode: SecStaticCode?
        let cfURL = URL(fileURLWithPath: path) as CFURL
        let createStatus = SecStaticCodeCreateWithPath(cfURL, SecCSFlags(), &staticCode)
        guard createStatus == errSecSuccess, let code = staticCode else {
            return CodesignSample(
                path: path,
                signed: false,
                notes: ["SecStaticCodeCreateWithPath failed: \(createStatus)"]
            )
        }

        var infoCF: CFDictionary?
        // Signing info includes identifier, team, flags, entitlements.
        let copyStatus = SecCodeCopySigningInformation(
            code,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &infoCF
        )
        guard copyStatus == errSecSuccess, let infoCF else {
            return CodesignSample(
                path: path,
                signed: false,
                notes: ["SecCodeCopySigningInformation failed: \(copyStatus)"]
            )
        }

        let info = infoCF as NSDictionary
        let identifier = info[kSecCodeInfoIdentifier as String] as? String
        let team = info[kSecCodeInfoTeamIdentifier as String] as? String

        var hardened: Bool?
        if let flagsNum = info[kSecCodeInfoFlags as String] as? NSNumber {
            let flags = flagsNum.uint32Value
            // SecCodeSignatureRuntime - hardened runtime bit.
            hardened = (flags & UInt32(SecCodeSignatureFlags.runtime.rawValue)) != 0
        }

        let entitlements = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any]
        func entBool(_ key: String) -> Bool? {
            guard let entitlements else { return nil }
            if let b = entitlements[key] as? Bool { return b }
            if let n = entitlements[key] as? NSNumber { return n.boolValue }
            return entitlements[key] != nil ? true : nil
        }

        return CodesignSample(
            path: path,
            signed: true,
            identifier: identifier,
            teamIdentifier: team,
            hardenedRuntime: hardened,
            getTaskAllow: entBool("com.apple.security.get-task-allow"),
            disableLibraryValidation: entBool("com.apple.security.cs.disable-library-validation"),
            allowDyldEnvironmentVariables: entBool("com.apple.security.cs.allow-dyld-environment-variables"),
            allowUnsignedExecutableMemory: entBool("com.apple.security.cs.allow-unsigned-executable-memory"),
            notes: []
        )
    }

    static func injectabilityHit(from sample: CodesignSample) -> InjectabilityHit {
        var flags: [String] = []
        if sample.getTaskAllow == true { flags.append("get-task-allow") }
        if sample.disableLibraryValidation == true { flags.append("disable-library-validation") }
        if sample.allowDyldEnvironmentVariables == true { flags.append("allow-dyld-environment-variables") }
        if sample.allowUnsignedExecutableMemory == true { flags.append("allow-unsigned-executable-memory") }
        if sample.hardenedRuntime == false { flags.append("no-hardened-runtime") }
        if sample.signed == false { flags.append("unsigned-or-unreadable") }

        return InjectabilityHit(
            path: sample.path,
            hardenedRuntime: sample.hardenedRuntime,
            getTaskAllow: sample.getTaskAllow,
            disableLibraryValidation: sample.disableLibraryValidation,
            allowDyldEnvironmentVariables: sample.allowDyldEnvironmentVariables,
            allowUnsignedExecutableMemory: sample.allowUnsignedExecutableMemory,
            riskFlags: flags,
            notes: sample.notes
        )
    }
}

// MARK: - Lightweight Mach-O weak dylib scan

enum MachOWeakDylibScanner {
    private static let mhMagic64: UInt32 = 0xFEED_FACF
    private static let mhCigam64: UInt32 = 0xCFFA_EDFE
    private static let fatMagic: UInt32 = 0xCAFE_BABE
    private static let fatCigam: UInt32 = 0xBEBA_FECA
    private static let lcLoadWeakDylib: UInt32 = 0x8000_0018

    /// Returns weak-dylib install names from a thin MH_MAGIC_64 (or first thin slice of a fat binary).
    static func weakDylibs(at path: String, maxBytes: Int = 2_000_000) -> (paths: [String], notes: [String]) {
        guard let handle = FileHandle(forReadingAtPath: path) else {
            return ([], ["unreadable"])
        }
        defer { try? handle.close() }

        let data: Data
        do {
            if let full = try handle.read(upToCount: maxBytes) {
                data = full
            } else {
                return ([], ["empty"])
            }
        } catch {
            return ([], ["read failed"])
        }

        guard data.count >= 32 else { return ([], ["too small"]) }

        let magic = readU32(data, 0, bigEndian: false)
        if magic == fatMagic || magic == fatCigam {
            let be = magic == fatCigam || magic == fatMagic
            // fat_header: magic, nfat_arch
            let nArch = Int(readU32(data, 4, bigEndian: true))
            guard nArch > 0, data.count >= 8 + 20 else {
                return ([], ["fat header truncated"])
            }
            // Prefer arm64 / x86_64 first arch that looks like MH_MAGIC_64
            for i in 0..<min(nArch, 8) {
                let base = 8 + i * 20
                guard base + 20 <= data.count else { break }
                let offset = Int(readU32(data, base + 8, bigEndian: true))
                if offset + 32 <= data.count {
                    let slice = data.subdata(in: offset..<data.count)
                    let sliceMagic = readU32(slice, 0, bigEndian: false)
                    if sliceMagic == mhMagic64 || sliceMagic == mhCigam64 {
                        return parseThin64(slice)
                    }
                }
            }
            _ = be
            return ([], ["no MH_MAGIC_64 fat slice found"])
        }

        if magic == mhMagic64 || magic == mhCigam64 {
            return parseThin64(data)
        }

        return ([], ["not MH_MAGIC_64 (magic=\(String(magic, radix: 16)))"])
    }

    private static func parseThin64(_ data: Data) -> (paths: [String], notes: [String]) {
        let swap = readU32(data, 0, bigEndian: false) == mhCigam64
        // mach_header_64: magic,cputype,cpusubtype,filetype,ncmds,sizeofcmds,flags,reserved
        guard data.count >= 32 else { return ([], ["header truncated"]) }
        let ncmds = Int(readU32(data, 16, bigEndian: swap))
        let sizeofcmds = Int(readU32(data, 20, bigEndian: swap))
        var offset = 32
        let end = min(data.count, 32 + sizeofcmds)
        var weak: [String] = []

        for _ in 0..<ncmds {
            guard offset + 8 <= end else { break }
            let cmd = readU32(data, offset, bigEndian: swap)
            let cmdsize = Int(readU32(data, offset + 4, bigEndian: swap))
            guard cmdsize >= 8, offset + cmdsize <= data.count else { break }

            if cmd == lcLoadWeakDylib {
                // dylib_command: cmd, cmdsize, dylib { name offset, timestamp, current, compat }
                guard cmdsize >= 24 else {
                    offset += cmdsize
                    continue
                }
                let nameOffset = Int(readU32(data, offset + 8, bigEndian: swap))
                if nameOffset > 0, offset + nameOffset < offset + cmdsize {
                    let start = offset + nameOffset
                    let limit = offset + cmdsize
                    if let name = cString(data, start: start, end: limit) {
                        weak.append(name)
                    }
                }
            }
            offset += cmdsize
        }
        return (weak, [])
    }

    private static func readU32(_ data: Data, _ offset: Int, bigEndian: Bool) -> UInt32 {
        let b0 = UInt32(data[offset])
        let b1 = UInt32(data[offset + 1])
        let b2 = UInt32(data[offset + 2])
        let b3 = UInt32(data[offset + 3])
        let le = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
        if bigEndian {
            return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
        }
        return le
    }

    private static func cString(_ data: Data, start: Int, end: Int) -> String? {
        var bytes: [UInt8] = []
        var i = start
        while i < end {
            let b = data[i]
            if b == 0 { break }
            bytes.append(b)
            i += 1
        }
        return bytes.isEmpty ? nil : String(bytes: bytes, encoding: .utf8)
    }
}
