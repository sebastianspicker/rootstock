import Foundation

/// Maps TCC service identifiers to human-readable display names.
enum TCCServiceRegistry {
    private static let names: [String: String] = [
        "kTCCServiceSystemPolicyAllFiles":          "Full Disk Access",
        "kTCCServiceAccessibility":                 "Accessibility",
        "kTCCServiceScreenCapture":                 "Screen Recording",
        "kTCCServiceMicrophone":                    "Microphone",
        "kTCCServiceCamera":                        "Camera",
        "kTCCServiceAppleEvents":                   "Automation",
        "kTCCServiceListenEvent":                   "Input Monitoring",
        "kTCCServicePostEvent":                     "Keyboard Event Injection",
        "kTCCServiceSystemPolicyDesktopFolder":     "Desktop Folder",
        "kTCCServiceSystemPolicyDocumentsFolder":   "Documents Folder",
        "kTCCServiceSystemPolicyDownloadsFolder":   "Downloads Folder",
        "kTCCServiceSystemPolicyRemovableVolumes":  "Removable Volumes",
        "kTCCServiceSystemPolicyNetworkVolumes":    "Network Volumes",
        "kTCCServiceEndpointSecurityClient":        "Endpoint Security",
        "kTCCServiceLocation":                      "Location Services",
        "kTCCServicePhotos":                        "Photos",
        "kTCCServiceContacts":                      "Contacts",
        "kTCCServiceCalendar":                      "Calendar",
        "kTCCServiceReminders":                     "Reminders",
        "kTCCServiceAddressBook":                   "Address Book",
        "kTCCServiceSpeechRecognition":             "Speech Recognition",
        "kTCCServiceBluetoothAlways":               "Bluetooth",
        "kTCCServiceUserTracking":                  "Tracking",
        "kTCCServiceFocusStatus":                   "Focus Status",
    ]

    /// Returns the display name for a TCC service identifier.
    /// Falls back to the raw service identifier for unknown services.
    static func displayName(for service: String) -> String {
        return names[service] ?? service
    }
}
