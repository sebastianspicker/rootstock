"""
models.py — Pydantic v2 models mirroring the Rootstock collector JSON schema.

These models validate scan output early and provide typed access throughout
the importer pipeline. They intentionally mirror `collector/schema/scan-result.schema.json`.
"""

from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, Field, model_validator


class ElevationInfo(BaseModel):
    is_root: bool
    has_fda: bool


class EntitlementData(BaseModel):
    name: str = Field(min_length=1)
    is_private: bool
    category: Literal["tcc", "injection", "privilege", "sandbox", "keychain", "network", "other"]
    is_security_critical: bool


InjectionMethod = Literal[
    "dyld_insert",
    "dyld_insert_via_entitlement",
    "missing_library_validation",
    "electron_env_var",
]


class ApplicationData(BaseModel):
    name: str = Field(min_length=1)
    bundle_id: str = Field(min_length=1)
    path: str = Field(min_length=1)
    version: str | None = None
    team_id: str | None = None
    hardened_runtime: bool
    library_validation: bool
    is_electron: bool
    is_system: bool
    signed: bool
    entitlements: list[EntitlementData] = Field(default_factory=list)
    injection_methods: list[InjectionMethod] = Field(default_factory=list)


class TCCGrantData(BaseModel):
    service: str = Field(min_length=1)
    display_name: str = Field(min_length=1)
    client: str = Field(min_length=1)
    client_type: int
    auth_value: int
    auth_reason: int
    scope: Literal["user", "system"]
    last_modified: int

    @property
    def allowed(self) -> bool:
        """auth_value 2 = allowed, 3 = limited (also allowed)."""
        return self.auth_value in (2, 3)

    @property
    def auth_reason_label(self) -> str:
        labels = {1: "user_prompt", 2: "system_settings", 3: "entitlement", 4: "mdm", 5: "system"}
        return labels.get(self.auth_reason, f"unknown_{self.auth_reason}")


class CollectionErrorData(BaseModel):
    source: str = Field(min_length=1)
    message: str = Field(min_length=1)
    recoverable: bool


class ScanResult(BaseModel):
    scan_id: str = Field(min_length=1)
    timestamp: str = Field(min_length=1)
    hostname: str = Field(min_length=1)
    macos_version: str = Field(min_length=1)
    collector_version: str = Field(min_length=1)
    elevation: ElevationInfo
    applications: list[ApplicationData] = Field(default_factory=list)
    tcc_grants: list[TCCGrantData] = Field(default_factory=list)
    errors: list[CollectionErrorData] = Field(default_factory=list)

    @model_validator(mode="after")
    def check_unique_bundle_ids(self) -> ScanResult:
        seen: set[str] = set()
        duplicates = []
        for app in self.applications:
            if app.bundle_id in seen:
                duplicates.append(app.bundle_id)
            seen.add(app.bundle_id)
        if duplicates:
            import warnings
            warnings.warn(f"Duplicate bundle_ids in scan: {duplicates}", stacklevel=2)
        return self
