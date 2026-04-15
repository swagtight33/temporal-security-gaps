"""
Firmware Cache Validator Package

Mitigating Cached Executable Persistence Across Security Policy Transitions
Derivative #63: Firmware/UEFI Cached Executable Persistence

Patent Portfolio: "System and Method for Mitigating Cached Executable Persistence
Across Security Policy Transitions"

Authors: Stanley Linton / STAAML Corp.
"""

from .firmware_cache_validator import (
    # Enumerations
    ValidationStatus,
    PolicyTransitionType,
    EFIBinaryType,

    # Data classes
    SignatureDatabaseEntry,
    SecureBootPolicy,
    EFIBinary,
    ValidationReport,
    TemporalBinding,
    MitigationAction,

    # Main classes
    FirmwareCacheDiscovery,
    FirmwarePolicyMonitor,
    FirmwareValidator,
    FirmwareMitigationController,
    UEFITemporalBinding,
    FirmwareSecurityOrchestrator,

    # Constants
    ESP_PATHS,
    EFIVARS_PATHS,
    EFI_SIGNATURE_LIST_MAGIC,
    EFI_SHA256_GUID,
    EFI_CERT_RSA2048_GUID,
    EFI_CERT_X509_GUID,
)

__version__ = "1.0.0"
__author__ = "Stanley Linton / STAAML Corp."
__license__ = "Proprietary - Patent Portfolio Protection"

__all__ = [
    # Enumerations
    "ValidationStatus",
    "PolicyTransitionType",
    "EFIBinaryType",

    # Data classes
    "SignatureDatabaseEntry",
    "SecureBootPolicy",
    "EFIBinary",
    "ValidationReport",
    "TemporalBinding",
    "MitigationAction",

    # Main classes
    "FirmwareCacheDiscovery",
    "FirmwarePolicyMonitor",
    "FirmwareValidator",
    "FirmwareMitigationController",
    "UEFITemporalBinding",
    "FirmwareSecurityOrchestrator",

    # Constants
    "ESP_PATHS",
    "EFIVARS_PATHS",
    "EFI_SIGNATURE_LIST_MAGIC",
    "EFI_SHA256_GUID",
    "EFI_CERT_RSA2048_GUID",
    "EFI_CERT_X509_GUID",
]
