"""
Derivative #71: PWA Installation Cache Validator

System and Method for Mitigating Cached Executable Persistence Across Security Policy Transitions
Patent Portfolio - STAAML Corp / Stanley Linton
"""

from .pwa_cache_validator import (
    PWACacheDiscovery,
    PWAPolicyMonitor,
    PWACacheValidator,
    PWAMitigationController,
    InstalledPWA,
    WebAppManifest,
    ServiceWorkerRegistration,
    PushSubscription,
    BackgroundSyncRegistration,
    CapabilityPolicy,
    PWACacheValidationResult,
    BrowserType,
    CapabilityType,
    ServiceWorkerScope,
    THREAT_MODEL,
)

__all__ = [
    "PWACacheDiscovery",
    "PWAPolicyMonitor",
    "PWACacheValidator",
    "PWAMitigationController",
    "InstalledPWA",
    "WebAppManifest",
    "ServiceWorkerRegistration",
    "PushSubscription",
    "BackgroundSyncRegistration",
    "CapabilityPolicy",
    "PWACacheValidationResult",
    "BrowserType",
    "CapabilityType",
    "ServiceWorkerScope",
    "THREAT_MODEL",
]

__version__ = "1.0.0"
__author__ = "Stanley Linton / STAAML Corp"
