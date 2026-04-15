"""
Browser Extension Cache Persistence Module
Derivative #67: Browser Extension Cache Persistence

Provides classes for discovering, monitoring, validating, and mitigating cached
browser extension code and storage that persists across enterprise extension policy transitions.

Supported Browsers:
    - Google Chrome
    - Mozilla Firefox
    - Microsoft Edge
    - Apple Safari
    - Brave

Cache Components Handled:
    - Background scripts and service workers
    - Content scripts
    - Popup and options pages
    - IndexedDB storage
    - localStorage storage
    - Cookies storage
    - WebRequest API handlers
    - declarativeNetRequest rules

Usage:
    from derivative_67_browser_extension_cache.extension_cache_validator import (
        ExtensionCacheDiscovery,
        ExtensionPolicyMonitor,
        ExtensionCacheValidator,
        ExtensionMitigationController
    )

    discovery = ExtensionCacheDiscovery()
    monitor = ExtensionPolicyMonitor()
    validator = ExtensionCacheValidator(monitor, discovery)
    controller = ExtensionMitigationController()
"""

__version__ = "1.0.0"
__author__ = "Stanley Linton / STAAML Corp"
__all__ = [
    "ExtensionCacheDiscovery",
    "ExtensionPolicyMonitor",
    "ExtensionCacheValidator",
    "ExtensionMitigationController",
    "BrowserType",
    "ExtensionComponentType",
    "PolicyRestrictionType",
    "ExtensionMetadata",
    "CachedExtensionComponent",
    "ExtensionPolicyTransition",
    "ExtensionComplianceResult",
    "THREAT_MODEL"
]
