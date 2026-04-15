"""
WebView Cache Validator - Derivative #62
Mitigating Cached Executable Persistence Across Security Policy Transitions

Patent Portfolio: STAAML Corp
Author: Stanley Linton

This package provides comprehensive discovery, enumeration, validation, and
mitigation of cached content in native app WebViews across iOS, Android,
macOS, Windows, Linux, and Electron platforms.
"""

from .webview_cache_validator import (
    # Main classes
    WebViewCacheDiscovery,
    WebViewCacheEnumerator,
    WebViewPolicyValidator,
    WebViewMitigationController,
    WebViewPostureAdapter,
    WebViewCacheValidator,
    # Enums
    ComplianceStatus,
    MitigationAction,
    PolicyTransitionEvent,
    CacheType,
    PlatformType,
    # Data classes
    SecurityPolicy,
    CachedItem,
    PolicyDelta,
    ValidationResult,
    WebViewAppInfo,
    # Constants
    THREAT_MODEL,
    PERF_TARGETS,
    CACHE_DISCOVERY_PATHS,
)

__version__ = "1.0.0"
__author__ = "Stanley Linton"
__license__ = "Proprietary - STAAML Corp"

__all__ = [
    # Main classes
    "WebViewCacheDiscovery",
    "WebViewCacheEnumerator",
    "WebViewPolicyValidator",
    "WebViewMitigationController",
    "WebViewPostureAdapter",
    "WebViewCacheValidator",
    # Enums
    "ComplianceStatus",
    "MitigationAction",
    "PolicyTransitionEvent",
    "CacheType",
    "PlatformType",
    # Data classes
    "SecurityPolicy",
    "CachedItem",
    "PolicyDelta",
    "ValidationResult",
    "WebViewAppInfo",
    # Constants
    "THREAT_MODEL",
    "PERF_TARGETS",
    "CACHE_DISCOVERY_PATHS",
]
