"""
Temporal Security Gaps Research

System and Method for Mitigating Cached Executable Persistence Across Security Policy Transitions
Patent Portfolio - STAAML Corp / Stanley Linton

This package contains implementations of four critical security research derivatives
addressing cache persistence vulnerabilities across security policy transitions.
"""

from derivative_68_shared_memory import (
    SharedMemoryDiscovery,
    SharedMemoryPolicyMonitor,
    SharedMemoryValidator,
    SharedMemoryMitigationController,
)

from derivative_69_tls_session_cache import (
    TLSSessionCacheDiscovery,
    NetworkPolicyMonitor,
    TLSSessionValidator,
    TLSMitigationController,
)

from derivative_70_package_manager_cache import (
    PackageCacheDiscovery,
    PackagePolicyMonitor,
    PackageCacheValidator,
    PackageMitigationController,
)

from derivative_71_pwa_installation_cache import (
    PWACacheDiscovery,
    PWAPolicyMonitor,
    PWACacheValidator,
    PWAMitigationController,
)

__all__ = [
    # Derivative 68
    "SharedMemoryDiscovery",
    "SharedMemoryPolicyMonitor",
    "SharedMemoryValidator",
    "SharedMemoryMitigationController",
    # Derivative 69
    "TLSSessionCacheDiscovery",
    "NetworkPolicyMonitor",
    "TLSSessionValidator",
    "TLSMitigationController",
    # Derivative 70
    "PackageCacheDiscovery",
    "PackagePolicyMonitor",
    "PackageCacheValidator",
    "PackageMitigationController",
    # Derivative 71
    "PWACacheDiscovery",
    "PWAPolicyMonitor",
    "PWACacheValidator",
    "PWAMitigationController",
]

__version__ = "1.0.0"
__author__ = "Stanley Linton / STAAML Corp"
