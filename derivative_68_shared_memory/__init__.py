"""
Derivative #68: Shared Memory Lateral Persistence Validator

System and Method for Mitigating Cached Executable Persistence Across Security Policy Transitions
Patent Portfolio - STAAML Corp / Stanley Linton
"""

from .shared_memory_validator import (
    SharedMemoryDiscovery,
    SharedMemoryPolicyMonitor,
    SharedMemoryValidator,
    SharedMemoryMitigationController,
    SharedMemorySegment,
    ProcessSecurityPolicy,
    MitigationAction,
    ProtectionFlag,
    ExecutableType,
    THREAT_MODEL,
)

__all__ = [
    "SharedMemoryDiscovery",
    "SharedMemoryPolicyMonitor",
    "SharedMemoryValidator",
    "SharedMemoryMitigationController",
    "SharedMemorySegment",
    "ProcessSecurityPolicy",
    "MitigationAction",
    "ProtectionFlag",
    "ExecutableType",
    "THREAT_MODEL",
]

__version__ = "1.0.0"
__author__ = "Stanley Linton / STAAML Corp"
