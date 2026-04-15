"""
CI/CD Build Artifact Cache Module
Derivative #65: CI/CD Build Artifact Cache

Provides classes for discovering, validating, and mitigating cached build artifacts
that persist across CI/CD supply chain security policy transitions.

Usage:
    from derivative_65_cicd_artifact_cache.cicd_cache_validator import (
        CICDCacheDiscovery,
        SupplyChainPolicyMonitor,
        ArtifactValidator,
        ArtifactMitigationController
    )

    discovery = CICDCacheDiscovery()
    monitor = SupplyChainPolicyMonitor()
    validator = ArtifactValidator(monitor, discovery)
    controller = ArtifactMitigationController()
"""

__version__ = "1.0.0"
__author__ = "Stanley Linton / STAAML Corp"
__all__ = [
    "CICDCacheDiscovery",
    "SupplyChainPolicyMonitor",
    "ArtifactValidator",
    "ArtifactMitigationController",
    "CIPlatform",
    "ArtifactType",
    "PolicyTransitionType",
    "CacheLocation",
    "CachedArtifact",
    "PolicyTransition",
    "ComplianceReport",
    "THREAT_MODEL"
]
