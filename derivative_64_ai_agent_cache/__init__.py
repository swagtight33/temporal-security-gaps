"""
AI Agent Tool Authorization and Credential Cache Validator

Derivative #64 - Patent Portfolio: STAAML Corp / Stanley Linton

This package implements security validation and mitigation for cached tool
authorizations, API credentials, and behavioral artifacts across AI agent
frameworks when permission policies, trust boundaries, or sandbox scopes change.

Example Usage:

    from derivative_64_ai_agent_cache import (
        AgentCacheSecurityOrchestrator,
        PolicyState,
        ComplianceStatus,
    )
    import asyncio

    async def main():
        # Initialize orchestrator
        orchestrator = AgentCacheSecurityOrchestrator()

        # Define current policy
        current_policy = PolicyState(
            policy_id="policy_v2",
            granted_tools={"tool_a", "tool_b"},
            granted_scopes={"read", "write"},
        )

        # Run full validation cycle
        result = await orchestrator.run_full_validation_cycle(
            current_policy=current_policy
        )

        print(f"Discovery: {result['discovery']}")
        print(f"Compliance: {result['compliance']}")
        if result.get('mitigation'):
            print(f"Mitigation: {result['mitigation']}")

    if __name__ == "__main__":
        asyncio.run(main())
"""

from .agent_cache_validator import (
    # Main classes
    AgentCacheDiscovery,
    AgentPolicyMonitor,
    AgentCacheValidator,
    AgentMitigationController,
    MCPPostureAdapter,
    AgentCacheSecurityOrchestrator,
    # Enums
    ComplianceStatus,
    FrameworkType,
    PolicyTransitionType,
    MitigationAction,
    # Data structures
    CachedTool,
    CachedCredential,
    CachedRAGIndex,
    CachedBehavior,
    PolicyState,
    PolicyTransition,
    ValidationResult,
    MitigationResult,
    # Constants
    THREAT_MODEL,
    CACHE_DISCOVERY_TIMEOUT_SEC,
    POLICY_MONITOR_CHECK_INTERVAL_SEC,
    MITIGATION_OPERATION_TIMEOUT_SEC,
    CREDENTIAL_TTL_DEFAULT_SEC,
)

__version__ = "1.0.0"
__author__ = "STAAML Corp / Stanley Linton"

__all__ = [
    # Main classes
    "AgentCacheDiscovery",
    "AgentPolicyMonitor",
    "AgentCacheValidator",
    "AgentMitigationController",
    "MCPPostureAdapter",
    "AgentCacheSecurityOrchestrator",
    # Enums
    "ComplianceStatus",
    "FrameworkType",
    "PolicyTransitionType",
    "MitigationAction",
    # Data structures
    "CachedTool",
    "CachedCredential",
    "CachedRAGIndex",
    "CachedBehavior",
    "PolicyState",
    "PolicyTransition",
    "ValidationResult",
    "MitigationResult",
    # Constants
    "THREAT_MODEL",
    "CACHE_DISCOVERY_TIMEOUT_SEC",
    "POLICY_MONITOR_CHECK_INTERVAL_SEC",
    "MITIGATION_OPERATION_TIMEOUT_SEC",
    "CREDENTIAL_TTL_DEFAULT_SEC",
]
