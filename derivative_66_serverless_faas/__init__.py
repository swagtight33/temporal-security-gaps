"""
Serverless/FaaS Compiled Function Cache Module
Derivative #66: Serverless/FaaS Compiled Function Cache

Provides classes for discovering, monitoring, validating, and mitigating cached
serverless function compilations that persist across IAM, VPC, and security policy transitions.

Supported Providers:
    - AWS Lambda
    - CloudFlare Workers
    - Vercel Edge Functions
    - Google Cloud Functions
    - Azure Functions

Usage:
    from derivative_66_serverless_faas.serverless_cache_validator import (
        ServerlessCacheDiscovery,
        ServerlessPolicyMonitor,
        FunctionCacheValidator,
        FunctionMitigationController
    )

    discovery = ServerlessCacheDiscovery()
    monitor = ServerlessPolicyMonitor()
    validator = FunctionCacheValidator(monitor, discovery)
    controller = FunctionMitigationController()
"""

__version__ = "1.0.0"
__author__ = "Stanley Linton / STAAML Corp"
__all__ = [
    "ServerlessCacheDiscovery",
    "ServerlessPolicyMonitor",
    "FunctionCacheValidator",
    "FunctionMitigationController",
    "ServerlessProvider",
    "CacheType",
    "PolicyChangeType",
    "ServerlessCacheLocation",
    "CompiledFunctionCache",
    "ServerlessPolicyTransition",
    "ExecutionContextSnapshot",
    "THREAT_MODEL"
]
