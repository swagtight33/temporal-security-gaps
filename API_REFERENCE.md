# Patent Portfolio API Reference

## Derivative #65: CI/CD Build Artifact Cache Validator

### Classes

#### CICDCacheDiscovery
Discovers cached build artifacts across CI/CD platforms.

**Methods:**
- `async discover_all() -> List[CacheLocation]` - Discover all caches across all platforms
- `async discover_github_actions() -> List[CacheLocation]`
- `async discover_jenkins() -> List[CacheLocation]`
- `async discover_bazel() -> List[CacheLocation]`
- `async discover_gradle() -> List[CacheLocation]`
- `async discover_docker() -> List[CacheLocation]`
- `async discover_package_manager_caches() -> List[CacheLocation]`

#### SupplyChainPolicyMonitor
Monitors supply chain security policy changes.

**Methods:**
- `async monitor_policy_changes() -> List[PolicyTransition]` - Detect all policy changes
- `async _check_cve_updates() -> Optional[PolicyTransition]`
- `async _check_sbom_policy() -> Optional[PolicyTransition]`
- `async _check_signing_key_rotation() -> Optional[PolicyTransition]`
- `async _check_blocklist_updates() -> Optional[PolicyTransition]`

#### ArtifactValidator
Validates cached artifacts against current policy.

**Methods:**
- `async validate_all_artifacts(artifacts) -> Dict[str, ComplianceReport]`
- `async validate_artifact(artifact) -> ComplianceReport`
- `async _check_cve_compliance(artifact) -> List[Dict]`
- `async _check_signature_compliance(artifact) -> List[str]`
- `async _check_blocklist_compliance(artifact) -> List[str]`
- `async _generate_sbom(artifact) -> List[Dict]`

#### ArtifactMitigationController
Purges and invalidates non-compliant artifacts.

**Methods:**
- `async purge_noncompliant_artifacts(artifacts, reports, dry_run=True) -> Dict`
- `async invalidate_docker_layers(layer_ids, dry_run=True) -> Dict`
- `async trigger_rebuild(affected_locations) -> Dict`
- `async atomic_cache_invalidation(locations, dry_run=True) -> Dict`

### Data Classes

- `CacheLocation` - Represents a cache directory location
- `CachedArtifact` - Represents a cached build artifact
- `PolicyTransition` - Represents a supply chain policy change
- `ComplianceReport` - SBOM-like compliance report

### Enums

- `CIPlatform` - GitHub Actions, Jenkins, Bazel, Gradle, Docker, npm, pip, cargo
- `ArtifactType` - Compiled binary, Docker layer, Dependency, SBOM, Build cache
- `PolicyTransitionType` - CVE update, SBOM change, Key rotation, Blocklist update

---

## Derivative #66: Serverless/FaaS Compiled Function Cache Validator

### Classes

#### ServerlessCacheDiscovery
Discovers cached function compilations across serverless providers.

**Methods:**
- `async discover_all_providers() -> List[ServerlessCacheLocation]`
- `async discover_lambda_caches() -> List[ServerlessCacheLocation]`
- `async discover_cloudflare_caches() -> List[ServerlessCacheLocation]`
- `async discover_vercel_caches() -> List[ServerlessCacheLocation]`
- `async discover_gcp_caches() -> List[ServerlessCacheLocation]`
- `async discover_azure_caches() -> List[ServerlessCacheLocation]`

#### ServerlessPolicyMonitor
Monitors serverless security policy changes.

**Methods:**
- `async monitor_all_policy_changes() -> List[ServerlessPolicyTransition]`
- `async _check_iam_changes() -> List[ServerlessPolicyTransition]`
- `async _check_vpc_changes() -> List[ServerlessPolicyTransition]`
- `async _check_network_policy_changes() -> List[ServerlessPolicyTransition]`
- `async _check_runtime_security_changes() -> List[ServerlessPolicyTransition]`

#### FunctionCacheValidator
Validates cached functions against current security context.

**Methods:**
- `async validate_all_caches(functions) -> Dict[str, bool]`
- `async validate_function(function) -> bool`
- `async _validate_iam_context(function) -> None`
- `async _validate_vpc_context(function) -> None`
- `async _validate_environment_context(function) -> None`
- `async _validate_network_policies(function) -> None`

#### FunctionMitigationController
Forces cold start and invalidates caches.

**Methods:**
- `async force_cold_start(functions, dry_run=True) -> Dict`
- `async invalidate_edge_caches(locations, dry_run=True) -> Dict`
- `async trigger_recompilation(functions, dry_run=True) -> Dict`
- `async coordinate_cross_region_invalidation(functions, dry_run=True) -> Dict`

### Data Classes

- `ServerlessCacheLocation` - Serverless cache location
- `CompiledFunctionCache` - Cached compiled function artifacts
- `ServerlessPolicyTransition` - Serverless policy change
- `ExecutionContextSnapshot` - Function execution context at compilation time

### Enums

- `ServerlessProvider` - AWS Lambda, CloudFlare Workers, Vercel, GCP, Azure
- `CacheType` - Execution environment, Compiled artifact, Edge cache, KV store, Build cache, Warm instance
- `PolicyChangeType` - IAM update, VPC change, Network guardrail, Env variable, Runtime security, Permission boundary

---

## Derivative #67: Browser Extension Cache Persistence Validator

### Classes

#### ExtensionCacheDiscovery
Discovers installed extensions and cached components across browsers.

**Methods:**
- `async discover_all_browsers() -> Tuple[List[ExtensionMetadata], List[CachedExtensionComponent]]`
- `async discover_chrome_extensions() -> Tuple[List, List]`
- `async discover_firefox_extensions() -> Tuple[List, List]`
- `async discover_edge_extensions() -> Tuple[List, List]`
- `async discover_safari_extensions() -> Tuple[List, List]`
- `async _parse_manifest(path, browser, id) -> ExtensionMetadata`
- `async _discover_chrome_components(id, path) -> List[CachedExtensionComponent]`

#### ExtensionPolicyMonitor
Monitors enterprise extension policies.

**Methods:**
- `async monitor_policy_changes() -> List[ExtensionPolicyTransition]`
- `async _check_blocklist_updates() -> Optional[ExtensionPolicyTransition]`
- `async _check_permission_changes() -> Optional[ExtensionPolicyTransition]`
- `async _check_policy_file_updates() -> Optional[ExtensionPolicyTransition]`
- `async _check_crx_blocklist() -> Optional[ExtensionPolicyTransition]`

#### ExtensionCacheValidator
Validates cached extensions against policy.

**Methods:**
- `async validate_all_extensions(extensions, components) -> Dict[str, ExtensionComplianceResult]`
- `async validate_extension(extension, components) -> ExtensionComplianceResult`
- `async _validate_signature(extension, result) -> None`

#### ExtensionMitigationController
Disables and purges non-compliant extensions.

**Methods:**
- `async force_disable_extensions(ids, dry_run=True) -> Dict`
- `async purge_extension_caches(components, dry_run=True) -> Dict`
- `async revoke_content_script_permissions(ids, dry_run=True) -> Dict`
- `async clear_indexed_db(ids, dry_run=True) -> Dict`
- `async clear_local_storage(ids, dry_run=True) -> Dict`

### Data Classes

- `ExtensionMetadata` - Extension metadata from manifest
- `CachedExtensionComponent` - Cached extension component
- `ExtensionPolicyTransition` - Extension policy change
- `ExtensionComplianceResult` - Extension compliance check result

### Enums

- `BrowserType` - Chrome, Firefox, Edge, Safari, Brave
- `ExtensionComponentType` - Background script, Content script, Popup, Options, Service worker, IndexedDB, localStorage, Cookies, Manifest
- `PolicyRestrictionType` - Category blocked, Extension blocked, Permission revoked, Update disabled, Installation prevented, Malware blocklist

---

## Common Patterns

All three modules follow these patterns:

### Discovery Pattern
```python
discovery = XyzCacheDiscovery()
items = await discovery.discover_all_*()
```

### Policy Monitoring Pattern
```python
monitor = XyzPolicyMonitor()
transitions = await monitor.monitor_*_changes()
```

### Validation Pattern
```python
validator = XyzValidator(monitor, discovery)
results = await validator.validate_all_*()
```

### Mitigation Pattern
```python
controller = XyzMitigationController()
summary = await controller.force_*/purge_*(items, dry_run=True)
```

### Main Execution Pattern
```python
async def main():
    discovery = XyzCacheDiscovery()
    monitor = XyzPolicyMonitor()
    validator = XyzValidator(monitor, discovery)
    controller = XyzMitigationController()
    
    # Workflow here
    
asyncio.run(main())
```

---

## THREAT_MODEL Structure

Each module includes a comprehensive THREAT_MODEL dictionary:

```python
THREAT_MODEL = {
    "attack_vectors": [
        {
            "vector": "attack_name",
            "description": "...",
            "impact": "...",
            "likelihood": "critical|high|medium|low",
            "mitigation": "..."
        },
        # ... more vectors
    ],
    "affected_components": ["component1", "component2", ...],
    "attack_prerequisites": ["prereq1", "prereq2", ...]
}
```

---

## Performance Constants

All three modules define optimization constants:

- Cache scan timeout: 180-300 seconds
- Policy check interval: 1800 seconds (30 minutes)
- Max concurrent validations: 5-10
- Timeout protection on all I/O operations

---

## Safety Features

All mitigation operations include:
- `dry_run` parameter (defaults to True for safety)
- Exception handling with detailed logging
- Rollback on partial failures
- Audit trail via logging
- Atomic operations where possible

