"""
CI/CD Build Artifact Cache Validator
Patent: System and Method for Mitigating Cached Executable Persistence Across Security Policy Transitions
Derivative #65: CI/CD Build Artifact Cache

Detects and mitigates supply chain security vulnerabilities from cached build artifacts
persisting across CI/CD security policy transitions.

Author: Stanley Linton / STAAML Corp
License: Patent Pending
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Callable
from abc import ABC, abstractmethod
import xml.etree.ElementTree as ET

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Performance constants
CACHE_SCAN_TIMEOUT_SECONDS = 300
POLICY_CHECK_INTERVAL_SECONDS = 3600
ARTIFACT_HASH_CHUNK_SIZE = 65536
SBOM_GENERATION_TIMEOUT_SECONDS = 120
MAX_CONCURRENT_VALIDATIONS = 5


class CIPlatform(Enum):
    """Supported CI/CD platforms."""
    GITHUB_ACTIONS = "github_actions"
    JENKINS = "jenkins"
    BAZEL = "bazel"
    GRADLE = "gradle"
    DOCKER = "docker"
    NPM = "npm"
    PIP = "pip"
    CARGO = "cargo"


class ArtifactType(Enum):
    """Types of cached artifacts."""
    COMPILED_BINARY = "compiled_binary"
    DOCKER_LAYER = "docker_layer"
    DEPENDENCY = "dependency"
    SBOM = "sbom"
    BUILD_CACHE = "build_cache"


class PolicyTransitionType(Enum):
    """Types of security policy transitions."""
    CVE_UPDATE = "cve_update"
    SBOM_POLICY_CHANGE = "sbom_policy_change"
    SIGNING_KEY_ROTATION = "signing_key_rotation"
    BLOCKLIST_UPDATE = "blocklist_update"
    SUPPLY_CHAIN_RULE_CHANGE = "supply_chain_rule_change"


@dataclass
class CacheLocation:
    """Represents a cache directory location."""
    platform: CIPlatform
    path: Path
    artifact_type: ArtifactType
    size_bytes: int = 0
    last_accessed: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash((self.platform, str(self.path), self.artifact_type))


@dataclass
class CachedArtifact:
    """Represents a cached build artifact."""
    artifact_id: str
    cache_location: CacheLocation
    artifact_type: ArtifactType
    created_timestamp: datetime
    content_hash: str
    size_bytes: int
    dependencies: List[str] = field(default_factory=list)
    signatures: Dict[str, str] = field(default_factory=dict)
    cve_matches: List[str] = field(default_factory=list)
    policy_compliant: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.artifact_id)


@dataclass
class PolicyTransition:
    """Represents a supply chain security policy change."""
    transition_type: PolicyTransitionType
    timestamp: datetime
    previous_state: Dict[str, Any]
    new_state: Dict[str, Any]
    affected_artifact_types: List[ArtifactType]
    severity: str  # critical, high, medium, low
    description: str


@dataclass
class ComplianceReport:
    """SBOM-like compliance report for artifacts."""
    artifact_id: str
    components: List[Dict[str, str]] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    policy_violations: List[str] = field(default_factory=list)
    compliant: bool = True
    generated_timestamp: datetime = field(default_factory=datetime.utcnow)


# Threat model for supply chain attacks through CI cache
THREAT_MODEL: Dict[str, Any] = {
    "attack_vectors": [
        {
            "vector": "cached_cve_artifact",
            "description": "Cached artifact containing CVE-affected dependency persists after CVE feed update",
            "impact": "Builds compiled against vulnerable dependency version despite policy update",
            "likelihood": "high",
            "mitigation": "Validate cached artifacts against updated CVE database on policy transition"
        },
        {
            "vector": "signed_artifact_key_rotation",
            "description": "Cached artifact signed with rotated/revoked key persists after signing policy change",
            "impact": "Compromised key could have signed artifact, but cache bypass invalidation check",
            "likelihood": "medium",
            "mitigation": "Invalidate all cached artifacts when signing key is rotated"
        },
        {
            "vector": "dependency_blocklist_bypass",
            "description": "Cached artifact built with now-blocked dependency due to supply chain attack",
            "impact": "Malicious dependency from prior policy persists in build cache",
            "likelihood": "high",
            "mitigation": "Cross-check cached artifacts against updated dependency blocklists"
        },
        {
            "vector": "sbom_policy_evasion",
            "description": "Cached Docker layer from pre-SBOM-policy era doesn't have provenance metadata",
            "impact": "Layer from unknown origin used despite new SBOM requirement",
            "likelihood": "medium",
            "mitigation": "Regenerate SBOM for cached artifacts; reject those without provenance"
        },
        {
            "vector": "distributed_runner_cache_persistence",
            "description": "CI runner with local cache not synchronized with central policy invalidation",
            "impact": "Decentralized runners continue using stale, non-compliant artifacts",
            "likelihood": "high",
            "mitigation": "Atomic cache invalidation across all runner instances"
        }
    ],
    "affected_components": [
        "GitHub Actions artifact cache",
        "Jenkins workspace and artifact cache",
        "Bazel output_base",
        "Gradle dependency cache",
        "Docker build cache and layer cache",
        "npm/pip/cargo package caches"
    ],
    "attack_prerequisites": [
        "Access to CI/CD system",
        "Ability to introduce policy mismatch (e.g., outdated vulnerability database)",
        "Presence of cached artifacts from prior security policy era"
    ]
}


class CICDCacheDiscovery:
    """Enumerate cached artifacts across CI platforms."""

    def __init__(self):
        """Initialize discovery engine."""
        self.discovered_locations: Set[CacheLocation] = set()
        self.logger = logger.getChild("CICDCacheDiscovery")

    async def discover_all(self) -> List[CacheLocation]:
        """
        Discover all cached artifacts across all platforms.

        Returns:
            List of discovered cache locations
        """
        tasks = [
            self.discover_github_actions(),
            self.discover_jenkins(),
            self.discover_bazel(),
            self.discover_gradle(),
            self.discover_docker(),
            self.discover_package_manager_caches()
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Discovery failed: {result}")
            elif result:
                self.discovered_locations.update(result)

        self.logger.info(f"Discovered {len(self.discovered_locations)} cache locations")
        return list(self.discovered_locations)

    async def discover_github_actions(self) -> List[CacheLocation]:
        """Discover GitHub Actions cache directories."""
        locations = []

        # Typical GitHub Actions runner cache paths
        github_home = os.getenv("GITHUB_ACTION_PATH") or os.path.expanduser("~/.github")
        cache_paths = [
            Path(github_home) / "_actions",
            Path("/opt/hostedtoolcache"),
            Path(os.path.expanduser("~/.cache/pip")),
            Path(os.path.expanduser("~/.npm")),
            Path(os.path.expanduser("~/.cargo/registry"))
        ]

        for path in cache_paths:
            if path.exists():
                try:
                    size = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
                    locations.append(CacheLocation(
                        platform=CIPlatform.GITHUB_ACTIONS,
                        path=path,
                        artifact_type=ArtifactType.BUILD_CACHE,
                        size_bytes=size,
                        last_accessed=datetime.fromtimestamp(path.stat().st_atime)
                    ))
                except (OSError, PermissionError) as e:
                    self.logger.warning(f"Cannot access {path}: {e}")

        return locations

    async def discover_jenkins(self) -> List[CacheLocation]:
        """Discover Jenkins workspace and artifact cache."""
        locations = []
        jenkins_home = os.getenv("JENKINS_HOME") or "/var/lib/jenkins"
        jenkins_path = Path(jenkins_home)

        if not jenkins_path.exists():
            return locations

        cache_paths = [
            jenkins_path / "workspace",
            jenkins_path / "artifacts",
            jenkins_path / ".m2",  # Maven cache
            jenkins_path / ".gradle"  # Gradle cache
        ]

        for path in cache_paths:
            if path.exists():
                try:
                    size = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
                    locations.append(CacheLocation(
                        platform=CIPlatform.JENKINS,
                        path=path,
                        artifact_type=ArtifactType.BUILD_CACHE,
                        size_bytes=size,
                        last_accessed=datetime.fromtimestamp(path.stat().st_atime)
                    ))
                except (OSError, PermissionError) as e:
                    self.logger.warning(f"Cannot access {path}: {e}")

        return locations

    async def discover_bazel(self) -> List[CacheLocation]:
        """Discover Bazel output_base and cache directories."""
        locations = []

        bazel_cache_paths = [
            Path(os.path.expanduser("~/.cache/bazel")),
            Path("/tmp/.bazel"),
            Path(os.path.expanduser("~/.bazelrc"))
        ]

        for path in bazel_cache_paths:
            if path.exists() and path.is_dir():
                try:
                    size = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
                    locations.append(CacheLocation(
                        platform=CIPlatform.BAZEL,
                        path=path,
                        artifact_type=ArtifactType.BUILD_CACHE,
                        size_bytes=size,
                        last_accessed=datetime.fromtimestamp(path.stat().st_atime)
                    ))
                except (OSError, PermissionError) as e:
                    self.logger.warning(f"Cannot access {path}: {e}")

        return locations

    async def discover_gradle(self) -> List[CacheLocation]:
        """Discover Gradle cache and build directories."""
        locations = []

        gradle_cache_paths = [
            Path(os.path.expanduser("~/.gradle/caches")),
            Path(os.path.expanduser("~/.gradle/wrapper")),
            Path(os.path.expanduser("~/build-cache"))
        ]

        for path in gradle_cache_paths:
            if path.exists():
                try:
                    size = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
                    locations.append(CacheLocation(
                        platform=CIPlatform.GRADLE,
                        path=path,
                        artifact_type=ArtifactType.BUILD_CACHE,
                        size_bytes=size,
                        last_accessed=datetime.fromtimestamp(path.stat().st_atime)
                    ))
                except (OSError, PermissionError) as e:
                    self.logger.warning(f"Cannot access {path}: {e}")

        return locations

    async def discover_docker(self) -> List[CacheLocation]:
        """Discover Docker layer cache and build cache."""
        locations = []

        docker_paths = [
            Path("/var/lib/docker/image"),
            Path("/var/lib/docker/overlay2"),
            Path("/var/lib/docker/buildkit/cache"),
            Path(os.path.expanduser("~/.docker"))
        ]

        for path in docker_paths:
            if path.exists():
                try:
                    size = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
                    locations.append(CacheLocation(
                        platform=CIPlatform.DOCKER,
                        path=path,
                        artifact_type=ArtifactType.DOCKER_LAYER,
                        size_bytes=size,
                        last_accessed=datetime.fromtimestamp(path.stat().st_atime)
                    ))
                except (OSError, PermissionError) as e:
                    self.logger.warning(f"Cannot access {path}: {e}")

        # Also query Docker daemon directly
        try:
            result = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    "docker", "images", "--format", "json",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                ),
                timeout=10
            )
            stdout, _ = await result.communicate()
            self.logger.debug(f"Docker images: {stdout.decode()}")
        except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
            self.logger.debug(f"Docker daemon unavailable: {e}")

        return locations

    async def discover_package_manager_caches(self) -> List[CacheLocation]:
        """Discover npm, pip, cargo package manager caches."""
        locations = []

        cache_configs = [
            (CIPlatform.NPM, Path(os.path.expanduser("~/.npm")), ArtifactType.DEPENDENCY),
            (CIPlatform.NPM, Path(os.path.expanduser("~/.cache/npm")), ArtifactType.DEPENDENCY),
            (CIPlatform.PIP, Path(os.path.expanduser("~/.cache/pip")), ArtifactType.DEPENDENCY),
            (CIPlatform.CARGO, Path(os.path.expanduser("~/.cargo/registry")), ArtifactType.DEPENDENCY),
            (CIPlatform.CARGO, Path(os.path.expanduser("~/.cargo/cache")), ArtifactType.DEPENDENCY),
        ]

        for platform, path, artifact_type in cache_configs:
            if path.exists():
                try:
                    size = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
                    locations.append(CacheLocation(
                        platform=platform,
                        path=path,
                        artifact_type=artifact_type,
                        size_bytes=size,
                        last_accessed=datetime.fromtimestamp(path.stat().st_atime)
                    ))
                except (OSError, PermissionError) as e:
                    self.logger.warning(f"Cannot access {path}: {e}")

        return locations


class SupplyChainPolicyMonitor:
    """Monitor supply chain security policy transitions."""

    def __init__(self):
        """Initialize policy monitor."""
        self.policy_transitions: List[PolicyTransition] = []
        self.current_cve_database: Dict[str, List[str]] = {}
        self.current_blocklist: Set[str] = set()
        self.signing_keyring: Dict[str, Dict[str, Any]] = {}
        self.sbom_policy_version: int = 1
        self.logger = logger.getChild("SupplyChainPolicyMonitor")

    async def monitor_policy_changes(self) -> List[PolicyTransition]:
        """
        Monitor for supply chain policy transitions.

        Returns:
            List of detected policy transitions
        """
        tasks = [
            self._check_cve_updates(),
            self._check_sbom_policy(),
            self._check_signing_key_rotation(),
            self._check_blocklist_updates(),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Policy check failed: {result}")
            elif isinstance(result, PolicyTransition):
                self.policy_transitions.append(result)

        return self.policy_transitions

    async def _check_cve_updates(self) -> Optional[PolicyTransition]:
        """Check for CVE database updates."""
        # Simulate fetching OSV/NVD feeds
        new_cve_data = await self._fetch_cve_feeds()

        if new_cve_data != self.current_cve_database:
            transition = PolicyTransition(
                transition_type=PolicyTransitionType.CVE_UPDATE,
                timestamp=datetime.utcnow(),
                previous_state={"cve_database": self.current_cve_database},
                new_state={"cve_database": new_cve_data},
                affected_artifact_types=[ArtifactType.COMPILED_BINARY, ArtifactType.DEPENDENCY],
                severity="high",
                description="CVE database updated with new vulnerability information"
            )
            self.current_cve_database = new_cve_data
            self.logger.info(f"CVE database updated: {len(new_cve_data)} entries")
            return transition

        return None

    async def _check_sbom_policy(self) -> Optional[PolicyTransition]:
        """Check for SBOM policy changes."""
        # Check if SBOM policy version has been incremented
        new_version = await self._fetch_sbom_policy_version()

        if new_version != self.sbom_policy_version:
            transition = PolicyTransition(
                transition_type=PolicyTransitionType.SBOM_POLICY_CHANGE,
                timestamp=datetime.utcnow(),
                previous_state={"sbom_version": self.sbom_policy_version},
                new_state={"sbom_version": new_version},
                affected_artifact_types=[ArtifactType.SBOM, ArtifactType.DOCKER_LAYER],
                severity="critical",
                description=f"SBOM policy upgraded from v{self.sbom_policy_version} to v{new_version}"
            )
            self.sbom_policy_version = new_version
            self.logger.warning(f"SBOM policy changed: version {new_version}")
            return transition

        return None

    async def _check_signing_key_rotation(self) -> Optional[PolicyTransition]:
        """Check for signing key rotation."""
        new_keyring = await self._fetch_signing_keyring()

        old_keys = set(self.signing_keyring.keys())
        new_keys = set(new_keyring.keys())

        if old_keys != new_keys:
            rotated = old_keys.symmetric_difference(new_keys)
            transition = PolicyTransition(
                transition_type=PolicyTransitionType.SIGNING_KEY_ROTATION,
                timestamp=datetime.utcnow(),
                previous_state={"keyring": list(old_keys)},
                new_state={"keyring": list(new_keys)},
                affected_artifact_types=[ArtifactType.COMPILED_BINARY, ArtifactType.DOCKER_LAYER],
                severity="critical",
                description=f"Signing key rotation detected: {len(rotated)} keys changed"
            )
            self.signing_keyring = new_keyring
            self.logger.critical(f"Signing keys rotated: {rotated}")
            return transition

        return None

    async def _check_blocklist_updates(self) -> Optional[PolicyTransition]:
        """Check for banned dependency list updates."""
        new_blocklist = await self._fetch_dependency_blocklist()

        if new_blocklist != self.current_blocklist:
            added = new_blocklist - self.current_blocklist
            removed = self.current_blocklist - new_blocklist
            transition = PolicyTransition(
                transition_type=PolicyTransitionType.BLOCKLIST_UPDATE,
                timestamp=datetime.utcnow(),
                previous_state={"blocklist": list(self.current_blocklist)},
                new_state={"blocklist": list(new_blocklist)},
                affected_artifact_types=[ArtifactType.DEPENDENCY],
                severity="high",
                description=f"Dependency blocklist updated: +{len(added)}, -{len(removed)}"
            )
            self.current_blocklist = new_blocklist
            self.logger.info(f"Blocklist updated: added {len(added)}, removed {len(removed)}")
            return transition

        return None

    async def _fetch_cve_feeds(self) -> Dict[str, List[str]]:
        """Fetch CVE data from OSV/NVD feeds."""
        # Placeholder for actual feed fetching
        return {
            "curl": ["CVE-2024-0001", "CVE-2024-0002"],
            "openssl": ["CVE-2024-0010"],
            "zlib": ["CVE-2024-0020"]
        }

    async def _fetch_sbom_policy_version(self) -> int:
        """Fetch current SBOM policy version."""
        # Placeholder for actual policy fetch
        return self.sbom_policy_version + 1

    async def _fetch_signing_keyring(self) -> Dict[str, Dict[str, Any]]:
        """Fetch current signing keyring."""
        # Placeholder for actual keyring fetch
        return {
            "key-001": {"fingerprint": "ABCD1234", "valid": True},
            "key-002": {"fingerprint": "EFGH5678", "valid": True},
        }

    async def _fetch_dependency_blocklist(self) -> Set[str]:
        """Fetch current banned dependency list."""
        # Placeholder for actual blocklist fetch
        return {"malware-pkg-v1.0", "xz-backdoor", "compromised-lib-v2.3"}


class ArtifactValidator:
    """Validate cached artifacts against current supply chain policy."""

    def __init__(
        self,
        policy_monitor: SupplyChainPolicyMonitor,
        cache_discovery: CICDCacheDiscovery
    ):
        """
        Initialize artifact validator.

        Args:
            policy_monitor: Supply chain policy monitor instance
            cache_discovery: Cache discovery instance
        """
        self.policy_monitor = policy_monitor
        self.cache_discovery = cache_discovery
        self.logger = logger.getChild("ArtifactValidator")

    async def validate_all_artifacts(
        self,
        artifacts: List[CachedArtifact]
    ) -> Dict[str, ComplianceReport]:
        """
        Validate all cached artifacts against current policy.

        Args:
            artifacts: List of artifacts to validate

        Returns:
            Dictionary mapping artifact ID to compliance report
        """
        # Limit concurrent validations
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_VALIDATIONS)

        async def validate_with_limit(artifact: CachedArtifact) -> Tuple[str, ComplianceReport]:
            async with semaphore:
                return artifact.artifact_id, await self.validate_artifact(artifact)

        results = await asyncio.gather(
            *[validate_with_limit(artifact) for artifact in artifacts],
            return_exceptions=True
        )

        reports = {}
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Validation failed: {result}")
            else:
                artifact_id, report = result
                reports[artifact_id] = report

        return reports

    async def validate_artifact(
        self,
        artifact: CachedArtifact
    ) -> ComplianceReport:
        """
        Validate a single artifact against current policy.

        Args:
            artifact: Artifact to validate

        Returns:
            Compliance report for the artifact
        """
        report = ComplianceReport(artifact_id=artifact.artifact_id)

        # Check against CVE database
        cve_violations = await self._check_cve_compliance(artifact)
        report.vulnerabilities.extend(cve_violations)

        # Check signature validity
        sig_violations = await self._check_signature_compliance(artifact)
        report.policy_violations.extend(sig_violations)

        # Check dependency blocklist
        blocklist_violations = await self._check_blocklist_compliance(artifact)
        report.policy_violations.extend(blocklist_violations)

        # Generate SBOM
        sbom_components = await self._generate_sbom(artifact)
        report.components.extend(sbom_components)

        # Determine overall compliance
        report.compliant = len(report.vulnerabilities) == 0 and len(report.policy_violations) == 0
        artifact.policy_compliant = report.compliant

        self.logger.info(
            f"Artifact {artifact.artifact_id} validation: "
            f"compliant={report.compliant}, "
            f"vulnerabilities={len(report.vulnerabilities)}, "
            f"violations={len(report.policy_violations)}"
        )

        return report

    async def _check_cve_compliance(self, artifact: CachedArtifact) -> List[Dict[str, Any]]:
        """Check artifact against CVE database."""
        vulnerabilities = []

        # Check dependencies against CVE database
        for dep in artifact.dependencies:
            dep_name = dep.split("@")[0] if "@" in dep else dep

            if dep_name in self.policy_monitor.current_cve_database:
                cves = self.policy_monitor.current_cve_database[dep_name]
                for cve in cves:
                    vulnerabilities.append({
                        "cve": cve,
                        "dependency": dep,
                        "severity": "high",
                        "remediation": f"Update {dep_name} to patched version"
                    })
                    artifact.cve_matches.append(cve)

        return vulnerabilities

    async def _check_signature_compliance(self, artifact: CachedArtifact) -> List[str]:
        """Check artifact signatures against current keyring."""
        violations = []

        for sig_id, signature in artifact.signatures.items():
            if sig_id not in self.policy_monitor.signing_keyring:
                violations.append(
                    f"Signature {sig_id} not found in current keyring (key rotation?)"
                )
            else:
                key_info = self.policy_monitor.signing_keyring[sig_id]
                if not key_info.get("valid", False):
                    violations.append(f"Signature {sig_id} from revoked key")

        return violations

    async def _check_blocklist_compliance(self, artifact: CachedArtifact) -> List[str]:
        """Check dependencies against blocklist."""
        violations = []

        for dep in artifact.dependencies:
            if dep in self.policy_monitor.current_blocklist:
                violations.append(f"Dependency {dep} is blocked by policy")

        return violations

    async def _generate_sbom(self, artifact: CachedArtifact) -> List[Dict[str, str]]:
        """Generate SBOM for artifact."""
        components = []

        for dep in artifact.dependencies:
            components.append({
                "name": dep,
                "version": "unknown",  # Would be extracted from metadata
                "type": "library",
                "purl": f"pkg:generic/{dep}"
            })

        return components


class ArtifactMitigationController:
    """Purge and invalidate non-compliant cached artifacts."""

    def __init__(self, logger_instance: logging.Logger = None):
        """
        Initialize mitigation controller.

        Args:
            logger_instance: Optional custom logger
        """
        self.logger = logger_instance or logger.getChild("ArtifactMitigationController")
        self.mitigation_history: List[Dict[str, Any]] = []

    async def purge_noncompliant_artifacts(
        self,
        artifacts: List[CachedArtifact],
        compliance_reports: Dict[str, ComplianceReport],
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """
        Purge non-compliant cached artifacts.

        Args:
            artifacts: Artifacts to potentially purge
            compliance_reports: Compliance reports from validation
            dry_run: If True, don't actually delete (safety measure)

        Returns:
            Summary of purge operations
        """
        purged = []
        failed = []

        for artifact in artifacts:
            report = compliance_reports.get(artifact.artifact_id)
            if not report or not report.compliant:
                try:
                    await self._purge_artifact(artifact, dry_run=dry_run)
                    purged.append(artifact.artifact_id)
                except Exception as e:
                    self.logger.error(f"Failed to purge {artifact.artifact_id}: {e}")
                    failed.append((artifact.artifact_id, str(e)))

        summary = {
            "purged_count": len(purged),
            "failed_count": len(failed),
            "purged_artifacts": purged,
            "failed_artifacts": failed,
            "timestamp": datetime.utcnow().isoformat(),
            "dry_run": dry_run
        }

        self.mitigation_history.append(summary)
        self.logger.info(f"Purge operation completed: {summary}")

        return summary

    async def _purge_artifact(
        self,
        artifact: CachedArtifact,
        dry_run: bool = True
    ) -> None:
        """
        Purge a single artifact.

        Args:
            artifact: Artifact to purge
            dry_run: If True, don't actually delete

        Raises:
            OSError: If deletion fails
        """
        path = artifact.cache_location.path

        if not dry_run and path.exists():
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()

            self.logger.warning(f"Purged artifact: {artifact.artifact_id} at {path}")
        else:
            self.logger.info(f"[DRY RUN] Would purge artifact: {artifact.artifact_id} at {path}")

    async def invalidate_docker_layers(
        self,
        layer_ids: List[str],
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """
        Invalidate Docker layers containing banned dependencies.

        Args:
            layer_ids: Docker layer IDs to invalidate
            dry_run: If True, don't actually delete

        Returns:
            Invalidation summary
        """
        invalidated = []

        for layer_id in layer_ids:
            try:
                if not dry_run:
                    # Run: docker image rm <layer_id>
                    await self._run_docker_prune(layer_id)
                invalidated.append(layer_id)
                self.logger.warning(f"Invalidated Docker layer: {layer_id}")
            except Exception as e:
                self.logger.error(f"Failed to invalidate layer {layer_id}: {e}")

        return {
            "invalidated_layers": invalidated,
            "count": len(invalidated),
            "timestamp": datetime.utcnow().isoformat()
        }

    async def _run_docker_prune(self, layer_id: str) -> None:
        """Run docker prune command."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "image", "rm", layer_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.wait(), timeout=30)
        except (asyncio.TimeoutError, FileNotFoundError):
            pass

    async def trigger_rebuild(
        self,
        affected_cache_locations: List[CacheLocation]
    ) -> Dict[str, Any]:
        """
        Trigger rebuild of affected artifacts.

        Args:
            affected_cache_locations: Cache locations requiring rebuild

        Returns:
            Rebuild trigger summary
        """
        rebuild_triggered = []

        for location in affected_cache_locations:
            self.logger.info(f"Triggering rebuild for {location.platform.value} at {location.path}")
            rebuild_triggered.append({
                "platform": location.platform.value,
                "path": str(location.path),
                "timestamp": datetime.utcnow().isoformat()
            })

        return {
            "rebuild_triggered": rebuild_triggered,
            "count": len(rebuild_triggered)
        }

    async def atomic_cache_invalidation(
        self,
        cache_locations: List[CacheLocation],
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """
        Atomically invalidate caches across distributed CI runners.

        Args:
            cache_locations: All cache locations to invalidate
            dry_run: If True, don't actually delete

        Returns:
            Invalidation summary
        """
        invalidated = []
        failed = []

        for location in cache_locations:
            try:
                if not dry_run and location.path.exists():
                    if location.path.is_dir():
                        shutil.rmtree(location.path)
                    else:
                        location.path.unlink()

                invalidated.append(str(location.path))
                self.logger.warning(f"Invalidated cache: {location.path}")
            except Exception as e:
                failed.append((str(location.path), str(e)))
                self.logger.error(f"Failed to invalidate {location.path}: {e}")

        return {
            "invalidated": invalidated,
            "failed": failed,
            "timestamp": datetime.utcnow().isoformat(),
            "dry_run": dry_run
        }


async def main():
    """Main execution demonstrating the full workflow."""
    logger.info("Starting CI/CD Cache Validator")

    # 1. Discover caches
    discovery = CICDCacheDiscovery()
    cache_locations = await discovery.discover_all()
    logger.info(f"Discovered {len(cache_locations)} cache locations")

    # 2. Monitor policy changes
    monitor = SupplyChainPolicyMonitor()
    transitions = await monitor.monitor_policy_changes()
    logger.info(f"Detected {len(transitions)} policy transitions")

    # 3. Create sample artifacts for validation
    sample_artifacts = [
        CachedArtifact(
            artifact_id="app-v1.0.0",
            cache_location=cache_locations[0] if cache_locations else CacheLocation(
                platform=CIPlatform.DOCKER,
                path=Path("/tmp/test"),
                artifact_type=ArtifactType.DOCKER_LAYER
            ),
            artifact_type=ArtifactType.COMPILED_BINARY,
            created_timestamp=datetime.utcnow() - timedelta(days=7),
            content_hash="abc123def456",
            size_bytes=1024000,
            dependencies=["curl@7.88.0", "openssl@3.0.1"],
            signatures={"key-001": "sig_abc123"},
            metadata={"platform": "linux/amd64"}
        )
    ]

    # 4. Validate artifacts
    validator = ArtifactValidator(monitor, discovery)
    reports = await validator.validate_all_artifacts(sample_artifacts)
    logger.info(f"Validation complete: {len(reports)} artifacts checked")

    # 5. Mitigate non-compliant artifacts
    controller = ArtifactMitigationController()
    purge_summary = await controller.purge_noncompliant_artifacts(
        sample_artifacts,
        reports,
        dry_run=True  # Safety: dry run by default
    )
    logger.info(f"Mitigation complete: {purge_summary}")


if __name__ == "__main__":
    asyncio.run(main())
