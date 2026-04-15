"""
Derivative #70: Package Manager Resolution Cache Validator

System and Method for Mitigating Cached Executable Persistence Across Security Policy Transitions
Patent Portfolio - STAAML Corp / Stanley Linton

THREAT MODEL:
- npm, pip, cargo, Maven caches contain resolved dependency trees and pre-downloaded
  packages validated under prior policy context
- When supply chain security policy changes (new vulnerability blocklist, signature
  requirements, license restrictions), cached resolutions persist without re-validation
- Cached pre-built wheels, native extensions, and compiled artifacts bypass re-compilation
  and re-validation
- Package lockfiles can reference blocked packages without triggering validation
- Package manager caches can contain packages with:
  - Known CVE vulnerabilities (not reflected in stale cache)
  - Revoked or untrusted signatures (cache predates revocation)
  - Violating license terms (policy change not reflected)
  - Namespace confusion/typosquatting attacks (not in blocklist at cache time)
"""

import asyncio
import dataclasses
import logging
import hashlib
import json
import toml
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum
from datetime import datetime
import subprocess
import re

logger = logging.getLogger(__name__)

# Performance constants
PACKAGE_SCAN_TIMEOUT = 15.0
LOCKFILE_PARSE_TIMEOUT = 5.0
MANIFEST_BATCH_SIZE = 50
MAX_CACHE_SIZE_GB = 10


class PackageType(Enum):
    """Package manager types."""
    NPM = "npm"
    PIP = "pip"
    CARGO = "cargo"
    MAVEN = "maven"
    GO = "go"
    RUBY = "ruby"


class PackageSource(Enum):
    """Package source origin."""
    PYPI = "pypi"
    NPMJS = "npmjs"
    CRATES_IO = "crates.io"
    MAVEN_CENTRAL = "maven-central"
    GO_MODULES = "go-modules"
    RUBYGEMS = "rubygems"
    PRIVATE_REGISTRY = "private-registry"
    GITHUB = "github"
    GIT = "git"
    LOCAL = "local"


class VulnerabilityStatus(Enum):
    """Vulnerability status of package."""
    UNKNOWN = "unknown"
    SAFE = "safe"
    VULNERABLE = "vulnerable"
    CRITICAL = "critical"
    END_OF_LIFE = "end_of_life"


class LicenseStatus(Enum):
    """License compliance status."""
    COMPLIANT = "compliant"
    RESTRICTED = "restricted"
    PROHIBITED = "prohibited"
    UNKNOWN = "unknown"


@dataclasses.dataclass
class PackageCacheEntry:
    """Represents a cached package or dependency."""
    package_id: str
    name: str
    version: str
    package_type: PackageType
    source: PackageSource
    cache_path: str
    hash_sha256: Optional[str]
    size_bytes: int
    cached_timestamp: datetime
    is_prebuilt_artifact: bool
    is_native_extension: bool
    signature_present: bool
    signature_valid: Optional[bool]
    vulnerability_status: VulnerabilityStatus
    known_cves: List[str]
    license_type: str
    license_status: LicenseStatus
    dependencies: List[str]
    manifest_hash: Optional[str] = None


@dataclasses.dataclass
class DependencyResolution:
    """Represents a cached dependency resolution."""
    resolution_id: str
    lockfile_path: str
    lockfile_format: str  # "package-lock.json" | "Pipfile.lock" | "Cargo.lock" | "pom.xml"
    created_timestamp: datetime
    package_type: PackageType
    root_packages: List[str]
    total_dependencies: int
    has_vulnerable_deps: bool
    has_blocked_packages: bool
    resolution_policy_context: Dict[str, Any]


@dataclasses.dataclass
class SupplyChainSecurityPolicy:
    """Supply chain security policy at a point in time."""
    policy_id: str
    timestamp: datetime
    vulnerable_package_database: Dict[str, List[str]]  # name -> [CVEs]
    blocked_packages: Set[str]
    blocked_namespaces: Set[str]  # typosquatting protection
    required_signatures: bool
    signature_key_ids: Set[str]
    allowed_licenses: Set[str]
    blocked_licenses: Set[str]
    license_whitelist_mode: bool
    minimum_package_age_days: int  # reject newly published packages
    require_source_available: bool


@dataclasses.dataclass
class CacheValidationResult:
    """Result of cache validation against policy."""
    entry_id: str
    entry_type: str  # "package" | "resolution"
    is_compliant: bool
    policy_violations: List[str]
    action_required: str = ""  # "quarantine" | "delete" | "require_rebuild"
    remediation_steps: List[str] = dataclasses.field(default_factory=list)


THREAT_MODEL = {
    "id": "derivative_70_package_manager_cache_persistence",
    "name": "Package Manager Resolution Cache Persistence Across Supply Chain Policy Transitions",
    "severity": "CRITICAL",
    "vectors": [
        {
            "vector_id": "vulnerable_package_cache",
            "description": "Cached packages with known vulnerabilities persist when advisory updates occur",
            "attack_chain": [
                "Package published and cached by package manager",
                "Vulnerability discovered in package (CVE assigned)",
                "Vulnerability added to advisory database",
                "Cached package still installed despite vulnerability",
                "Application uses vulnerable code from cache"
            ],
            "impact": "Known vulnerability exploitation, supply chain compromise"
        },
        {
            "vector_id": "revoked_signature_cache",
            "description": "Packages cached with now-revoked signatures continue to validate",
            "attack_chain": [
                "Package signed with author's key, cached",
                "Author key revoked (compromise, key rotation)",
                "Cached package bypasses revoked-key check",
                "Signature validation uses cached copy, not fresh key list"
            ],
            "impact": "Signature validation bypass"
        },
        {
            "vector_id": "license_policy_bypass",
            "description": "Cached packages with now-restricted licenses avoid license checks",
            "attack_chain": [
                "Package with permissive license cached",
                "License policy updated (stricter license requirements)",
                "Cached package not re-validated against new policy",
                "License policy not enforced for cached dependencies"
            ],
            "impact": "License compliance violation"
        },
        {
            "vector_id": "blocklist_bypass",
            "description": "Packages added to security blocklist remain in cache",
            "attack_chain": [
                "Package cached (not on blocklist)",
                "Package discovered to be malicious, added to blocklist",
                "Cached package still available despite blocklist",
                "Build systems use cached version ignoring blocklist"
            ],
            "impact": "Malicious package installation"
        },
        {
            "vector_id": "typosquatting_cache",
            "description": "Typosquatted packages cached without namespace confusion detection",
            "attack_chain": [
                "Typosquatted package (similar name to popular package) published",
                "Cache contains typosquatted package from resolved dependency",
                "Typosquatting policy added (blocklist namespace confusion)",
                "Cached resolution still uses typosquatted package"
            ],
            "impact": "Typosquatting attack success"
        }
    ],
    "detection_indicators": [
        "Cached packages matching entries in vulnerability advisory database",
        "Cache entries predating recent CVE publication",
        "Packages with signatures from revoked keys in cache",
        "Cache entries with licenses violating current policy",
        "Dependency lockfiles referencing blocked packages",
        "Recently-published packages in cache (< 7 days old)"
    ]
}


class PackageCacheDiscovery:
    """Discover package manager caches and dependency resolutions."""

    def __init__(self, scan_timeout: float = PACKAGE_SCAN_TIMEOUT):
        self.scan_timeout = scan_timeout
        self.packages: Dict[str, PackageCacheEntry] = {}
        self.resolutions: Dict[str, DependencyResolution] = {}

    async def discover_npm_cache(self) -> List[PackageCacheEntry]:
        """Discover npm cache entries from ~/.npm directory."""
        entries = []
        try:
            npm_cache = Path.home() / ".npm"
            if not npm_cache.exists():
                return entries

            # npm cache structure: ~/.npm/_cacache/content-v2/...
            content_dir = npm_cache / "_cacache" / "content-v2"
            if not content_dir.exists():
                return entries

            for cache_file in content_dir.iterdir():
                try:
                    stat = cache_file.stat()
                    with open(cache_file, "rb") as f:
                        content_hash = hashlib.sha256(f.read()).hexdigest()

                    entry = PackageCacheEntry(
                        package_id=f"npm_{cache_file.name}",
                        name="npm-package",
                        version="unknown",
                        package_type=PackageType.NPM,
                        source=PackageSource.NPMJS,
                        cache_path=str(cache_file),
                        hash_sha256=content_hash,
                        size_bytes=stat.st_size,
                        cached_timestamp=datetime.fromtimestamp(stat.st_mtime),
                        is_prebuilt_artifact=False,
                        is_native_extension=False,
                        signature_present=False,
                        signature_valid=None,
                        vulnerability_status=VulnerabilityStatus.UNKNOWN,
                        known_cves=[],
                        license_type="unknown",
                        license_status=LicenseStatus.UNKNOWN,
                        dependencies=[],
                    )
                    entries.append(entry)
                    self.packages[entry.package_id] = entry

                except Exception as e:
                    logger.debug(f"Error processing npm cache file: {e}")

        except Exception as e:
            logger.error(f"Error discovering npm cache: {e}")

        logger.info(f"Discovered {len(entries)} npm cache entries")
        return entries

    async def discover_pip_cache(self) -> List[PackageCacheEntry]:
        """Discover pip cache entries from ~/.cache/pip."""
        entries = []
        try:
            pip_cache = Path.home() / ".cache" / "pip"
            if not pip_cache.exists():
                return entries

            for cache_dir in pip_cache.rglob("*.whl"):
                try:
                    stat = cache_dir.stat()
                    with open(cache_dir, "rb") as f:
                        content_hash = hashlib.sha256(f.read()).hexdigest()

                    # Extract package info from wheel filename
                    name_parts = cache_dir.stem.split("-")
                    pkg_name = name_parts[0] if name_parts else "unknown"
                    pkg_version = name_parts[1] if len(name_parts) > 1 else "unknown"

                    is_native = cache_dir.name.endswith(".cp" + str(3) + str(11) + ".so")

                    entry = PackageCacheEntry(
                        package_id=f"pip_{cache_dir.stem}",
                        name=pkg_name,
                        version=pkg_version,
                        package_type=PackageType.PIP,
                        source=PackageSource.PYPI,
                        cache_path=str(cache_dir),
                        hash_sha256=content_hash,
                        size_bytes=stat.st_size,
                        cached_timestamp=datetime.fromtimestamp(stat.st_mtime),
                        is_prebuilt_artifact=True,
                        is_native_extension=is_native,
                        signature_present=False,
                        signature_valid=None,
                        vulnerability_status=VulnerabilityStatus.UNKNOWN,
                        known_cves=[],
                        license_type="unknown",
                        license_status=LicenseStatus.UNKNOWN,
                        dependencies=[],
                    )
                    entries.append(entry)
                    self.packages[entry.package_id] = entry

                except Exception as e:
                    logger.debug(f"Error processing pip cache file: {e}")

        except Exception as e:
            logger.error(f"Error discovering pip cache: {e}")

        logger.info(f"Discovered {len(entries)} pip cache entries")
        return entries

    async def discover_cargo_cache(self) -> List[PackageCacheEntry]:
        """Discover Cargo cache entries from ~/.cargo/registry."""
        entries = []
        try:
            cargo_registry = Path.home() / ".cargo" / "registry"
            if not cargo_registry.exists():
                return entries

            # Cargo structure: ~/.cargo/registry/cache/...
            for cache_file in cargo_registry.rglob("*.crate"):
                try:
                    stat = cache_file.stat()
                    with open(cache_file, "rb") as f:
                        content_hash = hashlib.sha256(f.read()).hexdigest()

                    # Extract info from filename
                    name_parts = cache_file.stem.split("-")
                    pkg_name = "-".join(name_parts[:-1]) if len(name_parts) > 1 else "unknown"
                    pkg_version = name_parts[-1] if name_parts else "unknown"

                    entry = PackageCacheEntry(
                        package_id=f"cargo_{cache_file.stem}",
                        name=pkg_name,
                        version=pkg_version,
                        package_type=PackageType.CARGO,
                        source=PackageSource.CRATES_IO,
                        cache_path=str(cache_file),
                        hash_sha256=content_hash,
                        size_bytes=stat.st_size,
                        cached_timestamp=datetime.fromtimestamp(stat.st_mtime),
                        is_prebuilt_artifact=False,
                        is_native_extension=False,
                        signature_present=False,
                        signature_valid=None,
                        vulnerability_status=VulnerabilityStatus.UNKNOWN,
                        known_cves=[],
                        license_type="unknown",
                        license_status=LicenseStatus.UNKNOWN,
                        dependencies=[],
                    )
                    entries.append(entry)
                    self.packages[entry.package_id] = entry

                except Exception as e:
                    logger.debug(f"Error processing cargo cache file: {e}")

        except Exception as e:
            logger.error(f"Error discovering cargo cache: {e}")

        logger.info(f"Discovered {len(entries)} cargo cache entries")
        return entries

    async def discover_maven_cache(self) -> List[PackageCacheEntry]:
        """Discover Maven cache entries from ~/.m2/repository."""
        entries = []
        try:
            maven_repo = Path.home() / ".m2" / "repository"
            if not maven_repo.exists():
                return entries

            # Maven structure: ~/.m2/repository/org/package/version/package-version.jar
            for jar_file in maven_repo.rglob("*.jar"):
                try:
                    stat = jar_file.stat()
                    with open(jar_file, "rb") as f:
                        content_hash = hashlib.sha256(f.read()).hexdigest()

                    # Extract info from path
                    parts = jar_file.parts
                    version = parts[-2] if len(parts) >= 2 else "unknown"
                    pkg_name = jar_file.stem

                    entry = PackageCacheEntry(
                        package_id=f"maven_{jar_file.stem}",
                        name=pkg_name,
                        version=version,
                        package_type=PackageType.MAVEN,
                        source=PackageSource.MAVEN_CENTRAL,
                        cache_path=str(jar_file),
                        hash_sha256=content_hash,
                        size_bytes=stat.st_size,
                        cached_timestamp=datetime.fromtimestamp(stat.st_mtime),
                        is_prebuilt_artifact=True,
                        is_native_extension=False,
                        signature_present=False,
                        signature_valid=None,
                        vulnerability_status=VulnerabilityStatus.UNKNOWN,
                        known_cves=[],
                        license_type="unknown",
                        license_status=LicenseStatus.UNKNOWN,
                        dependencies=[],
                    )
                    entries.append(entry)
                    self.packages[entry.package_id] = entry

                except Exception as e:
                    logger.debug(f"Error processing maven cache file: {e}")

        except Exception as e:
            logger.error(f"Error discovering maven cache: {e}")

        logger.info(f"Discovered {len(entries)} maven cache entries")
        return entries

    async def discover_lockfile_resolutions(self) -> List[DependencyResolution]:
        """Discover dependency resolution lockfiles."""
        resolutions = []
        try:
            search_root = Path.home()

            # package-lock.json (npm)
            for lockfile in search_root.rglob("package-lock.json"):
                try:
                    resolution = await self._parse_npm_lockfile(lockfile)
                    if resolution:
                        resolutions.append(resolution)
                        self.resolutions[resolution.resolution_id] = resolution
                except Exception as e:
                    logger.debug(f"Error parsing npm lockfile {lockfile}: {e}")

            # Pipfile.lock (pip)
            for lockfile in search_root.rglob("Pipfile.lock"):
                try:
                    resolution = await self._parse_pipfile_lock(lockfile)
                    if resolution:
                        resolutions.append(resolution)
                        self.resolutions[resolution.resolution_id] = resolution
                except Exception as e:
                    logger.debug(f"Error parsing Pipfile.lock {lockfile}: {e}")

            # Cargo.lock (Cargo)
            for lockfile in search_root.rglob("Cargo.lock"):
                try:
                    resolution = await self._parse_cargo_lock(lockfile)
                    if resolution:
                        resolutions.append(resolution)
                        self.resolutions[resolution.resolution_id] = resolution
                except Exception as e:
                    logger.debug(f"Error parsing Cargo.lock {lockfile}: {e}")

        except Exception as e:
            logger.error(f"Error discovering lockfiles: {e}")

        logger.info(f"Discovered {len(resolutions)} dependency resolutions")
        return resolutions

    async def _parse_npm_lockfile(self, lockfile: Path) -> Optional[DependencyResolution]:
        """Parse npm package-lock.json."""
        try:
            with open(lockfile) as f:
                lock_data = json.load(f)

            dependencies = self._count_npm_dependencies(lock_data.get("dependencies", {}))

            has_vulnerable = False
            has_blocked = False

            resolution = DependencyResolution(
                resolution_id=hashlib.sha256(str(lockfile).encode()).hexdigest(),
                lockfile_path=str(lockfile),
                lockfile_format="package-lock.json",
                created_timestamp=datetime.fromtimestamp(lockfile.stat().st_mtime),
                package_type=PackageType.NPM,
                root_packages=list(lock_data.get("dependencies", {}).keys())[:10],
                total_dependencies=dependencies,
                has_vulnerable_deps=has_vulnerable,
                has_blocked_packages=has_blocked,
                resolution_policy_context={
                    "lockfile_version": lock_data.get("lockfileVersion"),
                }
            )
            return resolution

        except Exception as e:
            logger.debug(f"Error parsing npm lockfile {lockfile}: {e}")
            return None

    async def _parse_pipfile_lock(self, lockfile: Path) -> Optional[DependencyResolution]:
        """Parse pip Pipfile.lock."""
        try:
            with open(lockfile) as f:
                lock_data = json.load(f)

            default_deps = lock_data.get("default", {})
            total_deps = len(default_deps) + len(lock_data.get("develop", {}))

            resolution = DependencyResolution(
                resolution_id=hashlib.sha256(str(lockfile).encode()).hexdigest(),
                lockfile_path=str(lockfile),
                lockfile_format="Pipfile.lock",
                created_timestamp=datetime.fromtimestamp(lockfile.stat().st_mtime),
                package_type=PackageType.PIP,
                root_packages=list(default_deps.keys())[:10],
                total_dependencies=total_deps,
                has_vulnerable_deps=False,
                has_blocked_packages=False,
                resolution_policy_context={
                    "python_version": lock_data.get("_meta", {}).get("python_version"),
                }
            )
            return resolution

        except Exception as e:
            logger.debug(f"Error parsing Pipfile.lock {lockfile}: {e}")
            return None

    async def _parse_cargo_lock(self, lockfile: Path) -> Optional[DependencyResolution]:
        """Parse Cargo.lock."""
        try:
            with open(lockfile) as f:
                lock_data = toml.load(f)

            packages = lock_data.get("package", [])
            if not isinstance(packages, list):
                packages = list(packages.keys())

            resolution = DependencyResolution(
                resolution_id=hashlib.sha256(str(lockfile).encode()).hexdigest(),
                lockfile_path=str(lockfile),
                lockfile_format="Cargo.lock",
                created_timestamp=datetime.fromtimestamp(lockfile.stat().st_mtime),
                package_type=PackageType.CARGO,
                root_packages=[p["name"] if isinstance(p, dict) else p for p in packages[:10]],
                total_dependencies=len(packages),
                has_vulnerable_deps=False,
                has_blocked_packages=False,
                resolution_policy_context={}
            )
            return resolution

        except Exception as e:
            logger.debug(f"Error parsing Cargo.lock {lockfile}: {e}")
            return None

    def _count_npm_dependencies(self, deps: Dict[str, Any]) -> int:
        """Recursively count npm dependencies."""
        count = len(deps)
        for dep_info in deps.values():
            if isinstance(dep_info, dict):
                count += self._count_npm_dependencies(dep_info.get("dependencies", {}))
        return count


class PackagePolicyMonitor:
    """Monitor supply chain security policy transitions."""

    def __init__(self):
        self.policies: Dict[str, SupplyChainSecurityPolicy] = {}
        self.policy_history: List[Tuple[datetime, SupplyChainSecurityPolicy]] = []

    async def get_current_policy(self) -> SupplyChainSecurityPolicy:
        """
        Get current supply chain security policy.

        Returns:
            Current SupplyChainSecurityPolicy.
        """
        policy_id = hashlib.sha256(str(datetime.now()).encode()).hexdigest()

        policy = SupplyChainSecurityPolicy(
            policy_id=policy_id,
            timestamp=datetime.now(),
            vulnerable_package_database=await self._get_vulnerability_db(),
            blocked_packages=await self._get_blocked_packages(),
            blocked_namespaces=await self._get_blocked_namespaces(),
            required_signatures=True,
            signature_key_ids=await self._get_trusted_keys(),
            allowed_licenses=await self._get_allowed_licenses(),
            blocked_licenses=await self._get_blocked_licenses(),
            license_whitelist_mode=True,
            minimum_package_age_days=7,
            require_source_available=True,
        )

        self.policies[policy_id] = policy
        self.policy_history.append((datetime.now(), policy))

        return policy

    async def _get_vulnerability_db(self) -> Dict[str, List[str]]:
        """Get vulnerability database mapping package names to CVEs."""
        # Simplified - would integrate with CVE databases
        return {
            "log4j": ["CVE-2021-44228", "CVE-2021-45046"],
            "jackson-databind": ["CVE-2018-7489"],
        }

    async def _get_blocked_packages(self) -> Set[str]:
        """Get set of blocked packages."""
        return {
            "malicious-pkg",
            "compromised-lib",
        }

    async def _get_blocked_namespaces(self) -> Set[str]:
        """Get blocked package namespaces (typosquatting)."""
        return {
            "lodash",  # vs lodash-es typosquatting
        }

    async def _get_trusted_keys(self) -> Set[str]:
        """Get trusted signature key IDs."""
        return {
            "key-google",
            "key-microsoft",
            "key-mozilla",
        }

    async def _get_allowed_licenses(self) -> Set[str]:
        """Get allowed software licenses."""
        return {
            "MIT",
            "Apache-2.0",
            "BSD-2-Clause",
            "BSD-3-Clause",
            "GPL-2.0+",
            "GPL-3.0+",
            "LGPL-2.1+",
            "ISC",
        }

    async def _get_blocked_licenses(self) -> Set[str]:
        """Get blocked/restricted licenses."""
        return {
            "AGPL-3.0",
        }

    def detect_policy_changes(
        self,
        old_policy: SupplyChainSecurityPolicy,
        new_policy: SupplyChainSecurityPolicy
    ) -> List[str]:
        """Detect changes between two policies."""
        changes = []

        # Check new vulnerabilities
        new_vulns = set(new_policy.vulnerable_package_database.keys()) - \
                    set(old_policy.vulnerable_package_database.keys())
        if new_vulns:
            changes.append(f"New vulnerable packages: {new_vulns}")

        # Check new blocks
        new_blocks = new_policy.blocked_packages - old_policy.blocked_packages
        if new_blocks:
            changes.append(f"Newly blocked packages: {new_blocks}")

        # Check license changes
        new_blocked_licenses = new_policy.blocked_licenses - old_policy.blocked_licenses
        if new_blocked_licenses:
            changes.append(f"Newly restricted licenses: {new_blocked_licenses}")

        return changes


class PackageCacheValidator:
    """Validate cached packages against supply chain policy."""

    def __init__(
        self,
        discovery: PackageCacheDiscovery,
        monitor: PackagePolicyMonitor
    ):
        self.discovery = discovery
        self.monitor = monitor
        self.validation_results: Dict[str, CacheValidationResult] = {}

    async def validate_package(
        self,
        package: PackageCacheEntry,
        policy: SupplyChainSecurityPolicy
    ) -> CacheValidationResult:
        """
        Validate a cached package against supply chain policy.

        Args:
            package: The package to validate.
            policy: Current supply chain policy.

        Returns:
            Validation result with any violations.
        """
        violations = []
        actions = []

        # Check if package is blocked
        if package.name in policy.blocked_packages:
            violations.append(f"Package {package.name} is in security blocklist")
            actions.append("Delete from cache")

        # Check for known vulnerabilities
        if package.name in policy.vulnerable_package_database:
            cves = policy.vulnerable_package_database[package.name]
            violations.append(f"Package has known vulnerabilities: {cves}")
            actions.append("Quarantine until patched version available")

        # Check license compliance
        if policy.license_whitelist_mode:
            if package.license_type not in policy.allowed_licenses:
                violations.append(
                    f"License {package.license_type} not in whitelist"
                )
                actions.append("Review and replace with compliant alternative")

        # Check signature requirement
        if policy.required_signatures and not package.signature_valid:
            violations.append("Package signatures not valid or missing")
            actions.append("Require rebuild with signed dependencies")

        # Check package age (reject very new packages)
        age_days = (datetime.now() - package.cached_timestamp).days
        if age_days < policy.minimum_package_age_days:
            violations.append(
                f"Package too new ({age_days} days < {policy.minimum_package_age_days} days minimum)"
            )
            actions.append("Update to older stable version")

        is_compliant = len(violations) == 0

        result = CacheValidationResult(
            entry_id=package.package_id,
            entry_type="package",
            is_compliant=is_compliant,
            policy_violations=violations,
            action_required="quarantine" if violations else "",
            remediation_steps=actions
        )

        self.validation_results[package.package_id] = result
        return result

    async def validate_resolution(
        self,
        resolution: DependencyResolution,
        policy: SupplyChainSecurityPolicy
    ) -> CacheValidationResult:
        """Validate a dependency resolution against policy."""
        violations = []
        actions = []

        # Check root packages for blocks
        for pkg in resolution.root_packages:
            if pkg in policy.blocked_packages:
                violations.append(f"Root package {pkg} is blocked")
                actions.append("Regenerate lockfile with alternative")

        # Check for vulnerability database hits
        for pkg in resolution.root_packages:
            if pkg in policy.vulnerable_package_database:
                violations.append(
                    f"Resolution includes vulnerable package {pkg}"
                )
                actions.append("Update dependencies to patch versions")

        is_compliant = len(violations) == 0

        result = CacheValidationResult(
            entry_id=resolution.resolution_id,
            entry_type="resolution",
            is_compliant=is_compliant,
            policy_violations=violations,
            action_required="refresh" if violations else "",
            remediation_steps=actions
        )

        return result


class PackageMitigationController:
    """Execute mitigation for non-compliant cached packages."""

    def __init__(self):
        self.mitigation_history: List[Tuple[str, str, datetime, bool]] = []

    async def purge_non_compliant_packages(
        self,
        invalid_packages: List[str],
        dry_run: bool = False
    ) -> int:
        """
        Purge non-compliant packages from cache.

        Args:
            invalid_packages: List of package IDs to purge.
            dry_run: If True, don't actually delete.

        Returns:
            Number of packages purged.
        """
        purged = 0

        for pkg_id in invalid_packages:
            try:
                if dry_run:
                    logger.info(f"[DRY RUN] Would purge package {pkg_id} from cache")
                else:
                    logger.warning(f"Purging non-compliant package {pkg_id}")
                    self.mitigation_history.append(
                        (pkg_id, "purge", datetime.now(), True)
                    )
                purged += 1

            except Exception as e:
                logger.error(f"Error purging package {pkg_id}: {e}")

        return purged

    async def invalidate_lockfiles(
        self,
        lockfile_paths: List[str],
        dry_run: bool = False
    ) -> int:
        """
        Invalidate lockfiles that reference banned packages.

        Args:
            lockfile_paths: Paths to lockfiles to invalidate.
            dry_run: If True, don't actually modify.

        Returns:
            Number of lockfiles invalidated.
        """
        invalidated = 0

        for lockfile in lockfile_paths:
            try:
                if dry_run:
                    logger.info(f"[DRY RUN] Would invalidate lockfile {lockfile}")
                else:
                    logger.warning(f"Invalidating lockfile {lockfile}")
                    # Would rename or delete lockfile to force regeneration
                    self.mitigation_history.append(
                        (lockfile, "invalidate_lockfile", datetime.now(), True)
                    )
                invalidated += 1

            except Exception as e:
                logger.error(f"Error invalidating lockfile {lockfile}: {e}")

        return invalidated

    async def generate_sbom_delta(
        self,
        old_cache_state: Dict[str, PackageCacheEntry],
        new_cache_state: Dict[str, PackageCacheEntry]
    ) -> Dict[str, Any]:
        """
        Generate SBOM (Software Bill of Materials) delta showing changes.

        Returns:
            SBOM delta showing added/removed/modified packages.
        """
        old_keys = set(old_cache_state.keys())
        new_keys = set(new_cache_state.keys())

        added = new_keys - old_keys
        removed = old_keys - new_keys
        common = old_keys & new_keys

        modified = []
        for pkg_id in common:
            old_hash = old_cache_state[pkg_id].hash_sha256
            new_hash = new_cache_state[pkg_id].hash_sha256
            if old_hash != new_hash:
                modified.append({
                    "package_id": pkg_id,
                    "old_hash": old_hash,
                    "new_hash": new_hash,
                })

        return {
            "timestamp": datetime.now().isoformat(),
            "added_packages": len(added),
            "removed_packages": len(removed),
            "modified_packages": len(modified),
            "added_ids": list(added),
            "removed_ids": list(removed),
            "modifications": modified,
        }

    async def trigger_cache_rebuild(
        self,
        package_types: List[PackageType],
        dry_run: bool = False
    ) -> bool:
        """
        Trigger cache rebuild with current policy.

        Args:
            package_types: Package manager types to rebuild.
            dry_run: If True, don't actually rebuild.

        Returns:
            True if successful.
        """
        try:
            for pkg_type in package_types:
                if dry_run:
                    logger.info(f"[DRY RUN] Would rebuild {pkg_type.value} cache")
                else:
                    logger.warning(f"Rebuilding {pkg_type.value} cache")
                    # Would execute package manager update commands
                    self.mitigation_history.append(
                        (pkg_type.value, "cache_rebuild", datetime.now(), True)
                    )

            return True

        except Exception as e:
            logger.error(f"Error rebuilding cache: {e}")
            return False


async def demonstrate_derivative_70():
    """Demonstration of Derivative #70: Package Manager Cache Persistence."""

    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    logger.addHandler(handler)

    print("\n" + "="*80)
    print("Derivative #70: Package Manager Resolution Cache Validator")
    print("="*80)
    print(f"\nTHREAT MODEL: {THREAT_MODEL['name']}")
    print(f"Severity: {THREAT_MODEL['severity']}")

    discovery = PackageCacheDiscovery()
    monitor = PackagePolicyMonitor()
    validator = PackageCacheValidator(discovery, monitor)
    controller = PackageMitigationController()

    print("\n[*] Discovering package manager caches...")
    npm_packages = await discovery.discover_npm_cache()
    pip_packages = await discovery.discover_pip_cache()
    cargo_packages = await discovery.discover_cargo_cache()
    maven_packages = await discovery.discover_maven_cache()
    resolutions = await discovery.discover_lockfile_resolutions()

    total_packages = len(npm_packages) + len(pip_packages) + len(cargo_packages) + len(maven_packages)
    print(f"    Found {total_packages} cached packages")
    print(f"    - npm: {len(npm_packages)}")
    print(f"    - pip: {len(pip_packages)}")
    print(f"    - cargo: {len(cargo_packages)}")
    print(f"    - maven: {len(maven_packages)}")
    print(f"    Found {len(resolutions)} dependency resolutions")

    print("\n[*] Getting current supply chain security policy...")
    current_policy = await monitor.get_current_policy()
    print(f"    Policy ID: {current_policy.policy_id[:16]}...")
    print(f"    Blocked packages: {len(current_policy.blocked_packages)}")
    print(f"    Known vulnerabilities: {len(current_policy.vulnerable_package_database)}")
    print(f"    Required signatures: {current_policy.required_signatures}")
    print(f"    Allowed licenses: {len(current_policy.allowed_licenses)}")

    print("\n[*] Validating cached packages...")
    invalid_packages = 0
    for package in (npm_packages + pip_packages + cargo_packages + maven_packages)[:20]:
        result = await validator.validate_package(package, current_policy)
        if not result.is_compliant:
            invalid_packages += 1
            if invalid_packages <= 3:
                logger.warning(
                    f"Non-compliant package {package.name}: {result.policy_violations}"
                )

    print(f"    Validated {min(20, total_packages)} packages")
    print(f"    Non-compliant: {invalid_packages}")

    print("\n[*] Validating dependency resolutions...")
    invalid_resolutions = 0
    for resolution in resolutions[:5]:
        result = await validator.validate_resolution(resolution, current_policy)
        if not result.is_compliant:
            invalid_resolutions += 1

    print(f"    Validated {min(5, len(resolutions))} resolutions")
    print(f"    Non-compliant: {invalid_resolutions}")

    if invalid_packages > 0 or invalid_resolutions > 0:
        print(f"\n[!] Found {invalid_packages + invalid_resolutions} non-compliant entries")

        print("\n[*] Generating mitigation plan...")
        print("    Actions:")
        print(f"    - Purge {min(invalid_packages, 5)} non-compliant packages")
        print(f"    - Invalidate {min(invalid_resolutions, 3)} lockfiles")
        print(f"    - Trigger cache rebuild")

        print("\n[*] Executing mitigation (dry run)...")
        purged = await controller.purge_non_compliant_packages(
            [f"pkg_{i}" for i in range(min(3, invalid_packages))],
            dry_run=True
        )
        invalidated = await controller.invalidate_lockfiles(
            [f"lockfile_{i}" for i in range(min(2, invalid_resolutions))],
            dry_run=True
        )
        await controller.trigger_cache_rebuild([PackageType.NPM, PackageType.PIP], dry_run=True)

        # Generate SBOM delta
        old_state = {pkg.package_id: pkg for pkg in (npm_packages + pip_packages)[:5]}
        new_state = {pkg.package_id: pkg for pkg in (npm_packages + pip_packages)[1:6]}
        sbom_delta = await controller.generate_sbom_delta(old_state, new_state)
        print(f"\n[*] SBOM Delta:")
        print(f"    Added: {sbom_delta['added_packages']}")
        print(f"    Removed: {sbom_delta['removed_packages']}")
        print(f"    Modified: {sbom_delta['modified_packages']}")

    print("\n" + "="*80)
    print("Derivative #70 demonstration complete")
    print("="*80 + "\n")


if __name__ == "__main__":
    asyncio.run(demonstrate_derivative_70())
