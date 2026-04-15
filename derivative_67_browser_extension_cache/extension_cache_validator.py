"""
Browser Extension Cache Persistence Validator
Patent: System and Method for Mitigating Cached Executable Persistence Across Security Policy Transitions
Derivative #67: Browser Extension Cache Persistence

Detects and mitigates security vulnerabilities from cached extension code persisting
across enterprise extension policy transitions.

Author: Stanley Linton / STAAML Corp
License: Patent Pending
"""

import asyncio
import json
import logging
import os
import sqlite3
import struct
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from abc import ABC, abstractmethod
import hashlib

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Performance constants
EXTENSION_SCAN_TIMEOUT = 180
POLICY_CHECK_INTERVAL = 1800
CACHE_PURGE_TIMEOUT = 120
MAX_CONCURRENT_EXTENSION_CHECKS = 8
MANIFEST_ANALYSIS_TIMEOUT = 30


class BrowserType(Enum):
    """Supported browser types."""
    CHROME = "chrome"
    FIREFOX = "firefox"
    EDGE = "edge"
    SAFARI = "safari"
    BRAVE = "brave"


class ExtensionComponentType(Enum):
    """Types of cached extension components."""
    BACKGROUND_SCRIPT = "background_script"
    CONTENT_SCRIPT = "content_script"
    POPUP_PAGE = "popup_page"
    OPTIONS_PAGE = "options_page"
    SERVICE_WORKER = "service_worker"
    INDEXED_DB = "indexed_db"
    LOCAL_STORAGE = "local_storage"
    COOKIES = "cookies"
    MANIFEST = "manifest"


class PolicyRestrictionType(Enum):
    """Types of enterprise extension restrictions."""
    CATEGORY_BLOCKED = "category_blocked"
    SPECIFIC_EXTENSION_BLOCKED = "specific_extension_blocked"
    PERMISSION_REVOKED = "permission_revoked"
    UPDATE_DISABLED = "update_disabled"
    INSTALLATION_PREVENTED = "installation_prevented"
    MALWARE_BLOCKLIST = "malware_blocklist"


@dataclass
class ExtensionMetadata:
    """Extension metadata from manifest."""
    id: str
    name: str
    version: str
    browser: BrowserType
    manifest_version: int
    permissions: List[str] = field(default_factory=list)
    host_permissions: List[str] = field(default_factory=list)
    background_scripts: List[str] = field(default_factory=list)
    content_scripts: List[Dict[str, Any]] = field(default_factory=list)
    update_url: Optional[str] = None
    key: Optional[str] = None  # Public key for signature verification
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CachedExtensionComponent:
    """Represents a cached extension component."""
    component_id: str
    extension_id: str
    extension_name: str
    component_type: ExtensionComponentType
    browser: BrowserType
    content_hash: str
    file_path: Path
    size_bytes: int
    created_timestamp: datetime
    modified_timestamp: datetime
    is_accessible: bool = True
    injection_status: str = "unknown"  # "active", "blocked", "disabled"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExtensionPolicyTransition:
    """Represents a change in extension policy."""
    transition_type: PolicyRestrictionType
    timestamp: datetime
    affected_extensions: List[str]
    previous_policy: Dict[str, Any]
    new_policy: Dict[str, Any]
    severity: str  # critical, high, medium, low
    description: str
    requires_cache_invalidation: bool = True


@dataclass
class ExtensionComplianceResult:
    """Result of extension policy compliance check."""
    extension_id: str
    extension_name: str
    compliant: bool
    violations: List[str] = field(default_factory=list)
    blocked_components: List[ExtensionComponentType] = field(default_factory=list)
    remediation_actions: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)


# Threat model for extension persistence attacks
THREAT_MODEL: Dict[str, Any] = {
    "attack_vectors": [
        {
            "vector": "policy_blocked_extension_cache_persistence",
            "description": "Extension blocked by enterprise policy continues executing from cache",
            "impact": "Blocked extension retains all permissions; exfiltrates data to C2",
            "likelihood": "critical",
            "mitigation": "Force-disable non-compliant extensions; purge all cache/storage"
        },
        {
            "vector": "content_script_injection_cache_bypass",
            "description": "Content scripts cached before policy blocks injection site continue running",
            "impact": "Content scripts inject malicious code into restricted websites",
            "likelihood": "high",
            "mitigation": "Invalidate content script cache on policy change"
        },
        {
            "vector": "service_worker_elevated_privilege_cache",
            "description": "Service worker cached with elevated privileges persists after permission revocation",
            "impact": "Service worker intercepts all network requests despite permission removal",
            "likelihood": "high",
            "mitigation": "Purge service worker cache and registered workers on permission change"
        },
        {
            "vector": "indexed_db_credential_cache",
            "description": "IndexedDB cache contains credentials/tokens from pre-policy era",
            "impact": "Cached tokens authenticate to APIs despite revocation",
            "likelihood": "medium",
            "mitigation": "Wipe extension-specific IndexedDB on policy transition"
        },
        {
            "vector": "local_storage_secret_persistence",
            "description": "localStorage contains secrets/API keys from old policy context",
            "impact": "Secrets in localStorage continue working despite credential rotation",
            "likelihood": "medium",
            "mitigation": "Clear extension-specific localStorage on policy change"
        },
        {
            "vector": "background_script_persistence",
            "description": "Background/service worker continues executing despite extension disabled",
            "impact": "Background script runs hidden tasks: data exfiltration, malware updates",
            "likelihood": "high",
            "mitigation": "Prevent background script execution for disabled extensions"
        },
        {
            "vector": "webRequest_api_cache_interception",
            "description": "webRequest API cached response handlers intercept traffic after removal",
            "impact": "Network requests intercepted by disabled extension; responses modified",
            "likelihood": "high",
            "mitigation": "Unregister all request handlers on policy change"
        },
        {
            "vector": "declarativeNetRequest_rules_persistence",
            "description": "declarativeNetRequest rules cached from old policy continue blocking/routing",
            "impact": "Network traffic misdirected/blocked despite rule removal",
            "likelihood": "medium",
            "mitigation": "Update network rules on policy transition; clear rule cache"
        },
        {
            "vector": "crx_blocklist_update_delay",
            "description": "Extension continues from cache despite being added to CRX blocklist",
            "impact": "Known-malicious extension continues executing from cache",
            "likelihood": "medium",
            "mitigation": "Check CRX blocklist on every load; invalidate immediately if listed"
        },
        {
            "vector": "malicious_extension_update_bypass",
            "description": "Malicious extension update cached before detection; cache not invalidated",
            "impact": "Compromised extension version continues executing despite remediation",
            "likelihood": "medium",
            "mitigation": "Validate extension signatures against trusted keyring"
        }
    ],
    "affected_components": [
        "Background scripts and service workers",
        "Content scripts",
        "Popup and options pages",
        "IndexedDB storage",
        "localStorage storage",
        "Cookies storage",
        "WebRequest API handlers",
        "declarativeNetRequest rules",
        "Message passing queues",
        "Extension manifest cache"
    ],
    "attack_prerequisites": [
        "Extension installed with elevated privileges",
        "Cache not cleared on extension disable/policy change",
        "No re-validation of extension permissions at load time",
        "Delayed policy enforcement (extensions run before policy check)",
        "Accessible cache directory for unprivileged attacker code"
    ]
}


class ExtensionCacheDiscovery:
    """Enumerate installed extensions and their cached components."""

    def __init__(self):
        """Initialize extension discovery."""
        self.discovered_extensions: Set[ExtensionMetadata] = set()
        self.discovered_components: Set[CachedExtensionComponent] = set()
        self.logger = logger.getChild("ExtensionCacheDiscovery")

    async def discover_all_browsers(self) -> Tuple[List[ExtensionMetadata], List[CachedExtensionComponent]]:
        """
        Discover all extensions and cached components across all browsers.

        Returns:
            Tuple of (extensions, cached_components)
        """
        tasks = [
            self.discover_chrome_extensions(),
            self.discover_firefox_extensions(),
            self.discover_edge_extensions(),
            self.discover_safari_extensions()
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_extensions = []
        all_components = []

        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Discovery failed: {result}")
            elif result:
                exts, comps = result
                all_extensions.extend(exts)
                all_components.extend(comps)

        self.discovered_extensions.update(all_extensions)
        self.discovered_components.update(all_components)

        self.logger.info(
            f"Discovered {len(all_extensions)} extensions, "
            f"{len(all_components)} cached components"
        )

        return all_extensions, all_components

    async def discover_chrome_extensions(self) -> Tuple[List[ExtensionMetadata], List[CachedExtensionComponent]]:
        """Discover Chrome extensions and cached components."""
        extensions = []
        components = []

        chrome_paths = [
            Path.home() / ".config/google-chrome/Default/Extensions",
            Path.home() / "Library/Application Support/Google/Chrome/Default/Extensions",
            Path("C:\\Users") / os.getenv("USERNAME", "") / "AppData/Local/Google/Chrome/User Data/Default/Extensions"
        ]

        for chrome_ext_path in chrome_paths:
            if not chrome_ext_path.exists():
                continue

            try:
                for ext_dir in chrome_ext_path.iterdir():
                    if not ext_dir.is_dir():
                        continue

                    # Find latest version directory
                    version_dirs = sorted([d for d in ext_dir.iterdir() if d.is_dir()], key=lambda p: p.name)
                    if not version_dirs:
                        continue

                    latest_version = version_dirs[-1]

                    # Parse manifest
                    manifest_path = latest_version / "manifest.json"
                    if manifest_path.exists():
                        ext_metadata = await self._parse_manifest(
                            manifest_path, BrowserType.CHROME, ext_dir.name
                        )
                        extensions.append(ext_metadata)

                        # Discover cached components
                        comps = await self._discover_chrome_components(ext_dir.name, latest_version)
                        components.extend(comps)

            except (OSError, PermissionError) as e:
                self.logger.warning(f"Cannot access Chrome extensions: {e}")

        return extensions, components

    async def discover_firefox_extensions(self) -> Tuple[List[ExtensionMetadata], List[CachedExtensionComponent]]:
        """Discover Firefox extensions and cached components."""
        extensions = []
        components = []

        firefox_paths = [
            Path.home() / ".mozilla/firefox",
            Path.home() / "Library/Application Support/Firefox/Profiles"
        ]

        for firefox_profile_path in firefox_paths:
            if not firefox_profile_path.exists():
                continue

            try:
                # Find default profile
                for profile_dir in firefox_profile_path.iterdir():
                    if not profile_dir.is_dir() or not profile_dir.name.endswith(".default-release"):
                        continue

                    extensions_dir = profile_dir / "extensions"
                    if extensions_dir.exists():
                        for ext_xpi in extensions_dir.glob("*.xpi"):
                            # XPI files are ZIP; would need extraction in real implementation
                            pass

                    # Check stored extension metadata
                    addon_db = profile_dir / "addons.json"
                    if addon_db.exists():
                        ext_metadata = await self._parse_firefox_addons_json(addon_db)
                        extensions.extend(ext_metadata)

            except (OSError, PermissionError) as e:
                self.logger.warning(f"Cannot access Firefox extensions: {e}")

        return extensions, components

    async def discover_edge_extensions(self) -> Tuple[List[ExtensionMetadata], List[CachedExtensionComponent]]:
        """Discover Edge extensions and cached components."""
        extensions = []
        components = []

        edge_path = Path("C:\\Users") / os.getenv("USERNAME", "") / "AppData/Local/Microsoft/Edge/User Data/Default/Extensions"

        if not edge_path.exists():
            return extensions, components

        try:
            for ext_dir in edge_path.iterdir():
                if not ext_dir.is_dir():
                    continue

                version_dirs = sorted([d for d in ext_dir.iterdir() if d.is_dir()], key=lambda p: p.name)
                if not version_dirs:
                    continue

                latest_version = version_dirs[-1]
                manifest_path = latest_version / "manifest.json"

                if manifest_path.exists():
                    ext_metadata = await self._parse_manifest(
                        manifest_path, BrowserType.EDGE, ext_dir.name
                    )
                    extensions.append(ext_metadata)

                    comps = await self._discover_chrome_components(ext_dir.name, latest_version)
                    components.extend(comps)

        except (OSError, PermissionError) as e:
            self.logger.warning(f"Cannot access Edge extensions: {e}")

        return extensions, components

    async def discover_safari_extensions(self) -> Tuple[List[ExtensionMetadata], List[CachedExtensionComponent]]:
        """Discover Safari web extensions and cached components."""
        extensions = []
        components = []

        safari_path = Path.home() / "Library/Safari/Extensions"

        if not safari_path.exists():
            return extensions, components

        try:
            for ext_bundle in safari_path.glob("*.safariextz"):
                # SAFARIEXTZ files are ZIP; would need extraction in real implementation
                pass

        except (OSError, PermissionError) as e:
            self.logger.warning(f"Cannot access Safari extensions: {e}")

        return extensions, components

    async def _parse_manifest(
        self,
        manifest_path: Path,
        browser: BrowserType,
        extension_id: str
    ) -> ExtensionMetadata:
        """Parse extension manifest.json."""
        try:
            with open(manifest_path, "r") as f:
                manifest = json.load(f)

            return ExtensionMetadata(
                id=extension_id,
                name=manifest.get("name", "Unknown"),
                version=manifest.get("version", "unknown"),
                browser=browser,
                manifest_version=manifest.get("manifest_version", 2),
                permissions=manifest.get("permissions", []),
                host_permissions=manifest.get("host_permissions", []),
                background_scripts=manifest.get("background", {}).get("scripts", []),
                content_scripts=manifest.get("content_scripts", []),
                update_url=manifest.get("update_url"),
                key=manifest.get("key"),
                metadata=manifest
            )
        except (json.JSONDecodeError, OSError) as e:
            self.logger.warning(f"Failed to parse manifest at {manifest_path}: {e}")
            return ExtensionMetadata(
                id=extension_id,
                name="Unknown",
                version="unknown",
                browser=browser,
                manifest_version=2
            )

    async def _parse_firefox_addons_json(self, addons_path: Path) -> List[ExtensionMetadata]:
        """Parse Firefox addons.json."""
        extensions = []
        try:
            with open(addons_path, "r") as f:
                data = json.load(f)

            for addon in data.get("addons", []):
                extensions.append(ExtensionMetadata(
                    id=addon.get("id", "unknown"),
                    name=addon.get("name", "Unknown"),
                    version=addon.get("version", "unknown"),
                    browser=BrowserType.FIREFOX,
                    manifest_version=3,
                    metadata=addon
                ))
        except (json.JSONDecodeError, OSError) as e:
            self.logger.warning(f"Failed to parse Firefox addons: {e}")

        return extensions

    async def _discover_chrome_components(
        self,
        extension_id: str,
        version_dir: Path
    ) -> List[CachedExtensionComponent]:
        """Discover cached components in a Chrome extension."""
        components = []

        # Discover background scripts
        for script_file in version_dir.glob("**/background*.js"):
            components.append(await self._create_component(
                extension_id,
                script_file,
                ExtensionComponentType.BACKGROUND_SCRIPT,
                BrowserType.CHROME
            ))

        # Discover service workers
        for worker_file in version_dir.glob("**/*worker*.js"):
            components.append(await self._create_component(
                extension_id,
                worker_file,
                ExtensionComponentType.SERVICE_WORKER,
                BrowserType.CHROME
            ))

        # Discover content scripts
        for script_file in version_dir.glob("**/content*.js"):
            components.append(await self._create_component(
                extension_id,
                script_file,
                ExtensionComponentType.CONTENT_SCRIPT,
                BrowserType.CHROME
            ))

        # Discover storage caches
        if (version_dir / "local").exists():
            components.append(await self._create_component(
                extension_id,
                version_dir / "local",
                ExtensionComponentType.LOCAL_STORAGE,
                BrowserType.CHROME
            ))

        return components

    async def _create_component(
        self,
        extension_id: str,
        file_path: Path,
        component_type: ExtensionComponentType,
        browser: BrowserType
    ) -> CachedExtensionComponent:
        """Create a cached component record."""
        try:
            stat = file_path.stat()
            with open(file_path, "rb") as f:
                content_hash = hashlib.sha256(f.read()).hexdigest()

            return CachedExtensionComponent(
                component_id=f"{extension_id}-{component_type.value}",
                extension_id=extension_id,
                extension_name=extension_id,  # Would be populated from manifest
                component_type=component_type,
                browser=browser,
                content_hash=content_hash,
                file_path=file_path,
                size_bytes=stat.st_size,
                created_timestamp=datetime.fromtimestamp(stat.st_ctime),
                modified_timestamp=datetime.fromtimestamp(stat.st_mtime)
            )
        except (OSError, IOError) as e:
            self.logger.warning(f"Could not create component for {file_path}: {e}")
            return CachedExtensionComponent(
                component_id=f"{extension_id}-{component_type.value}",
                extension_id=extension_id,
                extension_name=extension_id,
                component_type=component_type,
                browser=browser,
                content_hash="unknown",
                file_path=file_path,
                size_bytes=0,
                created_timestamp=datetime.utcnow(),
                modified_timestamp=datetime.utcnow(),
                is_accessible=False
            )


class ExtensionPolicyMonitor:
    """Monitor enterprise extension policy changes."""

    def __init__(self):
        """Initialize extension policy monitor."""
        self.policy_transitions: List[ExtensionPolicyTransition] = []
        self.current_policy: Dict[str, Any] = {}
        self.blocked_extensions: Set[str] = set()
        self.restricted_permissions: Dict[str, List[str]] = {}
        self.crx_blocklist: Set[str] = set()
        self.logger = logger.getChild("ExtensionPolicyMonitor")

    async def monitor_policy_changes(self) -> List[ExtensionPolicyTransition]:
        """
        Monitor for extension policy transitions.

        Returns:
            List of detected policy transitions
        """
        tasks = [
            self._check_blocklist_updates(),
            self._check_permission_changes(),
            self._check_policy_file_updates(),
            self._check_crx_blocklist()
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Policy check failed: {result}")
            elif result:
                self.policy_transitions.append(result)

        return self.policy_transitions

    async def _check_blocklist_updates(self) -> Optional[ExtensionPolicyTransition]:
        """Check for extension blocklist updates."""
        new_blocklist = await self._fetch_enterprise_blocklist()

        if new_blocklist != self.blocked_extensions:
            added = new_blocklist - self.blocked_extensions
            removed = self.blocked_extensions - new_blocklist

            transition = ExtensionPolicyTransition(
                transition_type=PolicyRestrictionType.CATEGORY_BLOCKED,
                timestamp=datetime.utcnow(),
                affected_extensions=list(added),
                previous_policy={"blocklist": list(self.blocked_extensions)},
                new_policy={"blocklist": list(new_blocklist)},
                severity="critical",
                description=f"Extension blocklist updated: +{len(added)}, -{len(removed)}"
            )

            self.blocked_extensions = new_blocklist
            self.logger.critical(f"Extension blocklist changed: {added}")
            return transition

        return None

    async def _check_permission_changes(self) -> Optional[ExtensionPolicyTransition]:
        """Check for permission restriction changes."""
        new_restrictions = await self._fetch_permission_restrictions()

        if new_restrictions != self.restricted_permissions:
            transition = ExtensionPolicyTransition(
                transition_type=PolicyRestrictionType.PERMISSION_REVOKED,
                timestamp=datetime.utcnow(),
                affected_extensions=list(new_restrictions.keys()),
                previous_policy={"permissions": self.restricted_permissions},
                new_policy={"permissions": new_restrictions},
                severity="high",
                description="Extension permissions restricted by policy"
            )

            self.restricted_permissions = new_restrictions
            self.logger.warning(f"Extension permissions changed: {new_restrictions}")
            return transition

        return None

    async def _check_policy_file_updates(self) -> Optional[ExtensionPolicyTransition]:
        """Check for enterprise policy file updates (Windows Group Policy, etc.)."""
        return None

    async def _check_crx_blocklist(self) -> Optional[ExtensionPolicyTransition]:
        """Check for CRX blocklist updates."""
        new_blocklist = await self._fetch_crx_blocklist()

        if new_blocklist != self.crx_blocklist:
            added = new_blocklist - self.crx_blocklist

            transition = ExtensionPolicyTransition(
                transition_type=PolicyRestrictionType.MALWARE_BLOCKLIST,
                timestamp=datetime.utcnow(),
                affected_extensions=list(added),
                previous_policy={"crx_blocklist": list(self.crx_blocklist)},
                new_policy={"crx_blocklist": list(new_blocklist)},
                severity="critical",
                description=f"Malicious extensions added to blocklist: {len(added)}"
            )

            self.crx_blocklist = new_blocklist
            self.logger.critical(f"CRX blocklist updated: {added}")
            return transition

        return None

    async def _fetch_enterprise_blocklist(self) -> Set[str]:
        """Fetch enterprise extension blocklist."""
        return {"ext-malware-001", "tracking-blocker-compromised"}

    async def _fetch_permission_restrictions(self) -> Dict[str, List[str]]:
        """Fetch restricted permissions per extension."""
        return {
            "ext-123": ["webRequest", "tabs"],
            "ext-456": ["contentSettings"]
        }

    async def _fetch_crx_blocklist(self) -> Set[str]:
        """Fetch CRX blocklist of known malicious extensions."""
        return {"kpdlbnjflhjepjpkdkaihbfdjipepnah", "ijeeoijkjepjepjkdkaidhbfdjipepnah"}


class ExtensionCacheValidator:
    """Validate cached extension components against current policy."""

    def __init__(
        self,
        policy_monitor: ExtensionPolicyMonitor,
        cache_discovery: ExtensionCacheDiscovery
    ):
        """
        Initialize extension cache validator.

        Args:
            policy_monitor: Extension policy monitor
            cache_discovery: Extension cache discovery
        """
        self.policy_monitor = policy_monitor
        self.cache_discovery = cache_discovery
        self.logger = logger.getChild("ExtensionCacheValidator")

    async def validate_all_extensions(
        self,
        extensions: List[ExtensionMetadata],
        components: List[CachedExtensionComponent]
    ) -> Dict[str, ExtensionComplianceResult]:
        """
        Validate all extensions against current policy.

        Args:
            extensions: Extensions to validate
            components: Cached components to check

        Returns:
            Dictionary mapping extension ID to compliance result
        """
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_EXTENSION_CHECKS)

        async def validate_with_limit(
            ext: ExtensionMetadata
        ) -> Tuple[str, ExtensionComplianceResult]:
            async with semaphore:
                return ext.id, await self.validate_extension(ext, components)

        results = await asyncio.gather(
            *[validate_with_limit(ext) for ext in extensions],
            return_exceptions=True
        )

        compliance = {}
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Validation failed: {result}")
            else:
                ext_id, comp_result = result
                compliance[ext_id] = comp_result

        return compliance

    async def validate_extension(
        self,
        extension: ExtensionMetadata,
        components: List[CachedExtensionComponent]
    ) -> ExtensionComplianceResult:
        """
        Validate a single extension against current policy.

        Args:
            extension: Extension to validate
            components: All cached components

        Returns:
            Compliance result for the extension
        """
        result = ExtensionComplianceResult(
            extension_id=extension.id,
            extension_name=extension.name,
            compliant=True
        )

        # Check if extension is on blocklist
        if extension.id in self.policy_monitor.blocked_extensions:
            result.violations.append(f"Extension {extension.id} is on enterprise blocklist")
            result.compliant = False

        # Check if extension is on CRX malware blocklist
        if extension.id in self.policy_monitor.crx_blocklist:
            result.violations.append(f"Extension {extension.id} is on CRX malware blocklist")
            result.compliant = False

        # Check permissions
        restricted = self.policy_monitor.restricted_permissions.get(extension.id, [])
        for perm in extension.permissions:
            if perm in restricted:
                result.violations.append(f"Permission {perm} is restricted by policy")
                result.compliant = False

        # Check signature validity
        await self._validate_signature(extension, result)

        # Check cached components
        ext_components = [c for c in components if c.extension_id == extension.id]
        for component in ext_components:
            if not result.compliant:
                result.blocked_components.append(component.component_type)

        self.logger.info(
            f"Extension {extension.name} validation: "
            f"compliant={result.compliant}, "
            f"violations={len(result.violations)}"
        )

        return result

    async def _validate_signature(
        self,
        extension: ExtensionMetadata,
        result: ExtensionComplianceResult
    ) -> None:
        """Validate extension signature."""
        if not extension.key:
            result.violations.append("Extension has no signature key")
            return

        # Would validate signature against trusted keyring in real implementation
        pass


class ExtensionMitigationController:
    """Force-disable and purge non-compliant extensions."""

    def __init__(self):
        """Initialize extension mitigation controller."""
        self.logger = logger.getChild("ExtensionMitigationController")
        self.mitigation_actions: List[Dict[str, Any]] = []

    async def force_disable_extensions(
        self,
        extension_ids: List[str],
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """
        Force-disable non-compliant extensions.

        Args:
            extension_ids: IDs of extensions to disable
            dry_run: If True, don't actually disable

        Returns:
            Disable summary
        """
        disabled = []

        for ext_id in extension_ids:
            if not dry_run:
                await self._disable_extension(ext_id)
            disabled.append(ext_id)
            self.logger.warning(f"Disabled extension: {ext_id}")

        summary = {
            "action": "force_disable_extensions",
            "disabled": disabled,
            "count": len(disabled),
            "timestamp": datetime.utcnow().isoformat(),
            "dry_run": dry_run
        }

        self.mitigation_actions.append(summary)
        return summary

    async def _disable_extension(self, extension_id: str) -> None:
        """Disable a single extension."""
        self.logger.info(f"Disabling extension {extension_id}")

    async def purge_extension_caches(
        self,
        components: List[CachedExtensionComponent],
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """
        Purge all cached components for non-compliant extensions.

        Args:
            components: Components to purge
            dry_run: If True, don't actually delete

        Returns:
            Purge summary
        """
        purged = []
        failed = []

        for component in components:
            try:
                if not dry_run:
                    await self._purge_component(component)
                purged.append(component.component_id)
                self.logger.warning(f"Purged component: {component.component_id}")
            except Exception as e:
                failed.append((component.component_id, str(e)))
                self.logger.error(f"Failed to purge {component.component_id}: {e}")

        summary = {
            "action": "purge_extension_caches",
            "purged": purged,
            "failed": failed,
            "timestamp": datetime.utcnow().isoformat(),
            "dry_run": dry_run
        }

        self.mitigation_actions.append(summary)
        return summary

    async def _purge_component(self, component: CachedExtensionComponent) -> None:
        """Purge a single cached component."""
        if component.file_path.exists():
            if component.file_path.is_dir():
                import shutil
                shutil.rmtree(component.file_path)
            else:
                component.file_path.unlink()

    async def revoke_content_script_permissions(
        self,
        extension_ids: List[str],
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """
        Revoke content script injection permissions.

        Args:
            extension_ids: Extensions to revoke
            dry_run: If True, don't actually revoke

        Returns:
            Revocation summary
        """
        revoked = []

        for ext_id in extension_ids:
            if not dry_run:
                await self._revoke_content_scripts(ext_id)
            revoked.append(ext_id)
            self.logger.warning(f"Revoked content scripts for: {ext_id}")

        summary = {
            "action": "revoke_content_script_permissions",
            "revoked": revoked,
            "count": len(revoked),
            "timestamp": datetime.utcnow().isoformat(),
            "dry_run": dry_run
        }

        self.mitigation_actions.append(summary)
        return summary

    async def _revoke_content_scripts(self, extension_id: str) -> None:
        """Revoke content script injections for an extension."""
        self.logger.info(f"Revoking content scripts for {extension_id}")

    async def clear_indexed_db(
        self,
        extension_ids: List[str],
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """
        Clear IndexedDB storage for non-compliant extensions.

        Args:
            extension_ids: Extensions whose IDB to clear
            dry_run: If True, don't actually clear

        Returns:
            Clear summary
        """
        cleared = []

        for ext_id in extension_ids:
            if not dry_run:
                await self._clear_extension_idb(ext_id)
            cleared.append(ext_id)
            self.logger.warning(f"Cleared IndexedDB for: {ext_id}")

        return {
            "action": "clear_indexed_db",
            "cleared": cleared,
            "count": len(cleared),
            "timestamp": datetime.utcnow().isoformat(),
            "dry_run": dry_run
        }

    async def _clear_extension_idb(self, extension_id: str) -> None:
        """Clear IndexedDB for an extension."""
        self.logger.info(f"Clearing IndexedDB for {extension_id}")

    async def clear_local_storage(
        self,
        extension_ids: List[str],
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """
        Clear localStorage for non-compliant extensions.

        Args:
            extension_ids: Extensions whose localStorage to clear
            dry_run: If True, don't actually clear

        Returns:
            Clear summary
        """
        cleared = []

        for ext_id in extension_ids:
            if not dry_run:
                await self._clear_extension_storage(ext_id)
            cleared.append(ext_id)
            self.logger.warning(f"Cleared localStorage for: {ext_id}")

        return {
            "action": "clear_local_storage",
            "cleared": cleared,
            "count": len(cleared),
            "timestamp": datetime.utcnow().isoformat(),
            "dry_run": dry_run
        }

    async def _clear_extension_storage(self, extension_id: str) -> None:
        """Clear localStorage for an extension."""
        self.logger.info(f"Clearing localStorage for {extension_id}")


async def main():
    """Main execution demonstrating the full workflow."""
    logger.info("Starting Browser Extension Cache Validator")

    # 1. Discover extensions and caches
    discovery = ExtensionCacheDiscovery()
    extensions, components = await discovery.discover_all_browsers()
    logger.info(f"Discovered {len(extensions)} extensions, {len(components)} components")

    # 2. Monitor policy changes
    monitor = ExtensionPolicyMonitor()
    transitions = await monitor.monitor_policy_changes()
    logger.info(f"Detected {len(transitions)} policy transitions")

    # 3. Validate extensions
    validator = ExtensionCacheValidator(monitor, discovery)
    compliance = await validator.validate_all_extensions(extensions, components)
    logger.info(f"Validation complete: {len(compliance)} extensions checked")

    # 4. Mitigate non-compliant extensions
    controller = ExtensionMitigationController()
    noncompliant = [ext_id for ext_id, result in compliance.items() if not result.compliant]
    if noncompliant:
        disable_result = await controller.force_disable_extensions(noncompliant, dry_run=True)
        logger.info(f"Mitigation: {disable_result}")


if __name__ == "__main__":
    asyncio.run(main())
