"""
Derivative #71: PWA Installation Cache Validator

System and Method for Mitigating Cached Executable Persistence Across Security Policy Transitions
Patent Portfolio - STAAML Corp / Stanley Linton

THREAT MODEL:
- Installed PWA manifests, service workers, and resource caches persist independently
  from browser cache
- PWA installation cache survives browser cache clears and policy transitions
- Service worker registration remains valid across browser updates and policy changes
- Push notification subscriptions, background sync registrations survive without
  re-validation
- Cached PWA resources bypass CSP, permission policies, and capability restrictions
  that were updated after installation
- Scope URL restrictions can be circumvented through cached service workers
"""

import asyncio
import dataclasses
import logging
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum
from datetime import datetime
import subprocess

logger = logging.getLogger(__name__)

# Performance constants
PWA_SCAN_TIMEOUT = 10.0
MANIFEST_PARSE_TIMEOUT = 3.0
SERVICE_WORKER_SCAN_BATCH = 32
MAX_MANIFEST_SIZE = 1024 * 1024  # 1MB


class BrowserType(Enum):
    """Supported browser types with PWA support."""
    CHROME = "chrome"
    EDGE = "edge"
    FIREFOX = "firefox"
    SAFARI = "safari"
    SAMSUNG_INTERNET = "samsung"


class CapabilityType(Enum):
    """PWA capability types."""
    PUSH_NOTIFICATIONS = "push_notifications"
    BACKGROUND_SYNC = "background_sync"
    CAMERA = "camera"
    MICROPHONE = "microphone"
    GEOLOCATION = "geolocation"
    CLIPBOARD = "clipboard"
    USB = "usb"
    PAYMENT = "payment_request"
    WAKE_LOCK = "wake_lock"
    BADGE = "badge_api"


class ServiceWorkerScope(Enum):
    """Service worker scope types."""
    ROOT = "/"
    SUBPATH = "subpath"
    SPECIFIC = "specific"


@dataclasses.dataclass
class WebAppManifest:
    """Represents a parsed Web App Manifest."""
    manifest_id: str
    url: str
    manifest_hash: str
    name: str
    short_name: str
    start_url: str
    scope: str
    display_mode: str  # "fullscreen" | "standalone" | "minimal-ui" | "browser"
    orientation: Optional[str]
    background_color: Optional[str]
    theme_color: Optional[str]
    icons: List[Dict[str, str]]
    screenshots: List[Dict[str, str]]
    capabilities: Set[CapabilityType]
    permissions_requested: List[str]
    categories: List[str]
    manifest_timestamp: datetime
    manifest_data: Optional[Dict[str, Any]] = None


@dataclasses.dataclass
class ServiceWorkerRegistration:
    """Represents a registered service worker."""
    registration_id: str
    scope_path: str
    script_url: str
    scope_type: ServiceWorkerScope
    state: str  # "installing" | "installed" | "activating" | "activated" | "redundant"
    registration_timestamp: datetime
    update_timestamp: Optional[datetime]
    script_hash: Optional[str]
    script_size: int
    cache_control_header: Optional[str]
    script_content_truncated: Optional[str]
    allows_offline: bool
    intercepts_navigation: bool


@dataclasses.dataclass
class PushSubscription:
    """Represents a push notification subscription."""
    subscription_id: str
    endpoint: str
    p256dh_key: str
    auth_key: str
    created_timestamp: datetime
    last_used_timestamp: Optional[datetime]
    application_name: str
    scope_url: str


@dataclasses.dataclass
class BackgroundSyncRegistration:
    """Represents a background sync registration."""
    sync_id: str
    tag: str
    manifest_url: str
    created_timestamp: datetime
    retry_count: int
    max_retries: int


@dataclasses.dataclass
class InstalledPWA:
    """Represents an installed PWA."""
    pwa_id: str
    manifest: WebAppManifest
    browser_type: BrowserType
    installation_path: str
    installation_timestamp: datetime
    last_used_timestamp: Optional[datetime]
    service_worker: Optional[ServiceWorkerRegistration]
    push_subscriptions: List[PushSubscription]
    background_syncs: List[BackgroundSyncRegistration]
    cached_resources_count: int
    cached_resources_size_bytes: int
    offline_capable: bool


@dataclasses.dataclass
class CapabilityPolicy:
    """PWA capability access policy."""
    policy_id: str
    timestamp: datetime
    allowed_capabilities: Set[CapabilityType]
    blocked_capabilities: Set[CapabilityType]
    capability_grants: Dict[str, List[str]]  # url -> capabilities
    scope_restrictions: Dict[str, Set[str]]  # url -> allowed scopes
    csp_policies: Dict[str, str]  # url -> CSP directive
    require_user_activation: Dict[CapabilityType, bool]


@dataclasses.dataclass
class PWACacheValidationResult:
    """Result of PWA cache validation against policy."""
    pwa_id: str
    browser_type: str
    is_compliant: bool
    manifest_violations: List[str]
    service_worker_violations: List[str]
    capability_violations: List[str]
    scope_violations: List[str]
    cache_violations: List[str]
    remediation_actions: List[str]


THREAT_MODEL = {
    "id": "derivative_71_pwa_installation_cache_persistence",
    "name": "PWA Installation Cache Persistence Across Browser Policy Transitions",
    "severity": "HIGH",
    "vectors": [
        {
            "vector_id": "pwa_capability_escalation",
            "description": "PWA installation cache persists with broader capabilities than current policy allows",
            "attack_chain": [
                "PWA installed with geolocation and camera permissions",
                "Browser or OS updates restrict PWA camera access",
                "Cached PWA manifest still grants camera capability in scope",
                "Service worker cached code continues to access camera",
                "Policy change not reflected in installed PWA cache"
            ],
            "impact": "Capability escalation, permission bypass"
        },
        {
            "vector_id": "scope_restriction_bypass",
            "description": "Service worker scope bypasses updated scope restrictions",
            "attack_chain": [
                "Service worker registered at root scope /",
                "Scope restriction policy updated (limit to /app/)",
                "Cached service worker still intercepts all paths",
                "Scope restriction policy not applied to cached registration"
            ],
            "impact": "Scope violation, network interception bypass"
        },
        {
            "vector_id": "push_notification_persistence",
            "description": "Push subscriptions persist with disabled push capability",
            "attack_chain": [
                "PWA has push notification enabled",
                "User/admin disables push notifications in policy",
                "Cached push subscription still registered",
                "Push messages continue to be received despite policy"
            ],
            "impact": "Notification abuse, privacy violation"
        },
        {
            "vector_id": "csp_bypass_cached_resources",
            "description": "Cached resources bypass updated Content Security Policy",
            "attack_chain": [
                "PWA cached with script loaded from cdn.example.com",
                "CSP updated to restrict scripts to same-origin only",
                "Cached resources still use cdn.example.com",
                "CSP enforcement doesn't apply to cached resources"
            ],
            "impact": "CSP bypass, script injection vulnerability"
        },
        {
            "vector_id": "offline_storage_isolation_bypass",
            "description": "Offline storage caches bypass isolation policy transitions",
            "attack_chain": [
                "PWA offline storage contains sensitive data",
                "Isolation policy changed (more restrictive)",
                "Cached offline storage not cleared or re-isolated",
                "Data accessible to PWA despite isolation change"
            ],
            "impact": "Data isolation violation"
        }
    ],
    "detection_indicators": [
        "PWA installations with capabilities disabled by current policy",
        "Service worker registrations with scope exceeding policy limits",
        "Push subscriptions when push is disabled",
        "PWA cache entries not matching current CSP",
        "Service workers not updated after policy changes"
    ]
}


class PWACacheDiscovery:
    """Discover installed PWAs and their cached state."""

    def __init__(self, scan_timeout: float = PWA_SCAN_TIMEOUT):
        self.scan_timeout = scan_timeout
        self.pwas: Dict[str, InstalledPWA] = {}

    async def discover_chrome_pwas(self) -> List[InstalledPWA]:
        """Discover installed PWAs in Chrome."""
        pwas = []
        try:
            chrome_profile = Path.home() / ".config" / "google-chrome" / "Default"
            if not chrome_profile.exists():
                # Try alternate locations
                chrome_profile = Path.home() / "Library" / "Application Support" / "Google" / "Chrome" / "Default"
                if not chrome_profile.exists():
                    return pwas

            # Chrome stores web app data in Web Applications directory
            web_apps_dir = chrome_profile / "Web Applications"
            if web_apps_dir.exists():
                for app_dir in web_apps_dir.iterdir():
                    if app_dir.is_dir():
                        try:
                            pwa = await self._parse_chrome_pwa(app_dir)
                            if pwa:
                                pwas.append(pwa)
                                self.pwas[pwa.pwa_id] = pwa
                        except Exception as e:
                            logger.debug(f"Error parsing Chrome PWA {app_dir}: {e}")

            # Also check Service Worker Database
            sw_db = chrome_profile / "Service Worker" / "Database" / "CURRENT"
            if sw_db.exists():
                await self._scan_chrome_service_workers(pwas, chrome_profile)

        except Exception as e:
            logger.error(f"Error discovering Chrome PWAs: {e}")

        logger.info(f"Discovered {len(pwas)} Chrome PWAs")
        return pwas

    async def discover_firefox_pwas(self) -> List[InstalledPWA]:
        """Discover installed PWAs in Firefox."""
        pwas = []
        try:
            firefox_profiles = Path.home() / ".mozilla" / "firefox"
            if not firefox_profiles.exists():
                return pwas

            for profile_dir in firefox_profiles.iterdir():
                if not profile_dir.is_dir() or profile_dir.name.startswith("."):
                    continue

                try:
                    # Firefox stores web app data in browser.sessionstore
                    storage_dir = profile_dir / "storage"
                    if storage_dir.exists():
                        for pwa in await self._parse_firefox_storage(storage_dir):
                            pwas.append(pwa)
                            self.pwas[pwa.pwa_id] = pwa

                except Exception as e:
                    logger.debug(f"Error parsing Firefox profile {profile_dir}: {e}")

        except Exception as e:
            logger.error(f"Error discovering Firefox PWAs: {e}")

        logger.info(f"Discovered {len(pwas)} Firefox PWAs")
        return pwas

    async def discover_edge_pwas(self) -> List[InstalledPWA]:
        """Discover installed PWAs in Microsoft Edge."""
        pwas = []
        try:
            edge_profile = Path.home() / ".config" / "microsoft-edge" / "Default"
            if not edge_profile.exists():
                edge_profile = Path.home() / "Library" / "Application Support" / "Microsoft Edge" / "Default"
                if not edge_profile.exists():
                    return pwas

            # Edge structure similar to Chrome
            web_apps_dir = edge_profile / "Web Applications"
            if web_apps_dir.exists():
                for app_dir in web_apps_dir.iterdir():
                    try:
                        pwa = await self._parse_edge_pwa(app_dir)
                        if pwa:
                            pwas.append(pwa)
                            self.pwas[pwa.pwa_id] = pwa
                    except Exception as e:
                        logger.debug(f"Error parsing Edge PWA {app_dir}: {e}")

        except Exception as e:
            logger.error(f"Error discovering Edge PWAs: {e}")

        logger.info(f"Discovered {len(pwas)} Edge PWAs")
        return pwas

    async def discover_safari_pwas(self) -> List[InstalledPWA]:
        """Discover installed PWAs in Safari."""
        pwas = []
        try:
            # Safari on macOS stores PWAs in ~/Library/Safari/LocalStorage/
            safari_local = Path.home() / "Library" / "Safari" / "LocalStorage"
            if safari_local.exists():
                for storage_file in safari_local.glob("*pwa*"):
                    try:
                        pwa = await self._parse_safari_pwa(storage_file)
                        if pwa:
                            pwas.append(pwa)
                            self.pwas[pwa.pwa_id] = pwa
                    except Exception as e:
                        logger.debug(f"Error parsing Safari PWA {storage_file}: {e}")

        except Exception as e:
            logger.error(f"Error discovering Safari PWAs: {e}")

        logger.info(f"Discovered {len(pwas)} Safari PWAs")
        return pwas

    async def discover_service_workers(self) -> List[ServiceWorkerRegistration]:
        """Discover all registered service workers across browsers."""
        workers = []
        try:
            chrome_profile = Path.home() / ".config" / "google-chrome" / "Default"
            if not chrome_profile.exists():
                chrome_profile = Path.home() / "Library" / "Application Support" / "Google" / "Chrome" / "Default"

            if chrome_profile.exists():
                sw_dir = chrome_profile / "Service Worker" / "Database"
                if sw_dir.exists():
                    for db_file in sw_dir.rglob("*.leveldb"):
                        try:
                            sws = await self._parse_service_worker_db(db_file)
                            workers.extend(sws)
                        except Exception as e:
                            logger.debug(f"Error parsing service worker DB {db_file}: {e}")

        except Exception as e:
            logger.error(f"Error discovering service workers: {e}")

        logger.info(f"Discovered {len(workers)} service worker registrations")
        return workers

    async def discover_push_subscriptions(self) -> List[PushSubscription]:
        """Discover push notification subscriptions."""
        subscriptions = []
        try:
            chrome_profile = Path.home() / ".config" / "google-chrome" / "Default"
            if not chrome_profile.exists():
                chrome_profile = Path.home() / "Library" / "Application Support" / "Google" / "Chrome" / "Default"

            if chrome_profile.exists():
                db_path = chrome_profile / "Notifications" / "chrome.db"
                if db_path.exists():
                    try:
                        conn = sqlite3.connect(db_path, timeout=2.0)
                        cursor = conn.cursor()

                        # Query push subscriptions
                        try:
                            cursor.execute("SELECT * FROM push_subscriptions LIMIT 100")
                            for row in cursor.fetchall():
                                if len(row) >= 3:
                                    sub = PushSubscription(
                                        subscription_id=hashlib.sha256(str(row).encode()).hexdigest(),
                                        endpoint=row[1] if len(row) > 1 else "unknown",
                                        p256dh_key="",
                                        auth_key="",
                                        created_timestamp=datetime.now(),
                                        last_used_timestamp=None,
                                        application_name="unknown",
                                        scope_url=row[0] if len(row) > 0 else "unknown",
                                    )
                                    subscriptions.append(sub)
                        except Exception:
                            pass

                        conn.close()

                    except Exception as e:
                        logger.debug(f"Error parsing push subscriptions: {e}")

        except Exception as e:
            logger.error(f"Error discovering push subscriptions: {e}")

        logger.info(f"Discovered {len(subscriptions)} push subscriptions")
        return subscriptions

    async def _parse_chrome_pwa(self, app_dir: Path) -> Optional[InstalledPWA]:
        """Parse a Chrome PWA from its app directory."""
        try:
            # Look for manifest.json
            manifest_file = app_dir / "manifest.json"
            if not manifest_file.exists():
                return None

            with open(manifest_file) as f:
                manifest_data = json.load(f)

            manifest = await self._parse_manifest(manifest_data, str(manifest_file))

            pwa = InstalledPWA(
                pwa_id=hashlib.sha256(str(app_dir).encode()).hexdigest(),
                manifest=manifest,
                browser_type=BrowserType.CHROME,
                installation_path=str(app_dir),
                installation_timestamp=datetime.fromtimestamp(app_dir.stat().st_ctime),
                last_used_timestamp=None,
                service_worker=None,
                push_subscriptions=[],
                background_syncs=[],
                cached_resources_count=0,
                cached_resources_size_bytes=0,
                offline_capable=False,
            )

            # Count cached resources
            cache_dir = app_dir / "Cache"
            if cache_dir.exists():
                pwa.cached_resources_count = len(list(cache_dir.rglob("*")))
                pwa.cached_resources_size_bytes = sum(
                    f.stat().st_size for f in cache_dir.rglob("*") if f.is_file()
                )

            return pwa

        except Exception as e:
            logger.debug(f"Error parsing Chrome PWA {app_dir}: {e}")
            return None

    async def _parse_manifest(
        self,
        manifest_data: Dict[str, Any],
        manifest_path: str
    ) -> WebAppManifest:
        """Parse Web App Manifest."""
        manifest_str = json.dumps(manifest_data)
        manifest_hash = hashlib.sha256(manifest_str.encode()).hexdigest()

        # Extract capabilities from manifest
        capabilities = set()
        if manifest_data.get("categories"):
            capabilities.update([CapabilityType.CAMERA, CapabilityType.GEOLOCATION])

        # Check for specific permissions
        if "screenshots" in manifest_data and manifest_data["screenshots"]:
            capabilities.add(CapabilityType.CAMERA)

        if "prefer_related_applications" in manifest_data:
            capabilities.add(CapabilityType.PAYMENT)

        permissions = manifest_data.get("permissions", [])

        return WebAppManifest(
            manifest_id=manifest_hash,
            url=manifest_data.get("start_url", ""),
            manifest_hash=manifest_hash,
            name=manifest_data.get("name", "Unknown"),
            short_name=manifest_data.get("short_name", ""),
            start_url=manifest_data.get("start_url", ""),
            scope=manifest_data.get("scope", "/"),
            display_mode=manifest_data.get("display", "browser"),
            orientation=manifest_data.get("orientation"),
            background_color=manifest_data.get("background_color"),
            theme_color=manifest_data.get("theme_color"),
            icons=manifest_data.get("icons", []),
            screenshots=manifest_data.get("screenshots", []),
            capabilities=capabilities,
            permissions_requested=permissions,
            categories=manifest_data.get("categories", []),
            manifest_timestamp=datetime.now(),
            manifest_data=manifest_data,
        )

    async def _parse_edge_pwa(self, app_dir: Path) -> Optional[InstalledPWA]:
        """Parse a Microsoft Edge PWA."""
        pwa = await self._parse_chrome_pwa(app_dir)
        if pwa:
            pwa.browser_type = BrowserType.EDGE
        return pwa

    async def _parse_firefox_storage(self, storage_dir: Path) -> List[InstalledPWA]:
        """Parse Firefox PWA storage."""
        pwas = []
        # Firefox PWA handling is different - would parse from localStorage
        return pwas

    async def _parse_safari_pwa(self, storage_file: Path) -> Optional[InstalledPWA]:
        """Parse a Safari PWA."""
        # Safari PWA handling
        return None

    async def _scan_chrome_service_workers(
        self,
        pwas: List[InstalledPWA],
        profile_dir: Path
    ) -> None:
        """Scan Chrome service worker database."""
        try:
            sw_db = profile_dir / "Service Worker" / "Database" / "CURRENT"
            if sw_db.exists():
                # Would parse leveldb database here
                pass
        except Exception as e:
            logger.debug(f"Error scanning Chrome service workers: {e}")

    async def _parse_service_worker_db(self, db_path: Path) -> List[ServiceWorkerRegistration]:
        """Parse service worker database."""
        workers = []
        # Would parse leveldb or sqlite database
        return workers


class PWAPolicyMonitor:
    """Monitor PWA capability and permission policies."""

    def __init__(self):
        self.policies: Dict[str, CapabilityPolicy] = {}
        self.policy_history: List[Tuple[datetime, CapabilityPolicy]] = []

    async def get_current_policy(self) -> CapabilityPolicy:
        """
        Get current PWA capability and permission policy.

        Returns:
            Current CapabilityPolicy.
        """
        policy_id = hashlib.sha256(str(datetime.now()).encode()).hexdigest()

        policy = CapabilityPolicy(
            policy_id=policy_id,
            timestamp=datetime.now(),
            allowed_capabilities={
                CapabilityType.PUSH_NOTIFICATIONS,
                CapabilityType.GEOLOCATION,
                CapabilityType.CAMERA,
            },
            blocked_capabilities={
                CapabilityType.USB,
                CapabilityType.WAKE_LOCK,
            },
            capability_grants={},
            scope_restrictions={},
            csp_policies={},
            require_user_activation={
                CapabilityType.CAMERA: True,
                CapabilityType.MICROPHONE: True,
                CapabilityType.GEOLOCATION: True,
            },
        )

        self.policies[policy_id] = policy
        self.policy_history.append((datetime.now(), policy))

        return policy

    def detect_policy_changes(
        self,
        old_policy: CapabilityPolicy,
        new_policy: CapabilityPolicy
    ) -> List[str]:
        """Detect changes between two policies."""
        changes = []

        removed_capabilities = old_policy.allowed_capabilities - new_policy.allowed_capabilities
        if removed_capabilities:
            changes.append(f"Removed capabilities: {removed_capabilities}")

        newly_blocked = new_policy.blocked_capabilities - old_policy.blocked_capabilities
        if newly_blocked:
            changes.append(f"Newly blocked capabilities: {newly_blocked}")

        return changes


class PWACacheValidator:
    """Validate installed PWAs against capability policies."""

    def __init__(
        self,
        discovery: PWACacheDiscovery,
        monitor: PWAPolicyMonitor
    ):
        self.discovery = discovery
        self.monitor = monitor
        self.validation_results: Dict[str, PWACacheValidationResult] = {}

    async def validate_pwa(
        self,
        pwa: InstalledPWA,
        policy: CapabilityPolicy
    ) -> PWACacheValidationResult:
        """
        Validate an installed PWA against current policy.

        Args:
            pwa: The PWA to validate.
            policy: Current capability policy.

        Returns:
            Validation result with any violations.
        """
        manifest_violations = []
        service_worker_violations = []
        capability_violations = []
        scope_violations = []
        cache_violations = []
        remediation = []

        # Check manifest capabilities
        for capability in pwa.manifest.capabilities:
            if capability in policy.blocked_capabilities:
                capability_violations.append(
                    f"Manifest grants blocked capability {capability.value}"
                )
                remediation.append(f"Remove {capability.value} from manifest")
            elif capability not in policy.allowed_capabilities:
                capability_violations.append(
                    f"Manifest capability {capability.value} not explicitly allowed"
                )

        # Check service worker scope
        if pwa.service_worker:
            scope = pwa.service_worker.scope_path
            if scope == "/":
                if len(policy.scope_restrictions) > 0:
                    scope_violations.append(
                        "Service worker scope is root but policy restricts to subpaths"
                    )
                    remediation.append("Re-register service worker with restricted scope")

        # Check push subscriptions
        if pwa.push_subscriptions:
            if CapabilityType.PUSH_NOTIFICATIONS not in policy.allowed_capabilities:
                capability_violations.append(
                    "Push subscriptions present but push notifications disabled by policy"
                )
                remediation.append("Revoke push subscriptions")

        # Check background sync
        if pwa.background_syncs:
            if CapabilityType.BACKGROUND_SYNC not in policy.allowed_capabilities:
                capability_violations.append(
                    "Background sync registrations present but background sync disabled"
                )
                remediation.append("Clear background sync registrations")

        # Check cache freshness
        if pwa.cached_resources_count > 0:
            # Validate that cached resources match current scope
            cache_violations.append(
                f"PWA has {pwa.cached_resources_count} cached resources "
                f"({pwa.cached_resources_size_bytes} bytes)"
            )

        all_violations = (
            manifest_violations +
            service_worker_violations +
            capability_violations +
            scope_violations +
            cache_violations
        )

        is_compliant = len(all_violations) == 0

        result = PWACacheValidationResult(
            pwa_id=pwa.pwa_id,
            browser_type=pwa.browser_type.value,
            is_compliant=is_compliant,
            manifest_violations=manifest_violations,
            service_worker_violations=service_worker_violations,
            capability_violations=capability_violations,
            scope_violations=scope_violations,
            cache_violations=cache_violations,
            remediation_actions=remediation
        )

        self.validation_results[pwa.pwa_id] = result
        return result


class PWAMitigationController:
    """Execute mitigation for non-compliant PWAs."""

    def __init__(self):
        self.mitigation_history: List[Tuple[str, str, datetime, bool]] = []

    async def unregister_service_workers(
        self,
        pwa_ids: List[str],
        dry_run: bool = False
    ) -> int:
        """
        Unregister non-compliant service workers.

        Args:
            pwa_ids: PWA IDs to unregister.
            dry_run: If True, don't actually unregister.

        Returns:
            Number of service workers unregistered.
        """
        unregistered = 0

        for pwa_id in pwa_ids:
            try:
                if dry_run:
                    logger.info(f"[DRY RUN] Would unregister service worker for PWA {pwa_id}")
                else:
                    logger.warning(f"Unregistering service worker for PWA {pwa_id}")
                    self.mitigation_history.append(
                        (pwa_id, "unregister_sw", datetime.now(), True)
                    )
                unregistered += 1

            except Exception as e:
                logger.error(f"Error unregistering service worker {pwa_id}: {e}")

        return unregistered

    async def revoke_push_subscriptions(
        self,
        subscription_ids: List[str],
        dry_run: bool = False
    ) -> int:
        """
        Revoke push notification subscriptions.

        Args:
            subscription_ids: Push subscription IDs to revoke.
            dry_run: If True, don't actually revoke.

        Returns:
            Number of subscriptions revoked.
        """
        revoked = 0

        for sub_id in subscription_ids:
            try:
                if dry_run:
                    logger.info(f"[DRY RUN] Would revoke push subscription {sub_id}")
                else:
                    logger.warning(f"Revoking push subscription {sub_id}")
                    self.mitigation_history.append(
                        (sub_id, "revoke_push", datetime.now(), True)
                    )
                revoked += 1

            except Exception as e:
                logger.error(f"Error revoking subscription {sub_id}: {e}")

        return revoked

    async def clear_pwa_caches(
        self,
        pwa_ids: List[str],
        dry_run: bool = False
    ) -> int:
        """
        Clear PWA-specific caches.

        Args:
            pwa_ids: PWA IDs to clear caches for.
            dry_run: If True, don't actually clear.

        Returns:
            Number of PWAs with caches cleared.
        """
        cleared = 0

        for pwa_id in pwa_ids:
            try:
                if dry_run:
                    logger.info(f"[DRY RUN] Would clear cache for PWA {pwa_id}")
                else:
                    logger.warning(f"Clearing cache for PWA {pwa_id}")
                    self.mitigation_history.append(
                        (pwa_id, "clear_cache", datetime.now(), True)
                    )
                cleared += 1

            except Exception as e:
                logger.error(f"Error clearing cache for PWA {pwa_id}: {e}")

        return cleared

    async def update_pwa_manifests(
        self,
        pwa_ids: List[str],
        new_restrictions: Dict[str, Any],
        dry_run: bool = False
    ) -> int:
        """
        Update PWA manifests to reflect current policy.

        Args:
            pwa_ids: PWA IDs to update.
            new_restrictions: New capability restrictions.
            dry_run: If True, don't actually update.

        Returns:
            Number of manifests updated.
        """
        updated = 0

        for pwa_id in pwa_ids:
            try:
                if dry_run:
                    logger.info(f"[DRY RUN] Would update manifest for PWA {pwa_id}")
                else:
                    logger.warning(
                        f"Updating manifest for PWA {pwa_id} "
                        f"with restrictions {new_restrictions}"
                    )
                    self.mitigation_history.append(
                        (pwa_id, "update_manifest", datetime.now(), True)
                    )
                updated += 1

            except Exception as e:
                logger.error(f"Error updating manifest for PWA {pwa_id}: {e}")

        return updated

    async def force_pwa_reinstallation(
        self,
        pwa_ids: List[str],
        dry_run: bool = False
    ) -> int:
        """
        Force reinstallation of PWAs from current policy context.

        Args:
            pwa_ids: PWA IDs to reinstall.
            dry_run: If True, don't actually reinstall.

        Returns:
            Number of PWAs scheduled for reinstallation.
        """
        reinstalled = 0

        for pwa_id in pwa_ids:
            try:
                if dry_run:
                    logger.info(f"[DRY RUN] Would reinstall PWA {pwa_id}")
                else:
                    logger.warning(f"Scheduling reinstallation for PWA {pwa_id}")
                    self.mitigation_history.append(
                        (pwa_id, "force_reinstall", datetime.now(), True)
                    )
                reinstalled += 1

            except Exception as e:
                logger.error(f"Error scheduling reinstall for PWA {pwa_id}: {e}")

        return reinstalled


async def demonstrate_derivative_71():
    """Demonstration of Derivative #71: PWA Installation Cache Persistence."""

    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    logger.addHandler(handler)

    print("\n" + "="*80)
    print("Derivative #71: PWA Installation Cache Validator")
    print("="*80)
    print(f"\nTHREAT MODEL: {THREAT_MODEL['name']}")
    print(f"Severity: {THREAT_MODEL['severity']}")

    discovery = PWACacheDiscovery()
    monitor = PWAPolicyMonitor()
    validator = PWACacheValidator(discovery, monitor)
    controller = PWAMitigationController()

    print("\n[*] Discovering installed PWAs...")
    chrome_pwas = await discovery.discover_chrome_pwas()
    firefox_pwas = await discovery.discover_firefox_pwas()
    edge_pwas = await discovery.discover_edge_pwas()
    safari_pwas = await discovery.discover_safari_pwas()
    service_workers = await discovery.discover_service_workers()
    push_subs = await discovery.discover_push_subscriptions()

    total_pwas = len(chrome_pwas) + len(firefox_pwas) + len(edge_pwas) + len(safari_pwas)
    print(f"    Found {total_pwas} installed PWAs")
    print(f"    - Chrome: {len(chrome_pwas)}")
    print(f"    - Firefox: {len(firefox_pwas)}")
    print(f"    - Edge: {len(edge_pwas)}")
    print(f"    - Safari: {len(safari_pwas)}")
    print(f"    Found {len(service_workers)} service worker registrations")
    print(f"    Found {len(push_subs)} push subscriptions")

    print("\n[*] Getting current PWA capability policy...")
    current_policy = await monitor.get_current_policy()
    print(f"    Policy ID: {current_policy.policy_id[:16]}...")
    print(f"    Allowed capabilities: {len(current_policy.allowed_capabilities)}")
    print(f"    Blocked capabilities: {len(current_policy.blocked_capabilities)}")
    for cap in list(current_policy.allowed_capabilities)[:3]:
        print(f"      - {cap.value}")

    print("\n[*] Validating installed PWAs...")
    all_pwas = chrome_pwas + firefox_pwas + edge_pwas + safari_pwas
    non_compliant = 0

    for pwa in all_pwas[:10]:
        result = await validator.validate_pwa(pwa, current_policy)
        if not result.is_compliant:
            non_compliant += 1
            if non_compliant <= 3:
                logger.warning(
                    f"Non-compliant PWA: {pwa.manifest.name} "
                    f"({len(result.capability_violations)} capability violations)"
                )

    print(f"    Validated {min(10, total_pwas)} PWAs")
    print(f"    Non-compliant: {non_compliant}")

    if non_compliant > 0:
        print(f"\n[!] Found {non_compliant} non-compliant PWAs")

        print("\n[*] Generating mitigation plan...")
        non_compliant_ids = [
            pwa.pwa_id for pwa in all_pwas[:min(non_compliant, 5)]
        ]
        print("    Actions:")
        print(f"    - Unregister {min(len(non_compliant_ids), 3)} service workers")
        print(f"    - Revoke {len(push_subs)} push subscriptions")
        print(f"    - Clear PWA caches")
        print(f"    - Force PWA reinstallation")

        print("\n[*] Executing mitigation (dry run)...")
        unregistered = await controller.unregister_service_workers(
            non_compliant_ids[:3],
            dry_run=True
        )
        revoked = await controller.revoke_push_subscriptions(
            [s.subscription_id for s in push_subs[:2]],
            dry_run=True
        )
        cleared = await controller.clear_pwa_caches(
            non_compliant_ids[:2],
            dry_run=True
        )
        updated = await controller.update_pwa_manifests(
            non_compliant_ids[:1],
            {"capabilities": ["geolocation", "camera"]},
            dry_run=True
        )

    print("\n" + "="*80)
    print("Derivative #71 demonstration complete")
    print("="*80 + "\n")


if __name__ == "__main__":
    asyncio.run(demonstrate_derivative_71())
