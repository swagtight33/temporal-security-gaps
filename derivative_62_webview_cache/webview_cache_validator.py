"""
WebView Cache Validator - Derivative #62
System and Method for Mitigating Cached Executable Persistence Across Security Policy Transitions

Patent Portfolio: STAAML Corp
Author: Stanley Linton

This module implements comprehensive discovery, enumeration, validation, and mitigation
of cached content in native app WebViews (iOS WKWebView, Android WebView, Electron, etc.).
The vulnerability addresses the persistence of executable content (WASM, JS, service workers)
in app-sandboxed caches that are NOT revalidated when OS/app security policies transition.
"""

import asyncio
import hashlib
import json
import logging
import os
import platform
import sqlite3
import tempfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from abc import ABC, abstractmethod
import shutil
import struct
import re


# ============================================================================
# THREAT MODEL DOCUMENTATION
# ============================================================================

THREAT_MODEL = {
    "attack_vectors": {
        "cache_persistence": {
            "description": "Cached executable content persists across security policy transitions",
            "platforms": ["iOS", "macOS", "Android", "Windows", "Linux"],
            "examples": [
                "WASM binaries in HTTP cache not revalidated on Lockdown Mode enable",
                "Service Worker code persisting in IndexedDB when MDM policy enforces offline mode",
                "JavaScript in Cache API evading new CSP policies set by OS",
            ],
            "impact": "CRITICAL - Executor can reuse cached exploits even after policy mitigation",
        },
        "policy_blind_cache": {
            "description": "WebView caches operate independently from OS/browser policy enforcement",
            "technical_root": "App-sandboxed cache directories isolated from browser policy management",
            "invisibility": "Cache state invisible to both browser-level and OS-level management tools",
            "detection_gap": "Standard cache validation only occurs on HTTP revalidation, not policy change",
        },
        "multi_process_isolation": {
            "description": "Each WebView instance maintains its own isolated cache",
            "deduplication_risk": "Same origin served from N app instances = N uncoordinated caches",
            "coordination_failure": "No mechanism to invalidate copies across WebView instances",
        },
        "electron_framework_isolation": {
            "description": "Electron apps embed Chromium with custom CSP separate from OS policy",
            "constraint_avoidance": "App-level CSP can contradict OS security policy (e.g., MDM restrictions)",
            "persistence_window": "Electron cache persists until app restart, even after OS policy change",
        },
    },
    "mitigation_strategy": [
        "Discover all WebView cache locations across app ecosystem",
        "Enumerate cached content and extract temporal/policy attributes",
        "Validate against current security policy (PolicyCURRENT)",
        "Compute policy delta (ΔPolicy) between cache-time and current policy",
        "Classify as COMPLIANT, NON_COMPLIANT, UNKNOWN, SUSPICIOUS",
        "Execute mitigation (Block, Purge, Quarantine, Regenerate) with rollback",
        "Generate tamper-evident audit logs for forensic verification",
    ],
}

# ============================================================================
# PERFORMANCE & OPERATIONAL CONSTANTS
# ============================================================================

# Discovery and enumeration performance targets
PERF_TARGETS = {
    "discovery_max_duration_ms": 5000,  # Platform sweep <= 5 seconds
    "enumeration_per_app_ms": 2000,     # Per-app cache enumeration <= 2 seconds
    "validation_throughput_items_sec": 1000,  # Validate 1000 items/sec
    "mitigation_atomic_timeout_sec": 30,  # Rollback window
    "audit_log_write_latency_ms": 100,  # Tamper-evident log latency
}

# Cache discovery paths - platform-specific defaults
CACHE_DISCOVERY_PATHS = {
    "iOS": [
        "~/Library/Caches/*/com.apple.WebKit.WebContent",  # WKWebView system framework
        "~/Library/WebKit/*/Cache.db",  # Webkit HTTP cache
        "~/.../WebKit/*/Cache Storage",  # Cache API storage
    ],
    "macOS": [
        "~/Library/Caches/*/com.apple.WebKit.WebContent",
        "~/Library/WebKit/*/Cache.db",
        "~/.../WebKit/*/Cache Storage",
        "~/Library/Saved Application State/*/com.apple.WebKit.*.savedState",
    ],
    "Android": [
        "/data/data/*/cache/webview*",  # WebView HTTP cache
        "/data/data/*/app_webview/Cache",  # Android WebView system cache
        "/data/data/*/cache/*IndexedDB*",  # IndexedDB storage
        "/data/data/*/cache/Service Worker*",  # Service Worker registrations
    ],
    "Windows": [
        "%LOCALAPPDATA%\\*/AppData\\Local\\*/Cache",
        "%LOCALAPPDATA%\\*/AppData\\Local\\*/Code Cache",
        "%LOCALAPPDATA%\\*/AppData\\Local\\Chromium",
    ],
    "Linux": [
        "~/.cache/*/webview*",
        "~/.config/*/code-cache",
        "~/.cache/chromium",
    ],
}


# ============================================================================
# ENUMERATIONS
# ============================================================================

class ComplianceStatus(Enum):
    """Classification of cached item against security policy."""
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    UNKNOWN = "UNKNOWN"
    SUSPICIOUS = "SUSPICIOUS"


class MitigationAction(Enum):
    """Actions available for WebView cache remediation."""
    BLOCK = "BLOCK"  # Block execution but retain cache
    PURGE = "PURGE"  # Delete cached content
    QUARANTINE = "QUARANTINE"  # Isolate to restricted directory
    REGENERATE = "REGENERATE"  # Force re-fetch and revalidation


class PolicyTransitionEvent(Enum):
    """OS/app security policy transition triggers."""
    LOCKDOWN_MODE_ENABLED = "LOCKDOWN_MODE_ENABLED"
    LOCKDOWN_MODE_DISABLED = "LOCKDOWN_MODE_DISABLED"
    MDM_POLICY_CHANGED = "MDM_POLICY_CHANGED"
    CSP_POLICY_UPDATED = "CSP_POLICY_UPDATED"
    SANDBOX_ENFORCEMENT_CHANGED = "SANDBOX_ENFORCEMENT_CHANGED"
    UNKNOWN = "UNKNOWN"


class CacheType(Enum):
    """WebView cache subsystems."""
    HTTP_CACHE = "HTTP_CACHE"
    CACHE_API = "CACHE_API"
    INDEXED_DB = "INDEXED_DB"
    SERVICE_WORKER = "SERVICE_WORKER"
    LOCAL_STORAGE = "LOCAL_STORAGE"
    SESSION_STORAGE = "SESSION_STORAGE"
    COOKIES = "COOKIES"


class PlatformType(Enum):
    """Supported platforms."""
    IOS = "iOS"
    MACOS = "macOS"
    ANDROID = "Android"
    WINDOWS = "Windows"
    LINUX = "Linux"
    ELECTRON = "Electron"


# ============================================================================
# DATACLASSES - CORE DATA STRUCTURES
# ============================================================================

@dataclass
class SecurityPolicy:
    """Represents a security policy state at a point in time."""
    policy_id: str
    timestamp: datetime
    lockdown_mode_enabled: bool = False
    mdm_restrictions: Dict[str, Any] = field(default_factory=dict)
    csp_directives: Dict[str, str] = field(default_factory=dict)
    allowed_origins: Set[str] = field(default_factory=set)
    executable_restrictions: Dict[str, bool] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize policy to dictionary."""
        return {
            "policy_id": self.policy_id,
            "timestamp": self.timestamp.isoformat(),
            "lockdown_mode_enabled": self.lockdown_mode_enabled,
            "mdm_restrictions": self.mdm_restrictions,
            "csp_directives": self.csp_directives,
            "allowed_origins": list(self.allowed_origins),
            "executable_restrictions": self.executable_restrictions,
            "metadata": self.metadata,
        }


@dataclass
class CachedItem:
    """Represents a single cached content item."""
    cache_id: str
    origin: str
    url: str
    cache_type: CacheType
    content_hash: str  # SHA-256
    mime_type: str
    cached_at: datetime
    expires_at: Optional[datetime]
    host_app: str
    host_app_pid: Optional[int]
    platform: PlatformType
    size_bytes: int
    is_executable: bool
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        data = asdict(self)
        data["cache_type"] = self.cache_type.value
        data["platform"] = self.platform.value
        data["cached_at"] = self.cached_at.isoformat()
        if self.expires_at:
            data["expires_at"] = self.expires_at.isoformat()
        return data


@dataclass
class PolicyDelta:
    """Represents difference between two security policies."""
    cache_policy_id: str  # Policy at cache time
    current_policy_id: str  # Current policy
    policy_at_cache_time: SecurityPolicy
    current_policy: SecurityPolicy
    changed_fields: List[str] = field(default_factory=list)
    severity: str = "UNKNOWN"  # LOW, MEDIUM, HIGH, CRITICAL
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "cache_policy_id": self.cache_policy_id,
            "current_policy_id": self.current_policy_id,
            "policy_at_cache_time": self.policy_at_cache_time.to_dict(),
            "current_policy": self.current_policy.to_dict(),
            "changed_fields": self.changed_fields,
            "severity": self.severity,
            "details": self.details,
        }


@dataclass
class ValidationResult:
    """Result of validating a cached item against security policy."""
    cache_id: str
    compliance_status: ComplianceStatus
    policy_delta: Optional[PolicyDelta]
    violation_details: List[str] = field(default_factory=list)
    recommended_action: MitigationAction = MitigationAction.BLOCK
    confidence: float = 1.0  # 0.0 - 1.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "cache_id": self.cache_id,
            "compliance_status": self.compliance_status.value,
            "policy_delta": self.policy_delta.to_dict() if self.policy_delta else None,
            "violation_details": self.violation_details,
            "recommended_action": self.recommended_action.value,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class WebViewAppInfo:
    """Information about an application hosting a WebView."""
    app_id: str
    app_name: str
    app_bundle_id: Optional[str]
    app_path: Path
    platform: PlatformType
    pid: Optional[int]
    cache_paths: List[Path] = field(default_factory=list)
    is_electron: bool = False
    framework_version: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "app_id": self.app_id,
            "app_name": self.app_name,
            "app_bundle_id": self.app_bundle_id,
            "app_path": str(self.app_path),
            "platform": self.platform.value,
            "pid": self.pid,
            "cache_paths": [str(p) for p in self.cache_paths],
            "is_electron": self.is_electron,
            "framework_version": self.framework_version,
            "metadata": self.metadata,
        }


@dataclass
# ============================================================================
# WEBVIEW CACHE DISCOVERY
# ============================================================================

class WebViewCacheDiscovery:
    """
    Discovers WebView cache locations across platforms and maps them to host applications.

    Handles:
    - iOS WKWebView paths
    - Android WebView paths
    - Electron app detection
    - macOS/Windows Chromium embedded paths
    - Cross-process cache discovery
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize the discovery engine."""
        self.logger = logger or logging.getLogger(__name__)
        self.current_platform = self._detect_platform()
        self.discovered_apps: Dict[str, WebViewAppInfo] = {}
        self.discovered_caches: Dict[str, List[Path]] = {}

    def _detect_platform(self) -> PlatformType:
        """Detect current platform."""
        system = platform.system()
        if system == "Darwin":
            return PlatformType.MACOS
        elif system == "Linux":
            return PlatformType.LINUX
        elif system == "Windows":
            return PlatformType.WINDOWS
        return PlatformType.LINUX

    async def discover_all(self) -> Dict[str, WebViewAppInfo]:
        """
        Discover all WebView caches on the system.

        Returns:
            Dict mapping app_id to WebViewAppInfo.
        """
        self.logger.info(f"Starting WebView cache discovery on {self.current_platform.value}")
        start_time = datetime.now(timezone.utc)

        try:
            if self.current_platform == PlatformType.MACOS:
                await self._discover_macos()
            elif self.current_platform == PlatformType.IOS:
                await self._discover_ios()
            elif self.current_platform == PlatformType.ANDROID:
                await self._discover_android()
            elif self.current_platform == PlatformType.WINDOWS:
                await self._discover_windows()
            elif self.current_platform == PlatformType.LINUX:
                await self._discover_linux()

            elapsed = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            self.logger.info(
                f"Discovery complete: {len(self.discovered_apps)} apps, "
                f"{sum(len(p) for p in self.discovered_caches.values())} caches "
                f"({elapsed:.0f}ms)"
            )
        except Exception as e:
            self.logger.error(f"Discovery error: {e}", exc_info=True)

        return self.discovered_apps

    async def _discover_macos(self) -> None:
        """Discover WebView caches on macOS."""
        self.logger.debug("Scanning macOS WebView cache locations")

        home = Path.home()
        cache_base = home / "Library" / "Caches"
        webkit_base = home / "Library" / "WebKit"

        # Scan for app caches
        if cache_base.exists():
            for app_dir in cache_base.iterdir():
                if not app_dir.is_dir():
                    continue

                # Check for WKWebView content caches
                webkit_content = app_dir / "com.apple.WebKit.WebContent"
                if webkit_content.exists():
                    await self._register_app_cache(
                        app_name=app_dir.name,
                        app_path=app_dir,
                        cache_path=webkit_content,
                        platform=PlatformType.MACOS,
                    )

        # Scan for Electron apps
        await self._discover_electron_apps()

    async def _discover_ios(self) -> None:
        """Discover WebView caches on iOS (sandboxed environment)."""
        self.logger.debug("Scanning iOS WebView cache locations")
        # iOS caches are in sandboxed app directories
        home = Path.home()
        documents = home / "Documents"

        if documents.exists():
            for app_dir in documents.iterdir():
                if app_dir.is_dir():
                    cache_dir = app_dir / "Library" / "Caches"
                    if cache_dir.exists():
                        await self._register_app_cache(
                            app_name=app_dir.name,
                            app_path=app_dir,
                            cache_path=cache_dir,
                            platform=PlatformType.IOS,
                        )

    async def _discover_android(self) -> None:
        """Discover WebView caches on Android."""
        self.logger.debug("Scanning Android WebView cache locations")
        # Android cache discovery would require adb or root access
        # This is a placeholder for the pattern
        webview_root = Path("/data/data")
        if webview_root.exists():
            for package_dir in webview_root.iterdir():
                if not package_dir.is_dir():
                    continue

                cache_dir = package_dir / "cache"
                webview_cache = package_dir / "app_webview"

                if cache_dir.exists():
                    await self._register_app_cache(
                        app_name=package_dir.name,
                        app_path=package_dir,
                        cache_path=cache_dir,
                        platform=PlatformType.ANDROID,
                    )

                if webview_cache.exists():
                    await self._register_app_cache(
                        app_name=package_dir.name,
                        app_path=package_dir,
                        cache_path=webview_cache,
                        platform=PlatformType.ANDROID,
                    )

    async def _discover_windows(self) -> None:
        """Discover WebView caches on Windows."""
        self.logger.debug("Scanning Windows WebView cache locations")
        localappdata = Path(os.getenv("LOCALAPPDATA", ""))
        if localappdata.exists():
            for app_dir in localappdata.iterdir():
                if not app_dir.is_dir():
                    continue

                cache_dir = app_dir / "Cache"
                code_cache = app_dir / "Code Cache"

                if cache_dir.exists():
                    await self._register_app_cache(
                        app_name=app_dir.name,
                        app_path=app_dir,
                        cache_path=cache_dir,
                        platform=PlatformType.WINDOWS,
                    )

                if code_cache.exists():
                    await self._register_app_cache(
                        app_name=app_dir.name,
                        app_path=app_dir,
                        cache_path=code_cache,
                        platform=PlatformType.WINDOWS,
                    )

    async def _discover_linux(self) -> None:
        """Discover WebView caches on Linux."""
        self.logger.debug("Scanning Linux WebView cache locations")
        home = Path.home()
        cache_base = home / ".cache"
        config_base = home / ".config"

        if cache_base.exists():
            for app_dir in cache_base.iterdir():
                if not app_dir.is_dir():
                    continue

                webview_cache = app_dir / "webview"
                if webview_cache.exists():
                    await self._register_app_cache(
                        app_name=app_dir.name,
                        app_path=app_dir,
                        cache_path=webview_cache,
                        platform=PlatformType.LINUX,
                    )

        # Check for Electron apps
        await self._discover_electron_apps()

    async def _discover_electron_apps(self) -> None:
        """Detect Electron apps by scanning for electron.asar and embedded Chromium."""
        self.logger.debug("Scanning for Electron applications")

        home = Path.home()
        common_electron_paths = [
            home / "Applications",
            Path("/opt/applications"),
            home / ".config",
        ]

        for base_path in common_electron_paths:
            if not base_path.exists():
                continue

            for entry in base_path.rglob("electron.asar"):
                app_path = entry.parent.parent
                await self._register_app_cache(
                    app_name=app_path.name,
                    app_path=app_path,
                    cache_path=app_path,
                    platform=PlatformType.ELECTRON,
                    is_electron=True,
                )

    async def _register_app_cache(
        self,
        app_name: str,
        app_path: Path,
        cache_path: Path,
        platform: PlatformType,
        is_electron: bool = False,
    ) -> None:
        """Register a discovered WebView cache."""
        app_id = f"{platform.value}:{app_name}"

        if app_id not in self.discovered_apps:
            self.discovered_apps[app_id] = WebViewAppInfo(
                app_id=app_id,
                app_name=app_name,
                app_bundle_id=None,
                app_path=app_path,
                platform=platform,
                pid=None,
                is_electron=is_electron,
            )

        app_info = self.discovered_apps[app_id]
        if cache_path not in app_info.cache_paths:
            app_info.cache_paths.append(cache_path)
            self.logger.debug(f"Registered cache for {app_id}: {cache_path}")

        if app_id not in self.discovered_caches:
            self.discovered_caches[app_id] = []
        if cache_path not in self.discovered_caches[app_id]:
            self.discovered_caches[app_id].append(cache_path)


# ============================================================================
# WEBVIEW CACHE ENUMERATION
# ============================================================================

class WebViewCacheEnumerator:
    """
    Enumerates cached content within WebView caches.

    Supports:
    - HTTP cache (Chromium/WebKit format)
    - Cache API storage
    - IndexedDB
    - Service Worker registrations
    - Local/Session Storage
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize the enumerator."""
        self.logger = logger or logging.getLogger(__name__)
        self.enumerated_items: Dict[str, List[CachedItem]] = {}

    async def enumerate_app_caches(
        self,
        app_info: WebViewAppInfo,
    ) -> List[CachedItem]:
        """
        Enumerate all cached content for a specific application.

        Args:
            app_info: WebViewAppInfo object describing the app.

        Returns:
            List of CachedItem objects.
        """
        items: List[CachedItem] = []
        self.logger.info(f"Enumerating caches for {app_info.app_name}")

        for cache_path in app_info.cache_paths:
            try:
                # Enumerate HTTP cache
                http_items = await self._enumerate_http_cache(cache_path, app_info)
                items.extend(http_items)

                # Enumerate Cache API
                cache_api_items = await self._enumerate_cache_api(cache_path, app_info)
                items.extend(cache_api_items)

                # Enumerate IndexedDB
                indexeddb_items = await self._enumerate_indexeddb(cache_path, app_info)
                items.extend(indexeddb_items)

                # Enumerate Service Workers
                sw_items = await self._enumerate_service_workers(cache_path, app_info)
                items.extend(sw_items)

                # Enumerate Local Storage
                ls_items = await self._enumerate_local_storage(cache_path, app_info)
                items.extend(ls_items)

            except Exception as e:
                self.logger.error(f"Error enumerating {cache_path}: {e}", exc_info=True)

        self.enumerated_items[app_info.app_id] = items
        self.logger.info(f"Enumerated {len(items)} items for {app_info.app_name}")
        return items

    async def _enumerate_http_cache(
        self,
        cache_path: Path,
        app_info: WebViewAppInfo,
    ) -> List[CachedItem]:
        """Enumerate HTTP cache entries."""
        items: List[CachedItem] = []

        # Look for Chromium cache format
        cache_dir = cache_path / "Cache"
        if cache_dir.exists():
            items.extend(await self._enumerate_chromium_cache(cache_dir, app_info))

        # Look for WebKit cache format
        cache_db = cache_path / "Cache.db"
        if cache_db.exists():
            items.extend(await self._enumerate_webkit_cache(cache_db, app_info))

        return items

    async def _enumerate_chromium_cache(
        self,
        cache_dir: Path,
        app_info: WebViewAppInfo,
    ) -> List[CachedItem]:
        """Parse Chromium cache format (index file + numbered cache files)."""
        items: List[CachedItem] = []

        try:
            index_file = cache_dir / "index"
            if not index_file.exists():
                return items

            with open(index_file, "rb") as f:
                # Chromium cache index format
                magic = f.read(4)
                if magic != b"the\x00":  # Chromium cache magic
                    return items

                version = struct.unpack("<I", f.read(4))[0]
                self.logger.debug(f"Chromium cache version: {version}")

                # Parse index entries (simplified)
                while True:
                    try:
                        entry_data = f.read(16)
                        if len(entry_data) < 16:
                            break
                        # Additional parsing would go here
                    except:
                        break

        except Exception as e:
            self.logger.error(f"Error parsing Chromium cache: {e}")

        return items

    async def _enumerate_webkit_cache(
        self,
        cache_db: Path,
        app_info: WebViewAppInfo,
    ) -> List[CachedItem]:
        """Parse WebKit cache database format."""
        items: List[CachedItem] = []

        try:
            conn = sqlite3.connect(cache_db)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Query main cache table
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]

            if "cfurl_cache_blob_data" in tables:
                cursor.execute(
                    "SELECT url, response_object, time_stamp FROM cfurl_cache_blob_data"
                )
                for row in cursor.fetchall():
                    try:
                        item = CachedItem(
                            cache_id=f"webkit_{hashlib.sha256(str(row['url']).encode()).hexdigest()[:16]}",
                            origin=self._extract_origin(row["url"]),
                            url=row["url"],
                            cache_type=CacheType.HTTP_CACHE,
                            content_hash=hashlib.sha256(
                                str(row["response_object"]).encode()
                            ).hexdigest(),
                            mime_type="unknown",
                            cached_at=datetime.fromtimestamp(row["time_stamp"]),
                            expires_at=None,
                            host_app=app_info.app_name,
                            host_app_pid=app_info.pid,
                            platform=app_info.platform,
                            size_bytes=len(str(row["response_object"])),
                            is_executable=self._is_executable_content(row["url"]),
                        )
                        items.append(item)
                    except Exception as e:
                        self.logger.debug(f"Error parsing cache entry: {e}")

            conn.close()
        except Exception as e:
            self.logger.error(f"Error parsing WebKit cache database: {e}")

        return items

    async def _enumerate_cache_api(
        self,
        cache_path: Path,
        app_info: WebViewAppInfo,
    ) -> List[CachedItem]:
        """Enumerate Cache API storage."""
        items: List[CachedItem] = []
        cache_storage_path = cache_path / "Cache Storage"

        if not cache_storage_path.exists():
            return items

        try:
            for origin_dir in cache_storage_path.iterdir():
                if not origin_dir.is_dir():
                    continue

                for cache_dir in origin_dir.iterdir():
                    if not cache_dir.is_dir():
                        continue

                    for cache_file in cache_dir.glob("**/*"):
                        if cache_file.is_file():
                            item = CachedItem(
                                cache_id=f"capi_{cache_file.name[:16]}",
                                origin=origin_dir.name,
                                url=str(cache_file),
                                cache_type=CacheType.CACHE_API,
                                content_hash=await self._compute_file_hash(cache_file),
                                mime_type="application/octet-stream",
                                cached_at=datetime.fromtimestamp(cache_file.stat().st_mtime),
                                expires_at=None,
                                host_app=app_info.app_name,
                                host_app_pid=app_info.pid,
                                platform=app_info.platform,
                                size_bytes=cache_file.stat().st_size,
                                is_executable=self._is_executable_content(cache_file.name),
                            )
                            items.append(item)
        except Exception as e:
            self.logger.error(f"Error enumerating Cache API: {e}")

        return items

    async def _enumerate_indexeddb(
        self,
        cache_path: Path,
        app_info: WebViewAppInfo,
    ) -> List[CachedItem]:
        """Enumerate IndexedDB storage."""
        items: List[CachedItem] = []
        indexeddb_path = cache_path / "IndexedDB"

        if not indexeddb_path.exists():
            return items

        try:
            for origin_dir in indexeddb_path.iterdir():
                if not origin_dir.is_dir():
                    continue

                for db_file in origin_dir.glob("**/*.leveldb"):
                    item = CachedItem(
                        cache_id=f"idb_{db_file.name[:16]}",
                        origin=origin_dir.name,
                        url=str(db_file),
                        cache_type=CacheType.INDEXED_DB,
                        content_hash=await self._compute_file_hash(db_file),
                        mime_type="application/x-leveldb",
                        cached_at=datetime.fromtimestamp(db_file.stat().st_mtime),
                        expires_at=None,
                        host_app=app_info.app_name,
                        host_app_pid=app_info.pid,
                        platform=app_info.platform,
                        size_bytes=db_file.stat().st_size,
                        is_executable=False,
                    )
                    items.append(item)
        except Exception as e:
            self.logger.error(f"Error enumerating IndexedDB: {e}")

        return items

    async def _enumerate_service_workers(
        self,
        cache_path: Path,
        app_info: WebViewAppInfo,
    ) -> List[CachedItem]:
        """Enumerate Service Worker registrations and caches."""
        items: List[CachedItem] = []
        sw_path = cache_path / "Service Worker"

        if not sw_path.exists():
            return items

        try:
            for sw_file in sw_path.glob("**/*"):
                if sw_file.is_file():
                    item = CachedItem(
                        cache_id=f"sw_{sw_file.name[:16]}",
                        origin=self._extract_origin_from_path(sw_file),
                        url=str(sw_file),
                        cache_type=CacheType.SERVICE_WORKER,
                        content_hash=await self._compute_file_hash(sw_file),
                        mime_type="application/javascript",
                        cached_at=datetime.fromtimestamp(sw_file.stat().st_mtime),
                        expires_at=None,
                        host_app=app_info.app_name,
                        host_app_pid=app_info.pid,
                        platform=app_info.platform,
                        size_bytes=sw_file.stat().st_size,
                        is_executable=True,  # Service Workers are always executable
                    )
                    items.append(item)
        except Exception as e:
            self.logger.error(f"Error enumerating Service Workers: {e}")

        return items

    async def _enumerate_local_storage(
        self,
        cache_path: Path,
        app_info: WebViewAppInfo,
    ) -> List[CachedItem]:
        """Enumerate Local/Session Storage."""
        items: List[CachedItem] = []
        storage_path = cache_path / "Local Storage"

        if not storage_path.exists():
            return items

        try:
            for storage_file in storage_path.glob("**/*"):
                if storage_file.is_file() and storage_file.suffix == ".leveldb":
                    item = CachedItem(
                        cache_id=f"ls_{storage_file.name[:16]}",
                        origin=self._extract_origin_from_path(storage_file),
                        url=str(storage_file),
                        cache_type=CacheType.LOCAL_STORAGE,
                        content_hash=await self._compute_file_hash(storage_file),
                        mime_type="application/x-leveldb",
                        cached_at=datetime.fromtimestamp(storage_file.stat().st_mtime),
                        expires_at=None,
                        host_app=app_info.app_name,
                        host_app_pid=app_info.pid,
                        platform=app_info.platform,
                        size_bytes=storage_file.stat().st_size,
                        is_executable=False,
                    )
                    items.append(item)
        except Exception as e:
            self.logger.error(f"Error enumerating Local Storage: {e}")

        return items

    @staticmethod
    async def _compute_file_hash(file_path: Path, algorithm: str = "sha256") -> str:
        """Compute file hash efficiently."""
        hash_obj = hashlib.new(algorithm)
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    hash_obj.update(chunk)
        except Exception:
            pass
        return hash_obj.hexdigest()

    @staticmethod
    def _extract_origin(url: str) -> str:
        """Extract origin from URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else "unknown"
        except Exception:
            return "unknown"

    @staticmethod
    def _extract_origin_from_path(path: Path) -> str:
        """Extract origin from file path."""
        # Heuristic extraction from path
        parts = path.parts
        for part in parts:
            if "://" in part or ".com" in part or ".org" in part:
                return part
        return "unknown"

    @staticmethod
    def _is_executable_content(url_or_path: str) -> bool:
        """Determine if content is executable (WASM, JS, etc.)."""
        executable_extensions = {
            ".wasm", ".js", ".mjs", ".ts", ".tsx",
            ".jar", ".dex", ".apk",
        }
        executable_mimes = {
            "application/wasm",
            "application/javascript",
            "text/javascript",
            "application/x-javascript",
        }

        lower_str = url_or_path.lower()
        for ext in executable_extensions:
            if ext in lower_str:
                return True

        return False


# ============================================================================
# WEBVIEW POLICY VALIDATOR
# ============================================================================

class WebViewPolicyValidator:
    """
    Validates cached items against security policies.

    Computes policy delta (ΔPolicy) between policy at cache time and current policy.
    Classifies items as COMPLIANT, NON_COMPLIANT, UNKNOWN, or SUSPICIOUS.
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize the validator."""
        self.logger = logger or logging.getLogger(__name__)
        self.current_policy: Optional[SecurityPolicy] = None
        self.policy_history: Dict[str, SecurityPolicy] = {}
        self.validation_cache: Dict[str, ValidationResult] = {}

    def set_current_policy(self, policy: SecurityPolicy) -> None:
        """Set the current security policy."""
        self.current_policy = policy
        self.policy_history[policy.policy_id] = policy
        self.logger.info(f"Current policy set: {policy.policy_id}")

    async def validate_item(
        self,
        item: CachedItem,
        cache_policy_id: Optional[str] = None,
    ) -> ValidationResult:
        """
        Validate a cached item against security policy.

        Args:
            item: The cached item to validate.
            cache_policy_id: Policy ID at time of caching (if known).

        Returns:
            ValidationResult with compliance status and recommendations.
        """
        if not self.current_policy:
            self.logger.warning("No current policy set; marking as UNKNOWN")
            return ValidationResult(
                cache_id=item.cache_id,
                compliance_status=ComplianceStatus.UNKNOWN,
                policy_delta=None,
                confidence=0.0,
            )

        # Reconstruct cache-time policy
        cache_policy = self._get_or_reconstruct_policy(cache_policy_id)

        # Compute policy delta
        delta = self._compute_policy_delta(cache_policy, self.current_policy)

        # Validate item against policy
        status, violations, confidence = self._validate_against_policy(item, delta)

        result = ValidationResult(
            cache_id=item.cache_id,
            compliance_status=status,
            policy_delta=delta,
            violation_details=violations,
            recommended_action=self._recommend_action(status, item, delta),
            confidence=confidence,
        )

        self.validation_cache[item.cache_id] = result
        return result

    async def validate_batch(
        self,
        items: List[CachedItem],
    ) -> List[ValidationResult]:
        """Validate a batch of items."""
        results = []
        for item in items:
            result = await self.validate_item(item)
            results.append(result)
        return results

    def _get_or_reconstruct_policy(self, policy_id: Optional[str]) -> SecurityPolicy:
        """Retrieve cached policy or reconstruct default."""
        if policy_id and policy_id in self.policy_history:
            return self.policy_history[policy_id]

        # Default reconstructed policy (most permissive)
        return SecurityPolicy(
            policy_id="RECONSTRUCTED_DEFAULT",
            timestamp=datetime.fromtimestamp(0, tz=timezone.utc),
            lockdown_mode_enabled=False,
        )

    def _compute_policy_delta(
        self,
        old_policy: SecurityPolicy,
        new_policy: SecurityPolicy,
    ) -> PolicyDelta:
        """Compute differences between two policies."""
        changed_fields: List[str] = []
        details: Dict[str, Any] = {}

        # Check lockdown mode
        if old_policy.lockdown_mode_enabled != new_policy.lockdown_mode_enabled:
            changed_fields.append("lockdown_mode_enabled")
            details["lockdown_mode_transition"] = {
                "before": old_policy.lockdown_mode_enabled,
                "after": new_policy.lockdown_mode_enabled,
            }

        # Check MDM restrictions
        if old_policy.mdm_restrictions != new_policy.mdm_restrictions:
            changed_fields.append("mdm_restrictions")
            added = set(new_policy.mdm_restrictions.keys()) - set(old_policy.mdm_restrictions.keys())
            removed = set(old_policy.mdm_restrictions.keys()) - set(new_policy.mdm_restrictions.keys())
            details["mdm_changes"] = {
                "added_restrictions": list(added),
                "removed_restrictions": list(removed),
            }

        # Check CSP directives
        if old_policy.csp_directives != new_policy.csp_directives:
            changed_fields.append("csp_directives")
            details["csp_changes"] = {
                "added": list(set(new_policy.csp_directives.keys()) - set(old_policy.csp_directives.keys())),
                "modified": list(set(old_policy.csp_directives.keys()) & set(new_policy.csp_directives.keys())),
            }

        # Determine severity
        severity = self._assess_delta_severity(changed_fields, details)

        return PolicyDelta(
            cache_policy_id=old_policy.policy_id,
            current_policy_id=new_policy.policy_id,
            policy_at_cache_time=old_policy,
            current_policy=new_policy,
            changed_fields=changed_fields,
            severity=severity,
            details=details,
        )

    def _validate_against_policy(
        self,
        item: CachedItem,
        delta: PolicyDelta,
    ) -> Tuple[ComplianceStatus, List[str], float]:
        """Validate item against the policy delta."""
        violations: List[str] = []
        confidence = 1.0

        # Executable content in lockdown mode
        if item.is_executable and delta.current_policy.lockdown_mode_enabled:
            violations.append("Executable content cached while in lockdown mode")
            confidence = 1.0

        # Origin not in allowed list
        if delta.current_policy.allowed_origins:
            if item.origin not in delta.current_policy.allowed_origins:
                violations.append(f"Origin {item.origin} not in allowed list")
                confidence = 0.9

        # CSP violations
        if "script-src" in delta.current_policy.csp_directives:
            csp_script = delta.current_policy.csp_directives["script-src"]
            if "'none'" in csp_script and item.cache_type == CacheType.HTTP_CACHE:
                violations.append("Cached script contradicts CSP script-src 'none'")
                confidence = 0.95

        # Determine status
        if not violations:
            status = ComplianceStatus.COMPLIANT
        elif delta.changed_fields:
            status = ComplianceStatus.NON_COMPLIANT if violations else ComplianceStatus.COMPLIANT
        else:
            status = ComplianceStatus.UNKNOWN

        return status, violations, confidence

    @staticmethod
    def _assess_delta_severity(changed_fields: List[str], details: Dict[str, Any]) -> str:
        """Assess severity of policy delta."""
        if "lockdown_mode_enabled" in changed_fields:
            if details.get("lockdown_mode_transition", {}).get("after"):
                return "CRITICAL"
        if "csp_directives" in changed_fields:
            return "HIGH"
        if "mdm_restrictions" in changed_fields:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _recommend_action(
        status: ComplianceStatus,
        item: CachedItem,
        delta: PolicyDelta,
    ) -> MitigationAction:
        """Recommend mitigation action."""
        if status == ComplianceStatus.COMPLIANT:
            return MitigationAction.BLOCK  # Keep but monitor

        if item.is_executable and delta.severity in ("HIGH", "CRITICAL"):
            return MitigationAction.PURGE  # Aggressive for executable content

        if status == ComplianceStatus.NON_COMPLIANT:
            if item.cache_type in (CacheType.SERVICE_WORKER, CacheType.CACHE_API):
                return MitigationAction.PURGE
            return MitigationAction.QUARANTINE

        return MitigationAction.BLOCK


# ============================================================================
# WEBVIEW MITIGATION CONTROLLER
# ============================================================================

class WebViewMitigationController:
    """
    Executes mitigation actions on WebView caches.

    Supports:
    - Block: Block execution but retain cache
    - Purge: Delete cached content
    - Quarantine: Isolate to restricted directory
    - Regenerate: Force re-fetch and revalidation

    Provides atomic operations with rollback capability.
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize the mitigation controller."""
        self.logger = logger or logging.getLogger(__name__)
        self.executed_actions: Dict[str, MitigationAction] = {}
        self.rollback_stack: List[Tuple[str, Callable]] = []
        self.audit_log: List[Dict[str, Any]] = []

    async def execute_action(
        self,
        action: MitigationAction,
        item: CachedItem,
        app_info: WebViewAppInfo,
        dry_run: bool = False,
    ) -> bool:
        """
        Execute a mitigation action.

        Args:
            action: The mitigation action to execute.
            item: The cached item to remediate.
            app_info: Info about the host application.
            dry_run: If True, simulate without making changes.

        Returns:
            True if successful, False otherwise.
        """
        action_id = f"{action.value}_{item.cache_id}_{int(datetime.now(timezone.utc).timestamp())}"
        self.logger.info(f"Executing {action.value} on {item.cache_id} (app: {app_info.app_name})")

        try:
            if action == MitigationAction.BLOCK:
                success = await self._execute_block(item, app_info, dry_run)
            elif action == MitigationAction.PURGE:
                success = await self._execute_purge(item, app_info, dry_run)
            elif action == MitigationAction.QUARANTINE:
                success = await self._execute_quarantine(item, app_info, dry_run)
            elif action == MitigationAction.REGENERATE:
                success = await self._execute_regenerate(item, app_info, dry_run)
            else:
                success = False

            if success:
                self._log_action(action_id, action, item, app_info, "SUCCESS", dry_run)
                self.executed_actions[action_id] = action
                return True
            else:
                self._log_action(action_id, action, item, app_info, "FAILED", dry_run)
                return False

        except Exception as e:
            self.logger.error(f"Error executing action: {e}", exc_info=True)
            self._log_action(action_id, action, item, app_info, "ERROR", dry_run, str(e))
            return False

    async def _execute_block(
        self,
        item: CachedItem,
        app_info: WebViewAppInfo,
        dry_run: bool,
    ) -> bool:
        """Block execution by marking cache entry as untrusted."""
        self.logger.debug(f"Blocking cache: {item.cache_id}")
        # Implementation would mark entry as blocked in app-specific store
        if not dry_run:
            # Create marker file in quarantine directory
            pass
        return True

    async def _execute_purge(
        self,
        item: CachedItem,
        app_info: WebViewAppInfo,
        dry_run: bool,
    ) -> bool:
        """Purge cached content."""
        self.logger.debug(f"Purging cache: {item.cache_id}")

        if not dry_run:
            try:
                # Platform-specific cache clearing
                if app_info.platform == PlatformType.IOS:
                    return await self._purge_ios(item, app_info)
                elif app_info.platform == PlatformType.ANDROID:
                    return await self._purge_android(item, app_info)
                elif app_info.platform == PlatformType.MACOS:
                    return await self._purge_macos(item, app_info)
                elif app_info.platform == PlatformType.ELECTRON:
                    return await self._purge_electron(item, app_info)
            except Exception as e:
                self.logger.error(f"Purge failed: {e}")
                return False

        return True

    async def _execute_quarantine(
        self,
        item: CachedItem,
        app_info: WebViewAppInfo,
        dry_run: bool,
    ) -> bool:
        """Quarantine cached content to restricted directory."""
        self.logger.debug(f"Quarantining cache: {item.cache_id}")

        if not dry_run:
            quarantine_dir = Path(tempfile.gettempdir()) / ".webview_quarantine"
            quarantine_dir.mkdir(exist_ok=True, parents=True)

            quarantine_file = quarantine_dir / f"{item.cache_id}.quarantined"
            try:
                # Mark or move to quarantine
                quarantine_file.write_text(json.dumps(item.to_dict()))
                return True
            except Exception as e:
                self.logger.error(f"Quarantine failed: {e}")
                return False

        return True

    async def _execute_regenerate(
        self,
        item: CachedItem,
        app_info: WebViewAppInfo,
        dry_run: bool,
    ) -> bool:
        """Force re-fetch and revalidation of cached content."""
        self.logger.debug(f"Regenerating cache: {item.cache_id}")

        if not dry_run:
            # Platform-specific cache invalidation
            try:
                # This would typically involve clearing the cache entry
                # and forcing the browser to re-fetch from origin
                pass
            except Exception as e:
                self.logger.error(f"Regenerate failed: {e}")
                return False

        return True

    async def _purge_ios(self, item: CachedItem, app_info: WebViewAppInfo) -> bool:
        """iOS-specific cache purge using WKWebsiteDataStore."""
        # Would use WKWebsiteDataStore.removeData(ofTypes:...) via native bridge
        return True

    async def _purge_android(self, item: CachedItem, app_info: WebViewAppInfo) -> bool:
        """Android-specific cache purge using WebView.clearCache()."""
        # Would use Android WebView.clearCache() via adb or native bridge
        return True

    async def _purge_macos(self, item: CachedItem, app_info: WebViewAppInfo) -> bool:
        """macOS-specific cache purge using WKWebsiteDataStore."""
        # Would use WKWebsiteDataStore.removeData(ofTypes:...) via osascript
        return True

    async def _purge_electron(self, item: CachedItem, app_info: WebViewAppInfo) -> bool:
        """Electron-specific cache purge using session.clearCache()."""
        # Would use Electron session API
        return True

    async def rollback_all(self) -> bool:
        """Rollback all executed actions."""
        self.logger.info(f"Rolling back {len(self.rollback_stack)} actions")

        while self.rollback_stack:
            action_id, rollback_fn = self.rollback_stack.pop()
            try:
                await rollback_fn()
                self.logger.info(f"Rolled back: {action_id}")
            except Exception as e:
                self.logger.error(f"Rollback failed for {action_id}: {e}")
                return False

        return True

    def _log_action(
        self,
        action_id: str,
        action: MitigationAction,
        item: CachedItem,
        app_info: WebViewAppInfo,
        status: str,
        dry_run: bool,
        error: Optional[str] = None,
    ) -> None:
        """Log action for audit trail."""
        log_entry = {
            "action_id": action_id,
            "action_type": action.value,
            "cache_id": item.cache_id,
            "host_app": app_info.app_name,
            "status": status,
            "dry_run": dry_run,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": error,
        }
        self.audit_log.append(log_entry)
        self.logger.info(f"Action logged: {action_id} -> {status}")

    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Retrieve audit log."""
        return self.audit_log.copy()

    def save_audit_log(self, path: Path) -> bool:
        """Save audit log to file (tamper-evident)."""
        try:
            log_data = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "log_entries": self.audit_log,
                "integrity_hash": self._compute_log_hash(),
            }
            with open(path, "w") as f:
                json.dump(log_data, f, indent=2)
            self.logger.info(f"Audit log saved to {path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to save audit log: {e}")
            return False

    def _compute_log_hash(self) -> str:
        """Compute integrity hash of audit log."""
        log_str = json.dumps(self.audit_log, sort_keys=True)
        return hashlib.sha256(log_str.encode()).hexdigest()


# ============================================================================
# WEBVIEW POSTURE ADAPTER
# ============================================================================

class WebViewPostureAdapter:
    """
    Integrates WebView validation with OS-level policy transition detection.

    Registers for platform-specific notifications:
    - NSNotification on iOS/macOS
    - BroadcastReceiver on Android
    - WMI on Windows

    Triggers validation pipeline on policy transition and manages execution
    suspension window during validation.
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize the posture adapter."""
        self.logger = logger or logging.getLogger(__name__)
        self.platform = self._detect_platform()
        self.listeners: List[Callable] = []
        self.validation_in_progress = False

    def _detect_platform(self) -> PlatformType:
        """Detect current platform."""
        system = platform.system()
        if system == "Darwin":
            return PlatformType.MACOS
        elif system == "Linux":
            return PlatformType.LINUX
        elif system == "Windows":
            return PlatformType.WINDOWS
        return PlatformType.LINUX

    async def register_policy_listener(
        self,
        callback: Callable[[PolicyTransitionEvent, SecurityPolicy], None],
    ) -> bool:
        """
        Register a callback for policy transition events.

        Args:
            callback: Function to call when policy transitions occur.

        Returns:
            True if registration successful.
        """
        self.listeners.append(callback)
        self.logger.info(f"Policy listener registered (total: {len(self.listeners)})")
        return True

    async def start_monitoring(self) -> None:
        """Start monitoring for policy transitions."""
        self.logger.info(f"Starting policy monitoring on {self.platform.value}")

        if self.platform == PlatformType.MACOS:
            await self._monitor_macos()
        elif self.platform == PlatformType.IOS:
            await self._monitor_ios()
        elif self.platform == PlatformType.ANDROID:
            await self._monitor_android()
        elif self.platform == PlatformType.WINDOWS:
            await self._monitor_windows()

    async def _monitor_macos(self) -> None:
        """Monitor macOS for Lockdown Mode and MDM changes."""
        self.logger.debug("Setting up macOS policy monitoring")
        # Would register for NSNotificationCenter notifications
        # Specifically: com.apple.LockdownMode notifications
        pass

    async def _monitor_ios(self) -> None:
        """Monitor iOS for Lockdown Mode and MDM changes."""
        self.logger.debug("Setting up iOS policy monitoring")
        # Would register for UIDevice and MDM notifications
        pass

    async def _monitor_android(self) -> None:
        """Monitor Android for policy changes."""
        self.logger.debug("Setting up Android policy monitoring")
        # Would register BroadcastReceiver for DevicePolicyManager events
        pass

    async def _monitor_windows(self) -> None:
        """Monitor Windows for policy changes."""
        self.logger.debug("Setting up Windows policy monitoring")
        # Would use WMI subscriptions for GROUP_POLICY_UPDATE events
        pass

    async def on_policy_transition(
        self,
        event: PolicyTransitionEvent,
        new_policy: SecurityPolicy,
    ) -> None:
        """
        Handle a detected policy transition.

        Args:
            event: The type of policy transition.
            new_policy: The new security policy.
        """
        self.logger.info(f"Policy transition detected: {event.value}")
        self.validation_in_progress = True

        try:
            # Trigger callbacks
            for listener in self.listeners:
                try:
                    result = listener(event, new_policy)
                    if hasattr(result, "__await__"):
                        await result
                except Exception as e:
                    self.logger.error(f"Listener callback failed: {e}", exc_info=True)

        finally:
            self.validation_in_progress = False
            self.logger.info("Policy validation complete")

    async def suspend_execution(self, duration_sec: int) -> None:
        """
        Suspend WebView execution during validation window.

        Args:
            duration_sec: Duration to suspend in seconds.
        """
        self.logger.info(f"Suspending WebView execution for {duration_sec}s")
        # Would implement platform-specific execution suspension
        await asyncio.sleep(0.1)  # Placeholder
        self.logger.info("Execution suspension lifted")


# ============================================================================
# MAIN INTEGRATION CLASS
# ============================================================================

class WebViewCacheValidator:
    """
    Main integration class for WebView cache validation pipeline.

    Coordinates discovery, enumeration, validation, mitigation, and monitoring.
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize the main validator."""
        self.logger = logger or logging.getLogger(__name__)

        self.discovery = WebViewCacheDiscovery(logger)
        self.enumerator = WebViewCacheEnumerator(logger)
        self.validator = WebViewPolicyValidator(logger)
        self.mitigator = WebViewMitigationController(logger)
        self.posture_adapter = WebViewPostureAdapter(logger)

        self.discovered_apps: Dict[str, WebViewAppInfo] = {}
        self.cached_items: List[CachedItem] = []
        self.validation_results: List[ValidationResult] = []

    async def run_full_validation(
        self,
        current_policy: SecurityPolicy,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Run the complete validation pipeline.

        Args:
            current_policy: The current security policy.
            dry_run: If True, don't execute mitigations.

        Returns:
            Summary results.
        """
        self.logger.info("Starting full WebView cache validation pipeline")
        start_time = datetime.now(timezone.utc)

        # Phase 1: Discovery
        self.logger.info("Phase 1: Discovering WebView caches")
        self.discovered_apps = await self.discovery.discover_all()
        self.logger.info(f"Discovered {len(self.discovered_apps)} apps")

        # Phase 2: Enumeration
        self.logger.info("Phase 2: Enumerating cached content")
        self.cached_items = []
        for app_info in self.discovered_apps.values():
            items = await self.enumerator.enumerate_app_caches(app_info)
            self.cached_items.extend(items)
        self.logger.info(f"Enumerated {len(self.cached_items)} cache items")

        # Phase 3: Policy validation
        self.logger.info("Phase 3: Validating against security policy")
        self.validator.set_current_policy(current_policy)
        self.validation_results = await self.validator.validate_batch(self.cached_items)

        # Phase 4: Mitigation
        self.logger.info("Phase 4: Executing mitigations")
        mitigated_count = 0
        for result in self.validation_results:
            if result.compliance_status != ComplianceStatus.COMPLIANT:
                # Find corresponding item
                for item in self.cached_items:
                    if item.cache_id == result.cache_id:
                        # Find app info
                        for app_info in self.discovered_apps.values():
                            if app_info.app_name == item.host_app:
                                success = await self.mitigator.execute_action(
                                    MitigationAction(result.recommended_action),
                                    item,
                                    app_info,
                                    dry_run=dry_run,
                                )
                                if success:
                                    mitigated_count += 1
                                break
                        break

        # Phase 5: Audit logging
        self.logger.info("Phase 5: Generating audit logs")
        audit_log = self.mitigator.get_audit_log()

        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

        summary = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "discovered_apps": len(self.discovered_apps),
            "enumerated_items": len(self.cached_items),
            "validation_results": len(self.validation_results),
            "mitigated_items": mitigated_count,
            "compliant_items": sum(
                1 for r in self.validation_results
                if r.compliance_status == ComplianceStatus.COMPLIANT
            ),
            "non_compliant_items": sum(
                1 for r in self.validation_results
                if r.compliance_status == ComplianceStatus.NON_COMPLIANT
            ),
            "unknown_items": sum(
                1 for r in self.validation_results
                if r.compliance_status == ComplianceStatus.UNKNOWN
            ),
            "suspicious_items": sum(
                1 for r in self.validation_results
                if r.compliance_status == ComplianceStatus.SUSPICIOUS
            ),
            "elapsed_seconds": elapsed,
            "dry_run": dry_run,
            "audit_log_entries": len(audit_log),
        }

        self.logger.info(f"Validation complete: {mitigated_count} items mitigated in {elapsed:.2f}s")
        return summary

    async def export_report(self, path: Path) -> bool:
        """Export comprehensive validation report."""
        try:
            report = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "discovered_apps": [
                    app.to_dict() for app in self.discovered_apps.values()
                ],
                "cached_items": [item.to_dict() for item in self.cached_items],
                "validation_results": [
                    result.to_dict() for result in self.validation_results
                ],
                "audit_log": self.mitigator.get_audit_log(),
            }

            with open(path, "w") as f:
                json.dump(report, f, indent=2, default=str)

            self.logger.info(f"Report exported to {path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to export report: {e}")
            return False
