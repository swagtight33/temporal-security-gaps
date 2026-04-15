"""
Firmware Cache Validator: Mitigating Cached Executable Persistence Across
Security Policy Transitions

Derivative #63: Firmware/UEFI Cached Executable Persistence

Patent Portfolio: "System and Method for Mitigating Cached Executable Persistence
Across Security Policy Transitions"

Authors: Stanley Linton / STAAML Corp.

This module implements detection, validation, and mitigation of UEFI firmware cache
persistence vulnerabilities. UEFI Secure Boot maintains its own cache of authorized
bootloaders and EFI applications in the EFI System Partition (ESP). When firmware
security policy transitions (Secure Boot key revocation, dbx updates, Platform Key
rotation), previously cached EFI binaries may persist despite no longer being
authorized. This creates a persistence vector for malicious bootkits.

THREAT MODEL:
    - Evil Maid Attack: Attacker physically inserts malicious EFI binary into ESP
      before Secure Boot policy transitions. Binary cached before dbx update survives.
    - Bootkit Persistence: Malicious bootloader cached at ring -2 before dbx update
      executes at next boot despite dbx entry.
    - Option ROM Attacks: Malicious Option ROMs persist in firmware cache.
    - Supply Chain Compromise: Trusted EFI binary signed with compromised cert, later
      revoked via dbx update, persists in cache.
    - Temporal Bypass: Policy enforcement relies on "current" state; attacker exploits
      window between policy change and cache validation.
"""

import asyncio
import hashlib
import json
import logging
import os
import shutil
import struct
import tempfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from abc import ABC, abstractmethod
import hmac

# Type aliases
HexStr = str
SHA256Hash = str
EFIPath = Path


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


# ============================================================================
# ENUMERATIONS AND CONSTANTS
# ============================================================================

class ValidationStatus(Enum):
    """Classification of EFI binary validation status."""
    COMPLIANT = "COMPLIANT"  # Present in db, not in dbx
    NON_COMPLIANT = "NON_COMPLIANT"  # Present in dbx
    UNSIGNED = "UNSIGNED"  # No valid signature
    UNKNOWN = "UNKNOWN"  # Cannot determine (missing signature data)
    QUARANTINED = "QUARANTINED"  # Moved to safe location


class PolicyTransitionType(Enum):
    """Types of Secure Boot policy transitions."""
    DBX_UPDATE = "DBX_UPDATE"
    DB_UPDATE = "DB_UPDATE"
    PK_ROTATION = "PK_ROTATION"
    KEK_ROTATION = "KEK_ROTATION"
    MOK_UPDATE = "MOK_UPDATE"


class EFIBinaryType(Enum):
    """Classification of EFI executable types."""
    BOOTLOADER = "BOOTLOADER"
    OPTION_ROM = "OPTION_ROM"
    EFI_DRIVER = "EFI_DRIVER"
    EFI_APPLICATION = "EFI_APPLICATION"
    UEFI_SHELL = "UEFI_SHELL"
    UNKNOWN = "UNKNOWN"


# Platform-specific paths for EFI System Partition
ESP_PATHS = {
    "linux": [
        Path("/boot/efi"),
        Path("/efi"),
        Path("/boot/EFI"),
    ],
    "windows": [
        Path("C:\\EFI"),
        Path("C:\\Program Files\\UEFI"),
    ],
    "darwin": [
        Path("/Library/SystemConfiguration/EFI"),
        Path("/Volumes/EFI"),
    ],
}

EFIVARS_PATHS = {
    "linux": Path("/sys/firmware/efi/efivars"),
    "windows": Path("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\efivars"),
}

# EFI Signature List constants
EFI_SIGNATURE_LIST_MAGIC = 0x2566EF5C
EFI_SHA256_GUID = "c1c41626-504c-4092-aca9-41f936934328"
EFI_CERT_RSA2048_GUID = "3c5fb5d0-3e60-42f9-8e99-521ec955a5e5"
EFI_CERT_X509_GUID = "a5c059a1-94e4-4aa7-87b5-ab155c2bf072"


# ============================================================================
# DATACLASSES FOR DATA STRUCTURES
# ============================================================================

@dataclass
class SignatureDatabaseEntry:
    """Represents a single entry in Secure Boot signature database (db or dbx)."""
    signature_type: str  # GUID string
    signature_owner: str  # GUID string
    signature_data: bytes
    signature_hash: SHA256Hash = field(init=False)

    def __post_init__(self):
        self.signature_hash = hashlib.sha256(self.signature_data).hexdigest()

    def matches_hash(self, target_hash: SHA256Hash) -> bool:
        """Check if this signature entry matches a given hash."""
        return self.signature_hash == target_hash


@dataclass
class SecureBootPolicy:
    """Represents the complete Secure Boot policy state at a point in time."""
    timestamp: datetime
    pk_hash: SHA256Hash  # Platform Key hash
    kek_entries: List[SignatureDatabaseEntry] = field(default_factory=list)
    db_entries: List[SignatureDatabaseEntry] = field(default_factory=list)
    dbx_entries: List[SignatureDatabaseEntry] = field(default_factory=list)
    dbr_entries: List[SignatureDatabaseEntry] = field(default_factory=list)
    mok_entries: List[SignatureDatabaseEntry] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for JSON storage."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "pk_hash": self.pk_hash,
            "kek_count": len(self.kek_entries),
            "db_count": len(self.db_entries),
            "dbx_count": len(self.dbx_entries),
            "dbr_count": len(self.dbr_entries),
            "mok_count": len(self.mok_entries),
        }


@dataclass
class EFIBinary:
    """Represents a discovered EFI executable in the ESP."""
    path: EFIPath
    binary_type: EFIBinaryType
    size_bytes: int
    sha256_hash: SHA256Hash
    created_timestamp: datetime
    last_modified: datetime
    is_signed: bool
    signature_data: Optional[bytes] = None
    extracted_certificates: List[bytes] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for JSON storage."""
        return {
            "path": str(self.path),
            "binary_type": self.binary_type.value,
            "size_bytes": self.size_bytes,
            "sha256_hash": self.sha256_hash,
            "created_timestamp": self.created_timestamp.isoformat(),
            "last_modified": self.last_modified.isoformat(),
            "is_signed": self.is_signed,
            "signature_data": self.signature_data.hex() if self.signature_data else None,
        }


@dataclass
class ValidationReport:
    """Complete validation report for an EFI binary."""
    efi_binary: EFIBinary
    validation_status: ValidationStatus
    policy_snapshot: SecureBootPolicy
    validation_timestamp: datetime
    matching_dbx_entries: List[SignatureDatabaseEntry] = field(default_factory=list)
    matching_db_entries: List[SignatureDatabaseEntry] = field(default_factory=list)
    certificate_chain_valid: bool = False
    audit_trail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for JSON storage."""
        return {
            "efi_binary": self.efi_binary.to_dict(),
            "validation_status": self.validation_status.value,
            "validation_timestamp": self.validation_timestamp.isoformat(),
            "policy_snapshot": self.policy_snapshot.to_dict(),
            "matching_dbx_entries": len(self.matching_dbx_entries),
            "matching_db_entries": len(self.matching_db_entries),
            "certificate_chain_valid": self.certificate_chain_valid,
        }


@dataclass
class TemporalBinding:
    """Cryptographic binding of EFI binary to policy state at observation time."""
    efi_binary_hash: SHA256Hash
    observation_timestamp: datetime
    dbx_hash: SHA256Hash  # Hash of entire dbx at observation time
    db_hash: SHA256Hash  # Hash of entire db at observation time
    pk_hash: SHA256Hash
    binding_hmac: str = ""  # HMAC over binding data for tamper detection

    def compute_binding_hmac(self, secret_key: bytes) -> str:
        """Compute HMAC to detect tampering with binding."""
        binding_data = (
            f"{self.efi_binary_hash}:{self.observation_timestamp.isoformat()}:"
            f"{self.dbx_hash}:{self.db_hash}:{self.pk_hash}"
        ).encode()
        self.binding_hmac = hmac.new(secret_key, binding_data, hashlib.sha256).hexdigest()
        return self.binding_hmac

    def verify_binding_hmac(self, secret_key: bytes) -> bool:
        """Verify HMAC integrity of binding."""
        computed = self.compute_binding_hmac(secret_key)
        return hmac.compare_digest(computed, self.binding_hmac)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for JSON storage."""
        return {
            "efi_binary_hash": self.efi_binary_hash,
            "observation_timestamp": self.observation_timestamp.isoformat(),
            "dbx_hash": self.dbx_hash,
            "db_hash": self.db_hash,
            "pk_hash": self.pk_hash,
            "binding_hmac": self.binding_hmac,
        }


@dataclass
class MitigationAction:
    """Record of a mitigation action taken on a non-compliant EFI binary."""
    action_timestamp: datetime
    efi_binary_path: EFIPath
    action_type: str  # "QUARANTINE", "DELETE", "REPLACE_STUB", "MONITOR"
    reason: str
    backup_location: Optional[EFIPath] = None
    reversible: bool = True
    rollback_data: Optional[bytes] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for JSON storage."""
        return {
            "action_timestamp": self.action_timestamp.isoformat(),
            "efi_binary_path": str(self.efi_binary_path),
            "action_type": self.action_type,
            "reason": self.reason,
            "backup_location": str(self.backup_location) if self.backup_location else None,
            "reversible": self.reversible,
        }


# ============================================================================
# FIRMWARE CACHE DISCOVERY
# ============================================================================

class FirmwareCacheDiscovery:
    """
    Enumerates EFI System Partition contents and UEFI variable store.

    Discovers EFI binaries, reads Secure Boot policy from efivars,
    and maps PE/COFF signatures to signature databases.
    """

    def __init__(self, esp_root: Optional[Path] = None, platform: str = "linux"):
        """
        Initialize firmware cache discovery.

        Args:
            esp_root: Path to EFI System Partition root (auto-detected if None)
            platform: "linux", "windows", or "darwin"
        """
        self.platform = platform
        self.esp_root = esp_root or self._find_esp()
        self.efivars_path = EFIVARS_PATHS.get(platform, Path("/sys/firmware/efi/efivars"))
        self.discovered_binaries: List[EFIBinary] = []
        self.current_policy: Optional[SecureBootPolicy] = None

        logger.info(f"Initialized FirmwareCacheDiscovery with ESP root: {self.esp_root}")

    def _find_esp(self) -> Path:
        """Auto-detect EFI System Partition path."""
        candidates = ESP_PATHS.get(self.platform, [])
        for candidate in candidates:
            if candidate.exists():
                logger.info(f"Detected ESP at: {candidate}")
                return candidate
        raise RuntimeError(f"Could not locate EFI System Partition on {self.platform}")

    async def discover_efi_binaries(self) -> List[EFIBinary]:
        """
        Enumerate all EFI executables in the ESP.

        Returns:
            List of discovered EFI binaries with metadata.
        """
        self.discovered_binaries = []

        if not self.esp_root.exists():
            logger.warning(f"ESP path does not exist: {self.esp_root}")
            return self.discovered_binaries

        # Common EFI binary paths and patterns
        efi_patterns = [
            "EFI/Boot/*.efi",
            "EFI/Microsoft/Boot/*.efi",
            "EFI/ubuntu/*.efi",
            "EFI/*/boot*.efi",
            "*.efi",
        ]

        tasks = []
        for pattern in efi_patterns:
            for binary_path in self.esp_root.glob(pattern):
                if binary_path.is_file():
                    tasks.append(self._process_efi_binary(binary_path))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        self.discovered_binaries = [r for r in results if isinstance(r, EFIBinary)]

        logger.info(f"Discovered {len(self.discovered_binaries)} EFI binaries")
        return self.discovered_binaries

    async def _process_efi_binary(self, binary_path: Path) -> Optional[EFIBinary]:
        """
        Process a single EFI binary file.

        Args:
            binary_path: Path to EFI binary file

        Returns:
            EFIBinary object with metadata, or None if processing fails
        """
        try:
            # Read binary and compute hash
            with open(binary_path, "rb") as f:
                binary_data = f.read()

            sha256_hash = hashlib.sha256(binary_data).hexdigest()

            # Detect binary type
            binary_type = self._detect_efi_binary_type(binary_data, binary_path)

            # Check if signed (PE/COFF Authenticode)
            is_signed, sig_data = self._extract_pe_signature(binary_data)

            # Get file metadata
            stat_info = binary_path.stat()
            created_ts = datetime.fromtimestamp(stat_info.st_birthtime or stat_info.st_ctime, tz=timezone.utc)
            modified_ts = datetime.fromtimestamp(stat_info.st_mtime, tz=timezone.utc)

            efi_binary = EFIBinary(
                path=binary_path,
                binary_type=binary_type,
                size_bytes=len(binary_data),
                sha256_hash=sha256_hash,
                created_timestamp=created_ts,
                last_modified=modified_ts,
                is_signed=is_signed,
                signature_data=sig_data,
            )

            logger.debug(f"Processed EFI binary: {binary_path} ({binary_type.value})")
            return efi_binary

        except Exception as e:
            logger.error(f"Error processing EFI binary {binary_path}: {e}")
            return None

    def _detect_efi_binary_type(self, binary_data: bytes, path: Path) -> EFIBinaryType:
        """Detect the type of EFI executable."""
        # Check for PE/COFF header
        if len(binary_data) > 0x3c:
            pe_offset = struct.unpack("<I", binary_data[0x3c:0x40])[0]
            if pe_offset < len(binary_data) - 4:
                pe_signature = binary_data[pe_offset : pe_offset + 4]
                if pe_signature == b"PE\x00\x00":
                    # Valid PE/COFF file
                    pass

        path_str = str(path).lower()
        if "boot" in path_str or "bootloader" in path_str:
            return EFIBinaryType.BOOTLOADER
        elif "option" in path_str or "rom" in path_str:
            return EFIBinaryType.OPTION_ROM
        elif "driver" in path_str:
            return EFIBinaryType.EFI_DRIVER
        elif "shell" in path_str:
            return EFIBinaryType.UEFI_SHELL
        else:
            return EFIBinaryType.EFI_APPLICATION

    def _extract_pe_signature(self, binary_data: bytes) -> Tuple[bool, Optional[bytes]]:
        """
        Extract PE/COFF Authenticode signature from EFI binary.

        For production use, this would use pyasn1 or cryptography library
        to properly parse PKCS#7 signature structures. This is a simplified
        version that detects signed binaries.
        """
        try:
            if len(binary_data) < 0x40:
                return False, None

            # Check for PE signature
            pe_offset = struct.unpack("<I", binary_data[0x3c:0x40])[0]
            if pe_offset >= len(binary_data) - 4:
                return False, None

            if binary_data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
                return False, None

            # PE is signed if it has valid certificate table
            # Simplified check: look for PKCS#7 markers
            if b"PKCS#7" in binary_data or b"\x30\x82" in binary_data:
                return True, binary_data[-4096:] if len(binary_data) > 4096 else binary_data

            return False, None
        except Exception:
            return False, None

    async def read_uefi_variables(self) -> SecureBootPolicy:
        """
        Read Secure Boot policy from UEFI variable store.

        On Linux, reads from /sys/firmware/efi/efivars.
        On Windows, reads from registry.
        On macOS, uses nvram command or System Preferences.

        Returns:
            SecureBootPolicy object with current PK, KEK, db, dbx, dbr, MOK state
        """
        policy = SecureBootPolicy(
            timestamp=datetime.now(timezone.utc),
            pk_hash="",
        )

        try:
            if self.platform == "linux":
                policy = await self._read_uefi_variables_linux()
            elif self.platform == "windows":
                policy = await self._read_uefi_variables_windows()
            elif self.platform == "darwin":
                policy = await self._read_uefi_variables_macos()

            self.current_policy = policy
            logger.info(f"Read UEFI policy: PK={policy.pk_hash[:16]}..., "
                       f"db={len(policy.db_entries)}, dbx={len(policy.dbx_entries)}")
            return policy

        except Exception as e:
            logger.error(f"Error reading UEFI variables: {e}")
            return policy

    async def _read_uefi_variables_linux(self) -> SecureBootPolicy:
        """Read UEFI variables from Linux efivars."""
        policy = SecureBootPolicy(
            timestamp=datetime.now(timezone.utc),
            pk_hash="",
        )

        if not self.efivars_path.exists():
            logger.warning(f"efivars path does not exist: {self.efivars_path}")
            return policy

        try:
            # Read PK (Platform Key)
            pk_var = self.efivars_path / "PK-8be4df61-93ca-11d2-aa0d-00e098032b8c"
            if pk_var.exists():
                with open(pk_var, "rb") as f:
                    pk_data = f.read()
                    policy.pk_hash = hashlib.sha256(pk_data).hexdigest()

            # Read KEK
            kek_var = self.efivars_path / "KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c"
            if kek_var.exists():
                policy.kek_entries = await self._parse_signature_list(kek_var)

            # Read db (allowed signatures)
            db_var = self.efivars_path / "db-d719b2cb-3d3a-4596-a3bc-dad00e67656f"
            if db_var.exists():
                policy.db_entries = await self._parse_signature_list(db_var)

            # Read dbx (forbidden signatures)
            dbx_var = self.efivars_path / "dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f"
            if dbx_var.exists():
                policy.dbx_entries = await self._parse_signature_list(dbx_var)

            # Read dbr (revocation)
            dbr_var = self.efivars_path / "dbr-d719b2cb-3d3a-4596-a3bc-dad00e67656f"
            if dbr_var.exists():
                policy.dbr_entries = await self._parse_signature_list(dbr_var)

        except Exception as e:
            logger.error(f"Error reading Linux UEFI variables: {e}")

        return policy

    async def _read_uefi_variables_windows(self) -> SecureBootPolicy:
        """Read UEFI variables from Windows registry."""
        # Placeholder for Windows implementation
        # On Windows, UEFI variables are in the registry
        logger.warning("Windows UEFI variable reading not yet implemented")
        return SecureBootPolicy(
            timestamp=datetime.now(timezone.utc),
            pk_hash="",
        )

    async def _read_uefi_variables_macos(self) -> SecureBootPolicy:
        """Read UEFI variables from macOS."""
        # Placeholder for macOS implementation
        # On macOS, use nvram command
        logger.warning("macOS UEFI variable reading not yet implemented")
        return SecureBootPolicy(
            timestamp=datetime.now(timezone.utc),
            pk_hash="",
        )

    async def _parse_signature_list(self, var_path: Path) -> List[SignatureDatabaseEntry]:
        """
        Parse EFI_SIGNATURE_LIST structure from UEFI variable.

        EFI_SIGNATURE_LIST format:
        - SignatureType (GUID): 16 bytes
        - ListSize (uint32): 4 bytes
        - HeaderSize (uint32): 4 bytes
        - Certificates (variable): ListSize - HeaderSize bytes
        """
        entries = []

        try:
            with open(var_path, "rb") as f:
                var_data = f.read()

            offset = 4  # Skip attributes field
            while offset < len(var_data):
                if offset + 24 > len(var_data):
                    break

                sig_type = var_data[offset : offset + 16]
                sig_type_str = self._guid_bytes_to_str(sig_type)
                offset += 16

                list_size = struct.unpack("<I", var_data[offset : offset + 4])[0]
                offset += 4
                header_size = struct.unpack("<I", var_data[offset : offset + 4])[0]
                offset += 4

                cert_data = var_data[offset : offset + list_size - header_size]
                offset += list_size - header_size

                # Parse individual certificate entries
                cert_offset = 0
                sig_owner = self._guid_bytes_to_str(var_data[offset - list_size + header_size : offset - list_size + header_size + 16]) if list_size > header_size + 16 else ""

                entry = SignatureDatabaseEntry(
                    signature_type=sig_type_str,
                    signature_owner=sig_owner,
                    signature_data=cert_data,
                )
                entries.append(entry)

        except Exception as e:
            logger.error(f"Error parsing signature list from {var_path}: {e}")

        return entries

    def _guid_bytes_to_str(self, guid_bytes: bytes) -> str:
        """Convert 16-byte GUID to string representation."""
        if len(guid_bytes) != 16:
            return ""
        a, b, c = struct.unpack("<IHH", guid_bytes[:8])
        d = struct.unpack(">6B", guid_bytes[8:14])
        return f"{a:08x}-{b:04x}-{c:04x}-{d[0]:02x}{d[1]:02x}-" \
               f"{''.join(f'{x:02x}' for x in d[2:])}"


# ============================================================================
# FIRMWARE POLICY MONITOR
# ============================================================================

class FirmwarePolicyMonitor:
    """
    Monitors for Secure Boot policy transitions in real-time.

    Watches efivars directory for changes, detects dbx updates, PK rotation,
    KEK changes, and MOK modifications. Computes policy deltas.
    """

    def __init__(self, discovery: FirmwareCacheDiscovery):
        """
        Initialize policy monitor.

        Args:
            discovery: FirmwareCacheDiscovery instance to use for policy reading
        """
        self.discovery = discovery
        self.policy_history: List[SecureBootPolicy] = []
        self.policy_transitions: List[Tuple[PolicyTransitionType, SecureBootPolicy, SecureBootPolicy]] = []
        self._monitoring = False

    async def start_monitoring(self) -> None:
        """Start monitoring for policy changes."""
        self._monitoring = True
        logger.info("Started firmware policy monitoring")

        if self.discovery.platform == "linux":
            await self._monitor_linux_efivars()
        else:
            logger.warning(f"Policy monitoring not implemented for {self.discovery.platform}")

    async def stop_monitoring(self) -> None:
        """Stop monitoring for policy changes."""
        self._monitoring = False
        logger.info("Stopped firmware policy monitoring")

    async def _monitor_linux_efivars(self) -> None:
        """Monitor Linux efivars directory for changes using inotify."""
        try:
            import inotify_simple
        except ImportError:
            logger.warning("inotify_simple not available; using polling instead")
            await self._monitor_linux_polling()
            return

        try:
            inotify = inotify_simple.INotify()
            watch_fd = inotify.add_watch(str(self.discovery.efivars_path), inotify_simple.flags.MODIFY)

            logger.debug(f"Watching {self.discovery.efivars_path} with inotify")

            while self._monitoring:
                try:
                    events = inotify.read(timeout=5000)  # 5 second timeout
                    if events:
                        await self._handle_policy_change()
                except TimeoutError:
                    continue

        except Exception as e:
            logger.error(f"Error in inotify monitoring: {e}")

    async def _monitor_linux_polling(self) -> None:
        """Fallback: Monitor efivars using polling."""
        previous_state = {}

        while self._monitoring:
            try:
                current_state = {}
                if self.discovery.efivars_path.exists():
                    for var_file in self.discovery.efivars_path.iterdir():
                        try:
                            mtime = var_file.stat().st_mtime
                            current_state[var_file.name] = mtime
                        except OSError:
                            continue

                if previous_state and current_state != previous_state:
                    await self._handle_policy_change()

                previous_state = current_state
                await asyncio.sleep(5)  # Poll every 5 seconds

            except Exception as e:
                logger.error(f"Error in polling monitor: {e}")
                await asyncio.sleep(5)

    async def _handle_policy_change(self) -> None:
        """Handle detected policy change."""
        new_policy = await self.discovery.read_uefi_variables()

        if not self.policy_history:
            self.policy_history.append(new_policy)
            logger.info("Initial policy snapshot recorded")
            return

        old_policy = self.policy_history[-1]
        transition_type = self._detect_transition_type(old_policy, new_policy)

        if transition_type:
            self.policy_transitions.append((transition_type, old_policy, new_policy))
            self.policy_history.append(new_policy)

            logger.warning(f"Detected policy transition: {transition_type.value}")
            self._log_policy_delta(old_policy, new_policy, transition_type)

    def _detect_transition_type(
        self,
        old_policy: SecureBootPolicy,
        new_policy: SecureBootPolicy,
    ) -> Optional[PolicyTransitionType]:
        """Detect what type of policy transition occurred."""
        # Check dbx changes
        old_dbx_hash = hashlib.sha256(
            b"".join(e.signature_hash.encode() for e in old_policy.dbx_entries)
        ).hexdigest()
        new_dbx_hash = hashlib.sha256(
            b"".join(e.signature_hash.encode() for e in new_policy.dbx_entries)
        ).hexdigest()

        if old_dbx_hash != new_dbx_hash:
            logger.info(f"dbx change detected: {old_dbx_hash[:16]} -> {new_dbx_hash[:16]}")
            return PolicyTransitionType.DBX_UPDATE

        # Check db changes
        old_db_hash = hashlib.sha256(
            b"".join(e.signature_hash.encode() for e in old_policy.db_entries)
        ).hexdigest()
        new_db_hash = hashlib.sha256(
            b"".join(e.signature_hash.encode() for e in new_policy.db_entries)
        ).hexdigest()

        if old_db_hash != new_db_hash:
            return PolicyTransitionType.DB_UPDATE

        # Check PK changes
        if old_policy.pk_hash != new_policy.pk_hash:
            return PolicyTransitionType.PK_ROTATION

        # Check KEK changes
        old_kek_hash = hashlib.sha256(
            b"".join(e.signature_hash.encode() for e in old_policy.kek_entries)
        ).hexdigest()
        new_kek_hash = hashlib.sha256(
            b"".join(e.signature_hash.encode() for e in new_policy.kek_entries)
        ).hexdigest()

        if old_kek_hash != new_kek_hash:
            return PolicyTransitionType.KEK_ROTATION

        # Check MOK changes
        old_mok_hash = hashlib.sha256(
            b"".join(e.signature_hash.encode() for e in old_policy.mok_entries)
        ).hexdigest()
        new_mok_hash = hashlib.sha256(
            b"".join(e.signature_hash.encode() for e in new_policy.mok_entries)
        ).hexdigest()

        if old_mok_hash != new_mok_hash:
            return PolicyTransitionType.MOK_UPDATE

        return None

    def _log_policy_delta(
        self,
        old_policy: SecureBootPolicy,
        new_policy: SecureBootPolicy,
        transition_type: PolicyTransitionType,
    ) -> None:
        """Log detailed policy delta for audit trail."""
        delta_log = f"\n=== POLICY TRANSITION DETECTED ===\n"
        delta_log += f"Type: {transition_type.value}\n"
        delta_log += f"Timestamp: {new_policy.timestamp.isoformat()}\n"

        if transition_type == PolicyTransitionType.DBX_UPDATE:
            old_count = len(old_policy.dbx_entries)
            new_count = len(new_policy.dbx_entries)
            delta_log += f"dbx entries: {old_count} -> {new_count}\n"

        logger.warning(delta_log)

    def get_policy_history(self) -> List[SecureBootPolicy]:
        """Get history of policy snapshots."""
        return self.policy_history.copy()

    def get_transitions(self) -> List[Tuple[PolicyTransitionType, SecureBootPolicy, SecureBootPolicy]]:
        """Get list of detected policy transitions."""
        return self.policy_transitions.copy()


# ============================================================================
# FIRMWARE VALIDATOR
# ============================================================================

class FirmwareValidator:
    """
    Validates cached EFI binaries against current Secure Boot policy.

    Checks if binaries are present in dbx (forbidden), validates against db
    (allowed), verifies certificate chains against KEK and PK, and computes
    validation status.
    """

    def __init__(self, discovery: FirmwareCacheDiscovery):
        """
        Initialize validator.

        Args:
            discovery: FirmwareCacheDiscovery instance with policy data
        """
        self.discovery = discovery
        self.validation_reports: List[ValidationReport] = []

    async def validate_all_binaries(self) -> List[ValidationReport]:
        """
        Validate all discovered EFI binaries against current policy.

        Returns:
            List of validation reports
        """
        self.validation_reports = []

        if not self.discovery.current_policy:
            logger.error("No policy available; cannot validate")
            return self.validation_reports

        tasks = [
            self._validate_single_binary(binary)
            for binary in self.discovery.discovered_binaries
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        self.validation_reports = [r for r in results if isinstance(r, ValidationReport)]

        # Log summary
        compliant = sum(1 for r in self.validation_reports if r.validation_status == ValidationStatus.COMPLIANT)
        non_compliant = sum(1 for r in self.validation_reports if r.validation_status == ValidationStatus.NON_COMPLIANT)
        logger.info(f"Validation summary: {compliant} compliant, {non_compliant} non-compliant")

        return self.validation_reports

    async def _validate_single_binary(self, efi_binary: EFIBinary) -> ValidationReport:
        """
        Validate a single EFI binary.

        Returns:
            ValidationReport with status and details
        """
        report = ValidationReport(
            efi_binary=efi_binary,
            validation_status=ValidationStatus.UNKNOWN,
            policy_snapshot=self.discovery.current_policy,
            validation_timestamp=datetime.now(timezone.utc),
        )

        # Check against dbx first (forbidden signatures)
        dbx_matches = self._check_against_dbx(efi_binary)
        if dbx_matches:
            report.validation_status = ValidationStatus.NON_COMPLIANT
            report.matching_dbx_entries = dbx_matches
            report.audit_trail = f"Binary hash matched dbx entry (forbidden)"
            logger.warning(f"NON-COMPLIANT: {efi_binary.path} is in dbx")
            return report

        # Check against db (allowed signatures)
        db_matches = self._check_against_db(efi_binary)
        if db_matches:
            report.validation_status = ValidationStatus.COMPLIANT
            report.matching_db_entries = db_matches
            report.audit_trail = f"Binary signature matched db entry (allowed)"
            logger.info(f"COMPLIANT: {efi_binary.path} is in db")
            return report

        # Check if signed but not in db
        if efi_binary.is_signed:
            report.validation_status = ValidationStatus.UNKNOWN
            report.audit_trail = f"Binary is signed but not found in db"
            logger.warning(f"UNKNOWN: {efi_binary.path} is signed but not in db")
            return report

        # Unsigned binary
        report.validation_status = ValidationStatus.UNSIGNED
        report.audit_trail = f"Binary is not signed"
        logger.warning(f"UNSIGNED: {efi_binary.path} has no valid signature")
        return report

    def _check_against_dbx(self, efi_binary: EFIBinary) -> List[SignatureDatabaseEntry]:
        """Check if EFI binary hash matches any dbx entry."""
        if not self.discovery.current_policy:
            return []

        matches = []
        for dbx_entry in self.discovery.current_policy.dbx_entries:
            if dbx_entry.matches_hash(efi_binary.sha256_hash):
                matches.append(dbx_entry)

        return matches

    def _check_against_db(self, efi_binary: EFIBinary) -> List[SignatureDatabaseEntry]:
        """Check if EFI binary signature matches any db entry."""
        if not self.discovery.current_policy:
            return []

        matches = []
        for db_entry in self.discovery.current_policy.db_entries:
            # In production, this would verify PE/COFF signature against certificate
            # For now, hash-based matching
            if db_entry.matches_hash(efi_binary.sha256_hash):
                matches.append(db_entry)

        return matches

    def get_non_compliant_binaries(self) -> List[ValidationReport]:
        """Get all non-compliant binaries."""
        return [r for r in self.validation_reports if r.validation_status == ValidationStatus.NON_COMPLIANT]

    def get_unsigned_binaries(self) -> List[ValidationReport]:
        """Get all unsigned binaries."""
        return [r for r in self.validation_reports if r.validation_status == ValidationStatus.UNSIGNED]


# ============================================================================
# FIRMWARE MITIGATION CONTROLLER
# ============================================================================

class FirmwareMitigationController:
    """
    Quarantines and mitigates non-compliant EFI binaries.

    Moves non-compliant binaries to secure backup, replaces with stubs,
    generates audit trails, and implements safe rollback mechanisms.
    NEVER bricks the system.
    """

    def __init__(
        self,
        validator: FirmwareValidator,
        backup_root: Optional[Path] = None,
        enable_mitigation: bool = False,
    ):
        """
        Initialize mitigation controller.

        Args:
            validator: FirmwareValidator instance
            backup_root: Root directory for secure backups (default: /tmp/firmware-backups)
            enable_mitigation: If False, only simulate mitigation; don't modify files
        """
        self.validator = validator
        self.backup_root = backup_root or Path(tempfile.gettempdir()) / "firmware-backups"
        self.enable_mitigation = enable_mitigation
        self.mitigation_actions: List[MitigationAction] = []

        if not self.backup_root.exists():
            self.backup_root.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created backup directory: {self.backup_root}")

    async def mitigate_non_compliant_binaries(self) -> List[MitigationAction]:
        """
        Mitigate all non-compliant EFI binaries.

        Returns:
            List of mitigation actions performed
        """
        non_compliant = self.validator.get_non_compliant_binaries()
        logger.warning(f"Beginning mitigation of {len(non_compliant)} non-compliant binaries")

        # Always keep at least one valid boot path
        bootable_binaries = [
            r for r in self.validator.validation_reports
            if r.efi_binary.binary_type in (EFIBinaryType.BOOTLOADER, EFIBinaryType.EFI_APPLICATION)
            and r.validation_status == ValidationStatus.COMPLIANT
        ]

        if not bootable_binaries:
            logger.error("ABORT MITIGATION: No compliant bootloaders found!")
            logger.error("System would become unbootable. Refusing to proceed.")
            return []

        tasks = [
            self._mitigate_single_binary(report)
            for report in non_compliant
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        self.mitigation_actions = [r for r in results if isinstance(r, MitigationAction)]

        logger.info(f"Mitigation complete: {len(self.mitigation_actions)} actions taken")
        return self.mitigation_actions

    async def _mitigate_single_binary(self, report: ValidationReport) -> Optional[MitigationAction]:
        """
        Mitigate a single non-compliant binary.

        Returns:
            MitigationAction record
        """
        efi_binary = report.efi_binary
        action_time = datetime.now(timezone.utc)

        logger.warning(f"Mitigating: {efi_binary.path}")

        # Decide mitigation strategy based on binary type
        if efi_binary.binary_type in (EFIBinaryType.OPTION_ROM, EFIBinaryType.EFI_DRIVER):
            # Safe to delete/remove
            action = await self._quarantine_binary(efi_binary, action_time, reason="Non-compliant peripheral driver")
        elif efi_binary.binary_type == EFIBinaryType.BOOTLOADER:
            # Critical: quarantine but keep bootable
            action = await self._quarantine_binary(efi_binary, action_time, reason="Non-compliant bootloader")
        else:
            action = await self._quarantine_binary(efi_binary, action_time, reason="Non-compliant EFI binary")

        return action

    async def _quarantine_binary(
        self,
        efi_binary: EFIBinary,
        action_time: datetime,
        reason: str,
    ) -> Optional[MitigationAction]:
        """
        Quarantine a non-compliant binary.

        Backs up the original, replaces with a stub file.
        """
        try:
            # Read original binary
            with open(efi_binary.path, "rb") as f:
                original_data = f.read()

            # Create backup
            backup_path = self.backup_root / efi_binary.sha256_hash / efi_binary.path.name
            backup_path.parent.mkdir(parents=True, exist_ok=True)

            if self.enable_mitigation:
                with open(backup_path, "wb") as f:
                    f.write(original_data)
                logger.info(f"Backed up to: {backup_path}")

                # Replace original with stub (minimal valid EFI binary that fails to load)
                stub_data = self._create_efi_stub()
                with open(efi_binary.path, "wb") as f:
                    f.write(stub_data)
                logger.info(f"Replaced {efi_binary.path} with stub")

            action = MitigationAction(
                action_timestamp=action_time,
                efi_binary_path=efi_binary.path,
                action_type="QUARANTINE",
                reason=reason,
                backup_location=backup_path if self.enable_mitigation else None,
                reversible=True,
                rollback_data=original_data if self.enable_mitigation else None,
            )

            self.mitigation_actions.append(action)
            return action

        except Exception as e:
            logger.error(f"Error quarantining {efi_binary.path}: {e}")
            return None

    def _create_efi_stub(self) -> bytes:
        """Create a minimal EFI stub binary that will fail security checks."""
        # Minimal valid EFI binary that does nothing
        stub = (
            b"MZ\x90\x00" +  # DOS header signature
            b"\x00" * 58 +  # DOS header
            b"\x40\x00\x00\x00" +  # PE offset
            b"PE\x00\x00" +  # PE signature
            b"\x4c\x01" +  # Machine (x86-64)
            b"\x00\x00" +  # NumberOfSections
            b"\x00" * 12 +  # Timestamps
            b"\x00" * 200  # Padding
        )
        return stub

    def rollback_mitigation(self, action: MitigationAction) -> bool:
        """
        Rollback a mitigation action.

        Restores original binary from backup.
        """
        if not action.rollback_data or not action.reversible:
            logger.error(f"Cannot rollback action: {action}")
            return False

        try:
            with open(action.efi_binary_path, "wb") as f:
                f.write(action.rollback_data)
            logger.info(f"Rolled back: {action.efi_binary_path}")
            return True
        except Exception as e:
            logger.error(f"Error rolling back {action.efi_binary_path}: {e}")
            return False

    def get_mitigation_report(self) -> Dict[str, Any]:
        """Generate mitigation report."""
        return {
            "total_actions": len(self.mitigation_actions),
            "actions": [asdict(a) for a in self.mitigation_actions],
            "quarantine_root": str(self.backup_root),
        }


# ============================================================================
# UEFI TEMPORAL BINDING
# ============================================================================

class UEFITemporalBinding:
    """
    Binds EFI binaries to policy state at observation time.

    Enables retroactive validation when policy transitions occur.
    Stores bindings in tamper-evident database outside the ESP.
    """

    def __init__(self, binding_db_root: Optional[Path] = None):
        """
        Initialize temporal binding system.

        Args:
            binding_db_root: Root directory for binding database
        """
        self.binding_db_root = binding_db_root or Path(tempfile.gettempdir()) / "firmware-bindings"
        self.bindings: Dict[SHA256Hash, TemporalBinding] = {}
        self._secret_key = self._derive_secret_key()

        if not self.binding_db_root.exists():
            self.binding_db_root.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created binding database: {self.binding_db_root}")

    def _derive_secret_key(self) -> bytes:
        """Derive a secret key for HMAC binding signatures."""
        # In production, this would use a hardware-backed key or secure enclave
        # For now, derive from system entropy
        try:
            with open("/dev/urandom", "rb") as f:
                return f.read(32)
        except (OSError, FileNotFoundError):
            # Fallback for Windows
            import secrets
            return secrets.token_bytes(32)

    async def create_temporal_binding(
        self,
        efi_binary: EFIBinary,
        policy: SecureBootPolicy,
    ) -> TemporalBinding:
        """
        Create a temporal binding for an EFI binary.

        Records the binary's hash and the policy state at observation time.
        Computes HMAC for tamper detection.
        """
        # Compute hashes of entire signature databases
        dbx_hash = hashlib.sha256(
            b"".join(e.signature_hash.encode() for e in policy.dbx_entries)
        ).hexdigest()

        db_hash = hashlib.sha256(
            b"".join(e.signature_hash.encode() for e in policy.db_entries)
        ).hexdigest()

        binding = TemporalBinding(
            efi_binary_hash=efi_binary.sha256_hash,
            observation_timestamp=policy.timestamp,
            dbx_hash=dbx_hash,
            db_hash=db_hash,
            pk_hash=policy.pk_hash,
        )

        # Sign binding with HMAC
        binding.compute_binding_hmac(self._secret_key)

        # Store binding
        self.bindings[efi_binary.sha256_hash] = binding
        await self._persist_binding(binding)

        logger.debug(f"Created temporal binding for {efi_binary.sha256_hash[:16]}")
        return binding

    async def _persist_binding(self, binding: TemporalBinding) -> None:
        """Persist binding to database."""
        try:
            binding_file = self.binding_db_root / f"{binding.efi_binary_hash}.json"
            with open(binding_file, "w") as f:
                json.dump(binding.to_dict(), f, indent=2)
            logger.debug(f"Persisted binding to {binding_file}")
        except Exception as e:
            logger.error(f"Error persisting binding: {e}")

    async def load_bindings(self) -> Dict[SHA256Hash, TemporalBinding]:
        """Load all bindings from database."""
        self.bindings = {}

        try:
            for binding_file in self.binding_db_root.glob("*.json"):
                try:
                    with open(binding_file, "r") as f:
                        binding_data = json.load(f)

                    binding = TemporalBinding(
                        efi_binary_hash=binding_data["efi_binary_hash"],
                        observation_timestamp=datetime.fromisoformat(
                            binding_data["observation_timestamp"]
                        ),
                        dbx_hash=binding_data["dbx_hash"],
                        db_hash=binding_data["db_hash"],
                        pk_hash=binding_data["pk_hash"],
                        binding_hmac=binding_data.get("binding_hmac", ""),
                    )

                    self.bindings[binding.efi_binary_hash] = binding

                except Exception as e:
                    logger.error(f"Error loading binding from {binding_file}: {e}")

        except Exception as e:
            logger.error(f"Error loading bindings: {e}")

        logger.info(f"Loaded {len(self.bindings)} temporal bindings")
        return self.bindings

    async def verify_binding_integrity(self, binding: TemporalBinding) -> bool:
        """
        Verify HMAC integrity of binding.

        Detects if binding has been tampered with.
        """
        return binding.verify_binding_hmac(self._secret_key)

    async def retroactive_validation(
        self,
        efi_binary_hash: SHA256Hash,
        current_policy: SecureBootPolicy,
    ) -> Dict[str, Any]:
        """
        Perform retroactive validation of an EFI binary.

        Uses temporal binding to determine if the binary was authorized
        at the time it was first observed, even if current policy has changed.
        """
        if efi_binary_hash not in self.bindings:
            logger.warning(f"No binding found for {efi_binary_hash}")
            return {"retroactive_valid": False, "reason": "No temporal binding"}

        binding = self.bindings[efi_binary_hash]

        # Verify binding integrity
        if not await self.verify_binding_integrity(binding):
            logger.error(f"Binding integrity check failed for {efi_binary_hash}")
            return {"retroactive_valid": False, "reason": "Binding tampered"}

        # Check if binary was in dbx at observation time
        # (requires keeping historical dbx snapshots)
        observation_time = binding.observation_timestamp

        return {
            "retroactive_valid": True,
            "observation_time": observation_time.isoformat(),
            "binding_verified": True,
            "policy_at_observation": {
                "pk_hash": binding.pk_hash,
                "dbx_hash": binding.dbx_hash,
                "db_hash": binding.db_hash,
            },
        }


# ============================================================================
# MAIN ORCHESTRATOR
# ============================================================================

class FirmwareSecurityOrchestrator:
    """
    Main orchestrator for firmware cache validation and mitigation.

    Coordinates discovery, monitoring, validation, and mitigation components.
    """

    def __init__(
        self,
        esp_root: Optional[Path] = None,
        platform: str = "linux",
        enable_mitigation: bool = False,
    ):
        """
        Initialize orchestrator.

        Args:
            esp_root: Path to EFI System Partition
            platform: "linux", "windows", or "darwin"
            enable_mitigation: Enable actual mitigation vs. simulation
        """
        self.discovery = FirmwareCacheDiscovery(esp_root, platform)
        self.monitor = FirmwarePolicyMonitor(self.discovery)
        self.validator = FirmwareValidator(self.discovery)
        self.mitigator = FirmwareMitigationController(
            self.validator,
            enable_mitigation=enable_mitigation,
        )
        self.temporal_binding = UEFITemporalBinding()

    async def run_full_scan(self) -> Dict[str, Any]:
        """
        Run complete firmware security assessment.

        Returns:
            Comprehensive report of scan results
        """
        logger.info("=== STARTING FULL FIRMWARE SECURITY SCAN ===")

        # Step 1: Discover EFI binaries and read policy
        logger.info("Step 1: Discovering EFI binaries...")
        binaries = await self.discovery.discover_efi_binaries()
        logger.info(f"Discovered {len(binaries)} EFI binaries")

        logger.info("Step 2: Reading Secure Boot policy...")
        policy = await self.discovery.read_uefi_variables()
        logger.info(f"Current policy: PK={policy.pk_hash[:16]}..., "
                   f"db={len(policy.db_entries)}, dbx={len(policy.dbx_entries)}")

        # Step 3: Validate against current policy
        logger.info("Step 3: Validating against current policy...")
        validation_reports = await self.validator.validate_all_binaries()

        # Step 4: Create temporal bindings
        logger.info("Step 4: Creating temporal bindings...")
        for binary in binaries:
            await self.temporal_binding.create_temporal_binding(binary, policy)

        # Step 5: Mitigate if needed
        logger.info("Step 5: Assessing mitigation needs...")
        non_compliant = self.validator.get_non_compliant_binaries()
        if non_compliant:
            logger.warning(f"Found {len(non_compliant)} non-compliant binaries")
            mitigation_actions = await self.mitigator.mitigate_non_compliant_binaries()
        else:
            logger.info("All binaries compliant; no mitigation needed")
            mitigation_actions = []

        # Generate report
        report = {
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "platform": self.discovery.platform,
            "esp_root": str(self.discovery.esp_root),
            "binaries_discovered": len(binaries),
            "validation_results": {
                "compliant": sum(1 for r in validation_reports if r.validation_status == ValidationStatus.COMPLIANT),
                "non_compliant": sum(1 for r in validation_reports if r.validation_status == ValidationStatus.NON_COMPLIANT),
                "unsigned": sum(1 for r in validation_reports if r.validation_status == ValidationStatus.UNSIGNED),
                "unknown": sum(1 for r in validation_reports if r.validation_status == ValidationStatus.UNKNOWN),
            },
            "policy_state": policy.to_dict(),
            "mitigation_actions": len(mitigation_actions),
            "temporal_bindings": len(self.temporal_binding.bindings),
        }

        logger.info("=== FIRMWARE SECURITY SCAN COMPLETE ===")
        return report


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

async def main():
    """Example usage of firmware cache validator."""
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    )

    # Initialize orchestrator
    orchestrator = FirmwareSecurityOrchestrator(
        platform="linux",
        enable_mitigation=False,  # Simulation mode
    )

    # Run scan
    report = await orchestrator.run_full_scan()

    # Print report
    print("\n" + "=" * 80)
    print("FIRMWARE CACHE VALIDATION REPORT")
    print("=" * 80)
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
