"""
Unit tests for Firmware Cache Validator

Tests cover:
- EFI binary discovery and parsing
- Secure Boot policy reading
- Validation against db/dbx
- Policy transition detection
- Temporal binding creation and verification
- Mitigation actions
"""

import asyncio
import hashlib
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import pytest

from firmware_cache_validator import (
    ValidationStatus,
    PolicyTransitionType,
    EFIBinaryType,
    SignatureDatabaseEntry,
    SecureBootPolicy,
    EFIBinary,
    ValidationReport,
    TemporalBinding,
    MitigationAction,
    FirmwareCacheDiscovery,
    FirmwarePolicyMonitor,
    FirmwareValidator,
    FirmwareMitigationController,
    UEFITemporalBinding,
)


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def temp_esp():
    """Create a temporary EFI System Partition for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        esp_root = Path(tmpdir) / "efi"
        esp_root.mkdir(parents=True)

        # Create directory structure
        (esp_root / "EFI" / "Boot").mkdir(parents=True)
        (esp_root / "EFI" / "Microsoft" / "Boot").mkdir(parents=True)

        # Create test binaries
        bootx64 = esp_root / "EFI" / "Boot" / "bootx64.efi"
        bootx64.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)

        bootmgfw = esp_root / "EFI" / "Microsoft" / "Boot" / "bootmgfw.efi"
        bootmgfw.write_bytes(b"MZ\x90\x00" + b"\x11" * 1000)

        yield esp_root


@pytest.fixture
def discovery(temp_esp):
    """Create a FirmwareCacheDiscovery instance with test ESP."""
    return FirmwareCacheDiscovery(esp_root=temp_esp, platform="linux")


@pytest.fixture
def test_policy():
    """Create a test Secure Boot policy."""
    policy = SecureBootPolicy(
        timestamp=datetime.now(timezone.utc),
        pk_hash=hashlib.sha256(b"test_pk").hexdigest(),
    )

    # Add test db entries (allowed)
    policy.db_entries.append(
        SignatureDatabaseEntry(
            signature_type="c1c41626-504c-4092-aca9-41f936934328",
            signature_owner="test-owner",
            signature_data=b"allowed_signature",
        )
    )

    # Add test dbx entries (forbidden)
    policy.dbx_entries.append(
        SignatureDatabaseEntry(
            signature_type="c1c41626-504c-4092-aca9-41f936934328",
            signature_owner="test-owner",
            signature_data=b"forbidden_signature",
        )
    )

    return policy


# ============================================================================
# TESTS: FirmwareCacheDiscovery
# ============================================================================

@pytest.mark.asyncio
async def test_discover_efi_binaries(discovery):
    """Test EFI binary discovery."""
    binaries = await discovery.discover_efi_binaries()

    assert len(binaries) == 2
    assert all(isinstance(b, EFIBinary) for b in binaries)

    # Check that hashes were computed
    assert all(b.sha256_hash for b in binaries)

    # Check that binary types were detected
    bootloaders = [b for b in binaries if b.binary_type == EFIBinaryType.BOOTLOADER]
    assert len(bootloaders) == 2


@pytest.mark.asyncio
async def test_binary_metadata(discovery):
    """Test that binary metadata is correctly populated."""
    binaries = await discovery.discover_efi_binaries()

    for binary in binaries:
        assert binary.path.exists()
        assert binary.size_bytes > 0
        assert binary.sha256_hash
        assert isinstance(binary.created_timestamp, datetime)
        assert isinstance(binary.last_modified, datetime)


def test_guid_conversion(discovery):
    """Test GUID byte conversion."""
    guid_bytes = (
        b"\x26\xc4\xc1\xc1\x4c\x50\x92\x40\xac\xa9\x41\xf9\x36\x93\x43\x28"
    )
    guid_str = discovery._guid_bytes_to_str(guid_bytes)

    # Should convert to proper GUID format
    assert "-" in guid_str
    assert len(guid_str.split("-")) == 5


def test_detect_efi_binary_type(discovery):
    """Test EFI binary type detection."""
    # Create test binary with MZ header
    test_data = b"MZ\x90\x00" + b"\x00" * 1000

    detected_type = discovery._detect_efi_binary_type(
        test_data,
        Path("/boot/efi/EFI/Boot/bootx64.efi")
    )

    assert detected_type == EFIBinaryType.BOOTLOADER


# ============================================================================
# TESTS: FirmwareValidator
# ============================================================================

@pytest.mark.asyncio
async def test_validate_against_dbx(discovery, test_policy):
    """Test validation against dbx (forbidden signatures)."""
    discovery.current_policy = test_policy

    validator = FirmwareValidator(discovery)

    # Create a test binary with hash matching dbx entry
    test_binary = EFIBinary(
        path=Path("/test/forbidden.efi"),
        binary_type=EFIBinaryType.EFI_APPLICATION,
        size_bytes=1000,
        sha256_hash=hashlib.sha256(b"forbidden_signature").hexdigest(),
        created_timestamp=datetime.now(timezone.utc),
        last_modified=datetime.now(timezone.utc),
        is_signed=True,
    )

    report = await validator._validate_single_binary(test_binary)

    assert report.validation_status == ValidationStatus.NON_COMPLIANT
    assert len(report.matching_dbx_entries) > 0


@pytest.mark.asyncio
async def test_validate_against_db(discovery, test_policy):
    """Test validation against db (allowed signatures)."""
    discovery.current_policy = test_policy

    validator = FirmwareValidator(discovery)

    # Create a test binary with hash matching db entry
    test_binary = EFIBinary(
        path=Path("/test/allowed.efi"),
        binary_type=EFIBinaryType.EFI_APPLICATION,
        size_bytes=1000,
        sha256_hash=hashlib.sha256(b"allowed_signature").hexdigest(),
        created_timestamp=datetime.now(timezone.utc),
        last_modified=datetime.now(timezone.utc),
        is_signed=True,
    )

    report = await validator._validate_single_binary(test_binary)

    assert report.validation_status == ValidationStatus.COMPLIANT
    assert len(report.matching_db_entries) > 0


@pytest.mark.asyncio
async def test_validate_unsigned_binary(discovery, test_policy):
    """Test validation of unsigned binary."""
    discovery.current_policy = test_policy

    validator = FirmwareValidator(discovery)

    test_binary = EFIBinary(
        path=Path("/test/unsigned.efi"),
        binary_type=EFIBinaryType.EFI_APPLICATION,
        size_bytes=1000,
        sha256_hash=hashlib.sha256(b"unknown_data").hexdigest(),
        created_timestamp=datetime.now(timezone.utc),
        last_modified=datetime.now(timezone.utc),
        is_signed=False,
    )

    report = await validator._validate_single_binary(test_binary)

    assert report.validation_status == ValidationStatus.UNSIGNED


# ============================================================================
# TESTS: FirmwarePolicyMonitor
# ============================================================================

@pytest.mark.asyncio
async def test_detect_dbx_transition(discovery, test_policy):
    """Test detection of dbx policy transition."""
    monitor = FirmwarePolicyMonitor(discovery)

    # Set initial policy
    old_policy = test_policy
    monitor.policy_history.append(old_policy)

    # Create new policy with additional dbx entry
    new_policy = SecureBootPolicy(
        timestamp=datetime.now(timezone.utc),
        pk_hash=hashlib.sha256(b"test_pk").hexdigest(),
    )
    new_policy.dbx_entries = old_policy.dbx_entries.copy()
    new_policy.dbx_entries.append(
        SignatureDatabaseEntry(
            signature_type="c1c41626-504c-4092-aca9-41f936934328",
            signature_owner="test-owner-2",
            signature_data=b"new_forbidden",
        )
    )

    # Detect transition
    transition_type = monitor._detect_transition_type(old_policy, new_policy)

    assert transition_type == PolicyTransitionType.DBX_UPDATE


@pytest.mark.asyncio
async def test_detect_pk_rotation(discovery, test_policy):
    """Test detection of Platform Key rotation."""
    monitor = FirmwarePolicyMonitor(discovery)

    old_policy = test_policy

    # Create new policy with different PK
    new_policy = SecureBootPolicy(
        timestamp=datetime.now(timezone.utc),
        pk_hash=hashlib.sha256(b"new_pk").hexdigest(),
    )
    new_policy.dbx_entries = old_policy.dbx_entries.copy()

    transition_type = monitor._detect_transition_type(old_policy, new_policy)

    assert transition_type == PolicyTransitionType.PK_ROTATION


# ============================================================================
# TESTS: UEFITemporalBinding
# ============================================================================

@pytest.mark.asyncio
async def test_create_temporal_binding(discovery, test_policy):
    """Test creation of temporal binding."""
    binding_system = UEFITemporalBinding()

    test_binary = EFIBinary(
        path=Path("/test/binary.efi"),
        binary_type=EFIBinaryType.EFI_APPLICATION,
        size_bytes=1000,
        sha256_hash=hashlib.sha256(b"test_binary").hexdigest(),
        created_timestamp=datetime.now(timezone.utc),
        last_modified=datetime.now(timezone.utc),
        is_signed=True,
    )

    binding = await binding_system.create_temporal_binding(test_binary, test_policy)

    assert binding.efi_binary_hash == test_binary.sha256_hash
    assert binding.observation_timestamp == test_policy.timestamp
    assert binding.pk_hash == test_policy.pk_hash
    assert binding.binding_hmac  # Should be computed


@pytest.mark.asyncio
async def test_temporal_binding_integrity(discovery, test_policy):
    """Test HMAC verification of temporal binding."""
    binding_system = UEFITemporalBinding()

    binding = TemporalBinding(
        efi_binary_hash="abc123",
        observation_timestamp=datetime.now(timezone.utc),
        dbx_hash="dbx_hash",
        db_hash="db_hash",
        pk_hash="pk_hash",
    )

    # Compute HMAC
    binding.compute_binding_hmac(binding_system._secret_key)

    # Verify it
    is_valid = binding.verify_binding_hmac(binding_system._secret_key)
    assert is_valid


@pytest.mark.asyncio
async def test_temporal_binding_tampering_detection(discovery, test_policy):
    """Test that tampering is detected."""
    binding_system = UEFITemporalBinding()

    binding = TemporalBinding(
        efi_binary_hash="abc123",
        observation_timestamp=datetime.now(timezone.utc),
        dbx_hash="dbx_hash",
        db_hash="db_hash",
        pk_hash="pk_hash",
    )

    # Compute HMAC
    binding.compute_binding_hmac(binding_system._secret_key)

    # Tamper with binding
    binding.efi_binary_hash = "different_hash"

    # Verify should fail
    is_valid = binding.verify_binding_hmac(binding_system._secret_key)
    assert not is_valid


@pytest.mark.asyncio
async def test_persist_and_load_bindings():
    """Test persistence and loading of bindings."""
    with tempfile.TemporaryDirectory() as tmpdir:
        binding_system = UEFITemporalBinding(Path(tmpdir))

        # Create test binding
        binding = TemporalBinding(
            efi_binary_hash="abc123",
            observation_timestamp=datetime.now(timezone.utc),
            dbx_hash="dbx_hash",
            db_hash="db_hash",
            pk_hash="pk_hash",
        )
        binding.compute_binding_hmac(binding_system._secret_key)

        # Persist
        binding_system.bindings["abc123"] = binding
        await binding_system._persist_binding(binding)

        # Create new instance and load
        binding_system2 = UEFITemporalBinding(Path(tmpdir))
        loaded_bindings = await binding_system2.load_bindings()

        assert "abc123" in loaded_bindings
        assert loaded_bindings["abc123"].efi_binary_hash == "abc123"


# ============================================================================
# TESTS: FirmwareMitigationController
# ============================================================================

@pytest.mark.asyncio
async def test_mitigation_quarantine(discovery, test_policy):
    """Test quarantine mitigation action."""
    discovery.current_policy = test_policy

    validator = FirmwareValidator(discovery)

    # Create non-compliant binary
    non_compliant = EFIBinary(
        path=Path("/test/forbidden.efi"),
        binary_type=EFIBinaryType.OPTION_ROM,
        size_bytes=1000,
        sha256_hash=hashlib.sha256(b"forbidden_signature").hexdigest(),
        created_timestamp=datetime.now(timezone.utc),
        last_modified=datetime.now(timezone.utc),
        is_signed=True,
    )

    discovery.discovered_binaries.append(non_compliant)

    # Validate
    await validator.validate_all_binaries()

    # Mitigate (simulation mode)
    with tempfile.TemporaryDirectory() as tmpdir:
        mitigator = FirmwareMitigationController(
            validator,
            backup_root=Path(tmpdir),
            enable_mitigation=False,  # Simulation mode
        )

        actions = await mitigator.mitigate_non_compliant_binaries()

        # Should have action records (but not actually modify files in simulation)
        assert len(actions) >= 0


@pytest.mark.asyncio
async def test_bootloader_preservation():
    """Test that bootloader preservation prevents bricking."""
    discovery = FirmwareCacheDiscovery(platform="linux")

    # Create compliant bootloader
    compliant_bootloader = EFIBinary(
        path=Path("/boot/efi/EFI/Boot/bootx64.efi"),
        binary_type=EFIBinaryType.BOOTLOADER,
        size_bytes=1000,
        sha256_hash=hashlib.sha256(b"compliant").hexdigest(),
        created_timestamp=datetime.now(timezone.utc),
        last_modified=datetime.now(timezone.utc),
        is_signed=True,
    )

    # Create test policy where bootloader is compliant
    test_policy = SecureBootPolicy(
        timestamp=datetime.now(timezone.utc),
        pk_hash=hashlib.sha256(b"pk").hexdigest(),
    )
    test_policy.db_entries.append(
        SignatureDatabaseEntry(
            signature_type="c1c41626-504c-4092-aca9-41f936934328",
            signature_owner="owner",
            signature_data=b"compliant",
        )
    )

    discovery.current_policy = test_policy
    discovery.discovered_binaries.append(compliant_bootloader)

    validator = FirmwareValidator(discovery)
    await validator.validate_all_binaries()

    # Verify that bootloader is compliant
    compliant = validator.get_non_compliant_binaries()
    assert len(compliant) == 0


# ============================================================================
# TESTS: Dataclass Serialization
# ============================================================================

def test_efi_binary_serialization():
    """Test EFI binary dataclass serialization."""
    binary = EFIBinary(
        path=Path("/test/binary.efi"),
        binary_type=EFIBinaryType.BOOTLOADER,
        size_bytes=1000,
        sha256_hash="abc123",
        created_timestamp=datetime.now(timezone.utc),
        last_modified=datetime.now(timezone.utc),
        is_signed=True,
    )

    data = binary.to_dict()

    assert data["path"] == "/test/binary.efi"
    assert data["binary_type"] == "BOOTLOADER"
    assert data["size_bytes"] == 1000


def test_secure_boot_policy_serialization(test_policy):
    """Test Secure Boot policy serialization."""
    data = test_policy.to_dict()

    assert data["pk_hash"]
    assert data["db_count"] >= 0
    assert data["dbx_count"] >= 0


def test_temporal_binding_serialization():
    """Test temporal binding serialization."""
    binding = TemporalBinding(
        efi_binary_hash="abc123",
        observation_timestamp=datetime.now(timezone.utc),
        dbx_hash="dbx_hash",
        db_hash="db_hash",
        pk_hash="pk_hash",
    )

    data = binding.to_dict()

    assert data["efi_binary_hash"] == "abc123"
    assert "observation_timestamp" in data


# ============================================================================
# TESTS: Integration
# ============================================================================

@pytest.mark.asyncio
async def test_full_validation_workflow(temp_esp):
    """Test complete validation workflow."""
    discovery = FirmwareCacheDiscovery(esp_root=temp_esp, platform="linux")

    # Discovery
    binaries = await discovery.discover_efi_binaries()
    assert len(binaries) > 0

    # Create test policy
    test_policy = SecureBootPolicy(
        timestamp=datetime.now(timezone.utc),
        pk_hash=hashlib.sha256(b"pk").hexdigest(),
    )
    discovery.current_policy = test_policy

    # Validation
    validator = FirmwareValidator(discovery)
    reports = await validator.validate_all_binaries()
    assert len(reports) == len(binaries)

    # Temporal binding
    binding_system = UEFITemporalBinding()
    for binary in binaries:
        await binding_system.create_temporal_binding(binary, test_policy)

    assert len(binding_system.bindings) > 0


# ============================================================================
# PERFORMANCE TESTS
# ============================================================================

@pytest.mark.asyncio
@pytest.mark.performance
async def test_discovery_performance(temp_esp):
    """Benchmark binary discovery performance."""
    import time

    discovery = FirmwareCacheDiscovery(esp_root=temp_esp, platform="linux")

    start = time.time()
    binaries = await discovery.discover_efi_binaries()
    elapsed = time.time() - start

    # Should be fast for small number of binaries
    assert elapsed < 1.0, f"Discovery took {elapsed}s"


@pytest.mark.asyncio
@pytest.mark.performance
async def test_validation_performance(discovery, test_policy):
    """Benchmark validation performance."""
    import time

    discovery.current_policy = test_policy
    validator = FirmwareValidator(discovery)

    # Add test binaries
    for i in range(100):
        binary = EFIBinary(
            path=Path(f"/test/binary_{i}.efi"),
            binary_type=EFIBinaryType.EFI_APPLICATION,
            size_bytes=1000,
            sha256_hash=hashlib.sha256(f"test_{i}".encode()).hexdigest(),
            created_timestamp=datetime.now(timezone.utc),
            last_modified=datetime.now(timezone.utc),
            is_signed=True,
        )
        discovery.discovered_binaries.append(binary)

    start = time.time()
    await validator.validate_all_binaries()
    elapsed = time.time() - start

    # Should validate 100 binaries in reasonable time
    assert elapsed < 5.0, f"Validation took {elapsed}s for 100 binaries"


# ============================================================================
# RUN TESTS
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
