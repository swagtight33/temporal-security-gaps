# Firmware Cache Validator - Usage Guide

**Derivative #63: Firmware/UEFI Cached Executable Persistence**

---

## Quick Start

### Installation

```bash
# Requires Python 3.8+
pip install -r requirements.txt

# Optional: inotify for real-time policy monitoring (Linux)
pip install inotify_simple
```

### Basic Usage

```python
import asyncio
from firmware_cache_validator import FirmwareSecurityOrchestrator

async def main():
    # Initialize orchestrator
    orchestrator = FirmwareSecurityOrchestrator(
        platform="linux",
        enable_mitigation=False,  # Simulation mode
    )
    
    # Run full security assessment
    report = await orchestrator.run_full_scan()
    print(report)

asyncio.run(main())
```

---

## Component Overview

### 1. FirmwareCacheDiscovery

Discovers EFI binaries and reads Secure Boot policy.

```python
from firmware_cache_validator import FirmwareCacheDiscovery
from pathlib import Path

# Initialize discovery
discovery = FirmwareCacheDiscovery(
    esp_root=Path("/boot/efi"),
    platform="linux"
)

# Discover EFI binaries
binaries = await discovery.discover_efi_binaries()
for binary in binaries:
    print(f"{binary.path}: {binary.sha256_hash[:16]}")
    print(f"  Type: {binary.binary_type.value}")
    print(f"  Signed: {binary.is_signed}")

# Read Secure Boot policy
policy = await discovery.read_uefi_variables()
print(f"Platform Key: {policy.pk_hash}")
print(f"db entries: {len(policy.db_entries)}")
print(f"dbx entries: {len(policy.dbx_entries)}")
```

### 2. FirmwarePolicyMonitor

Monitors for Secure Boot policy transitions.

```python
from firmware_cache_validator import FirmwarePolicyMonitor, PolicyTransitionType

# Initialize monitor
monitor = FirmwarePolicyMonitor(discovery)

# Start monitoring (runs in background)
asyncio.create_task(monitor.start_monitoring())

# Let it run for a while...
await asyncio.sleep(3600)

# Check detected transitions
transitions = monitor.get_transitions()
for transition_type, old_policy, new_policy in transitions:
    print(f"Detected {transition_type.value}")
    print(f"  dbx entries: {len(old_policy.dbx_entries)} -> {len(new_policy.dbx_entries)}")

await monitor.stop_monitoring()
```

### 3. FirmwareValidator

Validates cached binaries against current policy.

```python
from firmware_cache_validator import FirmwareValidator, ValidationStatus

# Initialize validator
validator = FirmwareValidator(discovery)

# Validate all binaries
reports = await validator.validate_all_binaries()

# Check results
for report in reports:
    print(f"{report.efi_binary.path}")
    print(f"  Status: {report.validation_status.value}")
    if report.validation_status == ValidationStatus.NON_COMPLIANT:
        print(f"  ⚠️  FOUND IN DBX (forbidden)")
    print(f"  Audit: {report.audit_trail}")

# Get non-compliant binaries
non_compliant = validator.get_non_compliant_binaries()
print(f"\nTotal non-compliant: {len(non_compliant)}")
```

### 4. FirmwareMitigationController

Quarantines non-compliant binaries.

```python
from firmware_cache_validator import FirmwareMitigationController

# Initialize mitigator (simulation mode)
mitigator = FirmwareMitigationController(
    validator,
    enable_mitigation=False  # Change to True to actually modify files
)

# Mitigate non-compliant binaries
actions = await mitigator.mitigate_non_compliant_binaries()

for action in actions:
    print(f"Action: {action.action_type}")
    print(f"  Binary: {action.efi_binary_path}")
    print(f"  Reason: {action.reason}")
    print(f"  Backup: {action.backup_location}")
```

### 5. UEFITemporalBinding

Creates temporal bindings for retroactive validation.

```python
from firmware_cache_validator import UEFITemporalBinding

# Initialize temporal binding system
binding = UEFITemporalBinding()

# Create binding for each binary
for binary in discovery.discovered_binaries:
    temporal_binding = await binding.create_temporal_binding(
        binary,
        discovery.current_policy
    )
    print(f"Bound {binary.sha256_hash[:16]} at {temporal_binding.observation_timestamp}")

# Load all bindings
bindings = await binding.load_bindings()
print(f"Total bindings: {len(bindings)}")

# Retroactively validate a binary
result = await binding.retroactive_validation(
    efi_binary_hash="...",
    current_policy=discovery.current_policy
)
print(f"Retroactively valid: {result['retroactive_valid']}")
```

---

## Real-World Scenarios

### Scenario 1: Detect Non-Compliant Bootloaders

**Problem:** You suspect a bootkit may have persisted despite a dbx update.

```python
import asyncio
from firmware_cache_validator import FirmwareSecurityOrchestrator
from firmware_cache_validator import ValidationStatus

async def check_bootloaders():
    orchestrator = FirmwareSecurityOrchestrator(platform="linux")
    
    # Discover and read policy
    binaries = await orchestrator.discovery.discover_efi_binaries()
    policy = await orchestrator.discovery.read_uefi_variables()
    
    # Validate all binaries
    reports = await orchestrator.validator.validate_all_binaries()
    
    # Check bootloaders specifically
    bootloaders = [
        r for r in reports
        if r.efi_binary.binary_type.value == "BOOTLOADER"
    ]
    
    print(f"Found {len(bootloaders)} bootloaders")
    
    non_compliant_bootloaders = [
        r for r in bootloaders
        if r.validation_status == ValidationStatus.NON_COMPLIANT
    ]
    
    if non_compliant_bootloaders:
        print("⚠️  ALERT: Non-compliant bootloaders detected!")
        for report in non_compliant_bootloaders:
            print(f"  {report.efi_binary.path}")
            print(f"    Hash: {report.efi_binary.sha256_hash}")
            print(f"    Reason: {report.audit_trail}")
        
        return True
    else:
        print("✓ All bootloaders are compliant")
        return False

asyncio.run(check_bootloaders())
```

### Scenario 2: Monitor for Policy Transitions

**Problem:** You want to be alerted when Secure Boot policy changes.

```python
import asyncio
from firmware_cache_validator import FirmwareSecurityOrchestrator, PolicyTransitionType

async def monitor_policy_changes():
    orchestrator = FirmwareSecurityOrchestrator(platform="linux")
    
    # Start monitoring
    monitor_task = asyncio.create_task(orchestrator.monitor.start_monitoring())
    
    try:
        # Run for specified duration
        await asyncio.sleep(3600)  # 1 hour
    except KeyboardInterrupt:
        print("Stopping monitor...")
    finally:
        await orchestrator.monitor.stop_monitoring()
    
    # Check transitions
    transitions = orchestrator.monitor.get_transitions()
    
    if transitions:
        print(f"Detected {len(transitions)} policy transitions:")
        for transition_type, old_policy, new_policy in transitions:
            print(f"\n  Type: {transition_type.value}")
            print(f"  Timestamp: {new_policy.timestamp}")
            
            if transition_type == PolicyTransitionType.DBX_UPDATE:
                print(f"  dbx entries changed: {len(old_policy.dbx_entries)} -> {len(new_policy.dbx_entries)}")
                
                # Find newly added dbx entries
                old_hashes = {e.signature_hash for e in old_policy.dbx_entries}
                new_hashes = {e.signature_hash for e in new_policy.dbx_entries}
                added = new_hashes - old_hashes
                
                if added:
                    print(f"  Newly forbidden signatures: {len(added)}")
                    
                    # Check if any cached binaries match
                    binaries = await orchestrator.discovery.discover_efi_binaries()
                    for binary in binaries:
                        if binary.sha256_hash in added:
                            print(f"    ⚠️  CACHE MISMATCH: {binary.path}")
    else:
        print("No policy transitions detected during monitoring period")

asyncio.run(monitor_policy_changes())
```

### Scenario 3: Remediate Non-Compliant Binaries

**Problem:** You detected non-compliant binaries and need to safely remediate.

```python
import asyncio
from firmware_cache_validator import FirmwareSecurityOrchestrator, ValidationStatus

async def remediate_non_compliant():
    # NOTE: Only enable_mitigation=True in controlled environment!
    orchestrator = FirmwareSecurityOrchestrator(
        platform="linux",
        enable_mitigation=True  # ⚠️  CAREFUL: Actually modifies files
    )
    
    # Full scan
    report = await orchestrator.run_full_scan()
    
    # Check for non-compliant binaries
    non_compliant = orchestrator.validator.get_non_compliant_binaries()
    
    if not non_compliant:
        print("✓ No non-compliant binaries; no mitigation needed")
        return
    
    print(f"Remediating {len(non_compliant)} non-compliant binaries...")
    
    # Perform mitigation
    actions = await orchestrator.mitigator.mitigate_non_compliant_binaries()
    
    print(f"\nMitigation complete: {len(actions)} actions taken")
    for action in actions:
        print(f"\n  Action: {action.action_type}")
        print(f"  Binary: {action.efi_binary_path}")
        print(f"  Backup: {action.backup_location}")
        print(f"  Reversible: {action.reversible}")
    
    # Generate audit report
    mitigation_report = orchestrator.mitigator.get_mitigation_report()
    print(f"\nMitigation report: {mitigation_report}")

# Only run with explicit user confirmation!
# asyncio.run(remediate_non_compliant())
```

### Scenario 4: Audit Trail and Compliance

**Problem:** You need compliance documentation of firmware security state.

```python
import asyncio
import json
from datetime import datetime
from firmware_cache_validator import FirmwareSecurityOrchestrator

async def generate_compliance_report():
    orchestrator = FirmwareSecurityOrchestrator(platform="linux")
    
    # Run full scan
    scan_report = await orchestrator.run_full_scan()
    
    # Get validation details
    validation_reports = orchestrator.validator.validation_reports
    
    # Build compliance document
    compliance_doc = {
        "scan_timestamp": datetime.now().isoformat(),
        "scan_report": scan_report,
        "binaries": [],
    }
    
    for report in validation_reports:
        compliance_doc["binaries"].append({
            "path": str(report.efi_binary.path),
            "type": report.efi_binary.binary_type.value,
            "hash": report.efi_binary.sha256_hash,
            "signed": report.efi_binary.is_signed,
            "validation_status": report.validation_status.value,
            "audit_trail": report.audit_trail,
        })
    
    # Save to file
    with open("firmware_compliance_report.json", "w") as f:
        json.dump(compliance_doc, f, indent=2)
    
    print("✓ Compliance report saved to firmware_compliance_report.json")
    
    # Print summary
    print(f"\nFirmware Security Compliance Summary")
    print(f"====================================")
    print(f"Scan Time: {scan_report['scan_time']}")
    print(f"Platform: {scan_report['platform']}")
    print(f"Binaries Scanned: {scan_report['binaries_discovered']}")
    print(f"\nValidation Results:")
    print(f"  Compliant: {scan_report['validation_results']['compliant']}")
    print(f"  Non-Compliant: {scan_report['validation_results']['non_compliant']}")
    print(f"  Unsigned: {scan_report['validation_results']['unsigned']}")
    print(f"  Unknown: {scan_report['validation_results']['unknown']}")

asyncio.run(generate_compliance_report())
```

---

## Command-Line Interface

### Full Scan

```bash
python -m firmware_cache_validator scan --platform linux --esp-root /boot/efi
```

### Monitor Policy Changes

```bash
python -m firmware_cache_validator monitor --duration 3600 --alert-webhook https://...
```

### Validate Specific Binary

```bash
python -m firmware_cache_validator validate --binary /boot/efi/EFI/Boot/bootx64.efi
```

### Generate Report

```bash
python -m firmware_cache_validator report --output firmware_audit.json --include-binaries
```

---

## Configuration

### Environment Variables

```bash
# ESP location
export FW_ESP_ROOT=/boot/efi

# Backup directory
export FW_BACKUP_ROOT=/var/lib/firmware-backups

# Enable actual mitigation (dangerous!)
export FW_ENABLE_MITIGATION=false

# Logging level
export FW_LOG_LEVEL=INFO
```

### Configuration File

```yaml
# firmware_config.yaml
platform: linux
esp_root: /boot/efi
backup_root: /var/lib/firmware-backups

discovery:
  scan_recursive: true
  max_file_size: 10MB

monitoring:
  enabled: true
  method: inotify  # or polling
  poll_interval: 300  # seconds

validation:
  check_signatures: true
  check_timestamp: true

mitigation:
  enabled: false
  action: quarantine  # or delete, monitor
  preserve_bootability: true
```

---

## Troubleshooting

### Issue: "Could not locate EFI System Partition"

**Cause:** ESP not mounted or in non-standard location

**Solution:**
```bash
# Find ESP
lsblk -o NAME,FSTYPE | grep -i vfat
# or
efibootmgr -v | grep '^Boot'

# Mount manually
sudo mount -t vfat /dev/sda1 /mnt/efi
python firmware_cache_validator.py --esp-root /mnt/efi
```

### Issue: "Permission denied" when reading efivars

**Cause:** Running without sufficient privileges

**Solution:**
```bash
# Run with sudo
sudo python firmware_cache_validator.py

# Or grant user permissions
sudo setfacl -m u:$(whoami):r /sys/firmware/efi/efivars/*
```

### Issue: No binaries discovered

**Cause:** Wrong ESP location or no EFI binaries present

**Solution:**
```python
# Verify ESP location
from pathlib import Path
for candidate in [Path("/boot/efi"), Path("/efi"), Path("/boot/EFI")]:
    if candidate.exists():
        print(f"Found ESP at: {candidate}")
        for item in candidate.rglob("*.efi"):
            print(f"  {item}")
```

### Issue: Temporal binding verification fails

**Cause:** Binding database corrupted or secret key not available

**Solution:**
```bash
# Verify binding database integrity
python -c "
from firmware_cache_validator import UEFITemporalBinding
binding = UEFITemporalBinding()
import asyncio
bindings = asyncio.run(binding.load_bindings())
for hash, binding in bindings.items():
    try:
        asyncio.run(binding.verify_binding_integrity(binding))
        print(f'✓ {hash[:16]}: Valid')
    except:
        print(f'✗ {hash[:16]}: Invalid')
"
```

---

## Performance Considerations

### Optimization Tips

1. **Async Operations**
   - All I/O operations are async
   - Use `asyncio.gather()` for concurrent operations
   - Reduces latency when scanning many binaries

2. **Caching**
   - Cache policy reads to avoid repeated efivars access
   - Cache binary hash computations
   - Invalidate on detected policy transitions

3. **Monitoring**
   - Use inotify (Linux) instead of polling for real-time detection
   - Set appropriate poll interval for polling fallback
   - Consider dedicated monitoring thread/process

### Benchmarks

**Typical Scan Time (Linux, /boot/efi):**
- Discovery: ~100-500ms (10-50 binaries)
- Policy read: ~50-200ms
- Validation: ~10-50ms per binary
- **Total:** ~500ms - 2s for full system

**Memory Usage:**
- Base: ~20MB
- Per binary: ~100KB
- Policy: ~1-5MB
- Temporal bindings: ~10KB per binding

---

## Security Best Practices

### 1. Least Privilege

```bash
# Create dedicated user for monitoring
sudo useradd -r -s /usr/sbin/nologin fw-monitor

# Grant minimal privileges
sudo setfacl -m u:fw-monitor:r /sys/firmware/efi/efivars/*
```

### 2. Backup Before Mitigation

```python
# Always backup before enabling mitigation
import shutil
shutil.copytree("/boot/efi", "/mnt/external/efi_backup")

# Only then enable mitigation
orchestrator = FirmwareSecurityOrchestrator(enable_mitigation=True)
```

### 3. Audit Trail

```python
# Keep detailed logs
import logging
logging.basicConfig(
    filename="/var/log/firmware_validator.log",
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

### 4. Attestation

```python
# Use TPM for boot attestation
# Verify PCRs match expected values
# Store trusted baselines
```

---

## Integration Examples

### With systemd

```ini
# /etc/systemd/system/firmware-validator.service
[Unit]
Description=Firmware Cache Validator
After=network.target

[Service]
Type=simple
User=fw-monitor
ExecStart=/usr/local/bin/firmware-validator monitor
Restart=always

[Install]
WantedBy=multi-user.target
```

### With Prometheus

```python
from prometheus_client import Counter, Gauge

# Metrics
non_compliant_binaries = Gauge(
    "firmware_non_compliant_binaries",
    "Number of non-compliant EFI binaries"
)
policy_transitions = Counter(
    "firmware_policy_transitions_total",
    "Total Secure Boot policy transitions detected"
)

# Update metrics
non_compliant_binaries.set(len(validator.get_non_compliant_binaries()))
```

### With alerting

```python
import requests

def send_alert(severity, message):
    webhook_url = "https://hooks.slack.com/..."
    payload = {
        "severity": severity,
        "message": message,
        "timestamp": datetime.now().isoformat()
    }
    requests.post(webhook_url, json=payload)

# Use in mitigation or monitoring
if non_compliant:
    send_alert("critical", f"Found {len(non_compliant)} non-compliant binaries")
```

---

## Testing

### Unit Tests

```bash
# Run tests
pytest tests/

# With coverage
pytest --cov=firmware_cache_validator tests/
```

### Integration Tests

```bash
# Test on isolated ESP image
./tests/setup_test_esp.sh

# Run full test suite
./tests/run_integration_tests.sh
```

### Simulation Mode

```python
# All examples above use simulation mode by default
# Change to actual mitigation only when ready:

orchestrator = FirmwareSecurityOrchestrator(enable_mitigation=True)
```

---

## Support and Contact

**For bugs, security issues, or questions:**

- Email: security@staaml.com
- Website: https://staaml.com
- Patent inquiries: patents@staaml.com

---

**Status:** Production-Grade Implementation | Derivative #63 | Patent Protected
