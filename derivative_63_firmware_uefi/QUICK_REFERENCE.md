# Firmware Cache Validator - Quick Reference

**Derivative #63: Firmware/UEFI Cached Executable Persistence**

---

## Installation & Setup

```bash
# Clone/navigate to directory
cd derivative_63_firmware_uefi

# Install dependencies
pip install -r requirements.txt

# Verify installation
python3 -c "from firmware_cache_validator import FirmwareSecurityOrchestrator; print('✓ Ready')"
```

---

## Command-Line Quick Start

```bash
# Full security assessment
python3 -m firmware_cache_validator scan --platform linux

# Monitor policy changes (1 hour)
python3 -m firmware_cache_validator monitor --duration 3600

# Generate audit report
python3 -m firmware_cache_validator report --output audit.json

# Validate specific binary
python3 -m firmware_cache_validator validate --binary /boot/efi/EFI/Boot/bootx64.efi
```

---

## Python API Quick Start

### Minimal Example (2 lines)

```python
import asyncio
from firmware_cache_validator import FirmwareSecurityOrchestrator

orchestrator = FirmwareSecurityOrchestrator(platform="linux")
report = asyncio.run(orchestrator.run_full_scan())
print(report)
```

### Common Operations

#### Discover EFI Binaries

```python
discovery = FirmwareCacheDiscovery(platform="linux")
binaries = await discovery.discover_efi_binaries()

for binary in binaries:
    print(f"{binary.path}: {binary.binary_type.value}")
    print(f"  Hash: {binary.sha256_hash}")
    print(f"  Signed: {binary.is_signed}")
```

#### Read Secure Boot Policy

```python
policy = await discovery.read_uefi_variables()
print(f"db entries: {len(policy.db_entries)}")
print(f"dbx entries: {len(policy.dbx_entries)}")
print(f"PK hash: {policy.pk_hash[:16]}...")
```

#### Validate Binaries

```python
validator = FirmwareValidator(discovery)
reports = await validator.validate_all_binaries()

for report in reports:
    print(f"{report.efi_binary.path}: {report.validation_status.value}")
    
non_compliant = validator.get_non_compliant_binaries()
if non_compliant:
    print(f"⚠️  {len(non_compliant)} non-compliant binaries detected")
```

#### Monitor Policy Changes

```python
monitor = FirmwarePolicyMonitor(discovery)
task = asyncio.create_task(monitor.start_monitoring())

# ... wait for changes ...
await asyncio.sleep(3600)

transitions = monitor.get_transitions()
for transition_type, old_policy, new_policy in transitions:
    print(f"Policy change: {transition_type.value}")
```

#### Quarantine Non-Compliant Binaries

```python
mitigator = FirmwareMitigationController(
    validator,
    enable_mitigation=False  # Set to True to actually modify files
)

actions = await mitigator.mitigate_non_compliant_binaries()
for action in actions:
    print(f"Action: {action.action_type}")
    print(f"  Binary: {action.efi_binary_path}")
    print(f"  Backup: {action.backup_location}")
```

#### Create Temporal Bindings

```python
binding_system = UEFITemporalBinding()

for binary in binaries:
    temporal_binding = await binding_system.create_temporal_binding(
        binary,
        discovery.current_policy
    )

# Later, retroactively validate
result = await binding_system.retroactive_validation(
    binary_hash,
    current_policy
)
```

---

## Core Classes Cheat Sheet

| Class | Purpose | Key Methods |
|-------|---------|-------------|
| `FirmwareCacheDiscovery` | Find EFI binaries & read policy | `discover_efi_binaries()`, `read_uefi_variables()` |
| `FirmwarePolicyMonitor` | Watch for policy changes | `start_monitoring()`, `get_transitions()` |
| `FirmwareValidator` | Check binaries against policy | `validate_all_binaries()`, `get_non_compliant_binaries()` |
| `FirmwareMitigationController` | Quarantine bad binaries | `mitigate_non_compliant_binaries()`, `rollback_mitigation()` |
| `UEFITemporalBinding` | Create time-locked bindings | `create_temporal_binding()`, `retroactive_validation()` |
| `FirmwareSecurityOrchestrator` | Coordinate all components | `run_full_scan()` |

---

## Enumerations Reference

### ValidationStatus

```
COMPLIANT       - In db, not in dbx ✓
NON_COMPLIANT   - Found in dbx ✗
UNSIGNED        - No valid signature ⚠️
UNKNOWN         - Cannot determine ?
QUARANTINED     - Moved to safe location 🔒
```

### PolicyTransitionType

```
DBX_UPDATE      - Forbidden signatures updated
DB_UPDATE       - Allowed signatures updated
PK_ROTATION     - Platform Key changed
KEK_ROTATION    - Key Exchange Key changed
MOK_UPDATE      - Machine Owner Key changed
```

### EFIBinaryType

```
BOOTLOADER      - Primary boot loader
OPTION_ROM      - Firmware extension ROM
EFI_DRIVER      - UEFI driver module
EFI_APPLICATION - EFI application
UEFI_SHELL      - UEFI shell script
UNKNOWN         - Unknown type
```

---

## Error Handling

### Common Issues & Solutions

#### "Could not locate EFI System Partition"

```python
# Specify explicit path
discovery = FirmwareCacheDiscovery(
    esp_root=Path("/mnt/efi"),
    platform="linux"
)
```

#### "Permission denied" reading efivars

```bash
# Run with sudo
sudo python3 script.py

# Or grant permissions
sudo setfacl -m u:$(whoami):r /sys/firmware/efi/efivars/*
```

#### No binaries discovered

```python
# Verify ESP path
discovery = FirmwareCacheDiscovery(platform="linux")
print(f"ESP Root: {discovery.esp_root}")

# List contents
for item in discovery.esp_root.rglob("*.efi"):
    print(item)
```

---

## Integration Examples

### systemd Service

```ini
[Unit]
Description=Firmware Validator Monitor
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/fw-validator/monitor.py
Restart=always
User=fw-monitor

[Install]
WantedBy=multi-user.target
```

### Prometheus Metrics

```python
from prometheus_client import Counter, Gauge

non_compliant = Gauge(
    "firmware_non_compliant_binaries",
    "Number of non-compliant EFI binaries"
)

policy_transitions = Counter(
    "firmware_policy_transitions_total",
    "Total policy transitions detected"
)

# Update metrics
non_compliant.set(len(validator.get_non_compliant_binaries()))
```

### Webhook Alert

```python
import requests

def alert(severity, message):
    webhook = "https://hooks.slack.com/..."
    payload = {
        "severity": severity,
        "message": message,
        "timestamp": datetime.now().isoformat()
    }
    requests.post(webhook, json=payload)

# Use in monitoring
if non_compliant:
    alert("critical", f"{len(non_compliant)} non-compliant binaries detected")
```

---

## Performance Tips

1. **Use inotify for monitoring** (Linux only, requires `inotify_simple`)
   ```bash
   pip install inotify_simple
   ```

2. **Async/await for concurrent operations**
   ```python
   tasks = [
       validator._validate_single_binary(b)
       for b in binaries
   ]
   results = await asyncio.gather(*tasks)
   ```

3. **Cache policy snapshots**
   ```python
   # Read once, reuse many times
   policy = await discovery.read_uefi_variables()
   discovery.current_policy = policy
   ```

4. **Batch file I/O**
   ```python
   # Use async file operations
   binaries = await discovery.discover_efi_binaries()
   ```

---

## Testing

```bash
# Run all tests
pytest test_firmware_validator.py -v

# With coverage
pytest --cov=firmware_cache_validator test_firmware_validator.py

# Performance tests
pytest test_firmware_validator.py -m performance

# Specific test
pytest test_firmware_validator.py::test_validate_against_dbx -v
```

---

## Platform-Specific Notes

### Linux
- **ESP Default:** `/boot/efi`
- **Variables:** `/sys/firmware/efi/efivars/`
- **Best for:** Development and testing

### Windows
- **ESP Default:** `C:\EFI`
- **Variables:** Registry (HKEY_LOCAL_MACHINE\SYSTEM\...)
- **Note:** Limited access to UEFI variables

### macOS
- **ESP Default:** `/Volumes/EFI`
- **Variables:** `nvram` command
- **Note:** Limited UEFI compliance

---

## Danger Zones ⚠️

### NEVER do without backup:

```python
# ✗ BAD: No backup, production system
mitigator = FirmwareMitigationController(validator, enable_mitigation=True)
```

### DO first:

```python
# ✓ GOOD: Backup ESP
import shutil
shutil.copytree("/boot/efi", "/mnt/backup/efi_backup")

# ✓ GOOD: Test in simulation mode
mitigator = FirmwareMitigationController(validator, enable_mitigation=False)
actions = await mitigator.mitigate_non_compliant_binaries()
print(f"Would take {len(actions)} actions")

# ✓ GOOD: Only then enable mitigation
mitigator = FirmwareMitigationController(validator, enable_mitigation=True)
```

---

## Documentation Links

| Document | Content |
|----------|---------|
| `THREAT_MODEL.md` | Detailed threat analysis and attack scenarios |
| `USAGE_GUIDE.md` | Comprehensive usage examples and integration |
| `PROJECT_SUMMARY.md` | Architecture overview and feature summary |
| `test_firmware_validator.py` | Reference implementation and usage patterns |

---

## Key Concepts

### Temporal Binding

The core innovation: binding a cached binary to the policy state **at the time it was cached**, enabling retroactive validation if policy changes later.

```python
# At cache time (T0)
binding_t0 = await binding_system.create_temporal_binding(
    binary,
    policy_at_t0
)

# At analysis time (T1, after policy update)
# Can determine: Was this binary authorized at T0?
is_valid_at_t0 = await binding_system.retroactive_validation(
    binary.sha256_hash,
    policy_at_t0  # Use historical policy, not current
)
```

### Policy Transition

Moment when Secure Boot policy changes, creating a window where cached binaries may not match current policy.

```python
# Detected automatically
transition_type = monitor._detect_transition_type(old_policy, new_policy)
# Returns: PolicyTransitionType.DBX_UPDATE, .PK_ROTATION, etc.
```

### Validation Status

Every cached binary has a status relative to current policy:

```
COMPLIANT     ← Safe to execute (in db, not in dbx)
NON_COMPLIANT ← Dangerous (in dbx, forbidden)
UNSIGNED      ← No signature, cannot verify
UNKNOWN       ← Insufficient information
QUARANTINED   ← Moved to safe location
```

---

## One-Liners

```python
# Get all non-compliant binaries
non_compliant = await validator.validate_all_binaries() and validator.get_non_compliant_binaries()

# Check if system is clean
is_safe = len(validator.get_non_compliant_binaries()) == 0

# Find bootloaders
bootloaders = [b for b in binaries if b.binary_type == EFIBinaryType.BOOTLOADER]

# Full scan and mitigation (simulation)
report = await FirmwareSecurityOrchestrator(enable_mitigation=False).run_full_scan()
```

---

## Support

- **Email:** security@staaml.com
- **Docs:** See USAGE_GUIDE.md for comprehensive examples
- **Issues:** Check THREAT_MODEL.md for architectural decisions
- **Testing:** Run pytest test_firmware_validator.py -v

---

**Derivative #63: Firmware/UEFI Cached Executable Persistence**
**Patent Portfolio Active | Production-Grade Implementation**
