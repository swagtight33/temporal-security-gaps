# THREAT MODEL: Cached Executable Persistence Across Security Policy Transitions

**Derivative #63: Firmware/UEFI Cached Executable Persistence**

**Patent Portfolio:** "System and Method for Mitigating Cached Executable Persistence Across Security Policy Transitions"

**Authors:** Stanley Linton / STAAML Corp.

---

## Executive Summary

UEFI Secure Boot maintains internal caches of authorized boot loaders, Option ROMs, and EFI applications in the EFI System Partition (ESP). When firmware security policy transitions occur—such as Secure Boot key revocation, dbx (forbidden signatures database) update, or Platform Key rotation—previously cached EFI binaries may persist despite no longer being authorized by the new policy. This creates a **temporal persistence vector** that allows malicious code cached before a policy transition to execute at ring -2 (firmware execution level) after the transition.

### Core Vulnerability

The vulnerability arises from a **temporal mismatch** between policy enforcement and executable authorization:

1. **Caching Point:** EFI binary X is cached when it is authorized by current policy (signed with valid certificate, not in dbx)
2. **Policy Transition:** Secure Boot policy changes—dbx is updated, Platform Key rotated, or firmware certificate is revoked
3. **Persistence Window:** Binary X remains in ESP cache despite no longer being authorized
4. **Execution:** At next boot, firmware loads cached binary X at ring -2, bypassing authorization checks

**Attack Impact:** Ring -2 execution grants complete control over system boot sequence, memory, and peripherals before OS kernel loads.

---

## Threat Landscape

### 1. Evil Maid Attack with Policy Transition

**Threat Actor:** Physical attacker with device access

**Attack Flow:**
```
Day 1: Attacker with physical access to device
  └─> Inserts malicious EFI binary (e.g., shimx64.efi) into ESP
  └─> Binary is NOT signed with revoked certificate (yet compliant with current policy)
  └─> Firmware caches binary as authorized
  
Day 2: Manufacturer revokes compromised signing certificate
  └─> Revoked cert added to dbx via firmware update
  └─> System receives policy update: dbx now forbids cached binary's signature
  
Day 3: Device owner boots system
  └─> Firmware checks current policy: binary is now in dbx
  └─> BUT: Firmware loads from cache, bypassing dbx check
  └─> Malicious bootloader executes before OS, gains persistent control
```

**Exploit Windows:**
- Time between attacker placing binary and policy revocation
- Time between policy revocation and user's next boot with updated policy
- Firmware delay in applying policy updates

### 2. Bootkit Persistence via dbx Update

**Threat Actor:** Supply chain compromise, firmware vendor

**Attack Flow:**
```
Scenario: Vendor discovers bootkit in Option ROM cache

Phase 1 (Before dbx update):
  - Malicious Option ROM signed with vendor's legitimate certificate
  - Cached in firmware as authorized executable
  - Bootkit executes at ring -2 on every boot

Phase 2 (dbx update released):
  - Vendor revokes certificate and adds hash to dbx
  - Firmware image updated with new dbx
  - Users install update

Phase 3 (Persistence window):
  - Firmware loads cached Option ROM from NVRAM
  - Cache was populated BEFORE dbx update
  - Bootkit signature not yet validated against new dbx
  - Malicious code persists despite policy update
```

### 3. Option ROM Persistence Across Key Rotation

**Threat Actor:** Compromised OEM, supply chain attack

**Attack Scenario:**
```
Scenario: NVMe driver Option ROM persists after Platform Key rotation

Timeline:
  T0:  Compromised NVMe ROM cached in firmware, signed with old KEK
  T1:  Platform Key (PK) rotated, old KEK removed
  T1:  New KEK/db establish new trust chain
  T2:  User boots with new policy
  T2:  Firmware loads cached NVMe ROM using OLD KEK chain
  T2:  Exploit: Cache bypass allows execution with revoked certificate
  
Impact:
  - NVMe ROM executes at ring -2
  - Full access to memory, DMA, boot sequence
  - Can intercept encryption keys, inject OS-level rootkit
```

### 4. Multi-Stage Attack: Cache Persistence + Downgrade

**Threat Actor:** Sophisticated adversary with persistent access

**Attack Chain:**
```
Stage 1: Initial Compromise
  - Place Stage 1 bootkit in ESP (authority derived from current policy)
  - Bootkit cached by firmware
  
Stage 2: Policy Update Window
  - Stage 1 certificate revoked, added to dbx
  - Stage 1 bootkit persists in cache despite revocation
  
Stage 3: Exploitation
  - Boot with old firmware version
  - Firmware loads cached Stage 1 from cache
  - Stage 1 executes at ring -2
  - Stage 1 loads kernel module payload (Stage 2)
  - Operating system compromised
  
Result: Persistent, ring -2 rootkit resistant to offline detection
```

### 5. Temporal Desynchronization Attack

**Threat Actor:** Time-based exploit using policy update lag

**Vulnerability:**
```
Time window exploitation:

Timeline:
  T0:00  Admin initiates dbx update via management console
  T0:05  Update queued in firmware update service
  T0:10  User boots device
  T0:11  Firmware loads from cache (cache may not have new dbx)
  T0:20  Update service finally applies dbx change
  
Exploit:
  - Boot window (T0:10 to T0:20) allows execution of recently-revoked binaries
  - Cache persists across policy update transaction
  - Time desynchronization between policy application and boot sequence
```

---

## Technical Deep Dive: Cache Architecture

### EFI System Partition (ESP) Structure

```
/boot/efi (Linux example)
├── EFI/
│   ├── Boot/
│   │   └── bootx64.efi          ← Primary bootloader (cached)
│   ├── Microsoft/
│   │   └── Boot/
│   │       ├── bootmgfw.efi     ← Windows boot manager (cached)
│   │       └── winsipolicy.p7b
│   ├── ubuntu/
│   │   └── shimx64.efi          ← Shim loader (cached)
│   └── [OEM]/
│       └── firmware_*.efi       ← OEM drivers (cached)
├── System Volume Information/   ← Secure Boot metadata
└── [Cache files - firmware-managed]
```

### UEFI Variable Store Structure

**Secure Boot Policy Variables:**

```
Signature Databases:
  PK (Platform Key)           - 1 entry, highest privilege
  KEK (Key Exchange Key)      - Multiple entries, intermediate
  db (allowed signatures)     - Hash list + certificates
  dbx (forbidden signatures)  - Revocation list (binary hashes)
  dbr (revocation requests)   - Pending revocations

Cache State:
  SecureBoot variable         - Enable/Disable flag
  SetupMode variable          - User mode vs. Setup mode
  DeployedMode variable       - Firmware lockdown state
```

### UEFI Signature List (EFI_SIGNATURE_LIST) Format

```
Offset  Size   Field
------  ----   -----
0x00    16     SignatureType (GUID)
0x10    4      ListSize (total size including header)
0x14    4      HeaderSize (size of header)
0x18    ...    SignatureData (ListSize - HeaderSize bytes)

SignatureType GUIDs:
  {c1c41626-504c-4092-aca9-41f936934328}  - EFI_SHA256_GUID
  {3c5fb5d0-3e60-42f9-8e99-521ec955a5e5}  - EFI_CERT_RSA2048_GUID
  {a5c059a1-94e4-4aa7-87b5-ab155c2bf072}  - EFI_CERT_X509_GUID
```

### Cache Persistence Mechanism

**Linux (EFI Runtime Services):**
```
1. Firmware reads EFI variables from NVRAM
2. Variable buffer cached in firmware memory
3. Cache persists until NVRAM rewrite
4. NVRAM update requires:
   - Firmware support for variable write
   - Specific capability bits set
   - Often requires reboot to apply

Vulnerability: Cache may be queried before NVRAM update completes
```

**Windows (UEFI Specification):**
```
1. GetVariable() returns cached copy of variable
2. SetVariable() updates NVRAM but may not flush cache immediately
3. Subsequent boot may use stale cached copy
4. Cache invalidation timing depends on firmware implementation
```

---

## Exploit Techniques

### Technique 1: Signature Database Cache Bypass

**Attack:**
```python
# Attacker's approach
1. Discover bootloader binary hash
2. Exploit before certificate revocation: binary is authorized
3. Binary cached in firmware NVRAM
4. Certificate is revoked (added to dbx)
5. Binary persists in cache despite revocation
6. Boot sequence loads from cache, bypassing new dbx check

Result: Revoked binary executes at ring -2
```

**Code-level vulnerability:**
```c
// Pseudocode of vulnerable firmware logic
if (is_in_cache(binary_hash)) {
    load_from_cache(binary);          // No dbx check!
    return;
}
// Only reached if not cached
if (is_in_dbx(binary_hash, current_dbx)) {
    deny_execution();
}
```

### Technique 2: Race Condition in Policy Transition

**Attack:**
```
Firmware update application timing:

CPU Core 1                          CPU Core 2 (Boot CPU)
------                              -------
apply_dbx_update()
  lock(nvram)
  write(nvram, new_dbx)
                                    boot_sequence()
                                      cache = read_cache()
                                      for each cached binary:
                                        if in_cache && signed:
                                          load_binary()  // No dbx check
  write(nvram, updated_flag)
  unlock(nvram)

Vulnerability: Boot proceeds with stale cache while update in flight
```

### Technique 3: Firmware Update Rollback

**Attack:**
```
Timeline:
  T0:   v1.0 firmware with old policy
  T0:   Attacker places binary X (signed, authorized)
  T0:   X cached by firmware
  T1:   Firmware updates to v2.0 (new policy, X now in dbx)
  T1:   X persists in cache
  T2:   Attacker downgrades to v1.0
  T2:   v1.0 boots with old policy and cached X
  T2:   X is authorized again; executes
  
Result: Rollback attack combined with cache persistence
```

---

## Detection Challenges

### Why Cache Persistence Is Hard to Detect

1. **No Persistent Log in ESP:**
   - Cache contents not logged to disk
   - ESP may not be readable by OS after boot
   - Firmware event logs often don't cover cache operations

2. **Temporal Inconsistency:**
   - Binary timestamp on disk ≠ cache load timestamp
   - Current policy ≠ policy at cache time
   - No metadata recording when binary was cached

3. **Firmware Opacity:**
   - UEFI variable access requires elevated privileges
   - Some firmware implements variable access control
   - Cache contents not exposed through standard APIs

4. **Race Conditions:**
   - Policy update timing unpredictable
   - Multiple boot paths may bypass each other
   - Cache invalidation timing firmware-specific

---

## Mitigation Strategies

### Strategy 1: Temporal Binding

**Concept:** Bind each EFI binary to the policy state at observation time

**Implementation:**
```
Data Structure:
{
  "binary_hash": "sha256...",
  "observation_time": "2024-01-15T10:30:00Z",
  "dbx_hash": "sha256 of entire dbx at observation time",
  "db_hash": "sha256 of entire db at observation time",
  "pk_hash": "sha256 of platform key at observation time",
  "binding_hmac": "hmac(all_above, secret_key)"
}

Validation:
1. On every boot, compute new temporal binding
2. Compare against historical binding database
3. If binary was authorized at observation time but not now:
   - Check if authorization was revoked via policy transition
   - Allow execution if revocation is legitimate
   - Block if revocation suggests compromise
```

### Strategy 2: Cache Invalidation on Policy Transition

**Mitigation:**
```
On dbx/db/PK update:
1. Firmware intercepts policy update transaction
2. Invalidates cache entries affected by policy change
3. Mark affected binaries for re-validation on next boot
4. Refuse boot if critical binary fails validation

Requires firmware changes to UEFI implementation
```

### Strategy 3: Secure Boot Policy Versioning

**Concept:** Include version number in cached binary metadata

**Implementation:**
```
Cache Entry Format:
  {
    "binary": ...,
    "policy_version": "3.14",  // Version of policy at cache time
    "validation_timestamp": ...,
    "signature_chain": [...]
  }

On load:
  if (policy_version < current_policy_version) {
    re_validate(binary, current_policy)
  }
```

### Strategy 4: Hardware-Backed Policy Attestation

**Concept:** Use TPM 2.0 to attest to policy state

**Implementation:**
```
TPM PCR Extension:
1. Firmware extends TPM PCR with policy state before cache load
2. PCR reflects current dbx, db, PK state
3. OS kernel can verify PCR against known good values
4. If PCR indicates stale cache was used, kernel can audit/block

Requires TPM 2.0 and measured boot compliance
```

---

## Mitigation Implementation (In This Code)

### FirmwareCacheDiscovery
- Enumerates ESP and reads UEFI variables
- Discovers all cached EFI binaries
- Parses signature databases (db, dbx, dbr)

### FirmwarePolicyMonitor
- Watches for policy transitions in real-time
- Detects dbx updates, PK rotation, KEK changes
- Computes policy deltas

### FirmwareValidator
- Validates cached binaries against CURRENT policy
- Checks if binary hash is in dbx (forbidden)
- Verifies signatures against db (allowed)
- Classifies as COMPLIANT, NON_COMPLIANT, UNSIGNED, UNKNOWN

### FirmwareMitigationController
- Quarantines non-compliant binaries
- Creates secure backups
- Replaces with stub files to prevent loading
- Preserves bootability (never leaves system unbootable)

### UEFITemporalBinding
- Creates temporal binding at first observation
- Records policy state at observation time
- Enables retroactive validation after policy transitions
- Stores bindings in tamper-evident database

---

## Platform-Specific Considerations

### Linux

**ESP Location:**
- `/boot/efi` (standard)
- `/efi` (alternative)
- `/boot/EFI` (capitalized)

**UEFI Variables:**
- `/sys/firmware/efi/efivars/` (UEFI variable store)
- File naming: `<VarName>-<VarGUID>`

**Monitoring:**
- Use inotify on `/sys/firmware/efi/efivars/`
- Parse variable files directly as binary

**MOK (Machine Owner Key):**
- Extension to UEFI Secure Boot for Linux
- Variables in: `/sys/firmware/efi/efivars/MokList*`
- Managed via `mokutil` command-line tool

### Windows

**ESP Location:**
- `C:\EFI` (standard)
- May be hidden by default

**UEFI Variables:**
- Registry: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\efivars`
- Requires admin privileges to read

**Policy Updates:**
- Windows Update handles policy updates
- Updates applied at next boot

### macOS

**ESP Location:**
- `/Volumes/EFI` (mounted during boot)
- May not be accessible after OS loads

**UEFI Variables:**
- Use `nvram` command-line tool
- Variables not directly accessible via filesystem

**Limitations:**
- Limited access to firmware variables
- Apple firmware (T2 chip) not fully UEFI compliant

---

## Recommended Defensive Measures

### Short Term (Software-only)

1. **Inventory ESP Contents**
   - Regularly scan ESP for unexpected binaries
   - Compute hashes, maintain signed manifest
   - Flag new or modified binaries

2. **Monitor Policy Changes**
   - Watch for dbx updates
   - Track UEFI variable modifications
   - Alert on policy transitions

3. **Validate on Boot**
   - Implement validation at OS startup
   - Use TPM PCR measurements
   - Verify binary signatures against current policy

### Medium Term (Firmware Updates)

1. **Cache Invalidation**
   - Firmware should invalidate affected cache entries on policy update
   - Implement cache versioning tied to policy version
   - Require explicit re-authorization after policy change

2. **Temporal Attestation**
   - Firmware records timestamp of each cache operation
   - Exposes this via TPM or secure log
   - Enables audit of which policy version authorized cached binary

3. **Policy Signing**
   - Sign policy updates cryptographically
   - Include signature in cache metadata
   - Verify policy update integrity on load

### Long Term (Architecture)

1. **Measured Boot Enhancement**
   - PCR should include complete policy state
   - Enable secure attestation of policy version used
   - Support policy rollback detection

2. **Immutable Cache Option**
   - Support firmware mode that invalidates cache on boot
   - Or forces re-validation against current policy
   - Trade-off: performance vs. security

3. **Hardware Root of Trust**
   - Use secure enclave (e.g., TPM 2.0 NV RAM)
   - Store policy signatures in hardware
   - Hardware validates cache against stored policy

---

## References

- UEFI Forum: "UEFI Specification Version 2.10"
- Microsoft: "Secure Boot Implementation"
- Intel: "TXT (Trusted Execution Technology) Architecture"
- NIST: "SP 800-147: Guidelines for Implementing Secure Boot"
- James Bottomley: "The kernel in your UEFI"

---

## Patent Claim Summary

This implementation protects the following novel concepts:

1. **Temporal Binding of Cached Executables**
   - Binding cached binary to policy state at observation time
   - HMAC-based tamper detection

2. **Policy Transition Detection**
   - Real-time monitoring of Secure Boot policy changes
   - Delta computation between policy versions

3. **Retroactive Validation**
   - Validating executable against policy at observation time
   - Determining if revocation was legitimate vs. compromise

4. **Safe Mitigation Without Bricking**
   - Quarantine mechanism that preserves bootability
   - Rollback capability with audit trail

---

**Status:** Derivative #63 | Patent Portfolio Active | Production-Grade Implementation
