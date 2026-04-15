"""
Derivative #68: Shared Memory Lateral Persistence Validator

System and Method for Mitigating Cached Executable Persistence Across Security Policy Transitions
Patent Portfolio - STAAML Corp / Stanley Linton

THREAT MODEL:
- POSIX shared memory segments (/dev/shm) containing executable code persist across
  process security policy transitions
- System V shared memory (shmget/shmat) mapped by multiple processes with executable
  permissions remains executable when hardening occurs
- Memory-mapped files (mmap) with PROT_EXEC in shared regions bypass policy enforcement
- WASM/compiled code in shared memory executed by secondary process when primary
  process policy hardens
- Namespace boundary crossings (separate namespaces, same shared memory) violate
  containment assumptions
"""

import asyncio
import dataclasses
import logging
import os
import re
import struct
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)

# Performance constants
SHM_SCAN_TIMEOUT = 10.0
MPROTECT_BATCH_SIZE = 32
POLICY_TRANSITION_WINDOW_MS = 5000
MAX_SEGMENT_SIZE = 1024 * 1024 * 1024  # 1GB max for scanning


class ExecutableType(Enum):
    """Detected executable content types in shared memory."""
    ELF_BINARY = "elf_binary"
    ELF_SHARED_OBJECT = "elf_shared_object"
    PE_EXECUTABLE = "pe_executable"
    WASM_MODULE = "wasm_module"
    JAVA_CLASS = "java_class"
    UNKNOWN = "unknown"


class ProtectionFlag(Enum):
    """Memory protection flags as defined in mman.h."""
    PROT_NONE = 0x0
    PROT_READ = 0x1
    PROT_WRITE = 0x2
    PROT_EXEC = 0x4
    PROT_SEM = 0x8


@dataclasses.dataclass
class SharedMemorySegment:
    """Represents a discovered shared memory segment."""
    segment_id: str
    segment_type: str  # "posix" | "sysv" | "mmap"
    path: Optional[str]
    size: int
    key_or_inode: Optional[str]
    owner_uid: Optional[int]
    creation_time: Optional[datetime]
    is_executable: bool
    executable_type: ExecutableType
    protection_flags: Set[ProtectionFlag]
    mapping_processes: List[int]  # PIDs
    mapped_addresses: Dict[int, List[Tuple[int, int]]]  # pid -> [(addr, size)]
    cached_content_hash: Optional[str] = None


@dataclasses.dataclass
class ProcessSecurityPolicy:
    """Represents a process's current security policy context."""
    pid: int
    policy_hash: str
    namespace_ids: Dict[str, int]  # "pid" | "user" | "net" | "ipc" | "cgroup"
    allowed_exec_origins: Set[str]  # allowed memory regions for execution
    policy_transition_timestamp: datetime
    enforced_restrictions: List[str]


@dataclasses.dataclass
class MitigationAction:
    """Represents a mitigation action to take on non-compliant memory."""
    segment_id: str
    action_type: str  # "revoke_exec" | "unmap" | "signal_process"
    target_pids: List[int]
    new_protection_flags: Optional[Set[ProtectionFlag]] = None
    force_unmap: bool = False
    atomic_required: bool = True


THREAT_MODEL = {
    "id": "derivative_68_shared_memory_lateral_persistence",
    "name": "Shared Memory Lateral Persistence Across Policy Transitions",
    "severity": "CRITICAL",
    "vectors": [
        {
            "vector_id": "shm_exec_persistence",
            "description": "Executable code in POSIX /dev/shm persists when process policy hardens",
            "attack_chain": [
                "Attacker loads WASM/compiled code into /dev/shm under permissive policy",
                "Code marked with PROT_EXEC, shared with secondary process",
                "Primary process undergoes security hardening (new policy context)",
                "Secondary process continues executing code from shared memory",
                "Policy enforcement doesn't retroactively validate shared regions"
            ],
            "impact": "Code execution bypass, privilege boundary violation"
        },
        {
            "vector_id": "sysv_shm_boundary_crossing",
            "description": "System V shared memory crosses namespace boundaries without re-validation",
            "attack_chain": [
                "Code mapped in non-isolated namespace context",
                "Process migrates to stricter namespace (new cgroup, new pid_ns)",
                "Original memory mappings remain valid despite stricter namespace",
                "Execution context incompatible with new namespace policy"
            ],
            "impact": "Namespace isolation bypass"
        },
        {
            "vector_id": "mmap_exec_file_persistence",
            "description": "Memory-mapped executable files with PROT_EXEC bypass policy transitions",
            "attack_chain": [
                "File mmap'd with PROT_EXEC in shared location",
                "Multiple processes access same physical pages",
                "Policy change affects file-based access controls",
                "mmap PROT_EXEC remains valid despite file policy change"
            ],
            "impact": "File-level policy bypass"
        }
    ],
    "detection_indicators": [
        "POSIX shared memory with ELF/PE/WASM headers",
        "System V segments with PROT_EXEC mapped by isolated processes",
        "mmap regions with PROT_EXEC in /tmp, /dev/shm, or shared volumes",
        "Policy transition without corresponding memory re-validation",
        "Multiple processes mapping same segment with different namespace contexts"
    ]
}


class SharedMemoryDiscovery:
    """Enumerate and analyze shared memory segments for executable content."""

    def __init__(self, scan_timeout: float = SHM_SCAN_TIMEOUT):
        self.scan_timeout = scan_timeout
        self.segments: Dict[str, SharedMemorySegment] = {}

    async def discover_posix_shm(self) -> List[SharedMemorySegment]:
        """
        Enumerate POSIX shared memory segments in /dev/shm.

        Returns:
            List of discovered POSIX shared memory segments.
        """
        segments = []
        try:
            shm_path = Path("/dev/shm")
            if not shm_path.exists():
                logger.warning("/dev/shm not found on this system")
                return segments

            for item in shm_path.iterdir():
                try:
                    stat = item.stat()
                    content = await self._read_segment_safely(item)

                    exec_type = self._detect_executable_type(content)
                    is_exec = exec_type != ExecutableType.UNKNOWN

                    segment = SharedMemorySegment(
                        segment_id=f"posix_{item.name}",
                        segment_type="posix",
                        path=str(item),
                        size=stat.st_size,
                        key_or_inode=str(stat.st_ino),
                        owner_uid=stat.st_uid,
                        creation_time=datetime.fromtimestamp(stat.st_ctime),
                        is_executable=is_exec,
                        executable_type=exec_type,
                        protection_flags=await self._get_segment_protections(item),
                        mapping_processes=await self._get_mapping_processes(item),
                        mapped_addresses={},
                    )
                    segments.append(segment)
                    self.segments[segment.segment_id] = segment

                    if is_exec:
                        logger.warning(
                            f"Found executable content in POSIX shm: {item.name} "
                            f"(type={exec_type.value}, size={stat.st_size})"
                        )

                except Exception as e:
                    logger.error(f"Error scanning /dev/shm item {item}: {e}")

        except Exception as e:
            logger.error(f"Error discovering POSIX shared memory: {e}")

        return segments

    async def discover_sysv_shm(self) -> List[SharedMemorySegment]:
        """
        Enumerate System V shared memory segments via ipcs command.

        Returns:
            List of discovered System V segments.
        """
        segments = []
        try:
            result = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    "ipcs", "-m",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                ),
                timeout=self.scan_timeout
            )
            stdout, _ = await result.communicate()

            for line in stdout.decode().split("\n")[3:]:  # Skip header
                if not line.strip():
                    continue

                parts = line.split()
                if len(parts) < 6:
                    continue

                try:
                    key = parts[0]
                    shmid = parts[1]
                    owner = parts[2]
                    perms = parts[3]
                    size = int(parts[4])

                    # Skip segments that are too large to scan
                    if size > MAX_SEGMENT_SIZE:
                        logger.info(f"Skipping large System V segment {shmid} ({size} bytes)")
                        continue

                    # Try to read segment content
                    content = await self._read_sysv_segment(int(shmid))
                    exec_type = self._detect_executable_type(content) if content else ExecutableType.UNKNOWN
                    is_exec = exec_type != ExecutableType.UNKNOWN

                    segment = SharedMemorySegment(
                        segment_id=f"sysv_{shmid}",
                        segment_type="sysv",
                        path=None,
                        size=size,
                        key_or_inode=key,
                        owner_uid=None,
                        creation_time=None,
                        is_executable=is_exec,
                        executable_type=exec_type,
                        protection_flags=self._parse_perm_string(perms),
                        mapping_processes=await self._get_sysv_mappers(int(shmid)),
                        mapped_addresses={},
                    )
                    segments.append(segment)
                    self.segments[segment.segment_id] = segment

                    if is_exec:
                        logger.warning(
                            f"Found executable content in System V shm: {shmid} "
                            f"(type={exec_type.value}, size={size})"
                        )

                except Exception as e:
                    logger.error(f"Error processing System V segment: {e}")

        except asyncio.TimeoutError:
            logger.error("System V segment discovery timed out")
        except Exception as e:
            logger.error(f"Error discovering System V shared memory: {e}")

        return segments

    async def discover_mmap_exec_regions(self) -> List[SharedMemorySegment]:
        """
        Discover memory-mapped files with PROT_EXEC in shared locations.

        Returns:
            List of discovered mmap segments.
        """
        segments = []
        shared_locations = ["/tmp", "/dev/shm", "/var/tmp"]

        try:
            result = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    "lsof", "+L1", "-a", "-d", "cwd,rtd,txt",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                ),
                timeout=self.scan_timeout
            )
            stdout, _ = await result.communicate()

            # Parse lsof output to find mapped executable files
            for line in stdout.decode().split("\n")[1:]:
                if not line.strip():
                    continue

                # Extract file paths and check if in shared location
                parts = line.split()
                if len(parts) < 9:
                    continue

                filepath = parts[8]
                if not any(filepath.startswith(loc) for loc in shared_locations):
                    continue

                try:
                    path = Path(filepath)
                    stat = path.stat()
                    content = await self._read_segment_safely(path)

                    exec_type = self._detect_executable_type(content)
                    is_exec = exec_type != ExecutableType.UNKNOWN

                    if is_exec:
                        segment = SharedMemorySegment(
                            segment_id=f"mmap_{path.name}_{stat.st_ino}",
                            segment_type="mmap",
                            path=str(path),
                            size=stat.st_size,
                            key_or_inode=str(stat.st_ino),
                            owner_uid=stat.st_uid,
                            creation_time=datetime.fromtimestamp(stat.st_ctime),
                            is_executable=True,
                            executable_type=exec_type,
                            protection_flags={ProtectionFlag.PROT_EXEC},
                            mapping_processes=await self._get_mapping_processes(path),
                            mapped_addresses={},
                        )
                        segments.append(segment)
                        self.segments[segment.segment_id] = segment

                        logger.warning(
                            f"Found executable mmap in shared location: {filepath} "
                            f"(type={exec_type.value})"
                        )

                except Exception as e:
                    logger.error(f"Error analyzing mmap file {filepath}: {e}")

        except asyncio.TimeoutError:
            logger.error("mmap discovery timed out")
        except Exception as e:
            logger.error(f"Error discovering mmap executable regions: {e}")

        return segments

    async def _read_segment_safely(self, path: Path, max_bytes: int = 4096) -> bytes:
        """Safely read initial bytes from a segment for content inspection."""
        try:
            with open(path, "rb") as f:
                return f.read(max_bytes)
        except Exception as e:
            logger.debug(f"Could not read segment {path}: {e}")
            return b""

    async def _read_sysv_segment(self, shmid: int, max_bytes: int = 4096) -> Optional[bytes]:
        """Attempt to read initial bytes from a System V segment."""
        try:
            result = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    "ipcs", "-m", "-i", str(shmid),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                ),
                timeout=self.scan_timeout
            )
            # Note: Reading actual segment content requires elevated privileges
            # This is a placeholder; real implementation would use shmat()
            await result.wait()
            return None
        except Exception:
            return None

    def _detect_executable_type(self, content: bytes) -> ExecutableType:
        """Detect executable content type from magic bytes."""
        if len(content) < 4:
            return ExecutableType.UNKNOWN

        # ELF magic: 0x7f454c46
        if content[:4] == b'\x7fELF':
            if len(content) > 16:
                ei_type = struct.unpack("<H", content[16:18])[0]
                if ei_type == 3:
                    return ExecutableType.ELF_SHARED_OBJECT
                elif ei_type == 2:
                    return ExecutableType.ELF_BINARY
            return ExecutableType.ELF_BINARY

        # PE/COFF magic: 0x4d5a (MZ)
        if content[:2] == b'MZ':
            return ExecutableType.PE_EXECUTABLE

        # WASM magic: 0x00 0x61 0x73 0x6d
        if content[:4] == b'\x00asm':
            return ExecutableType.WASM_MODULE

        # Java class: 0xcafebabe
        if content[:4] == b'\xca\xfe\xba\xbe':
            return ExecutableType.JAVA_CLASS

        return ExecutableType.UNKNOWN

    async def _get_segment_protections(self, path: Path) -> Set[ProtectionFlag]:
        """Get protection flags for a segment from /proc/[pid]/maps."""
        flags = set()
        try:
            result = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    "grep", str(path),
                    "/proc/self/maps",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                ),
                timeout=2.0
            )
            stdout, _ = await result.communicate()

            for line in stdout.decode().split("\n"):
                if not line.strip():
                    continue
                # Format: address perms offset dev inode pathname
                parts = line.split()
                if len(parts) >= 2:
                    perms = parts[1]
                    flags.update(self._parse_perm_string(perms))

        except Exception:
            pass

        return flags

    async def _get_mapping_processes(self, path: Path) -> List[int]:
        """Find all processes that have this path mapped."""
        pids = []
        try:
            result = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    "lsof", str(path),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                ),
                timeout=self.scan_timeout
            )
            stdout, _ = await result.communicate()

            for line in stdout.decode().split("\n")[1:]:
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        pid = int(parts[1])
                        if pid not in pids:
                            pids.append(pid)
                    except ValueError:
                        pass

        except Exception:
            pass

        return pids

    async def _get_sysv_mappers(self, shmid: int) -> List[int]:
        """Find processes mapping a System V segment."""
        pids = []
        try:
            proc_path = Path("/proc")
            for pid_dir in proc_path.iterdir():
                if not pid_dir.is_dir() or not pid_dir.name.isdigit():
                    continue

                try:
                    maps_path = pid_dir / "maps"
                    if maps_path.exists():
                        with open(maps_path) as f:
                            content = f.read()
                            # Look for segment key identifier in maps
                            # This is a simplified check
                            if f"[shmid_{shmid}]" in content or f"[shm-{shmid}]" in content:
                                pids.append(int(pid_dir.name))
                except Exception:
                    pass

        except Exception:
            pass

        return pids

    def _parse_perm_string(self, perm_str: str) -> Set[ProtectionFlag]:
        """Parse permission string from /proc/[pid]/maps or ipcs."""
        flags = set()
        if 'r' in perm_str:
            flags.add(ProtectionFlag.PROT_READ)
        if 'w' in perm_str:
            flags.add(ProtectionFlag.PROT_WRITE)
        if 'x' in perm_str:
            flags.add(ProtectionFlag.PROT_EXEC)
        return flags


class SharedMemoryPolicyMonitor:
    """Monitor security policy transitions affecting shared memory."""

    def __init__(self):
        self.process_policies: Dict[int, ProcessSecurityPolicy] = {}
        self.policy_transition_history: List[Tuple[int, datetime, str]] = []

    async def get_process_policy(self, pid: int) -> ProcessSecurityPolicy:
        """
        Get the current security policy context of a process.

        Args:
            pid: Process ID to inspect.

        Returns:
            ProcessSecurityPolicy describing current constraints.
        """
        try:
            # Get namespace IDs
            ns_ids = await self._get_namespace_ids(pid)

            # Get enforced restrictions (from AppArmor, SELinux, seccomp, etc.)
            restrictions = await self._get_enforced_restrictions(pid)

            # Compute policy hash
            policy_str = f"{ns_ids}:{restrictions}"
            policy_hash = hashlib.sha256(policy_str.encode()).hexdigest()

            policy = ProcessSecurityPolicy(
                pid=pid,
                policy_hash=policy_hash,
                namespace_ids=ns_ids,
                allowed_exec_origins=await self._get_allowed_exec_origins(pid),
                policy_transition_timestamp=datetime.now(),
                enforced_restrictions=restrictions,
            )

            # Check if policy changed
            if pid in self.process_policies:
                if self.process_policies[pid].policy_hash != policy_hash:
                    logger.warning(
                        f"Policy transition detected for PID {pid}: "
                        f"{self.process_policies[pid].policy_hash[:8]} -> {policy_hash[:8]}"
                    )
                    self.policy_transition_history.append(
                        (pid, datetime.now(), policy_hash)
                    )

            self.process_policies[pid] = policy
            return policy

        except Exception as e:
            logger.error(f"Error getting policy for PID {pid}: {e}")
            raise

    async def _get_namespace_ids(self, pid: int) -> Dict[str, int]:
        """Extract namespace IDs from /proc/[pid]/ns/."""
        ns_ids = {}
        try:
            ns_path = Path(f"/proc/{pid}/ns")
            if not ns_path.exists():
                return ns_ids

            for ns_file in ns_path.iterdir():
                try:
                    ns_type = ns_file.name
                    stat = ns_file.stat()
                    # Extract namespace ID from stat.st_ino
                    ns_ids[ns_type] = stat.st_ino
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"Error getting namespaces for PID {pid}: {e}")

        return ns_ids

    async def _get_enforced_restrictions(self, pid: int) -> List[str]:
        """Get list of enforced security restrictions."""
        restrictions = []

        try:
            # Check AppArmor profile
            aa_path = Path(f"/proc/{pid}/attr/apparmor/current")
            if aa_path.exists():
                with open(aa_path) as f:
                    restrictions.append(f"apparmor:{f.read().strip()}")
        except Exception:
            pass

        try:
            # Check SELinux context
            selinux_path = Path(f"/proc/{pid}/attr/current")
            if selinux_path.exists():
                with open(selinux_path) as f:
                    restrictions.append(f"selinux:{f.read().strip()}")
        except Exception:
            pass

        try:
            # Check seccomp status
            status_path = Path(f"/proc/{pid}/status")
            if status_path.exists():
                with open(status_path) as f:
                    for line in f:
                        if line.startswith("Seccomp:"):
                            restrictions.append(f"seccomp:{line.split(':')[1].strip()}")
        except Exception:
            pass

        return restrictions

    async def _get_allowed_exec_origins(self, pid: int) -> Set[str]:
        """Determine allowed memory regions for execution."""
        origins = set()
        try:
            maps_path = Path(f"/proc/{pid}/maps")
            if maps_path.exists():
                with open(maps_path) as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 2:
                            perms = parts[1]
                            if 'x' in perms:  # Executable region
                                addr_range = parts[0]
                                origins.add(addr_range)
        except Exception:
            pass

        return origins

    def detect_policy_transitions(self) -> List[int]:
        """
        Detect processes that have undergone policy transitions recently.

        Returns:
            List of PIDs with recent policy changes.
        """
        recent_transitions = []
        cutoff = datetime.now().timestamp() - (POLICY_TRANSITION_WINDOW_MS / 1000.0)

        for pid, ts, _ in self.policy_transition_history:
            if ts.timestamp() > cutoff and pid not in recent_transitions:
                recent_transitions.append(pid)

        return recent_transitions


class SharedMemoryValidator:
    """Validate shared memory content against current security policies."""

    def __init__(
        self,
        discovery: SharedMemoryDiscovery,
        monitor: SharedMemoryPolicyMonitor
    ):
        self.discovery = discovery
        self.monitor = monitor
        self.validation_results: Dict[str, bool] = {}

    async def validate_segment(
        self,
        segment: SharedMemorySegment,
        policies: Dict[int, ProcessSecurityPolicy]
    ) -> bool:
        """
        Validate a segment against the most restrictive policy of all mappers.

        Args:
            segment: The segment to validate.
            policies: Current policies of all mapping processes.

        Returns:
            True if segment complies with all policies, False otherwise.
        """
        if not segment.is_executable:
            # Non-executable segments always pass
            self.validation_results[segment.segment_id] = True
            return True

        if not segment.mapping_processes:
            # No mappers, consider valid
            self.validation_results[segment.segment_id] = True
            return True

        # Get most restrictive policy among mappers
        most_restrictive = None
        most_restrictive_pid = None

        for pid in segment.mapping_processes:
            if pid not in policies:
                continue

            policy = policies[pid]

            if most_restrictive is None:
                most_restrictive = policy
                most_restrictive_pid = pid
            else:
                # Compare restriction levels
                if len(policy.enforced_restrictions) > len(most_restrictive.enforced_restrictions):
                    most_restrictive = policy
                    most_restrictive_pid = pid

        if not most_restrictive:
            logger.warning(f"No policy found for segment {segment.segment_id} mappers")
            self.validation_results[segment.segment_id] = False
            return False

        # Check if executable content is allowed for this mapper
        is_valid = await self._check_exec_permission(
            segment,
            most_restrictive_pid,
            most_restrictive
        )

        self.validation_results[segment.segment_id] = is_valid

        if not is_valid:
            logger.warning(
                f"Segment {segment.segment_id} contains non-compliant executable "
                f"(type={segment.executable_type.value}) for PID {most_restrictive_pid}"
            )

        return is_valid

    async def _check_exec_permission(
        self,
        segment: SharedMemorySegment,
        pid: int,
        policy: ProcessSecurityPolicy
    ) -> bool:
        """Check if a specific process is allowed to execute this segment."""
        # Shared memory is only allowed if explicitly in allowed_exec_origins
        return any(
            origin in policy.allowed_exec_origins
            for origin in (segment.path or "").split()
        )

    async def validate_all_segments(
        self,
        policies: Dict[int, ProcessSecurityPolicy]
    ) -> Dict[str, bool]:
        """
        Validate all discovered segments against current policies.

        Args:
            policies: Current policies for all processes.

        Returns:
            Dictionary mapping segment IDs to validation results.
        """
        for segment_id, segment in self.discovery.segments.items():
            try:
                await self.validate_segment(segment, policies)
            except Exception as e:
                logger.error(f"Error validating segment {segment_id}: {e}")
                self.validation_results[segment_id] = False

        return self.validation_results

    def get_non_compliant_segments(self) -> List[str]:
        """Get list of segments that failed validation."""
        return [sid for sid, valid in self.validation_results.items() if not valid]


class SharedMemoryMitigationController:
    """Execute mitigation actions for non-compliant shared memory."""

    def __init__(self):
        self.mitigation_history: List[Tuple[MitigationAction, datetime, bool]] = []
        self.locks: Dict[int, asyncio.Lock] = {}

    async def execute_mitigation(
        self,
        action: MitigationAction,
        dry_run: bool = False
    ) -> bool:
        """
        Execute a mitigation action atomically.

        Args:
            action: The mitigation action to execute.
            dry_run: If True, log but don't execute.

        Returns:
            True if successful, False otherwise.
        """
        try:
            # Ensure process-level locking for atomicity
            for pid in action.target_pids:
                if pid not in self.locks:
                    self.locks[pid] = asyncio.Lock()

            # Acquire all locks in PID order to avoid deadlock
            locks_to_acquire = sorted(set(action.target_pids))
            acquired_locks = []

            try:
                for pid in locks_to_acquire:
                    await self.locks[pid].acquire()
                    acquired_locks.append(self.locks[pid])

                # Execute mitigation with locks held
                success = await self._execute_action_locked(action, dry_run)

                self.mitigation_history.append(
                    (action, datetime.now(), success)
                )

                return success

            finally:
                # Release locks in reverse order
                for lock in reversed(acquired_locks):
                    lock.release()

        except Exception as e:
            logger.error(f"Error executing mitigation action: {e}")
            return False

    async def _execute_action_locked(
        self,
        action: MitigationAction,
        dry_run: bool
    ) -> bool:
        """Execute mitigation action with locks held."""

        if action.action_type == "revoke_exec":
            return await self._revoke_exec(action, dry_run)
        elif action.action_type == "unmap":
            return await self._unmap_segment(action, dry_run)
        elif action.action_type == "signal_process":
            return await self._signal_process(action, dry_run)
        else:
            logger.error(f"Unknown mitigation action type: {action.action_type}")
            return False

    async def _revoke_exec(self, action: MitigationAction, dry_run: bool) -> bool:
        """Revoke PROT_EXEC from a segment using mprotect."""
        try:
            # This would normally use ctypes to call mprotect()
            # Here we simulate with logging
            new_flags = action.new_protection_flags or {
                ProtectionFlag.PROT_READ,
                ProtectionFlag.PROT_WRITE
            }

            flag_str = "|".join(f.name for f in new_flags)

            if dry_run:
                logger.info(
                    f"[DRY RUN] Would revoke PROT_EXEC from segment {action.segment_id} "
                    f"for PIDs {action.target_pids}, setting to {flag_str}"
                )
            else:
                logger.warning(
                    f"Revoking PROT_EXEC from segment {action.segment_id} "
                    f"for PIDs {action.target_pids}, setting to {flag_str}"
                )
                # Real implementation would use ctypes + mprotect()
                # await self._call_mprotect(action.segment_id, action.target_pids, new_flags)

            return True

        except Exception as e:
            logger.error(f"Error revoking PROT_EXEC: {e}")
            return False

    async def _unmap_segment(self, action: MitigationAction, dry_run: bool) -> bool:
        """Unmap non-compliant shared segment from processes."""
        try:
            if dry_run:
                logger.info(
                    f"[DRY RUN] Would unmap segment {action.segment_id} "
                    f"from PIDs {action.target_pids}"
                )
            else:
                logger.warning(
                    f"Unmapping segment {action.segment_id} "
                    f"from PIDs {action.target_pids}"
                )
                # Real implementation would use munmap()

            return True

        except Exception as e:
            logger.error(f"Error unmapping segment: {e}")
            return False

    async def _signal_process(self, action: MitigationAction, dry_run: bool) -> bool:
        """Signal process of policy change."""
        try:
            for pid in action.target_pids:
                try:
                    # Signal with SIGUSR1 to allow graceful handling
                    if dry_run:
                        logger.info(f"[DRY RUN] Would send SIGUSR1 to PID {pid}")
                    else:
                        os.kill(pid, 16)  # SIGUSR1
                        logger.info(f"Signaled PID {pid} of security policy change")
                except ProcessLookupError:
                    logger.debug(f"Process {pid} not found (may have exited)")
                except Exception as e:
                    logger.error(f"Error signaling PID {pid}: {e}")

            return True

        except Exception as e:
            logger.error(f"Error in signal_process: {e}")
            return False

    async def generate_mitigation_plan(
        self,
        non_compliant_segments: List[SharedMemorySegment],
        policies: Dict[int, ProcessSecurityPolicy]
    ) -> List[MitigationAction]:
        """
        Generate mitigation actions for non-compliant segments.

        Args:
            non_compliant_segments: Segments that failed validation.
            policies: Current security policies.

        Returns:
            List of mitigation actions to execute.
        """
        actions = []

        for segment in non_compliant_segments:
            # Skip if no mappers
            if not segment.mapping_processes:
                continue

            # Strategy: revoke PROT_EXEC from all mappers
            action = MitigationAction(
                segment_id=segment.segment_id,
                action_type="revoke_exec",
                target_pids=segment.mapping_processes.copy(),
                new_protection_flags={
                    ProtectionFlag.PROT_READ,
                    ProtectionFlag.PROT_WRITE
                },
                force_unmap=False,
                atomic_required=True
            )
            actions.append(action)

            # Also signal all affected processes
            signal_action = MitigationAction(
                segment_id=segment.segment_id,
                action_type="signal_process",
                target_pids=segment.mapping_processes.copy(),
            )
            actions.append(signal_action)

        return actions


async def demonstrate_derivative_68():
    """Demonstration of Derivative #68: Shared Memory Lateral Persistence."""

    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    logger.addHandler(handler)

    print("\n" + "="*80)
    print("Derivative #68: Shared Memory Lateral Persistence Validator")
    print("="*80)
    print(f"\nTHREAT MODEL: {THREAT_MODEL['name']}")
    print(f"Severity: {THREAT_MODEL['severity']}")

    discovery = SharedMemoryDiscovery()
    monitor = SharedMemoryPolicyMonitor()
    validator = SharedMemoryValidator(discovery, monitor)
    controller = SharedMemoryMitigationController()

    print("\n[*] Discovering shared memory segments...")
    posix_segments = await discovery.discover_posix_shm()
    sysv_segments = await discovery.discover_sysv_shm()
    mmap_segments = await discovery.discover_mmap_exec_regions()

    all_segments = posix_segments + sysv_segments + mmap_segments
    print(f"    Found {len(all_segments)} total shared memory segments")
    print(f"    - POSIX: {len(posix_segments)}")
    print(f"    - System V: {len(sysv_segments)}")
    print(f"    - mmap: {len(mmap_segments)}")

    executable_count = sum(1 for s in all_segments if s.is_executable)
    if executable_count > 0:
        print(f"\n[!] WARNING: Found {executable_count} segments with executable content!")

    print("\n[*] Getting process security policies...")
    # Get policy for current process as example
    current_pid = os.getpid()
    policy = await monitor.get_process_policy(current_pid)
    print(f"    Current process (PID {current_pid}):")
    print(f"    - Policy hash: {policy.policy_hash[:16]}...")
    print(f"    - Namespaces: {len(policy.namespace_ids)} found")
    print(f"    - Restrictions: {len(policy.enforced_restrictions)} enforced")

    print("\n[*] Validating segments against policies...")
    results = await validator.validate_all_segments({current_pid: policy})
    valid = sum(1 for v in results.values() if v)
    invalid = sum(1 for v in results.values() if not v)
    print(f"    Valid segments: {valid}")
    print(f"    Invalid segments: {invalid}")

    non_compliant = validator.get_non_compliant_segments()
    if non_compliant:
        print(f"\n[!] Non-compliant segments: {non_compliant}")

        non_compliant_objs = [
            s for s in all_segments
            if s.segment_id in non_compliant
        ]

        print("\n[*] Generating mitigation plan...")
        actions = await controller.generate_mitigation_plan(
            non_compliant_objs,
            {current_pid: policy}
        )
        print(f"    Generated {len(actions)} mitigation actions")

        for action in actions[:3]:  # Show first 3
            print(f"    - {action.action_type}: {action.segment_id} for PIDs {action.target_pids}")

    print("\n" + "="*80)
    print("Derivative #68 demonstration complete")
    print("="*80 + "\n")


if __name__ == "__main__":
    import hashlib
    asyncio.run(demonstrate_derivative_68())
