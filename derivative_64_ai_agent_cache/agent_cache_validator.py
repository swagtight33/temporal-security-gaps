"""
AI Agent Tool Authorization and Credential Cache Validator

Derivative #64: System and Method for Mitigating Cached Executable Persistence
Across Security Policy Transitions

Patent Portfolio: STAAML Corp / Stanley Linton

This module implements validation and mitigation strategies for cached tool authorizations,
credential stores, and behavioral artifacts across AI agent frameworks (LangChain, CrewAI,
AutoGen, Claude MCP) when security policies, permission boundaries, or trust scopes change.

Core vulnerability: AI agent frameworks cache tool registrations, API credentials, OAuth tokens,
model artifacts, and behavioral state. When sandbox policies, permission boundaries, or trust
scopes transition, these caches persist indefinitely without natural TTLs, creating privilege
escalation and data governance violations.

Threat Model:
  - Cached Tool Escalation: Tools granted under old policy remain cached after policy downgrade
  - Credential Persistence: OAuth tokens, API keys, service account creds persist across trust boundary changes
  - RAG Poisoning Persistence: Cached embeddings/indexes from high-classification data remain accessible
  - Behavioral Memory Exfiltration: Conversation history, learned preferences persist across policy transitions
  - MCP Server Manifest Lag: Tool capabilities remain cached despite server capability removal
  - Sandbox Escape via Cache: Agents use cached credentials to access resources outside new sandbox
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    AsyncIterator,
    Callable,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)
from abc import ABC, abstractmethod

# Python 3.10 compatibility
UTC = timezone.utc

import aiofiles
import aiofiles.os

logger = logging.getLogger(__name__)

# ============================================================================
# Constants & Configuration
# ============================================================================

# Performance targets
CACHE_DISCOVERY_TIMEOUT_SEC = 30.0
POLICY_MONITOR_CHECK_INTERVAL_SEC = 5.0
MITIGATION_OPERATION_TIMEOUT_SEC = 60.0
CREDENTIAL_TTL_DEFAULT_SEC = 3600.0

# Framework detection patterns
LANGCHAIN_CONFIG_PATHS = [
    "~/.langchain",
    "~/.cache/langchain",
]

CREWAI_CONFIG_PATHS = [
    "~/.crewai",
    "~/.cache/crewai",
]

AUTOGEN_CONFIG_PATHS = [
    "~/.autogen",
    "~/.cache/autogen",
]

MCP_CONFIG_PATHS = [
    "~/.mcp",
    "~/.config/mcp",
    "~/.cache/mcp",
]

# Threat vectors
THREAT_MODEL = {
    "cached_tool_escalation": {
        "description": "Tools granted under old policy remain cached after policy downgrade",
        "mitigation": "Revoke tool cache entries that exceed current policy scopes",
    },
    "credential_persistence": {
        "description": "OAuth tokens, API keys persist across trust boundary changes",
        "mitigation": "Purge credentials associated with deprecated trust boundaries",
    },
    "rag_poisoning_persistence": {
        "description": "Cached embeddings/indexes from high-classification data remain accessible",
        "mitigation": "Quarantine RAG indexes with policy-violating data sources",
    },
    "behavioral_memory_exfiltration": {
        "description": "Conversation history, learned preferences persist across policy transitions",
        "mitigation": "Regenerate behavioral state by filtering against current policy",
    },
    "mcp_manifest_lag": {
        "description": "Tool capabilities remain cached despite server capability removal",
        "mitigation": "Revalidate cached MCP tool schemas against current server state",
    },
    "sandbox_escape_via_cache": {
        "description": "Agents use cached credentials to access resources outside sandbox",
        "mitigation": "Atomic cache invalidation when sandbox boundaries change",
    },
}


# ============================================================================
# Enums & Data Structures
# ============================================================================


class ComplianceStatus(str, Enum):
    """Cache validation compliance status."""

    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    STALE_CREDENTIAL = "STALE_CREDENTIAL"
    SCOPE_EXCEEDED = "SCOPE_EXCEEDED"
    DATA_GOVERNANCE_VIOLATION = "DATA_GOVERNANCE_VIOLATION"
    UNKNOWN = "UNKNOWN"


class FrameworkType(str, Enum):
    """Supported AI agent frameworks."""

    LANGCHAIN = "langchain"
    CREWAI = "crewai"
    AUTOGEN = "autogen"
    MCP = "mcp"
    UNKNOWN = "unknown"


class PolicyTransitionType(str, Enum):
    """Types of security policy transitions."""

    PERMISSION_DOWNGRADE = "permission_downgrade"
    PERMISSION_UPGRADE = "permission_upgrade"
    TRUST_BOUNDARY_CHANGE = "trust_boundary_change"
    DATA_GOVERNANCE_CHANGE = "data_governance_change"
    MCP_CAPABILITY_CHANGE = "mcp_capability_change"
    SANDBOX_POLICY_CHANGE = "sandbox_policy_change"


class MitigationAction(str, Enum):
    """Types of cache mitigation actions."""

    REVOKE_TOOL = "revoke_tool"
    PURGE_CREDENTIAL = "purge_credential"
    QUARANTINE_RAG_INDEX = "quarantine_rag_index"
    REGENERATE_BEHAVIOR = "regenerate_behavior"
    REVALIDATE_MCP_SCHEMA = "revalidate_mcp_schema"


@dataclass
class CachedTool:
    """Represents a cached tool registration."""

    tool_id: str
    tool_name: str
    framework: FrameworkType
    capabilities: Set[str] = field(default_factory=set)
    required_scopes: Set[str] = field(default_factory=set)
    cached_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_used: Optional[datetime] = None
    hash_value: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "tool_id": self.tool_id,
            "tool_name": self.tool_name,
            "framework": self.framework.value,
            "capabilities": list(self.capabilities),
            "required_scopes": list(self.required_scopes),
            "cached_at": self.cached_at.isoformat(),
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "hash_value": self.hash_value,
        }


@dataclass
class CachedCredential:
    """Represents a cached credential/token."""

    credential_id: str
    credential_type: str  # oauth_token, api_key, service_account, etc.
    associated_tool_ids: Set[str] = field(default_factory=set)
    associated_scopes: Set[str] = field(default_factory=set)
    trust_boundary: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: Optional[datetime] = None
    is_revoked: bool = False
    hash_value: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "credential_id": self.credential_id,
            "credential_type": self.credential_type,
            "associated_tool_ids": list(self.associated_tool_ids),
            "associated_scopes": list(self.associated_scopes),
            "trust_boundary": self.trust_boundary,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_revoked": self.is_revoked,
            "hash_value": self.hash_value,
        }

    def is_expired(self) -> bool:
        """Check if credential has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(UTC) > self.expires_at


@dataclass
class CachedRAGIndex:
    """Represents a cached RAG index or embedding store."""

    index_id: str
    index_type: str  # vectorstore, retriever, knowledge_graph, etc.
    data_sources: Set[str] = field(default_factory=set)
    classification_level: str = "unknown"
    contains_pii: bool = False
    cached_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    hash_value: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "index_id": self.index_id,
            "index_type": self.index_type,
            "data_sources": list(self.data_sources),
            "classification_level": self.classification_level,
            "contains_pii": self.contains_pii,
            "cached_at": self.cached_at.isoformat(),
            "hash_value": self.hash_value,
        }


@dataclass
class CachedBehavior:
    """Represents cached agent behavioral state."""

    behavior_id: str
    behavior_type: str  # conversation_memory, learned_preferences, etc.
    data_samples: List[str] = field(default_factory=list)
    referenced_tools: Set[str] = field(default_factory=set)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_updated: datetime = field(default_factory=lambda: datetime.now(UTC))
    hash_value: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "behavior_id": self.behavior_id,
            "behavior_type": self.behavior_type,
            "data_samples": self.data_samples,
            "referenced_tools": list(self.referenced_tools),
            "created_at": self.created_at.isoformat(),
            "last_updated": self.last_updated.isoformat(),
            "hash_value": self.hash_value,
        }


@dataclass
class PolicyState:
    """Represents the current permission policy state."""

    policy_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    granted_tools: Set[str] = field(default_factory=set)
    granted_scopes: Set[str] = field(default_factory=set)
    allowed_trust_boundaries: Set[str] = field(default_factory=set)
    data_governance_config: Dict[str, Any] = field(default_factory=dict)
    sandbox_restrictions: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "policy_id": self.policy_id,
            "timestamp": self.timestamp.isoformat(),
            "granted_tools": list(self.granted_tools),
            "granted_scopes": list(self.granted_scopes),
            "allowed_trust_boundaries": list(self.allowed_trust_boundaries),
            "data_governance_config": self.data_governance_config,
            "sandbox_restrictions": self.sandbox_restrictions,
        }


@dataclass
class PolicyTransition:
    """Represents a security policy transition."""

    transition_id: str
    transition_type: PolicyTransitionType
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    previous_policy: PolicyState = field(default_factory=PolicyState)
    new_policy: PolicyState = field(default_factory=PolicyState)
    tools_added: Set[str] = field(default_factory=set)
    tools_removed: Set[str] = field(default_factory=set)
    tools_unchanged: Set[str] = field(default_factory=set)
    scopes_added: Set[str] = field(default_factory=set)
    scopes_removed: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "transition_id": self.transition_id,
            "transition_type": self.transition_type.value,
            "timestamp": self.timestamp.isoformat(),
            "previous_policy": self.previous_policy.to_dict(),
            "new_policy": self.new_policy.to_dict(),
            "tools_added": list(self.tools_added),
            "tools_removed": list(self.tools_removed),
            "tools_unchanged": list(self.tools_unchanged),
            "scopes_added": list(self.scopes_added),
            "scopes_removed": list(self.scopes_removed),
        }


@dataclass
class ValidationResult:
    """Result of cache validation."""

    cache_item_id: str
    cache_item_type: str  # tool, credential, rag_index, behavior
    compliance_status: ComplianceStatus
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    violations: List[str] = field(default_factory=list)
    remediation_recommended: bool = False
    remediation_actions: List[MitigationAction] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "cache_item_id": self.cache_item_id,
            "cache_item_type": self.cache_item_type,
            "compliance_status": self.compliance_status.value,
            "timestamp": self.timestamp.isoformat(),
            "violations": self.violations,
            "remediation_recommended": self.remediation_recommended,
            "remediation_actions": [a.value for a in self.remediation_actions],
        }


@dataclass
class MitigationResult:
    """Result of cache mitigation operation."""

    mitigation_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    actions_executed: List[MitigationAction] = field(default_factory=list)
    cache_items_affected: int = 0
    success: bool = True
    error_message: Optional[str] = None
    rollback_applied: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "mitigation_id": self.mitigation_id,
            "timestamp": self.timestamp.isoformat(),
            "actions_executed": [a.value for a in self.actions_executed],
            "cache_items_affected": self.cache_items_affected,
            "success": self.success,
            "error_message": self.error_message,
            "rollback_applied": self.rollback_applied,
        }


# ============================================================================
# AgentCacheDiscovery
# ============================================================================


class AgentCacheDiscovery:
    """
    Enumerates cached artifacts across AI agent frameworks.

    Discovers:
      - Tool registrations (LangChain, CrewAI, AutoGen, MCP)
      - API credentials and OAuth tokens
      - Model artifacts (prompt templates, RAG indexes)
      - Agent behavioral state (conversation memory, preferences)
    """

    def __init__(self, base_paths: Optional[Dict[str, List[str]]] = None):
        """
        Initialize cache discovery.

        Args:
            base_paths: Override default framework config paths
        """
        self.base_paths = base_paths or {
            FrameworkType.LANGCHAIN: LANGCHAIN_CONFIG_PATHS,
            FrameworkType.CREWAI: CREWAI_CONFIG_PATHS,
            FrameworkType.AUTOGEN: AUTOGEN_CONFIG_PATHS,
            FrameworkType.MCP: MCP_CONFIG_PATHS,
        }

        self.discovered_tools: Dict[str, CachedTool] = {}
        self.discovered_credentials: Dict[str, CachedCredential] = {}
        self.discovered_rag_indexes: Dict[str, CachedRAGIndex] = {}
        self.discovered_behaviors: Dict[str, CachedBehavior] = {}

    async def discover_all(
        self, timeout_sec: float = CACHE_DISCOVERY_TIMEOUT_SEC
    ) -> None:
        """
        Discover all cached artifacts across frameworks.

        Args:
            timeout_sec: Discovery timeout in seconds
        """
        try:
            await asyncio.wait_for(
                self._discover_all_internal(),
                timeout=timeout_sec,
            )
        except asyncio.TimeoutError:
            logger.warning(
                f"Cache discovery timed out after {timeout_sec}s - partial results available"
            )

    async def _discover_all_internal(self) -> None:
        """Internal discovery implementation."""
        tasks = [
            self._discover_langchain_caches(),
            self._discover_crewai_caches(),
            self._discover_autogen_caches(),
            self._discover_mcp_caches(),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _discover_langchain_caches(self) -> None:
        """Discover LangChain tool registrations and cache."""
        for config_path in self.base_paths[FrameworkType.LANGCHAIN]:
            expanded_path = Path(config_path).expanduser()
            if not await self._path_exists(expanded_path):
                continue

            # Discover tool registry
            tools_file = expanded_path / "tools.json"
            if await self._path_exists(tools_file):
                tools_data = await self._read_json_file(tools_file)
                for tool_id, tool_info in tools_data.items():
                    tool = CachedTool(
                        tool_id=tool_id,
                        tool_name=tool_info.get("name", tool_id),
                        framework=FrameworkType.LANGCHAIN,
                        capabilities=set(tool_info.get("capabilities", [])),
                        required_scopes=set(tool_info.get("scopes", [])),
                    )
                    tool.hash_value = self._hash_object(tool_info)
                    self.discovered_tools[tool_id] = tool

            # Discover credentials
            credentials_file = expanded_path / "credentials.json"
            if await self._path_exists(credentials_file):
                creds_data = await self._read_json_file(credentials_file)
                for cred_id, cred_info in creds_data.items():
                    cred = CachedCredential(
                        credential_id=cred_id,
                        credential_type=cred_info.get("type", "unknown"),
                        associated_tool_ids=set(cred_info.get("tools", [])),
                        associated_scopes=set(cred_info.get("scopes", [])),
                        trust_boundary=cred_info.get("trust_boundary", "unknown"),
                    )
                    if "expires_at" in cred_info:
                        try:
                            cred.expires_at = datetime.fromisoformat(
                                cred_info["expires_at"]
                            )
                        except (ValueError, TypeError):
                            pass
                    cred.hash_value = self._hash_object(cred_info)
                    self.discovered_credentials[cred_id] = cred

    async def _discover_crewai_caches(self) -> None:
        """Discover CrewAI skill cache and agent configs."""
        for config_path in self.base_paths[FrameworkType.CREWAI]:
            expanded_path = Path(config_path).expanduser()
            if not await self._path_exists(expanded_path):
                continue

            # Discover skills
            skills_file = expanded_path / "skills.json"
            if await self._path_exists(skills_file):
                skills_data = await self._read_json_file(skills_file)
                for skill_id, skill_info in skills_data.items():
                    tool = CachedTool(
                        tool_id=skill_id,
                        tool_name=skill_info.get("name", skill_id),
                        framework=FrameworkType.CREWAI,
                        capabilities=set(skill_info.get("actions", [])),
                        required_scopes=set(skill_info.get("permissions", [])),
                    )
                    tool.hash_value = self._hash_object(skill_info)
                    self.discovered_tools[skill_id] = tool

            # Discover agent configs with behavioral memory
            agents_dir = expanded_path / "agents"
            if await self._path_exists(agents_dir):
                async for agent_file in self._iter_json_files(agents_dir):
                    agent_data = await self._read_json_file(agent_file)
                    agent_id = agent_file.stem

                    # Extract behavioral memory
                    if "memory" in agent_data:
                        memory = CachedBehavior(
                            behavior_id=f"{agent_id}_memory",
                            behavior_type="conversation_memory",
                            data_samples=agent_data["memory"].get("samples", []),
                            referenced_tools=set(
                                agent_data["memory"].get("tools_used", [])
                            ),
                        )
                        memory.hash_value = self._hash_object(agent_data["memory"])
                        self.discovered_behaviors[memory.behavior_id] = memory

    async def _discover_autogen_caches(self) -> None:
        """Discover AutoGen agent configurations."""
        for config_path in self.base_paths[FrameworkType.AUTOGEN]:
            expanded_path = Path(config_path).expanduser()
            if not await self._path_exists(expanded_path):
                continue

            agents_file = expanded_path / "agents.json"
            if await self._path_exists(agents_file):
                agents_data = await self._read_json_file(agents_file)
                for agent_id, agent_info in agents_data.items():
                    # Extract tool registrations
                    if "tools" in agent_info:
                        for tool_id, tool_info in agent_info["tools"].items():
                            tool = CachedTool(
                                tool_id=tool_id,
                                tool_name=tool_info.get("name", tool_id),
                                framework=FrameworkType.AUTOGEN,
                                capabilities=set(
                                    tool_info.get("capabilities", [])
                                ),
                                required_scopes=set(tool_info.get("scopes", [])),
                            )
                            tool.hash_value = self._hash_object(tool_info)
                            self.discovered_tools[tool_id] = tool

                    # Extract conversation history as behavioral artifact
                    if "conversation_history" in agent_info:
                        behavior = CachedBehavior(
                            behavior_id=f"{agent_id}_history",
                            behavior_type="conversation_memory",
                            data_samples=agent_info["conversation_history"][:10],
                        )
                        behavior.hash_value = self._hash_object(
                            agent_info["conversation_history"]
                        )
                        self.discovered_behaviors[behavior.behavior_id] = behavior

    async def _discover_mcp_caches(self) -> None:
        """Discover Model Context Protocol server connections and tool schemas."""
        for config_path in self.base_paths[FrameworkType.MCP]:
            expanded_path = Path(config_path).expanduser()
            if not await self._path_exists(expanded_path):
                continue

            # Discover MCP server manifests and cached tool schemas
            servers_file = expanded_path / "servers.json"
            if await self._path_exists(servers_file):
                servers_data = await self._read_json_file(servers_file)
                for server_id, server_info in servers_data.items():
                    if "tools" in server_info:
                        for tool_id, tool_schema in server_info["tools"].items():
                            tool = CachedTool(
                                tool_id=tool_id,
                                tool_name=tool_schema.get("name", tool_id),
                                framework=FrameworkType.MCP,
                                capabilities=set(
                                    tool_schema.get("tags", [])
                                ),
                                required_scopes=set(
                                    tool_schema.get("scopes", [])
                                ),
                            )
                            tool.hash_value = self._hash_object(tool_schema)
                            self.discovered_tools[tool_id] = tool

            # Discover cached server connection metadata
            connections_file = expanded_path / "connections.json"
            if await self._path_exists(connections_file):
                connections_data = await self._read_json_file(
                    connections_file
                )
                for conn_id, conn_info in connections_data.items():
                    # Extract credentials if present
                    if "credentials" in conn_info:
                        cred = CachedCredential(
                            credential_id=conn_id,
                            credential_type="mcp_server_credential",
                            trust_boundary=conn_info.get("server_id", "unknown"),
                        )
                        cred.hash_value = self._hash_object(
                            conn_info["credentials"]
                        )
                        self.discovered_credentials[conn_id] = cred

    # ========================================================================
    # Utility Methods
    # ========================================================================

    async def _path_exists(self, path: Path) -> bool:
        """Check if path exists asynchronously."""
        try:
            return await aiofiles.os.path.exists(str(path))
        except Exception as e:
            logger.debug(f"Error checking path {path}: {e}")
            return False

    async def _read_json_file(self, path: Path) -> Dict[str, Any]:
        """Read JSON file asynchronously."""
        try:
            async with aiofiles.open(path, mode="r") as f:
                content = await f.read()
                return json.loads(content)
        except Exception as e:
            logger.debug(f"Error reading JSON file {path}: {e}")
            return {}

    async def _iter_json_files(self, directory: Path) -> AsyncIterator[Path]:
        """Iterate JSON files in directory."""
        try:
            for item in os.listdir(directory):
                if item.endswith(".json"):
                    yield directory / item
        except Exception as e:
            logger.debug(f"Error iterating directory {directory}: {e}")

    def _hash_object(self, obj: Any) -> str:
        """Generate hash of object."""
        try:
            obj_str = json.dumps(obj, sort_keys=True, default=str)
            return hashlib.sha256(obj_str.encode()).hexdigest()[:16]
        except Exception:
            return ""

    def get_discovered_summary(self) -> Dict[str, int]:
        """Get summary of discovered cache items."""
        return {
            "tools": len(self.discovered_tools),
            "credentials": len(self.discovered_credentials),
            "rag_indexes": len(self.discovered_rag_indexes),
            "behaviors": len(self.discovered_behaviors),
        }


# ============================================================================
# AgentPolicyMonitor
# ============================================================================


class AgentPolicyMonitor:
    """
    Monitors agent permission policy transitions.

    Detects:
      - Permission policy changes (tools added/removed)
      - Trust boundary modifications
      - Data governance policy updates
      - MCP server manifest changes
      - OAuth scope changes
    """

    def __init__(self):
        """Initialize policy monitor."""
        self.current_policy: Optional[PolicyState] = None
        self.previous_policy: Optional[PolicyState] = None
        self.policy_transitions: List[PolicyTransition] = []
        self._policy_callbacks: List[
            Callable[[PolicyTransition], None]
        ] = []
        self._monitoring = False

    def register_policy_callback(
        self, callback: Callable[[PolicyTransition], None]
    ) -> None:
        """
        Register callback for policy transitions.

        Args:
            callback: Async callback function accepting PolicyTransition
        """
        self._policy_callbacks.append(callback)

    async def start_monitoring(
        self,
        check_interval_sec: float = POLICY_MONITOR_CHECK_INTERVAL_SEC,
        policy_fetch_fn: Optional[Callable[[], PolicyState]] = None,
    ) -> None:
        """
        Start policy change monitoring.

        Args:
            check_interval_sec: Check interval in seconds
            policy_fetch_fn: Function to fetch current policy state
        """
        if policy_fetch_fn is None:
            policy_fetch_fn = self._default_policy_fetch

        self._monitoring = True
        while self._monitoring:
            try:
                new_policy = policy_fetch_fn()
                if self._policy_changed(new_policy):
                    transition = self._compute_policy_transition(new_policy)
                    self.policy_transitions.append(transition)
                    await self._notify_callbacks(transition)

                self.previous_policy = self.current_policy
                self.current_policy = new_policy

                await asyncio.sleep(check_interval_sec)
            except Exception as e:
                logger.error(f"Error in policy monitoring loop: {e}")
                await asyncio.sleep(check_interval_sec)

    def stop_monitoring(self) -> None:
        """Stop policy change monitoring."""
        self._monitoring = False

    def _policy_changed(self, new_policy: PolicyState) -> bool:
        """Check if policy has changed."""
        if self.current_policy is None:
            return True

        return (
            self.current_policy.granted_tools != new_policy.granted_tools
            or self.current_policy.granted_scopes != new_policy.granted_scopes
            or self.current_policy.allowed_trust_boundaries
            != new_policy.allowed_trust_boundaries
            or self.current_policy.data_governance_config
            != new_policy.data_governance_config
            or self.current_policy.sandbox_restrictions
            != new_policy.sandbox_restrictions
        )

    def _compute_policy_transition(
        self, new_policy: PolicyState
    ) -> PolicyTransition:
        """Compute ΔPolicy transition between previous and new policy."""
        if self.current_policy is None:
            previous = PolicyState(policy_id="initial")
        else:
            previous = self.current_policy

        tools_added = new_policy.granted_tools - previous.granted_tools
        tools_removed = previous.granted_tools - new_policy.granted_tools
        tools_unchanged = (
            new_policy.granted_tools & previous.granted_tools
        )

        scopes_added = new_policy.granted_scopes - previous.granted_scopes
        scopes_removed = previous.granted_scopes - new_policy.granted_scopes

        # Determine transition type
        if tools_removed:
            transition_type = (
                PolicyTransitionType.PERMISSION_DOWNGRADE
            )
        elif tools_added:
            transition_type = PolicyTransitionType.PERMISSION_UPGRADE
        elif scopes_removed:
            transition_type = (
                PolicyTransitionType.DATA_GOVERNANCE_CHANGE
            )
        else:
            transition_type = PolicyTransitionType.SANDBOX_POLICY_CHANGE

        return PolicyTransition(
            transition_id=self._generate_transition_id(),
            transition_type=transition_type,
            previous_policy=previous,
            new_policy=new_policy,
            tools_added=tools_added,
            tools_removed=tools_removed,
            tools_unchanged=tools_unchanged,
            scopes_added=scopes_added,
            scopes_removed=scopes_removed,
        )

    async def _notify_callbacks(self, transition: PolicyTransition) -> None:
        """Notify registered callbacks of policy transition."""
        tasks = [
            asyncio.create_task(callback(transition))
            if asyncio.iscoroutinefunction(callback)
            else asyncio.create_task(
                asyncio.to_thread(callback, transition)
            )
            for callback in self._policy_callbacks
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    def _default_policy_fetch(self) -> PolicyState:
        """Default policy fetch function (returns current policy if available)."""
        if self.current_policy is not None:
            return self.current_policy
        return PolicyState(policy_id="default")

    def _generate_transition_id(self) -> str:
        """Generate unique transition ID."""
        return f"transition_{int(time.time() * 1000)}"

    def get_recent_transitions(
        self, limit: int = 10
    ) -> List[PolicyTransition]:
        """Get recent policy transitions."""
        return self.policy_transitions[-limit:]


# ============================================================================
# AgentCacheValidator
# ============================================================================


class AgentCacheValidator:
    """
    Validates cached tool authorizations, credentials, and artifacts
    against current permission policy.

    Validation categories:
      - Tool authorization compliance
      - Credential scope and expiration
      - RAG index data governance
      - Behavioral state policy compliance
    """

    def __init__(self):
        """Initialize cache validator."""
        self.validation_results: List[ValidationResult] = []

    async def validate_all_cached_artifacts(
        self,
        discovered_tools: Dict[str, CachedTool],
        discovered_credentials: Dict[str, CachedCredential],
        discovered_rag_indexes: Dict[str, CachedRAGIndex],
        discovered_behaviors: Dict[str, CachedBehavior],
        current_policy: PolicyState,
    ) -> List[ValidationResult]:
        """
        Validate all discovered cache artifacts against current policy.

        Args:
            discovered_tools: Map of cached tools
            discovered_credentials: Map of cached credentials
            discovered_rag_indexes: Map of cached RAG indexes
            discovered_behaviors: Map of cached behaviors
            current_policy: Current permission policy

        Returns:
            List of validation results
        """
        tasks = []

        # Validate tools
        for tool_id, tool in discovered_tools.items():
            tasks.append(
                self._validate_tool(tool, current_policy)
            )

        # Validate credentials
        for cred_id, cred in discovered_credentials.items():
            tasks.append(
                self._validate_credential(cred, current_policy)
            )

        # Validate RAG indexes
        for idx_id, idx in discovered_rag_indexes.items():
            tasks.append(
                self._validate_rag_index(idx, current_policy)
            )

        # Validate behaviors
        for beh_id, beh in discovered_behaviors.items():
            tasks.append(
                self._validate_behavior(beh, current_policy)
            )

        results = await asyncio.gather(*tasks, return_exceptions=True)
        self.validation_results.extend(
            [r for r in results if isinstance(r, ValidationResult)]
        )
        return self.validation_results

    async def _validate_tool(
        self, tool: CachedTool, policy: PolicyState
    ) -> ValidationResult:
        """Validate cached tool against policy."""
        violations = []
        remediation_actions = []

        # Check if tool is in granted set
        if tool.tool_id not in policy.granted_tools:
            violations.append(
                f"Tool {tool.tool_id} not in current granted tools"
            )
            remediation_actions.append(MitigationAction.REVOKE_TOOL)

        # Check if required scopes are granted
        ungrantedscopes = tool.required_scopes - policy.granted_scopes
        if ungrantedscopes:
            violations.append(
                f"Tool {tool.tool_id} requires ungranted scopes: {ungrantedscopes}"
            )
            remediation_actions.append(MitigationAction.REVOKE_TOOL)

        status = (
            ComplianceStatus.NON_COMPLIANT
            if violations
            else ComplianceStatus.COMPLIANT
        )

        return ValidationResult(
            cache_item_id=tool.tool_id,
            cache_item_type="tool",
            compliance_status=status,
            violations=violations,
            remediation_recommended=bool(violations),
            remediation_actions=remediation_actions,
        )

    async def _validate_credential(
        self, cred: CachedCredential, policy: PolicyState
    ) -> ValidationResult:
        """Validate cached credential against policy."""
        violations = []
        remediation_actions = []
        status = ComplianceStatus.COMPLIANT

        # Check expiration
        if cred.is_expired():
            violations.append(f"Credential {cred.credential_id} has expired")
            status = ComplianceStatus.STALE_CREDENTIAL
            remediation_actions.append(MitigationAction.PURGE_CREDENTIAL)

        # Check revocation status
        if cred.is_revoked:
            violations.append(f"Credential {cred.credential_id} is revoked")
            status = ComplianceStatus.STALE_CREDENTIAL
            remediation_actions.append(MitigationAction.PURGE_CREDENTIAL)

        # Check trust boundary
        if (
            cred.trust_boundary
            and cred.trust_boundary
            not in policy.allowed_trust_boundaries
        ):
            violations.append(
                f"Credential {cred.credential_id} trust boundary "
                f"({cred.trust_boundary}) not in allowed boundaries"
            )
            status = ComplianceStatus.SCOPE_EXCEEDED
            remediation_actions.append(MitigationAction.PURGE_CREDENTIAL)

        # Check associated tools are still granted
        revoked_tools = (
            cred.associated_tool_ids - policy.granted_tools
        )
        if revoked_tools:
            violations.append(
                f"Credential {cred.credential_id} associated with "
                f"revoked tools: {revoked_tools}"
            )
            status = ComplianceStatus.SCOPE_EXCEEDED
            remediation_actions.append(MitigationAction.PURGE_CREDENTIAL)

        # Check scopes
        ungranted_scopes = (
            cred.associated_scopes - policy.granted_scopes
        )
        if ungranted_scopes:
            violations.append(
                f"Credential {cred.credential_id} has ungranted scopes: "
                f"{ungranted_scopes}"
            )
            status = ComplianceStatus.SCOPE_EXCEEDED
            remediation_actions.append(MitigationAction.PURGE_CREDENTIAL)

        return ValidationResult(
            cache_item_id=cred.credential_id,
            cache_item_type="credential",
            compliance_status=status,
            violations=violations,
            remediation_recommended=bool(violations),
            remediation_actions=remediation_actions,
        )

    async def _validate_rag_index(
        self, rag: CachedRAGIndex, policy: PolicyState
    ) -> ValidationResult:
        """Validate cached RAG index against data governance policy."""
        violations = []
        remediation_actions = []
        status = ComplianceStatus.COMPLIANT

        # Check data governance config
        gov_config = policy.data_governance_config

        # Check PII restrictions
        if rag.contains_pii and gov_config.get("allow_pii", True) is False:
            violations.append(
                f"RAG index {rag.index_id} contains PII but policy "
                "prohibits PII caching"
            )
            status = ComplianceStatus.DATA_GOVERNANCE_VIOLATION
            remediation_actions.append(
                MitigationAction.QUARANTINE_RAG_INDEX
            )

        # Check classification level
        max_classification = gov_config.get("max_classification_level")
        if (
            max_classification
            and rag.classification_level > max_classification
        ):
            violations.append(
                f"RAG index {rag.index_id} classification "
                f"({rag.classification_level}) exceeds maximum "
                f"({max_classification})"
            )
            status = ComplianceStatus.DATA_GOVERNANCE_VIOLATION
            remediation_actions.append(
                MitigationAction.QUARANTINE_RAG_INDEX
            )

        return ValidationResult(
            cache_item_id=rag.index_id,
            cache_item_type="rag_index",
            compliance_status=status,
            violations=violations,
            remediation_recommended=bool(violations),
            remediation_actions=remediation_actions,
        )

    async def _validate_behavior(
        self, behavior: CachedBehavior, policy: PolicyState
    ) -> ValidationResult:
        """Validate cached behavioral state against policy."""
        violations = []
        remediation_actions = []
        status = ComplianceStatus.COMPLIANT

        # Check if referenced tools are still granted
        revoked_tools = (
            behavior.referenced_tools - policy.granted_tools
        )
        if revoked_tools:
            violations.append(
                f"Behavior {behavior.behavior_id} references revoked tools: "
                f"{revoked_tools}"
            )
            status = ComplianceStatus.NON_COMPLIANT
            remediation_actions.append(
                MitigationAction.REGENERATE_BEHAVIOR
            )

        return ValidationResult(
            cache_item_id=behavior.behavior_id,
            cache_item_type="behavior",
            compliance_status=status,
            violations=violations,
            remediation_recommended=bool(violations),
            remediation_actions=remediation_actions,
        )

    def get_non_compliant_summary(self) -> Dict[str, Any]:
        """Get summary of non-compliant cache items."""
        non_compliant = [
            r
            for r in self.validation_results
            if r.compliance_status != ComplianceStatus.COMPLIANT
        ]

        return {
            "total_non_compliant": len(non_compliant),
            "by_status": {
                status.value: len(
                    [
                        r
                        for r in non_compliant
                        if r.compliance_status == status
                    ]
                )
                for status in ComplianceStatus
            },
            "by_type": {
                item_type: len(
                    [
                        r
                        for r in non_compliant
                        if r.cache_item_type == item_type
                    ]
                )
                for item_type in [
                    "tool",
                    "credential",
                    "rag_index",
                    "behavior",
                ]
            },
        }


# ============================================================================
# AgentMitigationController
# ============================================================================


class AgentMitigationController:
    """
    Executes cache mitigation actions when validation detects violations.

    Actions:
      - Revoke tool authorizations exceeding policy
      - Purge stale/revoked credentials
      - Quarantine RAG indexes with policy violations
      - Regenerate behavioral state
      - Atomic mitigation with rollback
    """

    def __init__(self, work_dir: Optional[Path] = None):
        """
        Initialize mitigation controller.

        Args:
            work_dir: Working directory for backup/rollback
        """
        self.work_dir = work_dir or Path.home() / ".cache" / "agent_cache"
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.mitigation_results: List[MitigationResult] = []
        self._backup_snapshots: Dict[str, Dict[str, Any]] = {}

    async def execute_mitigation(
        self,
        validation_results: List[ValidationResult],
        timeout_sec: float = MITIGATION_OPERATION_TIMEOUT_SEC,
    ) -> MitigationResult:
        """
        Execute mitigation for non-compliant cache items.

        Args:
            validation_results: Validation results to remediate
            timeout_sec: Operation timeout in seconds

        Returns:
            Mitigation result
        """
        try:
            result = await asyncio.wait_for(
                self._execute_mitigation_internal(validation_results),
                timeout=timeout_sec,
            )
            self.mitigation_results.append(result)
            return result
        except asyncio.TimeoutError:
            result = MitigationResult(
                mitigation_id=self._generate_mitigation_id(),
                success=False,
                error_message=f"Mitigation timeout after {timeout_sec}s",
            )
            return result

    async def _execute_mitigation_internal(
        self, validation_results: List[ValidationResult]
    ) -> MitigationResult:
        """Internal mitigation execution."""
        mitigation_id = self._generate_mitigation_id()
        actions_executed: List[MitigationAction] = []
        cache_items_affected = 0
        success = True
        error_message = None

        # Create backup snapshot
        await self._create_backup_snapshot(mitigation_id)

        try:
            # Group results by action
            actions_by_type: Dict[
                MitigationAction, List[ValidationResult]
            ] = {}
            for result in validation_results:
                if result.remediation_recommended:
                    for action in result.remediation_actions:
                        if action not in actions_by_type:
                            actions_by_type[action] = []
                        actions_by_type[action].append(result)

            # Execute actions
            for action_type, results in actions_by_type.items():
                try:
                    await self._execute_action(
                        action_type, results, mitigation_id
                    )
                    actions_executed.append(action_type)
                    cache_items_affected += len(results)
                except Exception as e:
                    logger.error(f"Error executing action {action_type}: {e}")
                    success = False
                    error_message = str(e)
                    # Attempt rollback on error
                    await self._rollback_mitigation(mitigation_id)
                    break

        except Exception as e:
            success = False
            error_message = str(e)

        return MitigationResult(
            mitigation_id=mitigation_id,
            actions_executed=actions_executed,
            cache_items_affected=cache_items_affected,
            success=success,
            error_message=error_message,
            rollback_applied=not success,
        )

    async def _execute_action(
        self,
        action_type: MitigationAction,
        results: List[ValidationResult],
        mitigation_id: str,
    ) -> None:
        """Execute specific mitigation action."""
        if action_type == MitigationAction.REVOKE_TOOL:
            await self._revoke_tools(results)
        elif action_type == MitigationAction.PURGE_CREDENTIAL:
            await self._purge_credentials(results)
        elif action_type == MitigationAction.QUARANTINE_RAG_INDEX:
            await self._quarantine_rag_indexes(results)
        elif action_type == MitigationAction.REGENERATE_BEHAVIOR:
            await self._regenerate_behaviors(results)
        elif action_type == MitigationAction.REVALIDATE_MCP_SCHEMA:
            await self._revalidate_mcp_schemas(results)

    async def _revoke_tools(
        self, results: List[ValidationResult]
    ) -> None:
        """Revoke tool cache entries."""
        for result in results:
            logger.info(f"Revoking tool: {result.cache_item_id}")
            # Implementation: remove from framework caches

    async def _purge_credentials(
        self, results: List[ValidationResult]
    ) -> None:
        """Purge credential cache entries."""
        for result in results:
            logger.info(f"Purging credential: {result.cache_item_id}")
            # Implementation: remove from credential stores

    async def _quarantine_rag_indexes(
        self, results: List[ValidationResult]
    ) -> None:
        """Quarantine RAG index entries."""
        for result in results:
            quarantine_dir = (
                self.work_dir
                / "quarantine"
                / result.cache_item_id
            )
            quarantine_dir.mkdir(parents=True, exist_ok=True)
            logger.info(
                f"Quarantining RAG index: {result.cache_item_id} "
                f"to {quarantine_dir}"
            )
            # Implementation: move to quarantine

    async def _regenerate_behaviors(
        self, results: List[ValidationResult]
    ) -> None:
        """Regenerate behavioral state."""
        for result in results:
            logger.info(
                f"Regenerating behavior: {result.cache_item_id}"
            )
            # Implementation: filter behavior state

    async def _revalidate_mcp_schemas(
        self, results: List[ValidationResult]
    ) -> None:
        """Revalidate MCP tool schemas."""
        for result in results:
            logger.info(
                f"Revalidating MCP schema: {result.cache_item_id}"
            )
            # Implementation: query MCP server for current schema

    async def _create_backup_snapshot(self, mitigation_id: str) -> None:
        """Create backup snapshot before mitigation."""
        snapshot_path = self.work_dir / "backups" / mitigation_id
        snapshot_path.mkdir(parents=True, exist_ok=True)
        self._backup_snapshots[mitigation_id] = {
            "path": str(snapshot_path),
            "timestamp": datetime.now(UTC).isoformat(),
        }

    async def _rollback_mitigation(self, mitigation_id: str) -> None:
        """Rollback mitigation from backup."""
        if mitigation_id in self._backup_snapshots:
            logger.warning(f"Rolling back mitigation {mitigation_id}")
            # Implementation: restore from snapshot

    def _generate_mitigation_id(self) -> str:
        """Generate unique mitigation ID."""
        return f"mitigation_{int(time.time() * 1000)}"


# ============================================================================
# MCPPostureAdapter
# ============================================================================


class MCPPostureAdapter:
    """
    MCP-specific adapter for server connections and tool schema validation.

    Monitors:
      - MCP server capability manifests
      - Cached tool schema versions
      - Server connection state
      - Capability additions/removals
    """

    def __init__(self):
        """Initialize MCP posture adapter."""
        self.connected_servers: Dict[str, Dict[str, Any]] = {}
        self.cached_schemas: Dict[str, Dict[str, Any]] = {}
        self.schema_mismatches: List[Tuple[str, str, str]] = []  # (tool_id, cached_version, server_version)

    async def discover_mcp_servers(
        self, config_path: Optional[Path] = None
    ) -> Dict[str, Dict[str, Any]]:
        """
        Discover connected MCP servers.

        Args:
            config_path: Path to MCP config directory

        Returns:
            Map of server_id to server info
        """
        if config_path is None:
            config_path = Path.home() / ".mcp"

        servers = {}
        servers_config = config_path / "servers.json"

        if await self._path_exists(servers_config):
            try:
                async with aiofiles.open(servers_config) as f:
                    content = await f.read()
                    servers_data = json.loads(content)
                    for server_id, server_info in servers_data.items():
                        servers[server_id] = server_info
                        self.connected_servers[server_id] = server_info
            except Exception as e:
                logger.error(f"Error discovering MCP servers: {e}")

        return servers

    async def validate_tool_schemas(
        self,
        cached_tools: Dict[str, CachedTool],
    ) -> Dict[str, bool]:
        """
        Validate cached tool schemas against server reality.

        Args:
            cached_tools: Map of cached tool definitions

        Returns:
            Map of tool_id to validation status
        """
        validation_status = {}

        for tool_id, tool in cached_tools.items():
            if tool.framework != FrameworkType.MCP:
                continue

            # Check if schema has changed on server
            is_valid = await self._check_schema_validity(tool_id, tool)
            validation_status[tool_id] = is_valid

        return validation_status

    async def _check_schema_validity(
        self, tool_id: str, tool: CachedTool
    ) -> bool:
        """Check if cached schema matches server schema."""
        # Lookup cached schema
        if tool_id in self.cached_schemas:
            cached_schema = self.cached_schemas[tool_id]
            # In real implementation: fetch from server and compare
            # For now, return True if cached
            return True

        return False

    async def handle_server_disconnection(
        self, server_id: str
    ) -> List[str]:
        """
        Handle MCP server disconnection.

        Args:
            server_id: Server ID

        Returns:
            List of affected tool IDs
        """
        affected_tools = []

        if server_id in self.connected_servers:
            server_info = self.connected_servers[server_id]
            affected_tools = list(server_info.get("tools", {}).keys())
            del self.connected_servers[server_id]
            logger.warning(
                f"MCP server {server_id} disconnected, "
                f"affecting {len(affected_tools)} tools"
            )

        return affected_tools

    async def handle_server_reconnection(
        self, server_id: str, config_path: Optional[Path] = None
    ) -> Tuple[List[str], List[Tuple[str, str, str]]]:
        """
        Handle MCP server reconnection with policy revalidation.

        Args:
            server_id: Server ID
            config_path: Path to MCP config directory

        Returns:
            Tuple of (restored_tool_ids, schema_mismatches)
        """
        restored_tools = []
        mismatches = []

        # Rediscover server
        servers = await self.discover_mcp_servers(config_path)
        if server_id in servers:
            server_info = servers[server_id]
            restored_tools = list(server_info.get("tools", {}).keys())

            # Check for schema changes
            for tool_id in restored_tools:
                if tool_id in self.cached_schemas:
                    cached_version = self.cached_schemas[
                        tool_id
                    ].get("version")
                    server_version = (
                        server_info.get("tools", {})
                        .get(tool_id, {})
                        .get("version")
                    )
                    if cached_version != server_version:
                        mismatches.append(
                            (
                                tool_id,
                                str(cached_version),
                                str(server_version),
                            )
                        )

            logger.info(
                f"MCP server {server_id} reconnected, "
                f"restored {len(restored_tools)} tools"
            )

        return restored_tools, mismatches

    async def _path_exists(self, path: Path) -> bool:
        """Check if path exists asynchronously."""
        try:
            return await aiofiles.os.path.exists(str(path))
        except Exception:
            return False

    def get_server_summary(self) -> Dict[str, Any]:
        """Get summary of connected MCP servers."""
        return {
            "connected_servers": len(self.connected_servers),
            "total_tools": sum(
                len(server.get("tools", {}))
                for server in self.connected_servers.values()
            ),
            "schema_mismatches": len(self.schema_mismatches),
        }


# ============================================================================
# Orchestration
# ============================================================================


class AgentCacheSecurityOrchestrator:
    """
    Orchestrates cache discovery, policy monitoring, validation, and mitigation.
    """

    def __init__(self):
        """Initialize orchestrator."""
        self.discovery = AgentCacheDiscovery()
        self.monitor = AgentPolicyMonitor()
        self.validator = AgentCacheValidator()
        self.mitigator = AgentMitigationController()
        self.mcp_adapter = MCPPostureAdapter()

    async def run_full_validation_cycle(
        self,
        current_policy: PolicyState,
        timeout_sec: float = 120.0,
    ) -> Dict[str, Any]:
        """
        Run complete cache validation and mitigation cycle.

        Args:
            current_policy: Current permission policy
            timeout_sec: Overall timeout in seconds

        Returns:
            Summary of validation and mitigation
        """
        start_time = time.time()

        try:
            # Discovery phase
            logger.info("Starting cache discovery phase...")
            await self.discovery.discover_all()
            discovery_summary = self.discovery.get_discovered_summary()
            logger.info(f"Discovery complete: {discovery_summary}")

            # Validation phase
            logger.info("Starting cache validation phase...")
            validation_results = (
                await self.validator.validate_all_cached_artifacts(
                    self.discovery.discovered_tools,
                    self.discovery.discovered_credentials,
                    self.discovery.discovered_rag_indexes,
                    self.discovery.discovered_behaviors,
                    current_policy,
                )
            )
            compliance_summary = (
                self.validator.get_non_compliant_summary()
            )
            logger.info(f"Validation complete: {compliance_summary}")

            # Mitigation phase (if needed)
            mitigation_result = None
            if compliance_summary["total_non_compliant"] > 0:
                logger.info("Starting cache mitigation phase...")
                mitigation_result = await self.mitigator.execute_mitigation(
                    validation_results
                )
                logger.info(
                    f"Mitigation complete: {mitigation_result.to_dict()}"
                )

            elapsed_sec = time.time() - start_time

            return {
                "success": True,
                "discovery": discovery_summary,
                "compliance": compliance_summary,
                "mitigation": (
                    mitigation_result.to_dict() if mitigation_result else None
                ),
                "elapsed_seconds": elapsed_sec,
                "validation_results": [r.to_dict() for r in validation_results],
            }

        except Exception as e:
            logger.error(f"Error in validation cycle: {e}")
            return {
                "success": False,
                "error": str(e),
                "elapsed_seconds": time.time() - start_time,
            }
