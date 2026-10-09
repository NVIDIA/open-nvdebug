# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Target-owned lifecycle supervision for opt-in Host commands.

An SSH channel timeout is not proof that a remote process stopped. This module
installs a target-side deadline and supports two explicit cleanup scopes. The
legacy ``process_group`` scope wraps a foreground, non-daemonizing command in a
pinned session. The opt-in ``cgroup_v2`` scope creates an exclusive token-bound
leaf beneath a trusted ancestor, migrates the target supervisor before identity
or payload launch, and treats ``cgroup.kill``, repeated ``populated 0`` evidence,
and exact leaf removal as authoritative cleanup. A caller may therefore
distinguish a proved target timeout from an indeterminate transport failure.
After that proof, an explicit caller may request the same bounded artifact-tree
preparation used on success so timeout-left bytes can be collected as diagnostic
evidence without changing the timeout outcome.

Only a receipt delivered by the original primary wrapper is authoritative for
artifact cleanup or timeout fallback. Reconciliation is cleanup-only: it may
stop the exact owned cleanup scope and best-effort discard private children,
but without proof that the outer wrapper exited it retains the token-bound
launch tombstone and always reports cleanup as unverified.

This utility is deliberately opt-in. Existing Host command execution and the
managed-command default retain process-group behavior until governed collector
policy explicitly selects cgroup v2. Capability or setup failure in that mode
occurs before payload launch and never falls back to process-group cleanup.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import math
import posixpath
import re
import secrets
import shlex
from dataclasses import dataclass, field
from enum import Enum
from typing import Awaitable, Optional, Protocol, TypeAlias

RemoteCommandResult: TypeAlias = tuple[int, str, str]


class ManagedRemoteExecutor(Protocol):
    """
    One injected Host command transport.

    ``max_retries=1`` means one total transport attempt in DUTManager's Host SSH
    APIs. Managed payloads must never be replayed implicitly.
    """

    def __call__(
        self,
        command: str,
        *,
        timeout: float,
        max_retries: int,
    ) -> Awaitable[RemoteCommandResult]:
        """
        Apply the ManagedRemoteExecutor operation to the supplied input.

        The implementation uses ``command``, ``timeout``, and ``max_retries`` to
        apply the ManagedRemoteExecutor operation to the supplied input.

        Args:
            command: Text supplied as command in the format accepted by this
                function.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            max_retries: Upper bound enforced for max retries; the consuming
                boundary rejects or truncates values that exceed it.

        Returns:
            An awaitable yielding the remote-command result from the configured
            runner.
        """
        ...


class ManagedHostCommandOutcome(str, Enum):
    """
    Terminal disposition of one managed target command.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    SUCCESS = "success"
    TARGET_TIMEOUT = "target_timeout"
    NONZERO_EXIT = "nonzero_exit"
    CLEANUP_UNVERIFIED = "cleanup_unverified"
    TRANSPORT_ERROR = "transport_error"


class ManagedHostCleanupScope(str, Enum):
    """
    Kernel ownership primitive used for cleanup.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    PROCESS_GROUP = "process_group"
    CGROUP_V2 = "cgroup_v2"


class ManagedHostCleanupStatus(str, Enum):
    """
    Bounded cleanup evidence.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    VERIFIED_ABSENT = "verified_absent"
    FAILED = "failed"
    UNVERIFIED = "unverified"


@dataclass(frozen=True, slots=True)
class ManagedHostCommandCleanup:
    """
    Sanitized cleanup receipt suitable for policy mapping.

    The immutable record keeps ``scope`` and ``status`` together so consumers
    observe one managed host command cleanup state. Consumers receive the fields
    as one unit instead of assembling partial state.

    Attributes:
        scope: Scope retained as part of the record's public state.
        status: Canonical status exposed to downstream status consumers.
    """

    scope: ManagedHostCleanupScope = ManagedHostCleanupScope.PROCESS_GROUP
    status: ManagedHostCleanupStatus = ManagedHostCleanupStatus.UNVERIFIED


@dataclass(frozen=True, slots=True)
class ManagedHostCommandResult:
    """
    Bounded result with runtime-only artifact and diagnostic data.

    The artifact directory and captured target streams are intentionally omitted
    from ``repr`` so exception/log rendering cannot disclose remote paths or
    collected data. The run token, control path, PID, PGID, and session ID are
    never exposed by this public type.

    Attributes:
        outcome: Outcome retained as part of the record's public state.
        cleanup: Cleanup retained as part of the record's public state.
        target_exit_code: Numeric target exit code retained by this record.
        artifact_dir: Canonical text used as artifact dir.
        target_stdout: Canonical text used as target stdout.
        target_stderr: Canonical text used as target stderr.
        stdout_truncated: Whether stdout truncated applies to this record.
        stderr_truncated: Whether stderr truncated applies to this record.
        primary_deadline_exceeded: Whether the injected executor exhausted its
            caller-side deadline before delivering an authoritative receipt.
            This does not prove that the target command stopped; ``cleanup``
            remains the authoritative target-lifecycle evidence.
    """

    outcome: ManagedHostCommandOutcome
    cleanup: ManagedHostCommandCleanup
    target_exit_code: Optional[int] = None
    artifact_dir: str = field(default="", repr=False)
    target_stdout: str = field(default="", repr=False)
    target_stderr: str = field(default="", repr=False)
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    primary_deadline_exceeded: bool = False


class ManagedHostCommandConfigurationError(ValueError):
    """
    A managed-command input violated the fail-closed contract.

    Callers receive this exception when the managed host command configuration
    error invariant prevents the requested operation from completing. The
    distinct type lets them handle that boundary without parsing an error
    message.
    """


class ManagedRemoteExecutorTimeout(TimeoutError):
    """
    Signal that the injected executor exhausted its caller-side deadline.

    Host adapters raise this sanitized marker only after their own typed or
    exact-contract timeout result has been captured. The managed wrapper uses
    it to retain the primary cause across fail-closed reconciliation without
    treating transport expiry as proof that the target process stopped.
    """


class _ReceiptError(ValueError):
    """
    Internal marker for absent or malformed target receipts.

    Callers receive this exception when the receipt error invariant prevents the
    requested operation from completing. The distinct type lets them handle that
    boundary without parsing an error message.
    """


_TOKEN_RE = re.compile(r"\A[a-f0-9]{64}\Z")
_ROOT_RE = re.compile(r"\A/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\Z")
_RECEIPT_BEGIN = "NVDEBUG_MANAGED_COMMAND_V1"
_RECEIPT_END = "NVDEBUG_MANAGED_COMMAND_END"
_MAX_COMMAND_BYTES = 8192
_MAX_REMOTE_COMMAND_BYTES = 120 * 1024
_REMOTE_COMMAND_WRAPPER_OVERHEAD_BYTES = 512
_MAX_OUTPUT_LIMIT_BYTES = 64 * 1024
_MAX_ARTIFACT_DEPTH = 4
_MAX_ARTIFACT_ENTRIES = 256
_MAX_CGROUP_PATH_BYTES = 1024
_MAX_CGROUP_MEMBERSHIP_BYTES = 4096
_MAX_CGROUP_EVENT_BYTES = 1024
_MAX_CGROUP_CHILDREN = 64
_MAX_CGROUP_DEPTH = 8
# A system above this visible /proc inventory cannot provide bounded cleanup
# evidence within the managed-command budget, so the scan fails closed.
_MAX_SESSION_SCAN_PROCESSES = 32_768
_PRIMARY_ATTEMPTS = 1
# Reconciliation can wait this long for the target-side identity handshake
# before it must stop an exact pre-identity child.
MANAGED_IDENTITY_READINESS_GRACE_SECONDS = 5
# The deadline owner can spend one second waiting for capture EOF, followed by
# one second after TERM and one second after KILL.  Keep this visible to policy
# binders that must reserve enough time for bounded reconciliation evidence.
MANAGED_CLEANUP_VERIFICATION_GRACE_SECONDS = 3
_OWNED_DETACHED_TASKS: set[asyncio.Task] = set()


_CGROUP_V2_COMMON_SCRIPT = r"""
cgroup_root=/sys/fs/cgroup
cgroup_plan="$control_dir/cgroup_plan"
cgroup_identity="$control_dir/cgroup_identity"
cgroup_child_manifest="$control_dir/cgroup_children.$$"
cgroup_child_count="$control_dir/cgroup_child_count.$$"
cgroup_child_error="$control_dir/cgroup_child_error.$$"

bounded_unified_membership() {
  membership_file=$1
  [ -f "$membership_file" ] && [ ! -L "$membership_file" ] || return 1
  membership_bytes=$(wc -c < "$membership_file" 2>/dev/null) || return 1
  is_uint "$membership_bytes" &&
    [ "$membership_bytes" -le __MAX_CGROUP_MEMBERSHIP_BYTES__ ] || return 1
  membership_count=0
  membership_path=
  while IFS= read -r membership_line || [ -n "$membership_line" ]; do
    membership_count=$((membership_count + 1))
    [ "$membership_count" -le 16 ] || return 1
    case "$membership_line" in
      0::*)
        [ -z "$membership_path" ] || return 1
        membership_path=${membership_line#0::}
        ;;
      *) return 1 ;;
    esac
  done < "$membership_file"
  [ "$membership_count" -eq 1 ] && validate_cgroup_relative_path "$membership_path"
}

validate_cgroup_relative_path() {
  candidate_path=$1
  candidate_length=${#candidate_path}
  [ "$candidate_length" -ge 1 ] &&
    [ "$candidate_length" -le __MAX_CGROUP_PATH_BYTES__ ] || return 1
  case "$candidate_path" in
    /*) ;;
    *) return 1 ;;
  esac
  [ "$candidate_path" = / ] && return 0
  if [ "$candidate_path" != / ]; then
    case "$candidate_path/" in
      *//*|*/./*|*/../*) return 1 ;;
    esac
  fi
  printf '%s\n' "$candidate_path" |
    grep -Eq '^/[-A-Za-z0-9_.:@%+,/\\]+$'
}

validate_cgroup_chain() {
  validate_cgroup_relative_path "$cgroup_parent_relative" || return 1
  [ -d "$cgroup_root" ] && [ ! -L "$cgroup_root" ] || return 1
  [ "$(stat -f -c '%T' -- "$cgroup_root" 2>/dev/null)" = cgroup2fs ] || return 1
  root_metadata=$(stat -c '%u:%a:%d' -- "$cgroup_root" 2>/dev/null) || return 1
  saved_ifs=$IFS
  IFS=:
  set -- $root_metadata
  IFS=$saved_ifs
  [ "$#" -eq 3 ] || return 1
  [ "$1" = 0 ] || return 1
  case "$2" in [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;; *) return 1 ;; esac
  root_mode=$((0$2))
  [ $((root_mode & 0022)) -eq 0 ] || return 1
  cgroup_root_device=$3
  chain_candidate=$cgroup_root
  chain_remainder=${cgroup_parent_relative#/}
  chain_depth=0
  while [ -n "$chain_remainder" ]; do
    chain_depth=$((chain_depth + 1))
    [ "$chain_depth" -le 64 ] || return 1
    case "$chain_remainder" in
      */*) chain_component=${chain_remainder%%/*}; chain_remainder=${chain_remainder#*/} ;;
      *) chain_component=$chain_remainder; chain_remainder= ;;
    esac
    [ -n "$chain_component" ] || return 1
    chain_candidate="$chain_candidate/$chain_component"
    [ -d "$chain_candidate" ] && [ ! -L "$chain_candidate" ] || return 1
    [ "$(stat -f -c '%T' -- "$chain_candidate" 2>/dev/null)" = cgroup2fs ] || return 1
    chain_metadata=$(stat -c '%u:%a:%d' -- "$chain_candidate" 2>/dev/null) || return 1
    saved_ifs=$IFS
    IFS=:
    set -- $chain_metadata
    IFS=$saved_ifs
    [ "$#" -eq 3 ] && [ "$1" = 0 ] || return 1
    case "$2" in [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;; *) return 1 ;; esac
    chain_mode=$((0$2))
    [ $((chain_mode & 0022)) -eq 0 ] && [ "$3" = "$cgroup_root_device" ] || return 1
  done
  cgroup_parent=$chain_candidate
  return 0
}

select_cgroup_parent() {
  validate_cgroup_relative_path "$cgroup_owner_relative" || return 1
  [ -d "$cgroup_root" ] && [ ! -L "$cgroup_root" ] || return 1
  [ "$(stat -f -c '%T' -- "$cgroup_root" 2>/dev/null)" = cgroup2fs ] || return 1
  root_metadata=$(stat -c '%u:%a:%d' -- "$cgroup_root" 2>/dev/null) || return 1
  saved_ifs=$IFS
  IFS=:
  set -- $root_metadata
  IFS=$saved_ifs
  [ "$#" -eq 3 ] && [ "$1" = 0 ] || return 1
  case "$2" in [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;; *) return 1 ;; esac
  root_mode=$((0$2))
  [ $((root_mode & 0022)) -eq 0 ] || return 1
  cgroup_mount_device=$3
  selected_parent=$cgroup_root
  selected_relative=/
  chain_candidate=$cgroup_root
  chain_remainder=${cgroup_owner_relative#/}
  chain_depth=0
  while [ -n "$chain_remainder" ]; do
    chain_depth=$((chain_depth + 1))
    [ "$chain_depth" -le 64 ] || return 1
    case "$chain_remainder" in
      */*) chain_component=${chain_remainder%%/*}; chain_remainder=${chain_remainder#*/} ;;
      *) chain_component=$chain_remainder; chain_remainder= ;;
    esac
    [ -n "$chain_component" ] || return 1
    chain_candidate="$chain_candidate/$chain_component"
    [ -d "$chain_candidate" ] && [ ! -L "$chain_candidate" ] || return 1
    [ "$(stat -f -c '%T' -- "$chain_candidate" 2>/dev/null)" = cgroup2fs ] || return 1
    chain_metadata=$(stat -c '%u:%a:%d' -- "$chain_candidate" 2>/dev/null) || return 1
    saved_ifs=$IFS
    IFS=:
    set -- $chain_metadata
    IFS=$saved_ifs
    [ "$#" -eq 3 ] || return 1
    case "$2" in [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;; *) return 1 ;; esac
    [ "$3" = "$cgroup_mount_device" ] || return 1
    # The first non-root or group/other-writable component is the trust
    # boundary.  Never inspect or select any of its descendants for privileged
    # mutation.
    if [ "$1" != 0 ]; then break; fi
    chain_mode=$((0$2))
    if [ $((chain_mode & 0022)) -ne 0 ]; then break; fi
    selected_parent=$chain_candidate
    if [ "$selected_relative" = / ]; then
      selected_relative="/$chain_component"
    else
      selected_relative="$selected_relative/$chain_component"
    fi
  done
  cgroup_parent=$selected_parent
  cgroup_parent_relative=$selected_relative
  return 0
}

load_cgroup_plan() {
  [ -f "$cgroup_plan" ] && [ ! -L "$cgroup_plan" ] || return 1
  plan_bytes=$(wc -c < "$cgroup_plan" 2>/dev/null) || return 1
  is_uint "$plan_bytes" && [ "$plan_bytes" -le 2048 ] || return 1
  IFS=' ' read -r plan_version plan_token cgroup_owner_relative \
    cgroup_parent_relative cgroup_mount_device cgroup_parent_device cgroup_parent_inode \
    plan_extra < "$cgroup_plan" || return 1
  [ "$plan_version" = V1 ] && [ "$plan_token" = "$token" ] &&
    [ -z "$plan_extra" ] || return 1
  for plan_number in "$cgroup_mount_device" "$cgroup_parent_device" \
    "$cgroup_parent_inode"; do
    is_uint "$plan_number" && [ "$plan_number" -gt 0 ] || return 1
  done
  validate_cgroup_relative_path "$cgroup_owner_relative" || return 1
  validate_cgroup_chain || return 1
  if [ "$cgroup_parent_relative" != / ] &&
     [ "$cgroup_owner_relative" != "$cgroup_parent_relative" ]; then
    case "$cgroup_owner_relative" in
      "$cgroup_parent_relative"/*) ;;
      *) return 1 ;;
    esac
  fi
  cgroup_leaf="$cgroup_parent/nvdebug-$token"
  cgroup_leaf_relative="$cgroup_parent_relative"
  if [ "$cgroup_leaf_relative" = / ]; then
    cgroup_leaf_relative="/nvdebug-$token"
  else
    cgroup_leaf_relative="$cgroup_leaf_relative/nvdebug-$token"
  fi
  mount_metadata=$(stat -c '%d' -- "$cgroup_root" 2>/dev/null) || return 1
  parent_metadata=$(stat -c '%d:%i' -- "$cgroup_parent" 2>/dev/null) || return 1
  [ "$mount_metadata" = "$cgroup_mount_device" ] &&
    [ "$cgroup_mount_device" = "$cgroup_parent_device" ] &&
    [ "$parent_metadata" = "$cgroup_parent_device:$cgroup_parent_inode" ]
}

publish_cgroup_plan() {
  bounded_unified_membership /proc/self/cgroup || return 1
  cgroup_owner_relative=$membership_path
  select_cgroup_parent || return 1
  parent_metadata=$(stat -c '%d:%i' -- "$cgroup_parent" 2>/dev/null) || return 1
  cgroup_parent_device=${parent_metadata%%:*}
  cgroup_parent_inode=${parent_metadata#*:}
  plan_tmp="$control_dir/cgroup_plan.tmp.$$"
  printf 'V1 %s %s %s %s %s %s\n' "$token" "$cgroup_owner_relative" \
    "$cgroup_parent_relative" \
    "$cgroup_mount_device" "$cgroup_parent_device" "$cgroup_parent_inode" \
    > "$plan_tmp" || {
      rm -f "$plan_tmp"
      return 1
    }
  mv -f "$plan_tmp" "$cgroup_plan" || {
    rm -f "$plan_tmp"
    return 1
  }
  load_cgroup_plan
}

planned_cgroup_leaf_is_absent() {
  load_cgroup_plan || return 2
  if [ ! -e "$cgroup_leaf" ] && [ ! -L "$cgroup_leaf" ]; then return 0; fi
  return 1
}

load_cgroup_identity() {
  [ -f "$cgroup_identity" ] && [ ! -L "$cgroup_identity" ] || return 1
  identity_bytes=$(wc -c < "$cgroup_identity" 2>/dev/null) || return 1
  is_uint "$identity_bytes" && [ "$identity_bytes" -le 2048 ] || return 1
  IFS=' ' read -r cgroup_version cgroup_token identity_parent_relative \
    identity_mount_device identity_parent_device identity_parent_inode \
    identity_leaf_device identity_leaf_inode cgroup_extra \
    < "$cgroup_identity" || return 1
  [ "$cgroup_version" = V1 ] && [ "$cgroup_token" = "$token" ] &&
    [ -z "$cgroup_extra" ] || return 1
  for identity_number in "$identity_mount_device" "$identity_parent_device" \
    "$identity_parent_inode" "$identity_leaf_device" "$identity_leaf_inode"; do
    is_uint "$identity_number" && [ "$identity_number" -gt 0 ] || return 1
  done
  load_cgroup_plan || return 1
  [ "$identity_parent_relative" = "$cgroup_parent_relative" ] &&
    [ "$identity_mount_device" = "$cgroup_mount_device" ] &&
    [ "$identity_parent_device" = "$cgroup_parent_device" ] &&
    [ "$identity_parent_inode" = "$cgroup_parent_inode" ] || return 1
  cgroup_leaf_device=$identity_leaf_device
  cgroup_leaf_inode=$identity_leaf_inode
  return 0
}

validate_cgroup_leaf() {
  load_cgroup_identity || return 1
  [ -d "$cgroup_leaf" ] && [ ! -L "$cgroup_leaf" ] || return 1
  [ "$(stat -f -c '%T' -- "$cgroup_leaf" 2>/dev/null)" = cgroup2fs ] || return 1
  leaf_metadata=$(stat -c '%u:%a:%d:%i' -- "$cgroup_leaf" 2>/dev/null) || return 1
  saved_ifs=$IFS
  IFS=:
  set -- $leaf_metadata
  IFS=$saved_ifs
  [ "$#" -eq 4 ] && [ "$1" = 0 ] || return 1
  case "$2" in [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;; *) return 1 ;; esac
  leaf_mode=$((0$2))
  [ $((leaf_mode & 0022)) -eq 0 ] || return 1
  leaf_metadata="$3:$4"
  [ "$leaf_metadata" = "$cgroup_leaf_device:$cgroup_leaf_inode" ] || return 1
  [ "$cgroup_leaf_device" = "$cgroup_mount_device" ] || return 1
  for cgroup_control_file in cgroup.procs cgroup.events cgroup.kill; do
    control_path="$cgroup_leaf/$cgroup_control_file"
    [ -f "$control_path" ] && [ ! -L "$control_path" ] || return 1
    control_device=$(stat -c '%d' -- "$control_path" 2>/dev/null) || return 1
    [ "$control_device" = "$cgroup_leaf_device" ] || return 1
  done
  return 0
}

cgroup_leaf_is_absent() {
  load_cgroup_identity || return 2
  if [ ! -e "$cgroup_leaf" ] && [ ! -L "$cgroup_leaf" ]; then return 0; fi
  validate_cgroup_leaf || return 2
  return 1
}

cgroup_owner_is_outside() {
  load_cgroup_identity || return 1
  bounded_unified_membership /proc/self/cgroup || return 1
  [ "$membership_path" = "$cgroup_owner_relative" ] &&
    [ "$membership_path" != "$cgroup_leaf_relative" ]
}

cgroup_migrate_self() {
  validate_cgroup_leaf || return 1
  printf '%s\n' "$$" > "$cgroup_leaf/cgroup.procs" || return 1
  bounded_unified_membership /proc/self/cgroup || return 1
  [ "$membership_path" = "$cgroup_leaf_relative" ] || return 1
  validate_cgroup_leaf
}

read_cgroup_populated() {
  validate_cgroup_leaf || return 2
  events_file="$cgroup_leaf/cgroup.events"
  events_bytes=$(wc -c < "$events_file" 2>/dev/null) || return 2
  is_uint "$events_bytes" && [ "$events_bytes" -le __MAX_CGROUP_EVENT_BYTES__ ] || return 2
  events_lines=0
  populated_lines=0
  populated_value=
  while IFS=' ' read -r event_key event_value event_extra ||
    [ -n "$event_key$event_value$event_extra" ]; do
    events_lines=$((events_lines + 1))
    [ "$events_lines" -le 32 ] || return 2
    [ -n "$event_key" ] && [ -z "$event_extra" ] &&
      is_uint "$event_value" || return 2
    if [ "$event_key" = populated ]; then
      populated_lines=$((populated_lines + 1))
      populated_value=$event_value
    fi
  done < "$events_file"
  [ "$populated_lines" -eq 1 ] || return 2
  if [ "$populated_value" = 0 ]; then return 0; fi
  if [ "$populated_value" = 1 ]; then return 1; fi
  return 2
}

wait_cgroup_unpopulated() {
  cgroup_remaining=$1
  while [ "$cgroup_remaining" -gt 0 ]; do
    read_cgroup_populated
    populated_status=$?
    if [ "$populated_status" -eq 0 ]; then
      sleep 0.1
      read_cgroup_populated
      [ "$?" -eq 0 ] && return 0
    elif [ "$populated_status" -eq 2 ]; then
      return 2
    fi
    sleep 1
    cgroup_remaining=$((cgroup_remaining - 1))
  done
  read_cgroup_populated
  [ "$?" -eq 0 ] || return 1
  sleep 0.1
  read_cgroup_populated
}

kill_owned_cgroup() {
  validate_cgroup_leaf || return 1
  printf '1\n' > "$cgroup_leaf/cgroup.kill" || return 1
  validate_cgroup_leaf
}

clear_cgroup_child_manifest() {
  rm -f "$cgroup_child_manifest" "$cgroup_child_count" \
    "$cgroup_child_count.tmp" "$cgroup_child_error"
}

remove_cgroup_children_bounded() {
  validate_cgroup_leaf || return 1
  clear_cgroup_child_manifest
  : > "$cgroup_child_manifest" || return 1
  printf '0\n' > "$cgroup_child_count" || return 1
  find "$cgroup_leaf" -xdev -depth -mindepth 1 -maxdepth __MAX_CGROUP_DEPTH__ \
    \( ! -type d -o -exec sh -c '
      count_file=$1
      manifest=$2
      error_file=$3
      maximum=$4
      candidate=$5
      count=$(cat "$count_file" 2>/dev/null) || {
        printf "error\n" > "$error_file"
        exit 1
      }
      case "$count" in ""|*[!0-9]*)
        printf "error\n" > "$error_file"
        exit 1
      esac
      next=$((count + 1))
      printf "%s\n" "$next" > "$count_file.tmp" &&
        mv -f "$count_file.tmp" "$count_file" || {
          printf "error\n" > "$error_file"
          exit 1
        }
      [ "$next" -le "$maximum" ] || {
        printf "error\n" > "$error_file"
        exit 1
      }
      printf "%s\0" "$candidate" >> "$manifest" || {
        printf "error\n" > "$error_file"
        exit 1
      }
    ' managed-cgroup-manifest "$cgroup_child_count" "$cgroup_child_manifest" \
      "$cgroup_child_error" __MAX_CGROUP_CHILDREN__ {} \; -o -quit \) || {
        clear_cgroup_child_manifest
        return 1
      }
  child_count=$(cat "$cgroup_child_count" 2>/dev/null) || child_count=
  if ! is_uint "$child_count" || [ "$child_count" -gt __MAX_CGROUP_CHILDREN__ ] ||
    [ -e "$cgroup_child_error" ]; then
    clear_cgroup_child_manifest
    return 1
  fi
  xargs -0 -r -n 1 sh -c '
    root=$1
    root_device=$2
    maximum_depth=$3
    candidate=$4
    case "$candidate" in "$root"/*) relative=${candidate#"$root"/} ;; *) exit 255 ;; esac
    [ -n "$relative" ] && [ -d "$candidate" ] && [ ! -L "$candidate" ] || exit 255
    depth=1
    remainder=$relative
    while :; do
      case "$remainder" in
        */*) depth=$((depth + 1)); remainder=${remainder#*/} ;;
        *) break ;;
      esac
    done
    [ "$depth" -le "$maximum_depth" ] || exit 255
    [ "$(stat -f -c "%T" -- "$candidate" 2>/dev/null)" = cgroup2fs ] || exit 255
    candidate_device=$(stat -c "%d" -- "$candidate" 2>/dev/null) || exit 255
    [ "$candidate_device" = "$root_device" ] || exit 255
    events="$candidate/cgroup.events"
    [ -f "$events" ] && [ ! -L "$events" ] || exit 255
    events_bytes=$(wc -c < "$events" 2>/dev/null) || exit 255
    case "$events_bytes" in ""|*[!0-9]*) exit 255 ;; esac
    [ "$events_bytes" -le __MAX_CGROUP_EVENT_BYTES__ ] || exit 255
    event_lines=0
    populated_lines=0
    populated_value=
    while IFS=" " read -r event_key event_value event_extra ||
      [ -n "$event_key$event_value$event_extra" ]; do
      event_lines=$((event_lines + 1))
      [ "$event_lines" -le 32 ] || exit 255
      case "$event_value" in ""|*[!0-9]*) exit 255 ;; esac
      [ -n "$event_key" ] && [ -z "$event_extra" ] || exit 255
      if [ "$event_key" = populated ]; then
        populated_lines=$((populated_lines + 1))
        populated_value=$event_value
      fi
    done < "$events"
    [ "$populated_lines" -eq 1 ] && [ "$populated_value" = 0 ] || exit 255
    rmdir -- "$candidate"
  ' managed-cgroup-remove "$cgroup_leaf" "$cgroup_leaf_device" \
    __MAX_CGROUP_DEPTH__ < "$cgroup_child_manifest"
  remove_status=$?
  clear_cgroup_child_manifest
  [ "$remove_status" -eq 0 ]
}

remove_owned_cgroup() {
  validate_cgroup_leaf || return 1
  read_cgroup_populated || return 1
  sleep 0.1
  read_cgroup_populated || return 1
  remove_cgroup_children_bounded || return 1
  validate_cgroup_leaf || return 1
  wait_cgroup_unpopulated 1 || return 1
  rmdir -- "$cgroup_leaf" || return 1
  cgroup_leaf_is_absent
}

setup_owned_cgroup() {
  load_cgroup_plan || return 1
  [ ! -e "$cgroup_leaf" ] && [ ! -L "$cgroup_leaf" ] || return 1
  mkdir -- "$cgroup_leaf" || return 1
  leaf_metadata=$(stat -c '%d:%i' -- "$cgroup_leaf" 2>/dev/null) || {
    rmdir -- "$cgroup_leaf" 2>/dev/null || true
    return 1
  }
  cgroup_leaf_device=${leaf_metadata%%:*}
  cgroup_leaf_inode=${leaf_metadata#*:}
  identity_tmp="$control_dir/cgroup_identity.tmp.$$"
  printf 'V1 %s %s %s %s %s %s %s\n' "$token" \
    "$cgroup_parent_relative" "$cgroup_mount_device" "$cgroup_parent_device" \
    "$cgroup_parent_inode" "$cgroup_leaf_device" "$cgroup_leaf_inode" > "$identity_tmp" || {
      rm -f "$identity_tmp"
      rmdir -- "$cgroup_leaf" 2>/dev/null || true
      return 1
    }
  mv -f "$identity_tmp" "$cgroup_identity" || {
    rm -f "$identity_tmp"
    rmdir -- "$cgroup_leaf" 2>/dev/null || true
    return 1
  }
  if ! validate_cgroup_leaf || ! cgroup_owner_is_outside; then
    rmdir -- "$cgroup_leaf" 2>/dev/null || true
    return 1
  fi
  return 0
}

signal_pinned_group_term() {
  [ "${owned_session_authorized-0}" -eq 1 ] || return 1
  owned_session_leader_is_running || return 1
  kill -s TERM -- "-$owned_pgid" 2>/dev/null || true
}

owned_leader_is_in_cgroup() {
  identity_is_live || return 1
  bounded_unified_membership "/proc/$owned_pgid/cgroup" || return 1
  [ "$membership_path" = "$cgroup_leaf_relative" ]
}

stop_escaped_pinned_group_best_effort() {
  owned_session_authorized=1
  signal_pinned_group_term || true
  escaped_remaining=$term_grace
  while [ "$escaped_remaining" -gt 0 ]; do
    owned_session_leader_is_running || return 0
    sleep 1
    escaped_remaining=$((escaped_remaining - 1))
  done
  if owned_session_leader_is_running; then
    kill -s KILL -- "-$owned_pgid" 2>/dev/null || true
  fi
  return 0
}

stop_owned_cgroup() {
  stop_kind=$1
  load_cgroup_identity || return 1
  cgroup_leaf_is_absent
  absent_status=$?
  if [ "$absent_status" -eq 0 ]; then
    if identity_is_live; then
      stop_escaped_pinned_group_best_effort
      return 1
    fi
    return 0
  fi
  [ "$absent_status" -eq 1 ] || return 1
  # Keep a completed supervisor pinned until authoritative cgroup cleanup.  A
  # release-before-signal race could otherwise expose a stale PGID or zombie
  # observation; the already-published done record preserves its exit status.
  marker_intact=1
  if [ "$stop_kind" = timeout ]; then
    write_timeout_marker || marker_intact=0
  fi
  containment_intact=1
  if identity_is_live; then
    if ! owned_leader_is_in_cgroup; then containment_intact=0; fi
    if [ "$observed_state" != Z ]; then
      owned_session_authorized=1
      signal_pinned_group_term || true
    fi
  fi
  cgroup_remaining=$term_grace
  [ "$stop_kind" = complete ] && cgroup_remaining=0
  while [ "$cgroup_remaining" -gt 0 ]; do
    read_cgroup_populated
    [ "$?" -eq 0 ] && break
    sleep 1
    cgroup_remaining=$((cgroup_remaining - 1))
  done
  kill_owned_cgroup || return 1
  wait_cgroup_unpopulated "$kill_grace" || return 1
  remove_owned_cgroup || return 1
  if [ "$containment_intact" -ne 1 ]; then
    stop_escaped_pinned_group_best_effort
    return 1
  fi
  [ "$marker_intact" -eq 1 ]
}
"""
_CGROUP_V2_COMMON_SCRIPT = (
    _CGROUP_V2_COMMON_SCRIPT.replace(
        "__MAX_CGROUP_MEMBERSHIP_BYTES__", str(_MAX_CGROUP_MEMBERSHIP_BYTES)
    )
    .replace("__MAX_CGROUP_PATH_BYTES__", str(_MAX_CGROUP_PATH_BYTES))
    .replace("__MAX_CGROUP_EVENT_BYTES__", str(_MAX_CGROUP_EVENT_BYTES))
    .replace("__MAX_CGROUP_CHILDREN__", str(_MAX_CGROUP_CHILDREN))
    .replace("__MAX_CGROUP_DEPTH__", str(_MAX_CGROUP_DEPTH))
)


_OWNED_SESSION_SCAN_SCRIPT = r"""
session_scan_tag=__SESSION_SCAN_TAG__
session_scan_root=__SESSION_SCAN_ROOT__
session_proc_root=/proc

clear_owned_session_scan_state() {
  rm -f "$session_scan_root/session_scan_${session_scan_tag}_count" \
    "$session_scan_root/session_scan_${session_scan_tag}_count.tmp" \
    "$session_scan_root/session_scan_${session_scan_tag}_found" \
    "$session_scan_root/session_scan_${session_scan_tag}_error" \
    "$session_scan_root/session_scan_${session_scan_tag}_pids"
}

scan_owned_session() {
  is_uint "${owned_session-}" && [ "$owned_session" -gt 1 ] || return 2
  scan_count_file="$session_scan_root/session_scan_${session_scan_tag}_count"
  scan_found_file="$session_scan_root/session_scan_${session_scan_tag}_found"
  scan_error_file="$session_scan_root/session_scan_${session_scan_tag}_error"
  scan_count_tmp="$session_scan_root/session_scan_${session_scan_tag}_count.tmp"
  scan_pid_file="$session_scan_root/session_scan_${session_scan_tag}_pids"
  clear_owned_session_scan_state || return 2
  if ! : > "$scan_found_file" ||
     ! LC_ALL=C ls -1U "$session_proc_root" > "$scan_pid_file" 2>/dev/null; then
    clear_owned_session_scan_state || true
    return 2
  fi
  read_stat_bounded() {
    read_attempts=3
    while [ "$read_attempts" -gt 0 ]; do
      if IFS= read -r stat_line 2>/dev/null < "$1"; then return 0; fi
      [ -e "$1" ] || return 1
      read_attempts=$((read_attempts - 1))
    done
    return 2
  }
  scan_count=0
  while IFS= read -r pid; do
    case "$pid" in ""|*[!0-9]*) continue ;; esac
    scan_count=$((scan_count + 1))
    if [ "$scan_count" -gt __MAX_SESSION_SCAN_PROCESSES__ ]; then
      printf 'error\n' > "$scan_error_file"
      break
    fi
    stat_path="$session_proc_root/$pid/stat"
    read_stat_bounded "$stat_path"
    read_status=$?
    if [ "$read_status" -eq 1 ]; then continue; fi
    if [ "$read_status" -ne 0 ]; then
      printf 'error\n' > "$scan_error_file"
      break
    fi
    stat_tail=${stat_line##*) }
    set -f
    set -- $stat_tail
    set +f
    if [ "$#" -lt 20 ]; then
      printf 'error\n' > "$scan_error_file"
      break
    fi
    state=$1
    process_group=$3
    session_id=$4
    start_ticks=${20}
    [ "$state" != Z ] && [ "$session_id" = "$owned_session" ] || continue
    if ! printf '%s %s %s\n' "$pid" "$start_ticks" "$process_group" >> "$scan_found_file"; then
      printf 'error\n' > "$scan_error_file"
      break
    fi
  done < "$scan_pid_file"
  if ! printf '%s\n' "$scan_count" > "$scan_count_tmp" ||
     ! mv -f "$scan_count_tmp" "$scan_count_file"; then
    printf 'error\n' > "$scan_error_file" 2>/dev/null || true
  fi
  scan_result=0
  if [ -e "$scan_error_file" ]; then
    scan_result=2
  elif [ -s "$scan_found_file" ] && [ "$scan_result" -eq 0 ]; then
    scan_result=1
  fi
  clear_owned_session_scan_state || return 2
  return "$scan_result"
}

session_is_absent() {
  scan_owned_session
}

group_is_absent() {
  session_is_absent
}

wait_for_group_absence() {
  remaining=$1
  while [ "$remaining" -gt 0 ]; do
    group_is_absent
    group_status=$?
    if [ "$group_status" -eq 0 ]; then return 0; fi
    sleep 1
    remaining=$((remaining - 1))
  done
  group_is_absent
}
"""


_TARGET_SUPERVISOR_SCRIPT = r"""
set +e
token=$1
control_dir=$2
artifact_dir=$3
payload=$4
launch_stop=$5
containment=${6:-process_group}

is_uint() {
  case "$1" in ''|*[!0-9]*) return 1 ;; esac
  return 0
}

__CGROUP_V2_COMMON_SCRIPT__

valid_launch_stop() {
  [ -f "$launch_stop" ] && [ ! -L "$launch_stop" ] || return 1
  IFS=' ' read -r stop_version stop_token stop_value stop_extra < "$launch_stop" || return 1
  [ "$stop_version" = V1 ] && [ "$stop_token" = "$token" ] &&
    [ "$stop_value" = stop ] && [ -z "$stop_extra" ]
}

valid_launch_stop && exit 125

case "$containment" in
  process_group) ;;
  cgroup_v2)
    cgroup_migrate_self || exit 125
    valid_launch_stop && exit 125
    ;;
  *) exit 125 ;;
esac

stat_line=$(cat "/proc/$$/stat" 2>/dev/null) || exit 125
stat_tail=${stat_line##*) }
set -f
set -- $stat_tail
set +f
[ "$#" -ge 20 ] || exit 125
process_group=$3
session_id=$4
start_ticks=${20}
if [ "$$" -le 1 ] || [ "$$" -ne "$process_group" ] || [ "$$" -ne "$session_id" ]; then
  exit 125
fi

identity_tmp="$control_dir/identity.tmp.$$"
printf 'V1 %s %s %s %s\n' "$token" "$$" "$start_ticks" "$session_id" > "$identity_tmp" || exit 125
mv -f "$identity_tmp" "$control_dir/identity" || exit 125
cd "$artifact_dir" || exit 126
valid_launch_stop && exit 125

term_seen=0
trap 'term_seen=1' TERM HUP INT
sh -c "$payload" &
target_pid=$!
while :; do
  wait "$target_pid"
  target_exit=$?
  if kill -0 "$target_pid" 2>/dev/null; then
    continue
  fi
  break
done

done_tmp="$control_dir/done.tmp.$$"
printf 'V1 %s %s\n' "$token" "$target_exit" > "$done_tmp" || exit 125
mv -f "$done_tmp" "$control_dir/done" || exit 125

# Keep the session leader alive after command completion so its PGID cannot be
# reused between an identity check and a signal.  Normal completion requires a
# token-bound release; timeout/cancellation intentionally leaves it pinned for
# the out-of-group cleanup owner to kill.
while [ "$term_seen" -eq 0 ]; do
  if [ -f "$control_dir/release" ] && [ ! -L "$control_dir/release" ]; then
    IFS=' ' read -r release_version release_token release_value release_extra < "$control_dir/release" || true
    if [ "$release_version" = V1 ] && [ "$release_token" = "$token" ] && [ "$release_value" = release ] && [ -z "$release_extra" ]; then
      exit "$target_exit"
    fi
  fi
  sleep 0.1
done
trap ':' TERM HUP INT
while :; do sleep 1; done
"""
_TARGET_SUPERVISOR_SCRIPT = _TARGET_SUPERVISOR_SCRIPT.replace(
    "__CGROUP_V2_COMMON_SCRIPT__", _CGROUP_V2_COMMON_SCRIPT
)


_TARGET_DEADLINE_OWNER_SCRIPT = r"""
set +e
token=$1
control_dir=$2
artifact_dir=$3
payload=$4
target_timeout=$5
term_grace=$6
kill_grace=$7
launch_grace=$8
target_script=$9
stdout_fifo=${10}
stderr_fifo=${11}
stdout_file=${12}
stderr_file=${13}
capture_keep=${14}
launch_stop=${15}
containment=${16:-process_group}
umask 077

# The deadline owner is deliberately outside both the SSH wrapper's session
# and the payload's session.  Ignoring HUP protects the deadline from channel
# teardown; TERM remains a cooperative request from bounded reconciliation.
stop_requested=0
trap '' HUP
trap 'stop_requested=1' TERM INT

is_uint() {
  case "$1" in ''|*[!0-9]*) return 1 ;; esac
  return 0
}

__CGROUP_V2_COMMON_SCRIPT__

complete_owned_cgroup_setup() {
  publish_cgroup_plan || return 1
  # Setup runs in one synchronous helper which inherits HUP immunity and
  # ignores cooperative stop signals.  If the deadline owner is lost while
  # waiting, the orphaned helper still completes the leaf identity publication
  # needed by cleanup-only reconciliation.  No payload can launch in this
  # phase, and the owner never probes the PID after reaping it.
  if ! (
    trap '' HUP TERM INT
    setup_owned_cgroup
  ); then
    return 1
  fi
  validate_cgroup_leaf && cgroup_owner_is_outside
}

read_start_fields() {
  stat_line=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
  stat_tail=${stat_line##*) }
  set -f
  set -- $stat_tail
  set +f
  [ "$#" -ge 20 ] || return 1
  observed_state=$1
  observed_group=$3
  observed_session=$4
  observed_start=${20}
  return 0
}

load_identity() {
  [ -f "$control_dir/identity" ] && [ ! -L "$control_dir/identity" ] || return 1
  IFS=' ' read -r identity_version identity_token owned_pgid owned_start owned_session identity_extra < "$control_dir/identity" || return 1
  [ "$identity_version" = V1 ] && [ "$identity_token" = "$token" ] && [ -z "$identity_extra" ] || return 1
  is_uint "$owned_pgid" && is_uint "$owned_start" && is_uint "$owned_session" || return 1
  [ "$owned_pgid" -gt 1 ] && [ "$owned_start" -gt 0 ] && [ "$owned_session" = "$owned_pgid" ] || return 1
  return 0
}

identity_is_live() {
  load_identity || return 1
  read_start_fields "$owned_pgid" || return 1
  [ "$observed_group" = "$owned_pgid" ] && [ "$observed_session" = "$owned_session" ] && [ "$observed_start" = "$owned_start" ] || return 1
  return 0
}

owned_session_leader_is_running() {
  # The initial identity handshake pins these values before the steady-state
  # loop.  Avoid reloading a mutable receipt and avoid a full /proc inventory
  # on every timeout tick; leader loss moves immediately into bounded cleanup.
  is_uint "${owned_pgid-}" && is_uint "${owned_start-}" &&
    is_uint "${owned_session-}" || return 1
  read_start_fields "$owned_pgid" || return 1
  [ "$observed_state" != Z ] &&
    [ "$observed_group" = "$owned_pgid" ] &&
    [ "$observed_session" = "$owned_session" ] &&
    [ "$observed_start" = "$owned_start" ]
}

__OWNED_SESSION_SCAN_SCRIPT__

valid_marker() {
  marker_path=$1
  marker_kind=$2
  [ -f "$marker_path" ] && [ ! -L "$marker_path" ] || return 1
  IFS=' ' read -r marker_version marker_token marker_value marker_extra < "$marker_path" || return 1
  [ "$marker_version" = V1 ] && [ "$marker_token" = "$token" ] && [ -z "$marker_extra" ] || return 1
  if [ "$marker_kind" = done ]; then
    is_uint "$marker_value" && [ "$marker_value" -le 255 ] || return 1
  else
    [ "$marker_value" = stop ] || return 1
  fi
  return 0
}

write_launch_stop_marker() {
  stop_tmp="$attempt_dir/.launch_stop.tmp.$$"
  printf 'V1 %s stop\n' "$token" > "$stop_tmp" || return 1
  mv -f "$stop_tmp" "$launch_stop"
}

write_release_marker() {
  release_tmp="$control_dir/release.tmp.$$"
  printf 'V1 %s release\n' "$token" > "$release_tmp" || return 1
  mv -f "$release_tmp" "$control_dir/release"
}

write_timeout_marker() {
  timeout_tmp="$control_dir/timeout.tmp.$$"
  printf 'V1 %s target_timeout\n' "$token" > "$timeout_tmp" || return 1
  mv -f "$timeout_tmp" "$control_dir/timeout"
}

write_deadline_done() {
  deadline_status=$1
  deadline_tmp="$control_dir/deadline_done.tmp.$$"
  printf 'V1 %s %s\n' "$token" "$deadline_status" > "$deadline_tmp" || return 1
  mv -f "$deadline_tmp" "$control_dir/deadline_done"
}

wait_for_group_absence() {
  remaining=$1
  while [ "$remaining" -gt 0 ]; do
    group_is_absent
    group_status=$?
    # A scan error is uncertainty, not evidence of presence or absence. Retry
    # it inside the existing bounded grace window before failing closed.
    if [ "$group_status" -eq 0 ]; then break; fi
    sleep 1
    remaining=$((remaining - 1))
  done
  group_is_absent
}

signal_owned_process_group() {
  owned_signal=$1
  case "$owned_signal" in TERM|KILL) ;; *) return 1 ;; esac
  [ "${owned_session_authorized-0}" -eq 1 ] || return 1
  # Recheck the exact non-zombie leader immediately before signalling its
  # original group.  Never signal numeric PIDs discovered by a /proc scan.
  owned_session_leader_is_running || return 1
  kill -"$owned_signal" -"$owned_pgid" 2>/dev/null || true
}

stop_owned_group() {
  stop_kind=$1
  # Authorize only the original negative PGID while its exact non-zombie
  # leader is live.  The full session inventory remains observation-only; a
  # member that leaves this group makes cleanup fail closed.
  if [ "${owned_session_authorized-0}" -ne 1 ]; then
    identity_is_live || return 1
    [ "$observed_state" != Z ] || return 1
    owned_session_authorized=1
  fi
  if [ "$stop_kind" = complete ]; then
    write_release_marker || return 1
  elif [ "$stop_kind" = timeout ]; then
    write_timeout_marker || return 1
    signal_owned_process_group TERM || true
  else
    signal_owned_process_group TERM || true
  fi

  if wait_for_group_absence "$term_grace"; then return 0; fi
  signal_owned_process_group KILL || true
  wait_for_group_absence "$kill_grace"
}

owned_scope_is_live() {
  if [ "$containment" = cgroup_v2 ]; then
    if identity_is_live && ! owned_leader_is_in_cgroup; then return 1; fi
    read_cgroup_populated
    populated_status=$?
    [ "$populated_status" -eq 1 ]
    return $?
  fi
  owned_session_leader_is_running
}

wait_for_scope_absence() {
  scope_remaining=$1
  if [ "$containment" = cgroup_v2 ]; then
    while [ "$scope_remaining" -gt 0 ]; do
      cgroup_leaf_is_absent
      scope_status=$?
      if [ "$scope_status" -eq 0 ]; then return 0; fi
      [ "$scope_status" -eq 1 ] || return 2
      sleep 1
      scope_remaining=$((scope_remaining - 1))
    done
    cgroup_leaf_is_absent
    return $?
  fi
  wait_for_group_absence "$scope_remaining"
}

stop_owned_scope() {
  if [ "$containment" = cgroup_v2 ]; then
    stop_owned_cgroup "$1"
  else
    stop_owned_group "$1"
  fi
}

cleanup_cgroup_without_target() {
  if [ "$containment" != cgroup_v2 ]; then return 0; fi
  cgroup_leaf_is_absent
  no_target_absent=$?
  if [ "$no_target_absent" -eq 0 ]; then return 0; fi
  [ "$no_target_absent" -eq 1 ] || return 1
  owned_session_authorized=0
  stop_owned_cgroup stop
}

child_is_settled() {
  child_pid=$1
  child_start=$2
  child_group=$3
  child_session=$4
  if [ ! -e "/proc/$child_pid/stat" ]; then return 0; fi
  if ! read_start_fields "$child_pid"; then
    if [ ! -e "/proc/$child_pid/stat" ]; then return 0; fi
    return 2
  fi
  [ "$observed_start" = "$child_start" ] && [ "$observed_group" = "$child_group" ] && [ "$observed_session" = "$child_session" ] || return 2
  if [ "$observed_state" = Z ]; then return 0; fi
  return 1
}

signal_child_if_live() {
  child_signal=$1
  child_pid=$2
  child_start=$3
  child_group=$4
  child_session=$5
  child_is_settled "$child_pid" "$child_start" "$child_group" "$child_session"
  child_status=$?
  if [ "$child_status" -eq 0 ]; then return 0; fi
  [ "$child_status" -eq 1 ] || return 2
  kill -"$child_signal" "$child_pid" 2>/dev/null || true
  return 0
}

captures_are_settled() {
  child_is_settled "$stdout_tail_pid" "$stdout_tail_start" "$stdout_tail_group" "$stdout_tail_session"
  stdout_status=$?
  child_is_settled "$stderr_tail_pid" "$stderr_tail_start" "$stderr_tail_group" "$stderr_tail_session"
  stderr_status=$?
  if [ "$stdout_status" -eq 0 ] && [ "$stderr_status" -eq 0 ]; then return 0; fi
  if [ "$stdout_status" -eq 2 ] || [ "$stderr_status" -eq 2 ]; then return 2; fi
  return 1
}

reap_settled_child() {
  child_pid=$1
  child_start=$2
  child_group=$3
  child_session=$4
  child_is_settled "$child_pid" "$child_start" "$child_group" "$child_session" || return 1
  # A missing or zombie direct child cannot block wait and cannot be reused
  # until its parent consumes the status.
  wait "$child_pid" 2>/dev/null || true
  return 0
}

finish_capture_bounded() {
  capture_mode=$1
  capture_forced=0
  if [ "$capture_mode" = natural ]; then
    remaining=10
    while [ "$remaining" -gt 0 ]; do
      captures_are_settled
      capture_status=$?
      if [ "$capture_status" -eq 0 ] || [ "$capture_status" -eq 2 ]; then break; fi
      sleep 0.1
      remaining=$((remaining - 1))
    done
    if ! captures_are_settled; then capture_forced=1; fi
  fi

  if ! captures_are_settled; then
    signal_child_if_live TERM "$stdout_tail_pid" "$stdout_tail_start" "$stdout_tail_group" "$stdout_tail_session" || true
    signal_child_if_live TERM "$stderr_tail_pid" "$stderr_tail_start" "$stderr_tail_group" "$stderr_tail_session" || true
    remaining=1
    while [ "$remaining" -gt 0 ]; do
      captures_are_settled && break
      sleep 1
      remaining=$((remaining - 1))
    done
  fi
  if ! captures_are_settled; then
    signal_child_if_live KILL "$stdout_tail_pid" "$stdout_tail_start" "$stdout_tail_group" "$stdout_tail_session" || true
    signal_child_if_live KILL "$stderr_tail_pid" "$stderr_tail_start" "$stderr_tail_group" "$stderr_tail_session" || true
    remaining=1
    while [ "$remaining" -gt 0 ]; do
      captures_are_settled && break
      sleep 1
      remaining=$((remaining - 1))
    done
  fi
  captures_are_settled || return 2
  reap_settled_child "$stdout_tail_pid" "$stdout_tail_start" "$stdout_tail_group" "$stdout_tail_session" || return 2
  reap_settled_child "$stderr_tail_pid" "$stderr_tail_start" "$stderr_tail_group" "$stderr_tail_session" || return 2
  [ "$capture_forced" -eq 0 ]
}

finish_owned_children() {
  capture_mode=$1
  runner_status=0
  if is_uint "${runner_pid-}"; then
    reap_settled_child "$runner_pid" "$runner_start" "$runner_group" "$runner_session" || runner_status=1
  fi
  finish_capture_bounded "$capture_mode"
  capture_status=$?
  [ "$runner_status" -eq 0 ] && [ "$capture_status" -eq 0 ]
}

runner_group_is_absent() {
  pgrep -g "$runner_pid" >/dev/null 2>&1
  runner_group_status=$?
  if [ "$runner_group_status" -eq 1 ]; then return 0; fi
  if [ "$runner_group_status" -eq 0 ]; then return 1; fi
  return 2
}

runner_state_by_start() {
  if [ ! -e "/proc/$runner_pid/stat" ]; then return 0; fi
  if ! read_start_fields "$runner_pid"; then
    if [ ! -e "/proc/$runner_pid/stat" ]; then return 0; fi
    return 2
  fi
  [ "$observed_start" = "$runner_start" ] || return 2
  if [ "$observed_group" = "$runner_pid" ] && [ "$observed_session" = "$runner_pid" ]; then
    runner_session_ready=1
  fi
  if [ "$observed_state" = Z ]; then return 0; fi
  return 1
}

published_runner_matches() {
  load_identity || return 1
  [ "$owned_pgid" = "$runner_pid" ] &&
    [ "$owned_start" = "$runner_start" ] &&
    [ "$owned_session" = "$runner_pid" ]
}

stop_published_runner() {
  if ! published_runner_matches; then
    # A valid token-bound identity is still safer to stop than to abandon,
    # even though a mismatch prevents a verified no-target result.
    if load_identity; then stop_owned_scope stop || true; fi
    return 1
  fi
  runner_session_ready=1
  if ! owned_scope_is_live; then
    if [ "$containment" = cgroup_v2 ]; then
      # A privileged payload may have escaped the leaf after publishing its
      # pinned identity.  Best-effort TERM still targets only that original
      # negative PGID, while cgroup.kill plus leaf removal remain the cleanup
      # authority for anything still owned by the leaf.
      owned_session_authorized=1
      stop_owned_scope stop
      return $?
    fi
    wait_for_scope_absence "$kill_grace"
    return $?
  fi
  owned_session_authorized=1
  stop_owned_scope stop
}

signal_runner_pid_if_live() {
  runner_signal=$1
  runner_state_by_start
  runner_status=$?
  if [ "$runner_status" -eq 0 ]; then return 0; fi
  [ "$runner_status" -eq 1 ] || return 2
  kill -"$runner_signal" "$runner_pid" 2>/dev/null || true
  if [ "$runner_session_ready" -eq 1 ] &&
     [ "$observed_group" = "$runner_pid" ] &&
     [ "$observed_session" = "$runner_pid" ]; then
    kill -"$runner_signal" -"$runner_pid" 2>/dev/null || true
  fi
  return 0
}

reap_unpublished_runner() {
  if [ ! -e "/proc/$runner_pid/stat" ]; then
    wait "$runner_pid" 2>/dev/null || true
    return 0
  fi
  read_start_fields "$runner_pid" || return 1
  [ "$observed_start" = "$runner_start" ] && [ "$observed_state" = Z ] || return 1
  if [ "$runner_session_ready" -eq 1 ]; then
    [ "$observed_group" = "$runner_pid" ] && [ "$observed_session" = "$runner_pid" ] || return 1
    group_count=$(pgrep -c -g "$runner_pid" 2>/dev/null)
    group_count_status=$?
    [ "$group_count_status" -eq 0 ] && [ "$group_count" = 1 ] || return 1
  fi
  wait "$runner_pid" 2>/dev/null || true
  return 0
}

stop_unidentified_runner() {
  if [ "$containment" = cgroup_v2 ]; then
    # Close both target-supervisor migration checks before deciding whether
    # the exact pre-migration child or the owned cgroup is authoritative.
    # Once published, the token-bound tombstone prevents a runner outside the
    # leaf from migrating after the leaf has been killed and verified empty.
    write_launch_stop_marker || return 1
    if load_identity; then stop_published_runner; return $?; fi
    if ! load_cgroup_identity; then return 1; fi
    runner_state_by_start
    runner_status=$?
    if [ "$runner_status" -eq 1 ] &&
       [ "$observed_group" = "$runner_pid" ] &&
       [ "$observed_session" = "$runner_pid" ]; then
      kill -TERM -"$runner_pid" 2>/dev/null || true
    elif [ "$runner_status" -eq 2 ]; then
      return 1
    fi

    remaining=$term_grace
    while [ "$remaining" -gt 0 ]; do
      if load_identity; then stop_published_runner; return $?; fi
      runner_state_by_start
      runner_status=$?
      if [ "$runner_status" -eq 0 ]; then break; fi
      [ "$runner_status" -eq 1 ] || return 1
      sleep 1
      remaining=$((remaining - 1))
    done
    if load_identity; then stop_published_runner; return $?; fi

    # Kill any runner which crossed the first launch barrier and migrated.
    # The launch tombstone prevents a still-unmigrated runner from entering
    # the leaf after this authoritative kill.
    kill_owned_cgroup || return 1
    wait_cgroup_unpopulated "$kill_grace" || return 1

    # A supervisor stopped before migration remains pinned by the original
    # start time, PGID, and session.  Revalidate all three and signal only its
    # negative, launch-time PGID; never signal a PID found by traversal.
    runner_state_by_start
    runner_status=$?
    if [ "$runner_status" -eq 1 ]; then
      [ "$observed_group" = "$runner_pid" ] &&
        [ "$observed_session" = "$runner_pid" ] || return 1
      kill -s KILL -- "-$runner_pid" 2>/dev/null || true
    elif [ "$runner_status" -eq 2 ]; then
      return 1
    fi
    remaining=$kill_grace
    while [ "$remaining" -gt 0 ]; do
      if load_identity; then stop_published_runner; return $?; fi
      runner_state_by_start
      runner_status=$?
      if [ "$runner_status" -eq 0 ]; then break; fi
      [ "$runner_status" -eq 1 ] || return 1
      sleep 1
      remaining=$((remaining - 1))
    done
    if load_identity; then stop_published_runner; return $?; fi
    reap_unpublished_runner || return 1
    remove_owned_cgroup
    return $?
  fi
  if load_identity; then stop_published_runner; return $?; fi
  signal_runner_pid_if_live TERM || true
  remaining=$term_grace
  while [ "$remaining" -gt 0 ]; do
    if load_identity; then stop_published_runner; return $?; fi
    runner_state_by_start
    runner_status=$?
    if [ "$runner_status" -eq 0 ]; then break; fi
    sleep 1
    remaining=$((remaining - 1))
  done
  if load_identity; then stop_published_runner; return $?; fi
  signal_runner_pid_if_live KILL || true
  remaining=$kill_grace
  while [ "$remaining" -gt 0 ]; do
    if load_identity; then stop_published_runner; return $?; fi
    runner_state_by_start
    runner_status=$?
    if [ "$runner_status" -eq 0 ]; then break; fi
    sleep 1
    remaining=$((remaining - 1))
  done
  if load_identity; then stop_published_runner; return $?; fi

  # If setsid became ready but publication never completed, the exact direct
  # child still pins the session identity.  Kill any setup descendants before
  # reaping that leader; the fixed supervisor cannot launch the payload until
  # after the token-bound identity publication above.
  if [ "$runner_session_ready" -eq 1 ] && read_start_fields "$runner_pid"; then
    if [ "$observed_start" = "$runner_start" ] &&
       [ "$observed_group" = "$runner_pid" ] &&
       [ "$observed_session" = "$runner_pid" ]; then
      kill -KILL -"$runner_pid" 2>/dev/null || true
    fi
  fi
  remaining=$kill_grace
  while [ "$remaining" -gt 0 ]; do
    if load_identity; then stop_published_runner; return $?; fi
    reap_unpublished_runner || true
    runner_group_is_absent && break
    sleep 1
    remaining=$((remaining - 1))
  done
  if load_identity; then stop_published_runner; return $?; fi
  reap_unpublished_runner || return 1
  runner_group_is_absent
}

# Publish an exact, token-bound process identity before a payload can exist.
# This owner, rather than the transport wrapper, launches the target session.
read_start_fields "$$" || exit 125
if [ "$$" -le 1 ] || [ "$$" -ne "$observed_group" ] || [ "$$" -ne "$observed_session" ]; then
  exit 125
fi
deadline_identity_tmp="$control_dir/deadline_identity.tmp.$$"
printf 'V1 %s %s %s %s\n' "$token" "$$" "$observed_start" "$observed_session" > "$deadline_identity_tmp" || exit 125
mv -f "$deadline_identity_tmp" "$control_dir/deadline_identity" || exit 125

if [ "$containment" = cgroup_v2 ]; then
  if ! complete_owned_cgroup_setup; then
    stop_owned_cgroup stop || true
    write_deadline_done failed || true
    exit 0
  fi
fi

# The independent owner launches both bounded capture readers and the target.
# Therefore no payload can exist unless its deadline owner already exists.
tail -c "$capture_keep" < "$stdout_fifo" > "$stdout_file" &
stdout_tail_pid=$!
tail -c "$capture_keep" < "$stderr_fifo" > "$stderr_file" &
stderr_tail_pid=$!
if ! read_start_fields "$stdout_tail_pid"; then
  kill -KILL "$stdout_tail_pid" "$stderr_tail_pid" 2>/dev/null || true
  cleanup_cgroup_without_target || true
  write_deadline_done failed || true
  exit 0
fi
stdout_tail_start=$observed_start
stdout_tail_group=$observed_group
stdout_tail_session=$observed_session
if ! read_start_fields "$stderr_tail_pid"; then
  kill -KILL "$stdout_tail_pid" "$stderr_tail_pid" 2>/dev/null || true
  cleanup_cgroup_without_target || true
  write_deadline_done failed || true
  exit 0
fi
stderr_tail_start=$observed_start
stderr_tail_group=$observed_group
stderr_tail_session=$observed_session

if [ "$stop_requested" -eq 1 ] || valid_marker "$launch_stop" stop || valid_marker "$control_dir/stop_watchdog" stop; then
  if finish_owned_children force && cleanup_cgroup_without_target; then deadline_status=no_target; else deadline_status=failed; fi
  write_deadline_done "$deadline_status" || true
  exit 0
fi

setsid sh -c "$target_script" managed-target "$token" "$control_dir" "$artifact_dir" "$payload" "$launch_stop" "$containment" > "$stdout_fifo" 2> "$stderr_fifo" < /dev/null &
runner_pid=$!
if ! read_start_fields "$runner_pid"; then
  kill -KILL "$runner_pid" 2>/dev/null || true
  finish_capture_bounded force || true
  cleanup_cgroup_without_target || true
  write_deadline_done failed || true
  exit 0
fi
runner_start=$observed_start
# The child may still be between fork and exec when first observed.  Its
# start time is stable, but setsid has not necessarily installed the final
# PGID/session yet.  The token-bound target identity below is the readiness
# handshake; these are the exact values that successful setsid must publish.
runner_group=$runner_pid
runner_session=$runner_pid
runner_session_ready=0
if [ "$observed_group" = "$runner_pid" ] && [ "$observed_session" = "$runner_pid" ]; then
  runner_session_ready=1
fi

# Target setup publishes its identity before it launches the payload.  If
# setup cannot do so, stop the exact child session and prove it absent.
remaining=$((launch_grace * 10))
while ! load_identity && [ "$remaining" -gt 0 ]; do
  if ! read_start_fields "$runner_pid"; then
    # A transient /proc read must not abandon a live pre-identity child.
    sleep 0.1
    remaining=$((remaining - 1))
    continue
  fi
  if [ "$observed_start" != "$runner_start" ]; then
    break
  fi
  if [ "$observed_group" = "$runner_pid" ] && [ "$observed_session" = "$runner_pid" ]; then
    runner_session_ready=1
  fi
  if [ "$observed_state" = Z ]; then
    break
  fi
  sleep 0.1
  remaining=$((remaining - 1))
done
if ! load_identity; then
  stop_unidentified_runner
  runner_stop_status=$?
  finish_owned_children force
  child_finish_status=$?
  if [ "$runner_stop_status" -eq 0 ] && [ "$child_finish_status" -eq 0 ]; then deadline_status=no_target; else deadline_status=failed; fi
  write_deadline_done "$deadline_status" || true
  exit 0
fi
if [ "$owned_pgid" != "$runner_pid" ] || [ "$owned_start" != "$runner_start" ] || [ "$owned_session" != "$runner_pid" ]; then
  stop_owned_scope stop || true
  finish_owned_children force || true
  write_deadline_done failed || true
  exit 0
fi
if ! owned_scope_is_live; then
  if [ "$containment" = cgroup_v2 ]; then
    if stop_owned_scope stop; then deadline_status=verified_absent; else deadline_status=failed; fi
  elif wait_for_scope_absence "$kill_grace"; then
    deadline_status=verified_absent
  else
    deadline_status=failed
  fi
  if ! finish_owned_children natural; then deadline_status=failed; fi
  write_deadline_done "$deadline_status" || true
  exit 0
fi
owned_session_authorized=1

if [ "$stop_requested" -eq 1 ] || valid_marker "$launch_stop" stop || valid_marker "$control_dir/stop_watchdog" stop; then
  if stop_owned_scope stop; then deadline_status=verified_absent; else deadline_status=failed; fi
  if ! finish_owned_children natural; then deadline_status=failed; fi
  write_deadline_done "$deadline_status" || true
  exit 0
fi

elapsed=0
while [ "$elapsed" -lt "$target_timeout" ]; do
  if valid_marker "$control_dir/done" done; then
    if stop_owned_scope complete; then deadline_status=verified_absent; else deadline_status=failed; fi
    if ! finish_owned_children natural; then deadline_status=failed; fi
    write_deadline_done "$deadline_status" || true
    exit 0
  fi
  if [ "$stop_requested" -eq 1 ] || valid_marker "$launch_stop" stop || valid_marker "$control_dir/stop_watchdog" stop; then
    if stop_owned_scope stop; then deadline_status=verified_absent; else deadline_status=failed; fi
    if ! finish_owned_children natural; then deadline_status=failed; fi
    write_deadline_done "$deadline_status" || true
    exit 0
  fi
  if ! owned_scope_is_live; then
    if stop_owned_scope stop; then deadline_status=verified_absent; else deadline_status=failed; fi
    if ! finish_owned_children natural; then deadline_status=failed; fi
    write_deadline_done "$deadline_status" || true
    exit 0
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done

if stop_owned_scope timeout; then deadline_status=verified_absent; else deadline_status=failed; fi
if ! finish_owned_children natural; then deadline_status=failed; fi
write_deadline_done "$deadline_status" || true
exit 0
"""
_TARGET_DEADLINE_OWNER_SCRIPT = (
    _TARGET_DEADLINE_OWNER_SCRIPT.replace(
        "__OWNED_SESSION_SCAN_SCRIPT__", _OWNED_SESSION_SCAN_SCRIPT
    )
    .replace("__SESSION_SCAN_TAG__", "owner")
    .replace("__SESSION_SCAN_ROOT__", '"$control_dir"')
    .replace("__MAX_SESSION_SCAN_PROCESSES__", str(_MAX_SESSION_SCAN_PROCESSES))
    .replace("__CGROUP_V2_COMMON_SCRIPT__", _CGROUP_V2_COMMON_SCRIPT)
)


# The artifact manifest's GNU find predicate visits at most one entry beyond
# the accepted bound and quits before a large directory can expand into argv.
_PRIMARY_WRAPPER_SCRIPT = r"""
set +e
token=$1
attempt_dir=$2
payload=$3
target_timeout=$4
term_grace=$5
kill_grace=$6
output_limit=$7
target_script=$8
deadline_script=$9
launch_grace=${10}
containment=${11:-process_group}
prepare_on=${12:-0}
artifact_dir="$attempt_dir/artifacts"
control_dir="$attempt_dir/.control"
launch_stop="$attempt_dir/.launch_stop"
artifact_ready="$control_dir/artifact_ready"
remote_root=${attempt_dir%/*}
stdout_fifo="$control_dir/stdout.fifo"
stderr_fifo="$control_dir/stderr.fifo"
stdout_file="$control_dir/stdout"
stderr_file="$control_dir/stderr"
capture_keep=$((output_limit + 1))
umask 077

is_uint() {
  case "$1" in ''|*[!0-9]*) return 1 ;; esac
  return 0
}

__CGROUP_V2_COMMON_SCRIPT__

read_start_fields() {
  stat_line=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
  stat_tail=${stat_line##*) }
  set -f
  set -- $stat_tail
  set +f
  [ "$#" -ge 20 ] || return 1
  observed_group=$3
  observed_session=$4
  observed_start=${20}
  return 0
}

load_identity() {
  [ -f "$control_dir/identity" ] && [ ! -L "$control_dir/identity" ] || return 1
  IFS=' ' read -r identity_version identity_token owned_pgid owned_start owned_session identity_extra < "$control_dir/identity" || return 1
  [ "$identity_version" = V1 ] && [ "$identity_token" = "$token" ] && [ -z "$identity_extra" ] || return 1
  is_uint "$owned_pgid" && is_uint "$owned_start" && is_uint "$owned_session" || return 1
  [ "$owned_pgid" -gt 1 ] && [ "$owned_start" -gt 0 ] && [ "$owned_session" = "$owned_pgid" ] || return 1
  return 0
}

identity_is_live() {
  load_identity || return 1
  read_start_fields "$owned_pgid" || return 1
  [ "$observed_group" = "$owned_pgid" ] && [ "$observed_session" = "$owned_session" ] && [ "$observed_start" = "$owned_start" ] || return 1
  return 0
}

load_deadline_identity() {
  [ -f "$control_dir/deadline_identity" ] && [ ! -L "$control_dir/deadline_identity" ] || return 1
  IFS=' ' read -r deadline_version deadline_token deadline_pgid deadline_start deadline_session deadline_extra < "$control_dir/deadline_identity" || return 1
  [ "$deadline_version" = V1 ] && [ "$deadline_token" = "$token" ] && [ -z "$deadline_extra" ] || return 1
  is_uint "$deadline_pgid" && is_uint "$deadline_start" && is_uint "$deadline_session" || return 1
  [ "$deadline_pgid" -gt 1 ] && [ "$deadline_start" -gt 0 ] && [ "$deadline_session" = "$deadline_pgid" ] || return 1
  return 0
}

deadline_group_is_absent() {
  load_deadline_identity || return 2
  pgrep -g "$deadline_pgid" >/dev/null 2>&1
  deadline_group_status=$?
  if [ "$deadline_group_status" -eq 1 ]; then return 0; fi
  if [ "$deadline_group_status" -eq 0 ]; then return 1; fi
  return 2
}

valid_marker() {
  marker_path=$1
  marker_kind=$2
  [ -f "$marker_path" ] && [ ! -L "$marker_path" ] || return 1
  IFS=' ' read -r marker_version marker_token marker_value marker_extra < "$marker_path" || return 1
  [ "$marker_version" = V1 ] && [ "$marker_token" = "$token" ] && [ -z "$marker_extra" ] || return 1
  if [ "$marker_kind" = done ]; then
    is_uint "$marker_value" && [ "$marker_value" -le 255 ] || return 1
  else
    [ "$marker_value" = target_timeout ] || return 1
  fi
  return 0
}

valid_deadline_done() {
  [ -f "$control_dir/deadline_done" ] && [ ! -L "$control_dir/deadline_done" ] || return 1
  IFS=' ' read -r deadline_done_version deadline_done_token deadline_done_status deadline_done_extra < "$control_dir/deadline_done" || return 1
  [ "$deadline_done_version" = V1 ] && [ "$deadline_done_token" = "$token" ] && [ -z "$deadline_done_extra" ] || return 1
  case "$deadline_done_status" in
    verified_absent|no_target|failed) return 0 ;;
    *) return 1 ;;
  esac
}

write_release_marker() {
  release_tmp="$control_dir/release.tmp.$$"
  printf 'V1 %s release\n' "$token" > "$release_tmp" || return 1
  mv -f "$release_tmp" "$control_dir/release"
}

valid_stop_marker() {
  [ -f "$control_dir/stop_watchdog" ] && [ ! -L "$control_dir/stop_watchdog" ] || return 1
  IFS=' ' read -r marker_version marker_token marker_value marker_extra < "$control_dir/stop_watchdog" || return 1
  [ "$marker_version" = V1 ] && [ "$marker_token" = "$token" ] && [ "$marker_value" = stop ] && [ -z "$marker_extra" ]
}

valid_launch_stop() {
  [ -f "$launch_stop" ] && [ ! -L "$launch_stop" ] || return 1
  IFS=' ' read -r marker_version marker_token marker_value marker_extra < "$launch_stop" || return 1
  [ "$marker_version" = V1 ] && [ "$marker_token" = "$token" ] && [ "$marker_value" = stop ] && [ -z "$marker_extra" ]
}

write_timeout_marker() {
  timeout_tmp="$control_dir/timeout.tmp.$$"
  printf 'V1 %s target_timeout\n' "$token" > "$timeout_tmp" || return 1
  mv -f "$timeout_tmp" "$control_dir/timeout"
}

__OWNED_SESSION_SCAN_SCRIPT__

trim_capture() {
  capture_path=$1
  truncated_path=$2
  capture_size=$(wc -c < "$capture_path" 2>/dev/null) || return 1
  if [ "$capture_size" -gt "$output_limit" ]; then
    tail -c "$output_limit" "$capture_path" > "$capture_path.trimmed" || return 1
    mv -f "$capture_path.trimmed" "$capture_path" || return 1
    printf '1\n' > "$truncated_path" || return 1
  else
    printf '0\n' > "$truncated_path" || return 1
  fi
}

clear_artifact_manifest() {
  rm -f "$control_dir/artifact_manifest" "$control_dir/artifact_count" "$control_dir/artifact_count.tmp" "$control_dir/artifact_error"
}

build_artifact_manifest() {
  artifact_manifest="$control_dir/artifact_manifest"
  artifact_count_file="$control_dir/artifact_count"
  artifact_error_file="$control_dir/artifact_error"
  clear_artifact_manifest
  : > "$artifact_manifest" || return 1
  printf '0\n' > "$artifact_count_file" || return 1

  find "$artifact_dir" -xdev -depth -mindepth 1 -maxdepth __ARTIFACT_SCAN_DEPTH__ \
    \( -exec sh -c '
      count_file=$1
      manifest=$2
      error_file=$3
      maximum=$4
      candidate=$5
      count=$(cat "$count_file" 2>/dev/null) || {
        printf "error\n" > "$error_file"
        exit 1
      }
      case "$count" in ""|*[!0-9]*)
        printf "error\n" > "$error_file"
        exit 1
      esac
      next=$((count + 1))
      printf "%s\n" "$next" > "$count_file.tmp" &&
        mv -f "$count_file.tmp" "$count_file" || {
          printf "error\n" > "$error_file"
          exit 1
        }
      [ "$next" -le "$maximum" ] || exit 1
      printf "%s\0" "$candidate" >> "$manifest" || {
        printf "error\n" > "$error_file"
        exit 1
      }
    ' managed-artifact-manifest "$artifact_count_file" "$artifact_manifest" "$artifact_error_file" __MAX_ARTIFACT_ENTRIES__ {} \; -o -quit \) || {
      clear_artifact_manifest
      return 1
    }
  artifact_count=$(cat "$artifact_count_file" 2>/dev/null) || artifact_count=
  if ! is_uint "$artifact_count" || [ "$artifact_count" -gt __MAX_ARTIFACT_ENTRIES__ ] || [ -e "$artifact_error_file" ]; then
    clear_artifact_manifest
    return 1
  fi
  return 0
}

load_artifact_transfer_identity() {
  execution_uid=$(id -u 2>/dev/null) || return 1
  execution_gid=$(id -g 2>/dev/null) || return 1
  is_uint "$execution_uid" && is_uint "$execution_gid" || return 1
  use_sudo_owner=0
  privileged_sudo_transfer=0
  sudo_uid=${SUDO_UID-}
  sudo_gid=${SUDO_GID-}
  if is_uint "$sudo_uid" && is_uint "$sudo_gid"; then
    use_sudo_owner=1
    if [ "$execution_uid" -eq 0 ] && [ "$sudo_uid" -ne "$execution_uid" ]; then
      privileged_sudo_transfer=1
    fi
  fi
}

load_directory_metadata() {
  directory_metadata=$(stat -c '%u:%g:%a:%f' -- "$1" 2>/dev/null) || return 1
  saved_ifs=$IFS
  IFS=:
  set -- $directory_metadata
  IFS=$saved_ifs
  [ "$#" -eq 4 ] || return 1
  directory_uid=$1
  directory_gid=$2
  directory_mode=$3
  directory_type=$4
  is_uint "$directory_uid" && is_uint "$directory_gid" || return 1
  case "$directory_mode" in
    [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;;
    *) return 1 ;;
  esac
  case "$directory_type" in
    ''|*[!0-9a-fA-F]*) return 1 ;;
  esac
  directory_mode_bits=$((0$directory_mode))
  directory_type_bits=$((0x$directory_type & 0xf000))
  [ "$directory_type_bits" -eq 16384 ]
}

validate_protected_remote_root_chain() {
  [ -n "$remote_root" ] && [ "${remote_root#/}" != "$remote_root" ] || return 1
  root_candidate=/
  root_remainder=${remote_root#/}
  trusted_root_uid=
  while :; do
    load_directory_metadata "$root_candidate" || return 1
    if [ "$root_candidate" = / ]; then
      trusted_root_uid=$directory_uid
    else
      [ "$directory_uid" = "$trusted_root_uid" ] ||
        [ "$directory_uid" = "$execution_uid" ] || return 1
    fi
    if [ $((directory_mode_bits & 01000)) -eq 0 ] &&
       [ $((directory_mode_bits & 00022)) -ne 0 ]; then
      return 1
    fi
    [ -n "$root_remainder" ] || return 0
    case "$root_remainder" in
      */*) root_component=${root_remainder%%/*}; root_remainder=${root_remainder#*/} ;;
      *) root_component=$root_remainder; root_remainder= ;;
    esac
    if [ "$root_candidate" = / ]; then
      root_candidate="/$root_component"
    else
      root_candidate="$root_candidate/$root_component"
    fi
  done
}

validate_private_directory() {
  load_directory_metadata "$1" || return 1
  [ "$directory_uid" = "$execution_uid" ] || return 1
  [ $((directory_mode_bits & 00700)) -eq 448 ] || return 1
  [ $((directory_mode_bits & 00077)) -eq 0 ]
}

validate_private_artifact_layout() {
  validate_protected_remote_root_chain || return 1
  validate_private_directory "$attempt_dir" || return 1
  validate_private_directory "$control_dir" || return 1
  validate_private_directory "$artifact_dir"
}

validate_attempt_directory() {
  load_directory_metadata "$attempt_dir" || return 1
  [ "$directory_uid" = "$execution_uid" ] || return 1
  [ "$directory_mode_bits" -eq 448 ] || [ "$directory_mode_bits" -eq 457 ]
}

validate_control_layout() {
  load_artifact_transfer_identity || return 1
  validate_protected_remote_root_chain || return 1
  validate_attempt_directory || return 1
  validate_private_directory "$control_dir"
}

valid_artifact_ready() {
  [ -f "$artifact_ready" ] && [ ! -L "$artifact_ready" ] || return 1
  IFS=' ' read -r ready_version ready_token ready_value ready_extra < "$artifact_ready" || return 1
  [ "$ready_version" = V1 ] && [ "$ready_token" = "$token" ] &&
    [ "$ready_value" = ready ] && [ -z "$ready_extra" ]
}

write_artifact_ready() {
  ready_tmp="$control_dir/artifact_ready.tmp.$$"
  printf 'V1 %s ready\n' "$token" > "$ready_tmp" || return 1
  mv -f "$ready_tmp" "$artifact_ready"
}

complete_ready_artifact_transfer() {
  valid_artifact_ready || return 1
  validate_protected_remote_root_chain || return 1
  validate_private_directory "$control_dir" || return 1
  load_directory_metadata "$attempt_dir" || return 1
  [ "$directory_uid" = "$execution_uid" ] || return 1
  attempt_mode_bits=$directory_mode_bits
  expected_artifact_uid=$execution_uid
  if [ "$use_sudo_owner" -eq 1 ]; then expected_artifact_uid=$sudo_uid; fi
  load_directory_metadata "$artifact_dir" || return 1
  [ "$directory_uid" = "$expected_artifact_uid" ] || return 1
  [ "$directory_mode_bits" -eq 448 ] || return 1
  if [ "$attempt_mode_bits" -eq 457 ]; then return 0; fi
  [ "$attempt_mode_bits" -eq 448 ] || return 1
  [ "$privileged_sudo_transfer" -eq 1 ] || return 0
  # This is the accessibility transition and must remain the final path
  # operation in the successful preparation path.
  chmod 711 -- "$attempt_dir"
}

prepare_artifacts() {
  load_artifact_transfer_identity || return 1
  if valid_artifact_ready; then
    complete_ready_artifact_transfer
    return $?
  fi
  validate_private_artifact_layout || return 1
  artifact_device=$(stat -c '%d' -- "$artifact_dir" 2>/dev/null) || return 1
  build_artifact_manifest || return 1

  xargs -0 -r -n 1 sh -c '
    root=$1
    root_device=$2
    change_owner=$3
    owner_uid=$4
    owner_gid=$5
    maximum_depth=$6
    candidate=$7
    case "$candidate" in "$root"/*) relative=${candidate#"$root"/} ;; *) exit 255 ;; esac
    [ -n "$relative" ] && [ ! -L "$candidate" ] || exit 255
    depth=1
    remainder=$relative
    while :; do
      case "$remainder" in
        */*) depth=$((depth + 1)); remainder=${remainder#*/} ;;
        *) break ;;
      esac
    done
    [ "$depth" -le "$maximum_depth" ] || exit 255
    candidate_metadata=$(stat -c "%d:%h:%f" -- "$candidate" 2>/dev/null) || exit 255
    saved_ifs=$IFS
    IFS=:
    set -- $candidate_metadata
    IFS=$saved_ifs
    [ "$#" -eq 3 ] || exit 255
    candidate_device=$1
    link_count=$2
    candidate_type=$3
    case "$candidate_type" in ""|*[!0-9a-fA-F]*) exit 255 ;; esac
    [ "$candidate_device" = "$root_device" ] || exit 255
    candidate_type_bits=$((0x$candidate_type & 0xf000))
    if [ "$candidate_type_bits" -eq 16384 ]; then
      if [ "$change_owner" -eq 1 ]; then chown --no-dereference -- "$owner_uid:$owner_gid" "$candidate" || exit 255; fi
      chmod 700 -- "$candidate" || exit 255
    elif [ "$candidate_type_bits" -eq 32768 ]; then
      [ "$link_count" = 1 ] || exit 255
      if [ "$change_owner" -eq 1 ]; then chown --no-dereference -- "$owner_uid:$owner_gid" "$candidate" || exit 255; fi
      chmod 600 -- "$candidate" || exit 255
    else
      exit 255
    fi
  ' managed-artifact-prepare "$artifact_dir" "$artifact_device" "$use_sudo_owner" "$sudo_uid" "$sudo_gid" __MAX_ARTIFACT_DEPTH__ < "$artifact_manifest"
  prepare_status=$?
  clear_artifact_manifest
  [ "$prepare_status" -eq 0 ] || return 1

  load_directory_metadata "$artifact_dir" || return 1
  artifact_original_uid=$directory_uid
  artifact_original_gid=$directory_gid
  artifact_original_mode=$directory_mode
  if [ "$use_sudo_owner" -eq 1 ]; then
    chown --no-dereference -- "$sudo_uid:$sudo_gid" "$artifact_dir" || return 1
  fi
  chmod 700 -- "$artifact_dir" || {
    chown --no-dereference -- "$artifact_original_uid:$artifact_original_gid" "$artifact_dir" 2>/dev/null || true
    chmod "$artifact_original_mode" -- "$artifact_dir" 2>/dev/null || true
    return 1
  }
  load_directory_metadata "$artifact_dir" || return 1
  expected_artifact_uid=$execution_uid
  expected_artifact_gid=$directory_gid
  if [ "$use_sudo_owner" -eq 1 ]; then
    expected_artifact_uid=$sudo_uid
    expected_artifact_gid=$sudo_gid
  fi
  if [ "$directory_uid" != "$expected_artifact_uid" ] ||
     [ "$directory_gid" != "$expected_artifact_gid" ] ||
     [ "$directory_mode_bits" -ne 448 ]; then
    chown --no-dereference -- "$artifact_original_uid:$artifact_original_gid" "$artifact_dir" 2>/dev/null || true
    chmod "$artifact_original_mode" -- "$artifact_dir" 2>/dev/null || true
    return 1
  fi
  write_artifact_ready || {
    chown --no-dereference -- "$artifact_original_uid:$artifact_original_gid" "$artifact_dir" 2>/dev/null || true
    chmod "$artifact_original_mode" -- "$artifact_dir" 2>/dev/null || true
    return 1
  }
  if [ "$privileged_sudo_transfer" -eq 0 ]; then return 0; fi
  # Make the attempt directory traversable only after protected changes.
  chmod 711 -- "$attempt_dir" || {
    rm -f "$artifact_ready" "$control_dir/artifact_ready.tmp.$$"
    chown --no-dereference -- "$artifact_original_uid:$artifact_original_gid" "$artifact_dir" 2>/dev/null || true
    chmod "$artifact_original_mode" -- "$artifact_dir" 2>/dev/null || true
    return 1
  }
  return 0
}

discard_artifacts_bounded() {
  load_artifact_transfer_identity || return 1
  if valid_artifact_ready; then
    validate_protected_remote_root_chain || return 1
    load_directory_metadata "$attempt_dir" || return 1
    [ "$directory_uid" = "$execution_uid" ] || return 1
    [ "$directory_mode_bits" -eq 448 ] || [ "$directory_mode_bits" -eq 457 ] || return 1
    validate_private_directory "$control_dir" || return 1
    chmod 700 -- "$attempt_dir" || return 1
    validate_private_directory "$attempt_dir" || return 1
    expected_artifact_uid=$execution_uid
    if [ "$use_sudo_owner" -eq 1 ]; then expected_artifact_uid=$sudo_uid; fi
    load_directory_metadata "$artifact_dir" || return 1
    [ "$directory_uid" = "$expected_artifact_uid" ] &&
      [ "$directory_mode_bits" -eq 448 ] || return 1
    chown --no-dereference -- "$execution_uid:$execution_gid" "$artifact_dir" || return 1
    chmod 700 -- "$artifact_dir" || return 1
    rm -f "$artifact_ready" "$control_dir/artifact_ready.tmp.$$" || return 1
  fi
  validate_private_artifact_layout || return 1
  artifact_device=$(stat -c '%d' -- "$artifact_dir" 2>/dev/null) || return 1
  build_artifact_manifest || return 1
  xargs -0 -r -n 1 sh -c '
    root=$1
    root_device=$2
    maximum_depth=$3
    candidate=$4
    case "$candidate" in "$root"/*) relative=${candidate#"$root"/} ;; *) exit 255 ;; esac
    [ -n "$relative" ] || exit 255
    depth=1
    remainder=$relative
    while :; do
      case "$remainder" in
        */*) depth=$((depth + 1)); remainder=${remainder#*/} ;;
        *) break ;;
      esac
    done
    [ "$depth" -le "$maximum_depth" ] || exit 255
    if [ -L "$candidate" ]; then
      rm -f -- "$candidate" || exit 255
      exit 0
    fi
    candidate_device=$(stat -c "%d" -- "$candidate" 2>/dev/null) || exit 255
    [ "$candidate_device" = "$root_device" ] || exit 255
    if [ -d "$candidate" ]; then
      rmdir -- "$candidate" || exit 255
    else
      rm -f -- "$candidate" || exit 255
    fi
  ' managed-artifact-discard "$artifact_dir" "$artifact_device" __MAX_ARTIFACT_DEPTH__ < "$artifact_manifest"
  discard_status=$?
  clear_artifact_manifest
  [ "$discard_status" -eq 0 ] || return 1
  rmdir -- "$artifact_dir"
}

cleanup_control() {
  validate_control_layout || return 1
  supervisor_pid=
  if load_identity; then supervisor_pid=$owned_pgid; fi
  deadline_owner_pid=
  if load_deadline_identity; then deadline_owner_pid=$deadline_pgid; fi
  rm -f "$control_dir/session_scan_owner_count" "$control_dir/session_scan_owner_count.tmp" "$control_dir/session_scan_owner_found" "$control_dir/session_scan_owner_error" "$control_dir/session_scan_owner_pids" "$control_dir/session_scan_primary_count" "$control_dir/session_scan_primary_count.tmp" "$control_dir/session_scan_primary_found" "$control_dir/session_scan_primary_error" "$control_dir/session_scan_primary_pids" "$control_dir/session_scan_reconcile_count" "$control_dir/session_scan_reconcile_count.tmp" "$control_dir/session_scan_reconcile_found" "$control_dir/session_scan_reconcile_error" "$control_dir/session_scan_reconcile_pids" || return 1
  clear_cgroup_child_manifest || return 1
  rm -f "$control_dir/cgroup_plan" "$control_dir/cgroup_plan.tmp.$$" \
    "$control_dir/cgroup_identity" "$control_dir/cgroup_identity.tmp.$$" || return 1
  rm -f "$control_dir/identity" "$control_dir/identity.tmp.$$" "$control_dir/deadline_identity" "$control_dir/deadline_identity.tmp.$$" "$control_dir/deadline_done" "$control_dir/deadline_done.tmp.$$" "$control_dir/done" "$control_dir/done.tmp.$$" "$control_dir/release" "$control_dir/release.tmp.$$" "$control_dir/timeout" "$control_dir/timeout.tmp.$$" "$control_dir/stop_watchdog" "$control_dir/stop_watchdog.tmp.$$" "$control_dir/stdout" "$control_dir/stderr" "$control_dir/stdout.trimmed" "$control_dir/stderr.trimmed" "$control_dir/stdout_truncated" "$control_dir/stderr_truncated" "$control_dir/receipt" "$control_dir/receipt.tmp.$$" "$artifact_ready" "$control_dir/artifact_ready.tmp.$$" "$stdout_fifo" "$stderr_fifo" || return 1
  if is_uint "$supervisor_pid"; then
    rm -f "$control_dir/identity.tmp.$supervisor_pid" "$control_dir/done.tmp.$supervisor_pid"
  fi
  if is_uint "$deadline_owner_pid"; then
    rm -f "$control_dir/cgroup_plan.tmp.$deadline_owner_pid" "$control_dir/deadline_identity.tmp.$deadline_owner_pid" "$control_dir/deadline_done.tmp.$deadline_owner_pid" "$control_dir/release.tmp.$deadline_owner_pid" "$control_dir/timeout.tmp.$deadline_owner_pid"
  fi
  rmdir "$control_dir" 2>/dev/null || return 1
  return 0
}

emit_receipt() {
  validate_control_layout || return 1
  outcome=$1
  exit_value=$2
  cleanup_status=$3
  stdout_truncated=$(cat "$control_dir/stdout_truncated" 2>/dev/null) || stdout_truncated=0
  stderr_truncated=$(cat "$control_dir/stderr_truncated" 2>/dev/null) || stderr_truncated=0
  stdout_b64=$(base64 "$stdout_file" 2>/dev/null | tr -d '\n') || stdout_b64=
  stderr_b64=$(base64 "$stderr_file" 2>/dev/null | tr -d '\n') || stderr_b64=
  receipt_tmp="$control_dir/receipt.tmp.$$"
  printf 'V1 %s %s %s %s\n' "$token" "$outcome" "$exit_value" "$cleanup_status" > "$receipt_tmp" || return 1
  mv -f "$receipt_tmp" "$control_dir/receipt" || return 1
  printf '%s\n' '__RECEIPT_BEGIN__'
  printf 'attempt_token=%s\n' "$token"
  printf 'outcome=%s\n' "$outcome"
  printf 'exit_code=%s\n' "$exit_value"
  printf 'cleanup=%s\n' "$cleanup_status"
  printf 'stdout_truncated=%s\n' "$stdout_truncated"
  printf 'stderr_truncated=%s\n' "$stderr_truncated"
  printf 'stdout_b64=%s\n' "$stdout_b64"
  printf 'stderr_b64=%s\n' "$stderr_b64"
  printf '%s\n' '__RECEIPT_END__'
}

emit_setup_failure() {
  printf '%s\n' '__RECEIPT_BEGIN__'
  printf 'attempt_token=%s\n' "$token"
  printf '%s\n' 'outcome=cleanup_unverified' 'exit_code=none' 'cleanup=unverified' 'stdout_truncated=0' 'stderr_truncated=0' 'stdout_b64=' 'stderr_b64='
  printf '%s\n' '__RECEIPT_END__'
}

for required_command in setsid tail base64 stat find xargs chmod chown pgrep id ls; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    emit_setup_failure
    exit 0
  fi
done
if [ "$containment" = cgroup_v2 ]; then
  for required_command in grep wc mkdir rmdir; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
      emit_setup_failure
      exit 0
    fi
  done
elif [ "$containment" != process_group ]; then
  emit_setup_failure
  exit 0
fi
case "$prepare_on" in 0|1|2|3) ;; *) emit_setup_failure; exit 0 ;; esac
if ! load_artifact_transfer_identity || ! validate_protected_remote_root_chain; then
  emit_setup_failure
  exit 0
fi
if [ -e "$attempt_dir" ] || ! mkdir -m 700 "$attempt_dir"; then
  emit_setup_failure
  exit 0
fi
if valid_launch_stop; then
  # Reconciliation owns this token-bound launch barrier.  Keep the top-level
  # reservation until every potentially late remote command has settled.
  emit_setup_failure
  exit 0
fi
if ! mkdir -m 700 "$control_dir" "$artifact_dir" || ! mkfifo -m 600 "$stdout_fifo" "$stderr_fifo"; then
  rm -f "$stdout_fifo" "$stderr_fifo"
  rmdir "$control_dir" "$artifact_dir" 2>/dev/null
  emit_setup_failure
  exit 0
fi
if valid_launch_stop; then
  rm -f "$stdout_fifo" "$stderr_fifo" "$control_dir/stop_watchdog" "$control_dir/stop_watchdog.tmp.$$"
  rmdir "$control_dir" "$artifact_dir" 2>/dev/null
  # Do not remove launch_stop or attempt_dir: reconcile may still be resolving
  # this exact token, and vacating it would permit an attacker replacement.
  emit_setup_failure
  exit 0
fi

setsid sh -c "$deadline_script" managed-deadline-owner "$token" "$control_dir" "$artifact_dir" "$payload" "$target_timeout" "$term_grace" "$kill_grace" "$launch_grace" "$target_script" "$stdout_fifo" "$stderr_fifo" "$stdout_file" "$stderr_file" "$capture_keep" "$launch_stop" "$containment" < /dev/null > /dev/null 2>&1 &
deadline_owner_pid=$!
wait "$deadline_owner_pid" 2>/dev/null || true
rm -f "$stdout_fifo" "$stderr_fifo"
trim_capture "$stdout_file" "$control_dir/stdout_truncated" || true
trim_capture "$stderr_file" "$control_dir/stderr_truncated" || true

cleanup_status=unverified
expected_deadline_status=
if load_identity; then
  if { [ "$containment" = cgroup_v2 ] && cgroup_leaf_is_absent; } ||
     { [ "$containment" = process_group ] && wait_for_group_absence "$kill_grace"; }; then
    cleanup_status=verified_absent
    expected_deadline_status=verified_absent
  else
    cleanup_status=failed
  fi
elif valid_deadline_done && [ "$deadline_done_status" = no_target ]; then
  if { [ "$containment" = cgroup_v2 ] && cgroup_leaf_is_absent; } ||
     [ "$containment" = process_group ]; then
    cleanup_status=verified_absent
    expected_deadline_status=no_target
  else
    cleanup_status=failed
  fi
fi
if [ "$cleanup_status" = verified_absent ]; then
  if ! valid_deadline_done || [ "$deadline_done_status" != "$expected_deadline_status" ] || ! deadline_group_is_absent; then
    cleanup_status=failed
  fi
fi

if [ "$cleanup_status" != verified_absent ]; then
  emit_receipt cleanup_unverified none "$cleanup_status" || true
  exit 0
fi
if valid_marker "$control_dir/timeout" timeout; then
  outcome=target_timeout
  exit_value=none
elif valid_marker "$control_dir/done" done; then
  target_exit=$marker_value
  if [ "$target_exit" -eq 0 ]; then outcome=success; else outcome=nonzero_exit; fi
  exit_value=$target_exit
else
  outcome=transport_error
  exit_value=none
fi
if [ "$outcome" = success ]; then
  prepare_artifacts || { outcome=transport_error; exit_value=none; }
else
  case "$outcome:$prepare_on" in
    target_timeout:1|target_timeout:3|nonzero_exit:2|nonzero_exit:3)
      prepare_artifacts || true ;;
  esac
fi
emit_receipt "$outcome" "$exit_value" verified_absent || true
if [ "$outcome" = transport_error ]; then discard_artifacts_bounded || true; fi
if cleanup_control; then
  if [ "$outcome" = target_timeout ] || [ "$outcome" = transport_error ]; then
    rmdir "$artifact_dir" 2>/dev/null || true
  fi
fi
exit 0
"""
_PRIMARY_WRAPPER_SCRIPT = (
    _PRIMARY_WRAPPER_SCRIPT.replace(
        "__OWNED_SESSION_SCAN_SCRIPT__", _OWNED_SESSION_SCAN_SCRIPT
    )
    .replace("__SESSION_SCAN_TAG__", "primary")
    .replace("__SESSION_SCAN_ROOT__", '"$attempt_dir"')
    .replace("__MAX_SESSION_SCAN_PROCESSES__", str(_MAX_SESSION_SCAN_PROCESSES))
    .replace("__CGROUP_V2_COMMON_SCRIPT__", _CGROUP_V2_COMMON_SCRIPT)
    .replace("__MAX_ARTIFACT_ENTRIES__", str(_MAX_ARTIFACT_ENTRIES))
    .replace("__MAX_ARTIFACT_DEPTH__", str(_MAX_ARTIFACT_DEPTH))
    .replace("__ARTIFACT_SCAN_DEPTH__", str(_MAX_ARTIFACT_DEPTH + 1))
    .replace("__RECEIPT_BEGIN__", _RECEIPT_BEGIN)
    .replace("__RECEIPT_END__", _RECEIPT_END)
)


_RECONCILE_SCRIPT = r"""
set +e
token=$1
attempt_dir=$2
term_grace=$3
kill_grace=$4
output_limit=$5
identity_wait=$6
discard_artifacts=$7
cleanup_grace=$8
containment=${9:-process_group}
artifact_dir="$attempt_dir/artifacts"
control_dir="$attempt_dir/.control"
launch_stop="$attempt_dir/.launch_stop"
artifact_ready="$control_dir/artifact_ready"
remote_root=${attempt_dir%/*}
stdout_file="$control_dir/stdout"
stderr_file="$control_dir/stderr"
umask 077

is_uint() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; return 0; }

__CGROUP_V2_COMMON_SCRIPT__

read_start_fields() {
  stat_line=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
  stat_tail=${stat_line##*) }
  set -f
  set -- $stat_tail
  set +f
  [ "$#" -ge 20 ] || return 1
  observed_state=$1
  observed_group=$3
  observed_session=$4
  observed_start=${20}
}

load_identity() {
  [ -d "$attempt_dir" ] && [ ! -L "$attempt_dir" ] || return 1
  [ -d "$control_dir" ] && [ ! -L "$control_dir" ] || return 1
  [ -f "$control_dir/identity" ] && [ ! -L "$control_dir/identity" ] || return 1
  IFS=' ' read -r identity_version identity_token owned_pgid owned_start owned_session identity_extra < "$control_dir/identity" || return 1
  [ "$identity_version" = V1 ] && [ "$identity_token" = "$token" ] && [ -z "$identity_extra" ] || return 1
  is_uint "$owned_pgid" && is_uint "$owned_start" && is_uint "$owned_session" || return 1
  [ "$owned_pgid" -gt 1 ] && [ "$owned_start" -gt 0 ] && [ "$owned_session" = "$owned_pgid" ] || return 1
}

load_deadline_identity() {
  [ -d "$attempt_dir" ] && [ ! -L "$attempt_dir" ] || return 1
  [ -d "$control_dir" ] && [ ! -L "$control_dir" ] || return 1
  [ -f "$control_dir/deadline_identity" ] && [ ! -L "$control_dir/deadline_identity" ] || return 1
  IFS=' ' read -r deadline_version deadline_token deadline_pgid deadline_start deadline_session deadline_extra < "$control_dir/deadline_identity" || return 1
  [ "$deadline_version" = V1 ] && [ "$deadline_token" = "$token" ] && [ -z "$deadline_extra" ] || return 1
  is_uint "$deadline_pgid" && is_uint "$deadline_start" && is_uint "$deadline_session" || return 1
  [ "$deadline_pgid" -gt 1 ] && [ "$deadline_start" -gt 0 ] && [ "$deadline_session" = "$deadline_pgid" ] || return 1
}

identity_is_live() {
  load_identity || return 1
  read_start_fields "$owned_pgid" || return 1
  [ "$observed_group" = "$owned_pgid" ] && [ "$observed_session" = "$owned_session" ] && [ "$observed_start" = "$owned_start" ] || return 1
  return 0
}

owned_session_leader_is_running() {
  identity_is_live || return 1
  [ "$observed_state" != Z ]
}

deadline_group_is_absent() {
  load_deadline_identity || return 2
  pgrep -g "$deadline_pgid" >/dev/null 2>&1
  deadline_group_status=$?
  if [ "$deadline_group_status" -eq 1 ]; then return 0; fi
  if [ "$deadline_group_status" -eq 0 ]; then return 1; fi
  return 2
}

__OWNED_SESSION_SCAN_SCRIPT__

valid_marker() {
  marker_path=$1
  marker_kind=$2
  [ -f "$marker_path" ] && [ ! -L "$marker_path" ] || return 1
  IFS=' ' read -r marker_version marker_token marker_value marker_extra < "$marker_path" || return 1
  [ "$marker_version" = V1 ] && [ "$marker_token" = "$token" ] && [ -z "$marker_extra" ] || return 1
  if [ "$marker_kind" = done ]; then
    is_uint "$marker_value" && [ "$marker_value" -le 255 ] || return 1
  else
    [ "$marker_value" = target_timeout ] || return 1
  fi
}

valid_deadline_done() {
  [ -f "$control_dir/deadline_done" ] && [ ! -L "$control_dir/deadline_done" ] || return 1
  IFS=' ' read -r deadline_done_version deadline_done_token deadline_done_status deadline_done_extra < "$control_dir/deadline_done" || return 1
  [ "$deadline_done_version" = V1 ] && [ "$deadline_done_token" = "$token" ] && [ -z "$deadline_done_extra" ] || return 1
  case "$deadline_done_status" in
    verified_absent|no_target|failed) return 0 ;;
    *) return 1 ;;
  esac
}

write_release_marker() {
  release_tmp="$control_dir/release.tmp.$$"
  printf 'V1 %s release\n' "$token" > "$release_tmp" || return 1
  mv -f "$release_tmp" "$control_dir/release"
}

write_stop_watchdog_marker() {
  stop_tmp="$control_dir/stop_watchdog.tmp.$$"
  printf 'V1 %s stop\n' "$token" > "$stop_tmp" || return 1
  mv -f "$stop_tmp" "$control_dir/stop_watchdog"
}

valid_launch_stop() {
  [ -f "$launch_stop" ] && [ ! -L "$launch_stop" ] || return 1
  IFS=' ' read -r stop_version stop_token stop_value stop_extra < "$launch_stop" || return 1
  [ "$stop_version" = V1 ] && [ "$stop_token" = "$token" ] &&
    [ "$stop_value" = stop ] && [ -z "$stop_extra" ]
}

write_launch_stop_marker() {
  stop_tmp="$attempt_dir/.launch_stop.tmp.$$"
  printf 'V1 %s stop\n' "$token" > "$stop_tmp" || return 1
  mv -f "$stop_tmp" "$launch_stop"
}

trim_capture() {
  capture_path=$1
  truncated_path=$2
  if [ ! -f "$capture_path" ] || [ -L "$capture_path" ]; then : > "$capture_path"; fi
  capture_size=$(wc -c < "$capture_path" 2>/dev/null) || return 1
  if [ "$capture_size" -gt "$output_limit" ]; then
    tail -c "$output_limit" "$capture_path" > "$capture_path.trimmed" || return 1
    mv -f "$capture_path.trimmed" "$capture_path" || return 1
    printf '1\n' > "$truncated_path"
  else
    printf '0\n' > "$truncated_path"
  fi
}

clear_artifact_manifest() {
  rm -f "$control_dir/artifact_manifest" "$control_dir/artifact_count" "$control_dir/artifact_count.tmp" "$control_dir/artifact_error"
}

build_artifact_manifest() {
  artifact_manifest="$control_dir/artifact_manifest"
  artifact_count_file="$control_dir/artifact_count"
  artifact_error_file="$control_dir/artifact_error"
  clear_artifact_manifest
  : > "$artifact_manifest" || return 1
  printf '0\n' > "$artifact_count_file" || return 1
  find "$artifact_dir" -xdev -depth -mindepth 1 -maxdepth __ARTIFACT_SCAN_DEPTH__ \
    \( -exec sh -c '
      count_file=$1
      manifest=$2
      error_file=$3
      maximum=$4
      candidate=$5
      count=$(cat "$count_file" 2>/dev/null) || {
        printf "error\n" > "$error_file"
        exit 1
      }
      case "$count" in ""|*[!0-9]*)
        printf "error\n" > "$error_file"
        exit 1
      esac
      next=$((count + 1))
      printf "%s\n" "$next" > "$count_file.tmp" &&
        mv -f "$count_file.tmp" "$count_file" || {
          printf "error\n" > "$error_file"
          exit 1
        }
      [ "$next" -le "$maximum" ] || exit 1
      printf "%s\0" "$candidate" >> "$manifest" || {
        printf "error\n" > "$error_file"
        exit 1
      }
    ' managed-artifact-manifest "$artifact_count_file" "$artifact_manifest" "$artifact_error_file" __MAX_ARTIFACT_ENTRIES__ {} \; -o -quit \) || {
      clear_artifact_manifest
      return 1
    }
  artifact_count=$(cat "$artifact_count_file" 2>/dev/null) || artifact_count=
  if ! is_uint "$artifact_count" || [ "$artifact_count" -gt __MAX_ARTIFACT_ENTRIES__ ] || [ -e "$artifact_error_file" ]; then
    clear_artifact_manifest
    return 1
  fi
  return 0
}

load_artifact_transfer_identity() {
  execution_uid=$(id -u 2>/dev/null) || return 1
  execution_gid=$(id -g 2>/dev/null) || return 1
  is_uint "$execution_uid" && is_uint "$execution_gid" || return 1
  use_sudo_owner=0
  privileged_sudo_transfer=0
  sudo_uid=${SUDO_UID-}
  sudo_gid=${SUDO_GID-}
  if is_uint "$sudo_uid" && is_uint "$sudo_gid"; then
    use_sudo_owner=1
    if [ "$execution_uid" -eq 0 ] && [ "$sudo_uid" -ne "$execution_uid" ]; then
      privileged_sudo_transfer=1
    fi
  fi
}

load_directory_metadata() {
  directory_metadata=$(stat -c '%u:%g:%a:%f' -- "$1" 2>/dev/null) || return 1
  saved_ifs=$IFS
  IFS=:
  set -- $directory_metadata
  IFS=$saved_ifs
  [ "$#" -eq 4 ] || return 1
  directory_uid=$1
  directory_gid=$2
  directory_mode=$3
  directory_type=$4
  is_uint "$directory_uid" && is_uint "$directory_gid" || return 1
  case "$directory_mode" in
    [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;;
    *) return 1 ;;
  esac
  case "$directory_type" in
    ''|*[!0-9a-fA-F]*) return 1 ;;
  esac
  directory_mode_bits=$((0$directory_mode))
  directory_type_bits=$((0x$directory_type & 0xf000))
  [ "$directory_type_bits" -eq 16384 ]
}

validate_protected_remote_root_chain() {
  [ -n "$remote_root" ] && [ "${remote_root#/}" != "$remote_root" ] || return 1
  root_candidate=/
  root_remainder=${remote_root#/}
  trusted_root_uid=
  while :; do
    load_directory_metadata "$root_candidate" || return 1
    if [ "$root_candidate" = / ]; then
      trusted_root_uid=$directory_uid
    else
      [ "$directory_uid" = "$trusted_root_uid" ] ||
        [ "$directory_uid" = "$execution_uid" ] || return 1
    fi
    if [ $((directory_mode_bits & 01000)) -eq 0 ] &&
       [ $((directory_mode_bits & 00022)) -ne 0 ]; then
      return 1
    fi
    [ -n "$root_remainder" ] || return 0
    case "$root_remainder" in
      */*) root_component=${root_remainder%%/*}; root_remainder=${root_remainder#*/} ;;
      *) root_component=$root_remainder; root_remainder= ;;
    esac
    if [ "$root_candidate" = / ]; then
      root_candidate="/$root_component"
    else
      root_candidate="$root_candidate/$root_component"
    fi
  done
}

validate_private_directory() {
  load_directory_metadata "$1" || return 1
  [ "$directory_uid" = "$execution_uid" ] || return 1
  [ $((directory_mode_bits & 00700)) -eq 448 ] || return 1
  [ $((directory_mode_bits & 00077)) -eq 0 ]
}

validate_private_artifact_layout() {
  validate_protected_remote_root_chain || return 1
  validate_private_directory "$attempt_dir" || return 1
  validate_private_directory "$control_dir" || return 1
  validate_private_directory "$artifact_dir"
}

validate_attempt_directory() {
  load_directory_metadata "$attempt_dir" || return 1
  [ "$directory_uid" = "$execution_uid" ] || return 1
  [ "$directory_mode_bits" -eq 448 ] || [ "$directory_mode_bits" -eq 457 ]
}

validate_control_layout() {
  load_artifact_transfer_identity || return 1
  validate_protected_remote_root_chain || return 1
  validate_attempt_directory || return 1
  validate_private_directory "$control_dir"
}

valid_artifact_ready() {
  [ -f "$artifact_ready" ] && [ ! -L "$artifact_ready" ] || return 1
  IFS=' ' read -r ready_version ready_token ready_value ready_extra < "$artifact_ready" || return 1
  [ "$ready_version" = V1 ] && [ "$ready_token" = "$token" ] &&
    [ "$ready_value" = ready ] && [ -z "$ready_extra" ]
}

write_artifact_ready() {
  ready_tmp="$control_dir/artifact_ready.tmp.$$"
  printf 'V1 %s ready\n' "$token" > "$ready_tmp" || return 1
  mv -f "$ready_tmp" "$artifact_ready"
}

complete_ready_artifact_transfer() {
  valid_artifact_ready || return 1
  validate_protected_remote_root_chain || return 1
  validate_private_directory "$control_dir" || return 1
  load_directory_metadata "$attempt_dir" || return 1
  [ "$directory_uid" = "$execution_uid" ] || return 1
  attempt_mode_bits=$directory_mode_bits
  expected_artifact_uid=$execution_uid
  if [ "$use_sudo_owner" -eq 1 ]; then expected_artifact_uid=$sudo_uid; fi
  load_directory_metadata "$artifact_dir" || return 1
  [ "$directory_uid" = "$expected_artifact_uid" ] || return 1
  [ "$directory_mode_bits" -eq 448 ] || return 1
  if [ "$attempt_mode_bits" -eq 457 ]; then return 0; fi
  [ "$attempt_mode_bits" -eq 448 ] || return 1
  [ "$privileged_sudo_transfer" -eq 1 ] || return 0
  # This is the accessibility transition and must remain the final path
  # operation in the successful preparation path.
  chmod 711 -- "$attempt_dir"
}

prepare_artifacts() {
  load_artifact_transfer_identity || return 1
  if valid_artifact_ready; then
    complete_ready_artifact_transfer
    return $?
  fi
  validate_private_artifact_layout || return 1
  artifact_device=$(stat -c '%d' -- "$artifact_dir" 2>/dev/null) || return 1
  build_artifact_manifest || return 1
  xargs -0 -r -n 1 sh -c '
    root=$1
    root_device=$2
    change_owner=$3
    owner_uid=$4
    owner_gid=$5
    maximum_depth=$6
    candidate=$7
    case "$candidate" in "$root"/*) relative=${candidate#"$root"/} ;; *) exit 255 ;; esac
    [ -n "$relative" ] && [ ! -L "$candidate" ] || exit 255
    depth=1
    remainder=$relative
    while :; do
      case "$remainder" in
        */*) depth=$((depth + 1)); remainder=${remainder#*/} ;;
        *) break ;;
      esac
    done
    [ "$depth" -le "$maximum_depth" ] || exit 255
    candidate_metadata=$(stat -c "%d:%h:%f" -- "$candidate" 2>/dev/null) || exit 255
    saved_ifs=$IFS
    IFS=:
    set -- $candidate_metadata
    IFS=$saved_ifs
    [ "$#" -eq 3 ] || exit 255
    candidate_device=$1
    link_count=$2
    candidate_type=$3
    case "$candidate_type" in ""|*[!0-9a-fA-F]*) exit 255 ;; esac
    [ "$candidate_device" = "$root_device" ] || exit 255
    candidate_type_bits=$((0x$candidate_type & 0xf000))
    if [ "$candidate_type_bits" -eq 16384 ]; then
      if [ "$change_owner" -eq 1 ]; then chown --no-dereference -- "$owner_uid:$owner_gid" "$candidate" || exit 255; fi
      chmod 700 -- "$candidate" || exit 255
    elif [ "$candidate_type_bits" -eq 32768 ]; then
      [ "$link_count" = 1 ] || exit 255
      if [ "$change_owner" -eq 1 ]; then chown --no-dereference -- "$owner_uid:$owner_gid" "$candidate" || exit 255; fi
      chmod 600 -- "$candidate" || exit 255
    else
      exit 255
    fi
  ' managed-artifact-prepare "$artifact_dir" "$artifact_device" "$use_sudo_owner" "$sudo_uid" "$sudo_gid" __MAX_ARTIFACT_DEPTH__ < "$artifact_manifest"
  prepare_status=$?
  clear_artifact_manifest
  [ "$prepare_status" -eq 0 ] || return 1

  load_directory_metadata "$artifact_dir" || return 1
  artifact_original_uid=$directory_uid
  artifact_original_gid=$directory_gid
  artifact_original_mode=$directory_mode
  if [ "$use_sudo_owner" -eq 1 ]; then
    chown --no-dereference -- "$sudo_uid:$sudo_gid" "$artifact_dir" || return 1
  fi
  chmod 700 -- "$artifact_dir" || {
    chown --no-dereference -- "$artifact_original_uid:$artifact_original_gid" "$artifact_dir" 2>/dev/null || true
    chmod "$artifact_original_mode" -- "$artifact_dir" 2>/dev/null || true
    return 1
  }
  load_directory_metadata "$artifact_dir" || return 1
  expected_artifact_uid=$execution_uid
  expected_artifact_gid=$directory_gid
  if [ "$use_sudo_owner" -eq 1 ]; then
    expected_artifact_uid=$sudo_uid
    expected_artifact_gid=$sudo_gid
  fi
  if [ "$directory_uid" != "$expected_artifact_uid" ] ||
     [ "$directory_gid" != "$expected_artifact_gid" ] ||
     [ "$directory_mode_bits" -ne 448 ]; then
    chown --no-dereference -- "$artifact_original_uid:$artifact_original_gid" "$artifact_dir" 2>/dev/null || true
    chmod "$artifact_original_mode" -- "$artifact_dir" 2>/dev/null || true
    return 1
  fi
  write_artifact_ready || {
    chown --no-dereference -- "$artifact_original_uid:$artifact_original_gid" "$artifact_dir" 2>/dev/null || true
    chmod "$artifact_original_mode" -- "$artifact_dir" 2>/dev/null || true
    return 1
  }
  if [ "$privileged_sudo_transfer" -eq 0 ]; then return 0; fi
  # Do not add artifact/control path operations after this transition.  The
  # invoking account can traverse the root-owned attempt directory afterward,
  # but cannot rename either protected child entry.
  chmod 711 -- "$attempt_dir" || {
    rm -f "$artifact_ready" "$control_dir/artifact_ready.tmp.$$"
    chown --no-dereference -- "$artifact_original_uid:$artifact_original_gid" "$artifact_dir" 2>/dev/null || true
    chmod "$artifact_original_mode" -- "$artifact_dir" 2>/dev/null || true
    return 1
  }
  return 0
}

discard_artifacts_bounded() {
  load_artifact_transfer_identity || return 1
  if valid_artifact_ready; then
    validate_protected_remote_root_chain || return 1
    load_directory_metadata "$attempt_dir" || return 1
    [ "$directory_uid" = "$execution_uid" ] || return 1
    [ "$directory_mode_bits" -eq 448 ] || [ "$directory_mode_bits" -eq 457 ] || return 1
    validate_private_directory "$control_dir" || return 1
    chmod 700 -- "$attempt_dir" || return 1
    validate_private_directory "$attempt_dir" || return 1
    expected_artifact_uid=$execution_uid
    if [ "$use_sudo_owner" -eq 1 ]; then expected_artifact_uid=$sudo_uid; fi
    load_directory_metadata "$artifact_dir" || return 1
    [ "$directory_uid" = "$expected_artifact_uid" ] &&
      [ "$directory_mode_bits" -eq 448 ] || return 1
    chown --no-dereference -- "$execution_uid:$execution_gid" "$artifact_dir" || return 1
    chmod 700 -- "$artifact_dir" || return 1
    rm -f "$artifact_ready" "$control_dir/artifact_ready.tmp.$$" || return 1
  fi
  validate_private_artifact_layout || return 1
  artifact_device=$(stat -c '%d' -- "$artifact_dir" 2>/dev/null) || return 1
  build_artifact_manifest || return 1
  xargs -0 -r -n 1 sh -c '
    root=$1
    root_device=$2
    maximum_depth=$3
    candidate=$4
    case "$candidate" in "$root"/*) relative=${candidate#"$root"/} ;; *) exit 255 ;; esac
    [ -n "$relative" ] || exit 255
    depth=1
    remainder=$relative
    while :; do
      case "$remainder" in
        */*) depth=$((depth + 1)); remainder=${remainder#*/} ;;
        *) break ;;
      esac
    done
    [ "$depth" -le "$maximum_depth" ] || exit 255
    if [ -L "$candidate" ]; then
      rm -f -- "$candidate" || exit 255
      exit 0
    fi
    candidate_device=$(stat -c "%d" -- "$candidate" 2>/dev/null) || exit 255
    [ "$candidate_device" = "$root_device" ] || exit 255
    if [ -d "$candidate" ]; then
      rmdir -- "$candidate" || exit 255
    else
      rm -f -- "$candidate" || exit 255
    fi
  ' managed-artifact-discard "$artifact_dir" "$artifact_device" __MAX_ARTIFACT_DEPTH__ < "$artifact_manifest"
  discard_status=$?
  clear_artifact_manifest
  [ "$discard_status" -eq 0 ] || return 1
  rmdir -- "$artifact_dir"
}

emit_receipt() {
  validate_control_layout || return 1
  outcome=$1
  exit_value=$2
  cleanup_status=$3
  trim_capture "$stdout_file" "$control_dir/stdout_truncated" || return 1
  trim_capture "$stderr_file" "$control_dir/stderr_truncated" || return 1
  stdout_truncated=$(cat "$control_dir/stdout_truncated")
  stderr_truncated=$(cat "$control_dir/stderr_truncated")
  stdout_b64=$(base64 "$stdout_file" 2>/dev/null | tr -d '\n') || return 1
  stderr_b64=$(base64 "$stderr_file" 2>/dev/null | tr -d '\n') || return 1
  printf '%s\n' '__RECEIPT_BEGIN__'
  printf 'attempt_token=%s\n' "$token"
  printf 'outcome=%s\n' "$outcome"
  printf 'exit_code=%s\n' "$exit_value"
  printf 'cleanup=%s\n' "$cleanup_status"
  printf 'stdout_truncated=%s\n' "$stdout_truncated"
  printf 'stderr_truncated=%s\n' "$stderr_truncated"
  printf 'stdout_b64=%s\n' "$stdout_b64"
  printf 'stderr_b64=%s\n' "$stderr_b64"
  printf '%s\n' '__RECEIPT_END__'
}

cleanup_control() {
  validate_control_layout || return 1
  supervisor_pid=
  if load_identity; then supervisor_pid=$owned_pgid; fi
  deadline_owner_pid=
  if load_deadline_identity; then deadline_owner_pid=$deadline_pgid; fi
  rm -f "$control_dir/session_scan_owner_count" "$control_dir/session_scan_owner_count.tmp" "$control_dir/session_scan_owner_found" "$control_dir/session_scan_owner_error" "$control_dir/session_scan_owner_pids" "$control_dir/session_scan_primary_count" "$control_dir/session_scan_primary_count.tmp" "$control_dir/session_scan_primary_found" "$control_dir/session_scan_primary_error" "$control_dir/session_scan_primary_pids" "$control_dir/session_scan_reconcile_count" "$control_dir/session_scan_reconcile_count.tmp" "$control_dir/session_scan_reconcile_found" "$control_dir/session_scan_reconcile_error" "$control_dir/session_scan_reconcile_pids" || return 1
  clear_cgroup_child_manifest || return 1
  rm -f "$control_dir/cgroup_plan" "$control_dir/cgroup_plan.tmp.$$" \
    "$control_dir/cgroup_identity" "$control_dir/cgroup_identity.tmp.$$" || return 1
  rm -f "$control_dir/identity" "$control_dir/identity.tmp.$$" "$control_dir/deadline_identity" "$control_dir/deadline_identity.tmp.$$" "$control_dir/deadline_done" "$control_dir/deadline_done.tmp.$$" "$control_dir/done" "$control_dir/done.tmp.$$" "$control_dir/release" "$control_dir/release.tmp.$$" "$control_dir/timeout" "$control_dir/timeout.tmp.$$" "$control_dir/stop_watchdog" "$control_dir/stop_watchdog.tmp.$$" "$control_dir/stdout" "$control_dir/stderr" "$control_dir/stdout.trimmed" "$control_dir/stderr.trimmed" "$control_dir/stdout_truncated" "$control_dir/stderr_truncated" "$control_dir/receipt" "$control_dir/receipt.tmp.$$" "$artifact_ready" "$control_dir/artifact_ready.tmp.$$" "$control_dir/stdout.fifo" "$control_dir/stderr.fifo" || return 1
  if is_uint "$supervisor_pid"; then
    rm -f "$control_dir/identity.tmp.$supervisor_pid" "$control_dir/done.tmp.$supervisor_pid"
  fi
  if is_uint "$deadline_owner_pid"; then
    rm -f "$control_dir/cgroup_plan.tmp.$deadline_owner_pid" "$control_dir/deadline_identity.tmp.$deadline_owner_pid" "$control_dir/deadline_done.tmp.$deadline_owner_pid" "$control_dir/release.tmp.$deadline_owner_pid" "$control_dir/timeout.tmp.$deadline_owner_pid"
  fi
  rmdir "$control_dir" 2>/dev/null || return 1
  return 0
}

emit_unverified() {
  printf '%s\n' '__RECEIPT_BEGIN__'
  printf 'attempt_token=%s\n' "$token"
  printf '%s\n' 'outcome=cleanup_unverified' 'exit_code=none' 'cleanup=unverified' 'stdout_truncated=0' 'stderr_truncated=0' 'stdout_b64=' 'stderr_b64='
  printf '%s\n' '__RECEIPT_END__'
}

emit_reserved_unverified() {
  printf '%s\n' '__RECEIPT_BEGIN__'
  printf 'attempt_token=%s\n' "$token"
  printf '%s\n' 'outcome=cleanup_unverified' 'exit_code=none' 'cleanup=unverified' 'stdout_truncated=0' 'stderr_truncated=0' 'stdout_b64=' 'stderr_b64='
  printf '%s\n' '__RECEIPT_END__'
}

if [ "$discard_artifacts" != 0 ] && [ "$discard_artifacts" != 1 ]; then
  emit_unverified
  exit 0
fi
for required_command in pgrep stat find xargs chmod chown id ls; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    emit_unverified
    exit 0
  fi
done
if [ "$containment" = cgroup_v2 ]; then
  for required_command in grep wc mkdir rmdir; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
      emit_unverified
      exit 0
    fi
  done
elif [ "$containment" != process_group ]; then
  emit_unverified
  exit 0
fi
if ! load_artifact_transfer_identity || ! validate_protected_remote_root_chain; then
  emit_unverified
  exit 0
fi

# Atomically reserve an as-yet absent exact-token path.  The primary wrapper's
# mkdir must then fail before it can launch an owner.  Keep this small launch
# tombstone in place because removing it before the original submit settles
# would reopen the late-delivery race.
if mkdir -m 700 "$attempt_dir" 2>/dev/null; then
  write_launch_stop_marker || {
    emit_unverified
    exit 0
  }
  emit_reserved_unverified
  exit 0
fi
if [ ! -d "$attempt_dir" ] || [ -L "$attempt_dir" ]; then
  emit_unverified
  exit 0
fi
if ! validate_attempt_directory; then
  emit_unverified
  exit 0
fi
if [ -e "$control_dir" ] || [ -L "$control_dir" ]; then
  if ! validate_private_directory "$control_dir"; then
    emit_unverified
    exit 0
  fi
fi

# If primary setup won mkdir, publish the top-level stop before waiting for
# either control directory or detached-owner identity.  The primary wrapper,
# owner, and target supervisor all check this token-bound barrier at their
# launch boundaries.
write_launch_stop_marker || {
  emit_unverified
  exit 0
}
if [ -d "$control_dir" ] && [ ! -L "$control_dir" ]; then
  write_stop_watchdog_marker || {
    emit_unverified
    exit 0
  }
fi

remaining=$identity_wait
while ! load_deadline_identity && [ "$remaining" -gt 0 ]; do
  sleep 1
  remaining=$((remaining - 1))
done
if ! load_deadline_identity; then
  emit_unverified
  exit 0
fi

if [ "$containment" = cgroup_v2 ]; then
  cgroup_cleanup_ok=0
  remaining=$identity_wait
  while ! load_cgroup_identity && [ "$remaining" -gt 0 ]; do
    sleep 1
    remaining=$((remaining - 1))
  done
  if load_cgroup_identity; then
    cgroup_leaf_is_absent
    cgroup_absent_status=$?
    if [ "$cgroup_absent_status" -eq 0 ]; then
      cgroup_cleanup_ok=1
    elif [ "$cgroup_absent_status" -eq 1 ]; then
      owned_session_authorized=0
      if stop_owned_cgroup stop; then cgroup_cleanup_ok=1; fi
    fi
  elif load_cgroup_plan; then
    # A plan without a full identity authorizes no mutation.  It can only
    # prove that setup never created the deterministic leaf, allowing bounded
    # control cleanup without adopting a colliding or substituted cgroup.
    planned_cgroup_leaf_is_absent
    if [ "$?" -eq 0 ]; then cgroup_cleanup_ok=1; fi
  fi

  # Direct cgroup cleanup above already consumed the TERM/KILL windows.  Only
  # the independently owned wrapper's final verification grace remains here,
  # keeping reconciliation within the governed cleanup timeout.
  remaining=$cleanup_grace
  while [ "$remaining" -gt 0 ]; do
    deadline_group_is_absent
    deadline_group_status=$?
    if [ "$deadline_group_status" -eq 0 ]; then break; fi
    sleep 1
    remaining=$((remaining - 1))
  done
  if [ "$cgroup_cleanup_ok" -eq 1 ] && deadline_group_is_absent; then
    discard_artifacts_bounded || true
    cleanup_control || true
  fi
  emit_unverified
  exit 0
fi

remaining=$identity_wait
while ! load_identity && [ "$remaining" -gt 0 ]; do
  sleep 1
  remaining=$((remaining - 1))
done

if ! load_identity; then
  remaining=$((term_grace + kill_grace + cleanup_grace))
  while [ "$remaining" -gt 0 ]; do
    deadline_group_is_absent
    deadline_group_status=$?
    if [ "$deadline_group_status" -eq 0 ]; then break; fi
    sleep 1
    remaining=$((remaining - 1))
  done
  if ! valid_deadline_done || [ "$deadline_done_status" != no_target ] || ! deadline_group_is_absent; then
    emit_unverified
    exit 0
  fi
  # Target absence does not prove the outer primary wrapper has exited.  Keep
  # the top-level launch tombstone and never authorize downstream cleanup or
  # fallback from a reconciliation-derived receipt.
  discard_artifacts_bounded || true
  cleanup_control || true
  emit_unverified
  exit 0
fi

if identity_is_live && valid_marker "$control_dir/done" done && ! valid_marker "$control_dir/timeout" timeout; then
  write_release_marker || true
fi

if ! wait_for_group_absence "$((term_grace + kill_grace))"; then
  printf '%s\n' '__RECEIPT_BEGIN__'
  printf 'attempt_token=%s\n' "$token"
  printf '%s\n' 'outcome=cleanup_unverified' 'exit_code=none' 'cleanup=failed' 'stdout_truncated=0' 'stderr_truncated=0' 'stdout_b64=' 'stderr_b64='
  printf '%s\n' '__RECEIPT_END__'
  exit 0
fi


remaining=$((cleanup_grace + kill_grace))
while [ "$remaining" -gt 0 ]; do
  deadline_group_is_absent
  deadline_group_status=$?
  if [ "$deadline_group_status" -eq 0 ]; then break; fi
  sleep 1
  remaining=$((remaining - 1))
done
if ! deadline_group_is_absent; then
  printf '%s\n' '__RECEIPT_BEGIN__'
  printf 'attempt_token=%s\n' "$token"
  printf '%s\n' 'outcome=cleanup_unverified' 'exit_code=none' 'cleanup=failed' 'stdout_truncated=0' 'stderr_truncated=0' 'stdout_b64=' 'stderr_b64='
  printf '%s\n' '__RECEIPT_END__'
  exit 0
fi
if ! valid_deadline_done || [ "$deadline_done_status" != verified_absent ]; then
  printf '%s\n' '__RECEIPT_BEGIN__'
  printf 'attempt_token=%s\n' "$token"
  printf '%s\n' 'outcome=cleanup_unverified' 'exit_code=none' 'cleanup=failed' 'stdout_truncated=0' 'stderr_truncated=0' 'stdout_b64=' 'stderr_b64='
  printf '%s\n' '__RECEIPT_END__'
  exit 0
fi

# Exact target/deadline absence is necessary process cleanup evidence, but it
# is not outer-wrapper absence evidence.  Best-effort discard only within the
# authenticated leaf, retain launch_stop + attempt_dir, and stay unverified.
discard_artifacts_bounded || true
cleanup_control || true
emit_unverified
exit 0
"""
_RECONCILE_SCRIPT = (
    _RECONCILE_SCRIPT.replace(
        "__OWNED_SESSION_SCAN_SCRIPT__", _OWNED_SESSION_SCAN_SCRIPT
    )
    .replace("__SESSION_SCAN_TAG__", "reconcile")
    .replace("__SESSION_SCAN_ROOT__", '"$control_dir"')
    .replace("__MAX_SESSION_SCAN_PROCESSES__", str(_MAX_SESSION_SCAN_PROCESSES))
    .replace("__CGROUP_V2_COMMON_SCRIPT__", _CGROUP_V2_COMMON_SCRIPT)
    .replace("__MAX_ARTIFACT_ENTRIES__", str(_MAX_ARTIFACT_ENTRIES))
    .replace("__MAX_ARTIFACT_DEPTH__", str(_MAX_ARTIFACT_DEPTH))
    .replace("__ARTIFACT_SCAN_DEPTH__", str(_MAX_ARTIFACT_DEPTH + 1))
    .replace("__RECEIPT_BEGIN__", _RECEIPT_BEGIN)
    .replace("__RECEIPT_END__", _RECEIPT_END)
)


def _positive_number(value: object, field_name: str) -> float:
    """
    Return the positive number.

    The implementation uses ``value`` and ``field_name`` to produce the positive
    number. If the function cannot produce the positive number, its exception
    reaches the caller instead of being converted into a successful result.

    Args:
        value: Value evaluated while performing positive number.
        field_name: Field label included in validation failures for the selected
            input.

    Returns:
        The validated ``resolved``.

    Raises:
        ManagedHostCommandConfigurationError: If the ``field_name`` is not a
            positive finite number.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ManagedHostCommandConfigurationError(
            f"{field_name} must be a positive finite number"
        )
    try:
        resolved = float(value)
    except (TypeError, ValueError, OverflowError) as error:
        raise ManagedHostCommandConfigurationError(
            f"{field_name} must be a positive finite number"
        ) from error
    if not math.isfinite(resolved) or resolved <= 0:
        raise ManagedHostCommandConfigurationError(
            f"{field_name} must be a positive finite number"
        )
    return resolved


def _positive_target_seconds(value: object, field_name: str) -> int:
    """
    Return the positive target seconds.

    After applying local validation, the function forwards ``value`` and
    ``field_name`` to ``int`` and preserves its return and exception contract.

    Args:
        value: Value evaluated while performing positive target seconds.
        field_name: Field label included in validation failures for the selected
            input.

    Returns:
        The numeric positive target seconds.

    Raises:
        ManagedHostCommandConfigurationError: If the ``field_name`` is not a
            whole number no greater than 86400.
    """
    resolved = _positive_number(value, field_name)
    if not resolved.is_integer() or resolved > 86_400:
        raise ManagedHostCommandConfigurationError(
            f"{field_name} must be a whole number no greater than 86400"
        )
    return int(resolved)


def _validate_remote_root(value: object) -> str:
    """
    Validate remote root.

    The implementation uses ``value`` to validate remote root. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        value: Value evaluated while performing remote root.

    Returns:
        The validated ``value``.

    Raises:
        ManagedHostCommandConfigurationError: If the remote_temp_root is not a
            normalized absolute POSIX path.
    """
    if not isinstance(value, str) or not _ROOT_RE.fullmatch(value):
        raise ManagedHostCommandConfigurationError(
            "remote_temp_root must be a normalized absolute POSIX path"
        )
    normalized = posixpath.normpath(value)
    if normalized != value or normalized == "/" or len(value) > 256:
        raise ManagedHostCommandConfigurationError(
            "remote_temp_root must be a normalized absolute POSIX path"
        )
    return value


def _validate_command(command: object) -> str:
    """
    Validate command.

    The implementation uses ``command`` to validate command. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        command: Command object whose ``encode`` and ``strip`` state is read
            while performing command.

    Returns:
        The validated ``command``.

    Raises:
        ManagedHostCommandConfigurationError: If the managed command is not a
            bounded non-empty single line.
    """
    if not isinstance(command, str):
        raise ManagedHostCommandConfigurationError(
            "managed command must be a bounded non-empty single line"
        )
    encoded = command.encode("utf-8")
    if (
        not command.strip()
        or len(encoded) > _MAX_COMMAND_BYTES
        or any(character in command for character in ("\x00", "\r", "\n"))
    ):
        raise ManagedHostCommandConfigurationError(
            "managed command must be a bounded non-empty single line"
        )
    return command


def _validate_output_limit(value: object) -> int:
    """
    Validate output limit.

    The implementation uses ``value`` to validate output limit. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        value: Value evaluated while performing output limit.

    Returns:
        The validated ``resolved``.

    Raises:
        ManagedHostCommandConfigurationError: If the output_limit_bytes are not
            an integer from 1 through 65536.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ManagedHostCommandConfigurationError(
            "output_limit_bytes must be an integer from 1 through 65536"
        )
    try:
        resolved = int(value)
    except (TypeError, ValueError, OverflowError) as error:
        raise ManagedHostCommandConfigurationError(
            "output_limit_bytes must be an integer from 1 through 65536"
        ) from error
    if resolved != value or not 1 <= resolved <= _MAX_OUTPUT_LIMIT_BYTES:
        raise ManagedHostCommandConfigurationError(
            "output_limit_bytes must be an integer from 1 through 65536"
        )
    return resolved


def _validate_containment(value: object) -> ManagedHostCleanupScope:
    """
    Resolve the opt-in kernel containment primitive.

    The legacy process-group scope remains the default. Unknown values are
    rejected before a transport command is constructed, so a collector that
    requests stronger containment never falls back silently.

    Args:
        value: Serialized cleanup scope supplied by governed configuration.

    Returns:
        The validated managed Host cleanup scope.

    Raises:
        ManagedHostCommandConfigurationError: If ``value`` is not one of the
            supported cleanup scopes.
    """
    if isinstance(value, ManagedHostCleanupScope):
        return value
    if not isinstance(value, str):
        raise ManagedHostCommandConfigurationError(
            "containment must be process_group or cgroup_v2"
        )
    try:
        return ManagedHostCleanupScope(value)
    except ValueError as error:
        raise ManagedHostCommandConfigurationError(
            "containment must be process_group or cgroup_v2"
        ) from error


def _build_remote_command(script: str, *arguments: object) -> str:
    """
    Pass all runtime values as positional arguments to one fixed script.

    After applying local validation, the function forwards ``script`` and
    ``arguments`` to ``shlex.join`` and preserves its return and exception
    contract.

    Args:
        script: Text supplied as script in the format accepted by this function.
        arguments: Additional positional values forwarded in caller-provided
            order.

    Returns:
        The canonical remote command text.
    """

    return shlex.join(
        ["sh", "-c", script, "managed-host-command", *map(str, arguments)]
    )


def _decode_bounded_output(value: str, output_limit: int) -> str:
    """
    Decode bounded output.

    After applying local validation, the function forwards ``value`` and
    ``output_limit`` to ``decoded.decode`` and preserves its return and
    exception contract. Parsing or I/O must finish before the validated
    representation is made available to the caller.

    Args:
        value: Text supplied as value in the format accepted by this function.
        output_limit: Upper bound enforced for output limit; the consuming
            boundary rejects or truncates values that exceed it.

    Returns:
        The canonical bounded output text.

    Raises:
        _ReceiptError: If managed command receipt output was malformed; or
            managed command receipt output exceeded its bound.
    """
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as error:
        raise _ReceiptError("managed command receipt output was malformed") from error
    if len(decoded) > output_limit:
        raise _ReceiptError("managed command receipt output exceeded its bound")
    return decoded.decode("utf-8", errors="replace")


def _parse_receipt(
    remote_result: object,
    *,
    expected_token: str,
    artifact_dir: str,
    output_limit: int,
    cleanup_scope: ManagedHostCleanupScope,
) -> ManagedHostCommandResult:
    """
    Parse receipt.

    After applying local validation, the function forwards ``remote_result``,
    ``expected_token``, ``artifact_dir``, and ``output_limit`` to
    ``ManagedHostCommandResult`` and preserves its return and exception
    contract. Parsing or I/O must finish before the validated representation is
    made available to the caller.

    Args:
        remote_result: Mapping supplying fields for receipt.
        expected_token: Text supplied as expected token in the format accepted
            by this function.
        artifact_dir: filesystem location used as the artifact dir for this
            operation.
        output_limit: Upper bound enforced for output limit; the consuming
            boundary rejects or truncates values that exceed it.
        cleanup_scope: Kernel ownership primitive selected before remote
            execution and applied to the authenticated receipt.

    Returns:
        A ``ManagedHostCommandResult`` representing receipt.

    Raises:
        _ReceiptError: If managed command transport result was malformed;
            managed command receipt exceeded its bound; managed command wrapper
            did not return a receipt; or managed command receipt framing was
            invalid; or another input invariant is violated.
    """
    if (
        not isinstance(remote_result, tuple)
        or len(remote_result) != 3
        or not isinstance(remote_result[0], int)
        or isinstance(remote_result[0], bool)
        or not isinstance(remote_result[1], str)
        or not isinstance(remote_result[2], str)
    ):
        raise _ReceiptError("managed command transport result was malformed")
    exit_code, stdout, _stderr = remote_result
    max_receipt_bytes = (2 * math.ceil(output_limit / 3) * 4) + 2048
    if len(stdout.encode("utf-8", errors="replace")) > max_receipt_bytes:
        raise _ReceiptError("managed command receipt exceeded its bound")
    if exit_code != 0:
        raise _ReceiptError("managed command wrapper did not return a receipt")
    lines = stdout.splitlines()
    if len(lines) != 10 or lines[0] != _RECEIPT_BEGIN or lines[-1] != _RECEIPT_END:
        raise _ReceiptError("managed command receipt framing was invalid")
    fields: dict[str, str] = {}
    for line in lines[1:-1]:
        key, separator, value = line.partition("=")
        if not separator or key in fields:
            raise _ReceiptError("managed command receipt fields were invalid")
        fields[key] = value
    if set(fields) != {
        "attempt_token",
        "outcome",
        "exit_code",
        "cleanup",
        "stdout_truncated",
        "stderr_truncated",
        "stdout_b64",
        "stderr_b64",
    }:
        raise _ReceiptError("managed command receipt fields were invalid")
    if not secrets.compare_digest(fields["attempt_token"], expected_token):
        raise _ReceiptError("managed command receipt attempt binding was invalid")
    try:
        outcome = ManagedHostCommandOutcome(fields["outcome"])
        cleanup_status = ManagedHostCleanupStatus(fields["cleanup"])
    except ValueError as error:
        raise _ReceiptError("managed command receipt enum was invalid") from error
    if fields["exit_code"] == "none":
        target_exit_code = None
    elif re.fullmatch(r"[0-9]{1,3}", fields["exit_code"]):
        target_exit_code = int(fields["exit_code"])
        if target_exit_code > 255:
            raise _ReceiptError("managed command receipt exit code was invalid")
    else:
        raise _ReceiptError("managed command receipt exit code was invalid")
    if (outcome is ManagedHostCommandOutcome.SUCCESS) != (target_exit_code == 0):
        raise _ReceiptError("managed command receipt outcome was inconsistent")
    if outcome is ManagedHostCommandOutcome.NONZERO_EXIT and (
        target_exit_code is None or target_exit_code == 0
    ):
        raise _ReceiptError("managed command receipt outcome was inconsistent")
    if (
        outcome
        not in {
            ManagedHostCommandOutcome.SUCCESS,
            ManagedHostCommandOutcome.NONZERO_EXIT,
        }
        and target_exit_code is not None
    ):
        raise _ReceiptError("managed command receipt outcome was inconsistent")
    if outcome is ManagedHostCommandOutcome.CLEANUP_UNVERIFIED:
        if cleanup_status is ManagedHostCleanupStatus.VERIFIED_ABSENT:
            raise _ReceiptError("managed command receipt cleanup was inconsistent")
    elif cleanup_status is not ManagedHostCleanupStatus.VERIFIED_ABSENT:
        raise _ReceiptError("managed command receipt cleanup was inconsistent")
    if fields["stdout_truncated"] not in {"0", "1"} or fields[
        "stderr_truncated"
    ] not in {"0", "1"}:
        raise _ReceiptError("managed command receipt truncation flag was invalid")
    return ManagedHostCommandResult(
        outcome=outcome,
        cleanup=ManagedHostCommandCleanup(
            scope=cleanup_scope,
            status=cleanup_status,
        ),
        target_exit_code=target_exit_code,
        artifact_dir=artifact_dir,
        target_stdout=_decode_bounded_output(fields["stdout_b64"], output_limit),
        target_stderr=_decode_bounded_output(fields["stderr_b64"], output_limit),
        stdout_truncated=fields["stdout_truncated"] == "1",
        stderr_truncated=fields["stderr_truncated"] == "1",
    )


def _uncertain_result(
    artifact_dir: str,
    cleanup_scope: ManagedHostCleanupScope,
    *,
    primary_deadline_exceeded: bool = False,
) -> ManagedHostCommandResult:
    """
    Return the uncertain result.

    After applying local validation, the function forwards ``artifact_dir`` to
    ``ManagedHostCommandResult`` and preserves its return and exception
    contract.

    Args:
        artifact_dir: filesystem location used as the artifact dir for this
            operation.
        cleanup_scope: Kernel ownership primitive selected for the attempt.
        primary_deadline_exceeded: Whether the injected executor exhausted its
            caller-side deadline before delivering an authoritative receipt.

    Returns:
        A ``ManagedHostCommandResult`` representing uncertain result.
    """
    return ManagedHostCommandResult(
        outcome=ManagedHostCommandOutcome.CLEANUP_UNVERIFIED,
        cleanup=ManagedHostCommandCleanup(
            scope=cleanup_scope,
            status=ManagedHostCleanupStatus.UNVERIFIED,
        ),
        artifact_dir=artifact_dir,
        primary_deadline_exceeded=primary_deadline_exceeded,
    )


def _observe_detached_task(task: asyncio.Task) -> None:
    """
    Release task ownership and consume any late, potentially sensitive error.

    The implementation uses ``task`` to release task ownership and consume any
    late, potentially sensitive error.

    Args:
        task: Task object whose ``cancelled`` and ``exception`` state is read
            while performing release task ownership and consume any late,
            potentially sensitive error.
    """

    _OWNED_DETACHED_TASKS.discard(task)
    if task.cancelled():
        return
    try:
        task.exception()
    except (asyncio.CancelledError, Exception):
        pass


def _own_detached_task(task: asyncio.Task) -> None:
    """
    Keep a strong reference until a detached task has settled.

    The implementation uses ``task`` to keep a strong reference until a detached
    task has settled.

    Args:
        task: Task object whose ``add_done_callback`` state is read while
            performing keep a strong reference until a detached task has
            settled.
    """

    _OWNED_DETACHED_TASKS.add(task)
    task.add_done_callback(_observe_detached_task)


async def _call_executor(
    execute_remote: ManagedRemoteExecutor,
    command: str,
    timeout: float,
) -> RemoteCommandResult:
    """
    Return the call executor.

    After applying local validation, the function forwards ``execute_remote``,
    ``command``, and ``timeout`` to ``execute_remote`` and preserves its return
    and exception contract. Owned asynchronous work is awaited before return, so
    completion does not leave an unobserved task behind.

    Args:
        execute_remote: Execute remote consumed while the function attempts to
            produce the call executor.
        command: Text supplied as command in the format accepted by this
            function.
        timeout: Maximum duration allowed before the operation is cancelled or
            fails.

    Returns:
        A ``RemoteCommandResult`` representing call executor.
    """
    return await execute_remote(command, timeout=timeout, max_retries=_PRIMARY_ATTEMPTS)


async def _bounded_reconcile(
    execute_remote: ManagedRemoteExecutor,
    command: str,
    *,
    timeout: float,
    artifact_dir: str,
    cleanup_scope: ManagedHostCleanupScope,
    primary_deadline_exceeded: bool = False,
) -> ManagedHostCommandResult:
    """
    Return the bounded reconcile.

    Reconciliation proves at most target/deadline process absence. Without an
    outer-wrapper identity handshake, its receipt cannot authorize Host cleanup,
    artifact handoff, or safe-mode fallback.

    Args:
        execute_remote: Execute remote consumed while the function attempts to
            produce the bounded reconcile.
        command: Text supplied as command in the format accepted by this
            function.
        timeout: Maximum duration allowed before the operation is cancelled or
            fails.
        artifact_dir: filesystem location used as the artifact dir for this
            operation.
        cleanup_scope: Kernel ownership primitive selected for the attempt.
        primary_deadline_exceeded: Whether the primary executor exhausted its
            caller-side deadline before reconciliation began.

    Returns:
        A ``ManagedHostCommandResult`` representing bounded reconcile.
    """
    task = asyncio.create_task(_call_executor(execute_remote, command, timeout))
    try:
        done, _ = await asyncio.wait({task}, timeout=timeout)
    except asyncio.CancelledError:
        task.cancel()
        _own_detached_task(task)
        raise
    if task not in done:
        task.cancel()
        _own_detached_task(task)
        return _uncertain_result(
            artifact_dir,
            cleanup_scope,
            primary_deadline_exceeded=primary_deadline_exceeded,
        )
    try:
        task.result()
    except (asyncio.CancelledError, Exception):
        pass
    # Reconciliation proves at most target/deadline process absence.  Without
    # an outer-wrapper identity handshake, its receipt cannot authorize Host
    # cleanup, artifact handoff, or safe-mode fallback.
    return _uncertain_result(
        artifact_dir,
        cleanup_scope,
        primary_deadline_exceeded=primary_deadline_exceeded,
    )


async def _shielded_reconcile(
    execute_remote: ManagedRemoteExecutor,
    command: str,
    *,
    timeout: float,
    artifact_dir: str,
    cleanup_scope: ManagedHostCleanupScope,
) -> None:
    """
    Perform shielded reconcile.

    The implementation uses ``execute_remote``, ``command``, ``timeout``, and
    ``artifact_dir`` to perform shielded reconcile. Owned asynchronous work is
    awaited before return, so completion does not leave an unobserved task
    behind.

    Args:
        execute_remote: Execute remote consumed while the function attempts to
            perform shielded reconcile.
        command: Text supplied as command in the format accepted by this
            function.
        timeout: Maximum duration allowed before the operation is cancelled or
            fails.
        artifact_dir: filesystem location used as the artifact dir for this
            operation.
        cleanup_scope: Kernel ownership primitive selected for the attempt.
    """
    cleanup_task = asyncio.create_task(
        _bounded_reconcile(
            execute_remote,
            command,
            timeout=timeout,
            artifact_dir=artifact_dir,
            cleanup_scope=cleanup_scope,
        )
    )
    _own_detached_task(cleanup_task)
    try:
        await asyncio.wait_for(asyncio.shield(cleanup_task), timeout=timeout + 0.5)
    except asyncio.CancelledError:
        raise
    except Exception:
        cleanup_task.cancel()


async def run_managed_host_command(
    execute_remote: ManagedRemoteExecutor,
    command: str,
    *,
    target_timeout_seconds: object,
    remote_temp_root: object = "/tmp",
    term_grace_seconds: object = 10,
    kill_grace_seconds: object = 5,
    transport_grace_seconds: object = 10,
    primary_pre_execution_grace_seconds: object = None,
    cleanup_timeout_seconds: object = 30,
    output_limit_bytes: object = 16 * 1024,
    containment: object = ManagedHostCleanupScope.PROCESS_GROUP.value,
    prepare_timeout_artifacts: object = False,
    prepare_nonzero_artifacts: object = False,
    command_via_stdin: bool = False,
) -> ManagedHostCommandResult:
    """
    Run one foreground command under target-owned timeout and cleanup.

    The primary wrapper is submitted exactly once. A second, one-attempt command
    is used only for bounded process reconciliation and best-effort cleanup
    inside the exact random run directory after transport/receipt uncertainty or
    caller cancellation. Without outer-wrapper absence proof, reconciliation
    retains the launch tombstone and stays cleanup-unverified. Only a directly
    delivered primary receipt can authorize artifact cleanup or timeout
    fallback.

    The optional primary pre-execution grace extends the first executor call and
    its caller-side owner by the bounded admission and connection allowance. It
    never enlarges the target-owned runtime embedded in the remote wrapper. When
    that allowance is present, the owner also keeps one configured transport
    grace so bounded connection close and an executor returning at its own
    deadline cannot race the local wait boundary.
    Cancellation remains control flow: bounded shielded reconciliation runs,
    then the original ``CancelledError`` is re-raised.

    Args:
        execute_remote: Execute remote consumed while the function attempts to
            run one foreground command under target-owned timeout and cleanup.
        command: Text supplied as command in the format accepted by this
            function.
        target_timeout_seconds: Maximum duration in seconds allowed for target
            timeout seconds.
        remote_temp_root: filesystem location used as the remote temp root for
            this operation.
        term_grace_seconds: Maximum duration in seconds allowed for term grace
            seconds.
        kill_grace_seconds: Maximum duration in seconds allowed for kill grace
            seconds.
        transport_grace_seconds: Maximum duration in seconds allowed for
            transport grace seconds.
        primary_pre_execution_grace_seconds: Optional positive allowance for
            transport queueing and a proven-pre-execution connection attempt
            before the primary wrapper begins. The allowance extends the first
            executor call and its local owner, but not the target-side deadline.
            ``None`` adds no allowance.
        cleanup_timeout_seconds: Maximum duration in seconds allowed for cleanup
            timeout seconds.
        output_limit_bytes: Output limit bytes consumed while the function
            attempts to run one foreground command under target-owned timeout
            and cleanup.
        containment: Governed kernel ownership primitive. ``process_group``
            preserves legacy behavior; ``cgroup_v2`` fails closed when its
            target-side capability cannot be established.
        prepare_timeout_artifacts: Whether bounded regular artifacts left by a
            target timeout should be made available to the invoking SSH
            identity after target cleanup is verified. Preparation failure
            does not suppress or replace the authoritative timeout outcome.
        prepare_nonzero_artifacts: Whether bounded regular artifacts left by a
            nonzero target exit should be made available to the invoking SSH
            identity after target cleanup is verified. This includes an inner
            utility's timeout exit. Preparation never changes the exit code,
            validates the artifact contents, or authorizes command replay.
        command_via_stdin: Whether the executor sends the wrapper over standard
            input to a fixed shell command. The same payload byte limit applies;
            only argument transport needs the additional shell-quoting allowance.

    Returns:
        A ``ManagedHostCommandResult`` representing run managed host command.

    Raises:
        ManagedHostCommandConfigurationError: If the execute_remote is not an
            async command callable; a numeric timeout or grace is invalid; the
            artifact-preparation or transport flags are not boolean; or
            cleanup_timeout_seconds does not cover TERM, KILL, and
            verification grace.
        RuntimeError: If managed command nonce generation failed.
    """

    if not callable(execute_remote):
        raise ManagedHostCommandConfigurationError(
            "execute_remote must be an async command callable"
        )
    resolved_command = _validate_command(command)
    resolved_root = _validate_remote_root(remote_temp_root)
    target_timeout = _positive_target_seconds(
        target_timeout_seconds, "target_timeout_seconds"
    )
    term_grace = _positive_target_seconds(term_grace_seconds, "term_grace_seconds")
    kill_grace = _positive_target_seconds(kill_grace_seconds, "kill_grace_seconds")
    transport_grace = _positive_number(
        transport_grace_seconds, "transport_grace_seconds"
    )
    primary_pre_execution_grace = (
        0.0
        if primary_pre_execution_grace_seconds is None
        else _positive_number(
            primary_pre_execution_grace_seconds,
            "primary_pre_execution_grace_seconds",
        )
    )
    cleanup_timeout = _positive_number(
        cleanup_timeout_seconds, "cleanup_timeout_seconds"
    )
    minimum_cleanup_timeout = (
        term_grace
        + kill_grace
        + MANAGED_IDENTITY_READINESS_GRACE_SECONDS
        + MANAGED_CLEANUP_VERIFICATION_GRACE_SECONDS
    )
    if cleanup_timeout < minimum_cleanup_timeout:
        raise ManagedHostCommandConfigurationError(
            "cleanup_timeout_seconds must cover TERM, KILL, and verification grace"
        )
    output_limit = _validate_output_limit(output_limit_bytes)
    cleanup_scope = _validate_containment(containment)
    if not isinstance(prepare_timeout_artifacts, bool):
        raise ManagedHostCommandConfigurationError(
            "prepare_timeout_artifacts must be boolean"
        )
    if not isinstance(prepare_nonzero_artifacts, bool):
        raise ManagedHostCommandConfigurationError(
            "prepare_nonzero_artifacts must be boolean"
        )
    if not isinstance(command_via_stdin, bool):
        raise ManagedHostCommandConfigurationError("command_via_stdin must be boolean")
    identity_wait = max(
        1,
        min(
            MANAGED_IDENTITY_READINESS_GRACE_SECONDS,
            int(cleanup_timeout - term_grace - kill_grace - 1),
        ),
    )

    token = secrets.token_hex(32)
    if not _TOKEN_RE.fullmatch(token):  # pragma: no cover - stdlib invariant
        raise RuntimeError("managed command nonce generation failed")
    attempt_dir = posixpath.join(resolved_root, f".nvdebug-managed-{token}")
    artifact_dir = posixpath.join(attempt_dir, "artifacts")
    # One positional bitmask preserves the wrapper's bounded wire footprint:
    # timeout preparation is bit 0 and nonzero preparation is bit 1. Neither
    # failed-command path changes the original outcome when preparation fails.
    artifact_preparation = int(prepare_timeout_artifacts) | (
        int(prepare_nonzero_artifacts) << 1
    )
    primary_command = _build_remote_command(
        _PRIMARY_WRAPPER_SCRIPT,
        token,
        attempt_dir,
        resolved_command,
        target_timeout,
        term_grace,
        kill_grace,
        output_limit,
        _TARGET_SUPERVISOR_SCRIPT,
        _TARGET_DEADLINE_OWNER_SCRIPT,
        identity_wait,
        cleanup_scope.value,
        artifact_preparation,
    )
    reconcile_command = _build_remote_command(
        _RECONCILE_SCRIPT,
        token,
        attempt_dir,
        term_grace,
        kill_grace,
        output_limit,
        identity_wait,
        1,
        MANAGED_CLEANUP_VERIFICATION_GRACE_SECONDS,
        cleanup_scope.value,
    )
    stdin_terminator_bytes = int(command_via_stdin)
    if (
        len(primary_command.encode("utf-8")) + stdin_terminator_bytes
        > _MAX_REMOTE_COMMAND_BYTES
        or len(reconcile_command.encode("utf-8")) + stdin_terminator_bytes
        > _MAX_REMOTE_COMMAND_BYTES
        or (
            not command_via_stdin
            and (
                len(shlex.quote(primary_command).encode("utf-8"))
                + _REMOTE_COMMAND_WRAPPER_OVERHEAD_BYTES
                > _MAX_REMOTE_COMMAND_BYTES
                or len(shlex.quote(reconcile_command).encode("utf-8"))
                + _REMOTE_COMMAND_WRAPPER_OVERHEAD_BYTES
                > _MAX_REMOTE_COMMAND_BYTES
            )
        )
    ):
        raise ManagedHostCommandConfigurationError(
            "managed wrapper command exceeded its transport-safe bound"
        )
    cancellation_cleanup_command = reconcile_command
    primary_timeout = target_timeout + term_grace + kill_grace + transport_grace
    primary_executor_timeout = primary_timeout + primary_pre_execution_grace
    primary_wait_timeout = primary_executor_timeout + (
        transport_grace if primary_pre_execution_grace > 0 else 0.0
    )
    primary_task = asyncio.create_task(
        _call_executor(execute_remote, primary_command, primary_executor_timeout)
    )
    try:
        done, _ = await asyncio.wait({primary_task}, timeout=primary_wait_timeout)
    except asyncio.CancelledError:
        primary_task.cancel()
        _own_detached_task(primary_task)
        await _shielded_reconcile(
            execute_remote,
            cancellation_cleanup_command,
            timeout=cleanup_timeout,
            artifact_dir=artifact_dir,
            cleanup_scope=cleanup_scope,
        )
        raise

    if primary_task not in done:
        primary_task.cancel()
        _own_detached_task(primary_task)
        return await _bounded_reconcile(
            execute_remote,
            reconcile_command,
            timeout=cleanup_timeout,
            artifact_dir=artifact_dir,
            cleanup_scope=cleanup_scope,
            primary_deadline_exceeded=True,
        )
    try:
        primary_result = primary_task.result()
        return _parse_receipt(
            primary_result,
            expected_token=token,
            artifact_dir=artifact_dir,
            output_limit=output_limit,
            cleanup_scope=cleanup_scope,
        )
    except asyncio.CancelledError:
        return await _bounded_reconcile(
            execute_remote,
            reconcile_command,
            timeout=cleanup_timeout,
            artifact_dir=artifact_dir,
            cleanup_scope=cleanup_scope,
        )
    except ManagedRemoteExecutorTimeout:
        return await _bounded_reconcile(
            execute_remote,
            reconcile_command,
            timeout=cleanup_timeout,
            artifact_dir=artifact_dir,
            cleanup_scope=cleanup_scope,
            primary_deadline_exceeded=True,
        )
    except Exception:
        return await _bounded_reconcile(
            execute_remote,
            reconcile_command,
            timeout=cleanup_timeout,
            artifact_dir=artifact_dir,
            cleanup_scope=cleanup_scope,
        )


__all__ = [
    "ManagedHostCleanupScope",
    "ManagedHostCleanupStatus",
    "ManagedHostCommandCleanup",
    "ManagedHostCommandConfigurationError",
    "ManagedHostCommandOutcome",
    "ManagedHostCommandResult",
    "ManagedRemoteExecutorTimeout",
    "ManagedRemoteExecutor",
    "run_managed_host_command",
]
