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
Validate catalog assertions about independent diagnostic capacity pools.

Exact action aliases share an authored pool. Manager ownership must also match
cached discovery; different addresses, resource names or collector IDs never
establish independence. Unqualified routes retain the runner's domain gate.
"""

from __future__ import annotations

import re
from typing import Any

DIAGNOSTIC_CAPACITY_POOLS_KEY = "diagnostic_capacity_pools"
_PATH = re.compile(r"/(?:[A-Za-z0-9_.~-]+/)*[A-Za-z0-9_.~-]+")


def validate_diagnostic_capacity_pools(value: Any) -> dict[str, dict[str, Any]]:
    """
    Validate a bounded optional map of pool labels to exact action aliases.

    Each action belongs to one pool; the catalog must declare its manager and
    managed System explicitly instead of deriving ownership from path names.

    Args:
        value: Catalog baseboard metadata, or an empty mapping when unqualified.

    Returns:
        A detached pool map with unambiguous action membership.

    Raises:
        ValueError: If fields, labels, paths or aliases are malformed or overlap.
    """

    if value in (None, "", {}):
        return {}
    if not isinstance(value, dict) or len(value) > 16:
        raise ValueError("diagnostic_capacity_pools must be a bounded mapping")
    result = {}
    seen_actions = set()
    for label, pool in value.items():
        if not isinstance(label, str) or not re.fullmatch(
            r"[a-z][a-z0-9_-]{0,63}", label
        ):
            raise ValueError("diagnostic capacity pool label is invalid")
        if not isinstance(pool, dict) or set(pool) != {
            "manager_uri",
            "system_uri",
            "action_uris",
        }:
            raise ValueError(
                "diagnostic capacity pool requires manager, system and actions"
            )
        actions = pool["action_uris"]
        if not isinstance(actions, list) or not 1 <= len(actions) <= 16:
            raise ValueError("diagnostic capacity action aliases must be bounded")
        for path in [pool["manager_uri"], pool["system_uri"], *actions]:
            if (
                not isinstance(path, str)
                or len(path) > 512
                or not _PATH.fullmatch(path)
                or any(segment in {".", ".."} for segment in path.split("/"))
            ):
                raise ValueError(
                    "diagnostic capacity paths must be exact absolute paths"
                )
        for action in actions:
            if action in seen_actions:
                raise ValueError(
                    "diagnostic capacity action belongs to multiple aliases/pools"
                )
            seen_actions.add(action)
        result[label] = {**pool, "action_uris": list(actions)}
    return result


def resolve_diagnostic_capacity_pool(
    pools: Any, action_uri: str, managers: Any
) -> str | None:
    """
    Resolve a catalog pool only when cached Manager ownership corroborates it.

    The caller owns route qualification. Missing, duplicate or conflicting
    ManagerForServers relationships do not establish a producer identity.

    Args:
        pools: Validated baseboard pool map.
        action_uri: Exact action path being submitted.
        managers: Cached complete Manager resources keyed by member ID.

    Returns:
        The qualified pool label, or ``None`` when ownership is unknown.
    """

    if not isinstance(managers, dict):
        return None
    for member_id, manager in managers.items():
        if not isinstance(manager, dict):
            return None
        identity = manager.get("@odata.id")
        links = manager.get("Links")
        if (
            not isinstance(identity, str)
            or identity.rsplit("/", 1)[-1] != member_id
            or not isinstance(links, dict)
            or not isinstance(links.get("ManagerForServers"), list)
            or "ManagerForServers@odata.nextLink" in links
            or (
                "ManagerForServers@odata.count" in links
                and (
                    type(links["ManagerForServers@odata.count"]) is not int
                    or links["ManagerForServers@odata.count"]
                    != len(links["ManagerForServers"])
                )
            )
            or any(
                not isinstance(server, dict)
                or not isinstance(server.get("@odata.id"), str)
                or not _PATH.fullmatch(server["@odata.id"])
                for server in links["ManagerForServers"]
            )
        ):
            return None
    for label, pool in pools.items():
        if action_uri not in pool["action_uris"]:
            continue
        owners = []
        for manager in managers.values():
            links = manager.get("Links", {})
            servers = (
                links.get("ManagerForServers", []) if isinstance(links, dict) else []
            )
            if isinstance(servers, list) and any(
                isinstance(server, dict)
                and server.get("@odata.id") == pool["system_uri"]
                for server in servers
            ):
                owners.append(manager.get("@odata.id"))
        return label if owners == [pool["manager_uri"]] else None
    return None
