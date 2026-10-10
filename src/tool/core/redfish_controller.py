#!/usr/bin/env python3
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
Own collector-specific Redfish controller sessions without changing DUT routing.

A task-local view selects the Host BMC while unrelated collectors retain their
normal endpoint, credentials, sessions and cache. Views reuse the existing TLS,
authentication, request and cleanup boundaries and never borrow an HMC token.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import Any, AsyncIterator

from .dut_session_registry import (
    close_redfish_session,
    create_fallback_redfish_session,
    create_redfish_session,
    initialize_redfish_session_pool,
)

_ACTIVE_CONTROLLER: ContextVar[tuple[Any, Any] | None] = ContextVar(
    "nvdebug_redfish_controller", default=None
)


def resolve_collector_controller(policy: Any, config: dict[str, Any]) -> str:
    """
    Select a supported controller from the authored baseboard routing policy.

    Only the default endpoint and the configured Host BMC are accepted. The
    policy cannot supply an arbitrary endpoint or alter transport credentials.

    Args:
        policy: Catalog mapping with a default and optional baseboard overrides.
        config: Resolved DUT configuration containing its canonical baseboard.

    Returns:
        The selected default or BMC controller name.

    Raises:
        ValueError: If the policy or any controller selection is unsupported.
    """

    if not isinstance(policy, dict) or set(policy) - {"default", "baseboards"}:
        raise ValueError("Invalid collector Redfish controller policy")
    overrides = policy.get("baseboards", {})
    default = policy.get("default", "default")
    if not isinstance(overrides, dict) or any(
        value not in ("default", "bmc") for value in [default, *overrides.values()]
    ):
        raise ValueError("Unsupported collector Redfish controller")
    baseboard = config.get("TargetBaseboard") or config.get("baseboard", "")
    return overrides.get(baseboard, default)


def request_controller_dut(dut: Any) -> Any:
    """
    Resolve the task-local transport view for the exact owning DUT object.

    Checking object identity prevents a nested request for another DUT from
    inheriting the active collector's controller or credentials.

    Args:
        dut: Original DUT selected by the manager for the request.

    Returns:
        Its active controller view, or the original DUT outside that scope.
    """

    active = _ACTIVE_CONTROLLER.get()
    return active[1] if active is not None and active[0] is dut else dut


def collector_controllers(
    definition: dict[str, Any], config: dict[str, Any]
) -> set[str]:
    """
    Resolve the controllers required by a collector's execution hooks.

    Hooks without a routing policy retain the default controller. Validation
    and preflight use this same catalog policy as execution, without inferring
    a controller from a collector identifier or platform name.

    Args:
        definition: Authored collector definition including execution stages.
        config: Resolved DUT configuration used for baseboard policy lookup.

    Returns:
        Nonempty set of required controller names.

    Raises:
        ValueError: If an execution hook declares an invalid routing policy.
    """

    hooks = definition.get("stages", {}).get("execution", {}).get("hooks", [])
    controllers = set()
    for hook in hooks:
        policy = hook.get("params", {}).get("redfish_controller")
        controllers.add(
            resolve_collector_controller(policy, config)
            if policy is not None
            else "default"
        )
    return controllers or {"default"}


def collector_preflight_result(
    preflight: dict[str, Any],
    service: str,
    definition: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    """
    Select transport evidence for the controllers a collector actually uses.

    An aggregate Redfish failure must not block a healthy peer controller.
    Legacy service evidence remains valid for the default route only; it cannot
    establish that a separately authenticated Host BMC was checked.

    Args:
        preflight: One DUT's recorded service preflight outcomes.
        service: Canonical service owning the collector.
        definition: Collector whose execution hooks declare routing policy.
        config: Resolved DUT configuration for platform overrides.

    Returns:
        Matching service outcome, a failed required-controller outcome, or an
        unknown outcome when the required controller has no preflight evidence.
    """

    result = preflight.get("services", {}).get(service, {})
    if service != "redfish":
        return result
    required = collector_controllers(definition, config)
    controllers = result.get("controllers", {})
    if not controllers:
        return result if required == {"default"} else {}
    selected = [controllers.get(name, {}) for name in sorted(required)]
    for outcome in selected:
        if outcome.get("status") == "fail":
            return outcome
    if any(outcome.get("status") != "pass" for outcome in selected):
        return {"status": "unknown", "message": "Required controller was not checked"}
    return {
        "status": "pass",
        "message": "; ".join(outcome.get("message", "") for outcome in selected),
    }


def metadata_controller(preflight: dict[str, Any] | None) -> str:
    """
    Select the verified route for shared discovery in a BMC-only collection.

    A successful Host BMC probe is not evidence that an HMC tunnel works.
    Mixed-controller and legacy runs retain their established default route.

    Args:
        preflight: DUT service outcomes, either directly or under ``services``.

    Returns:
        BMC only when it was the sole checked and successful Redfish controller;
        otherwise the default route remains authoritative.
    """

    if not preflight:
        return "default"
    services = preflight.get("services", preflight)
    controllers = services.get("redfish", {}).get("controllers", {})
    if set(controllers) == {"bmc"} and controllers["bmc"].get("status") == "pass":
        return "bmc"
    return "default"


class _BmcControllerView:
    """
    Hold independent HTTP resources while borrowing the DUT's transport policy.

    Only immutable configuration, logging and TLS helpers are delegated. Session
    handles are owned here, and response caching is disabled to keep controller
    namespaces separate without changing the default DUT cache.
    """

    def __init__(self, origin: Any) -> None:
        """
        Initialize an empty owner for the configured Host BMC transport.

        Session initialization is deferred to the asynchronous collector scope.
        No connection state, credentials or routing fields on the DUT are changed.

        Args:
            origin: DUT whose BMC route and security policy remain authoritative.
        """

        self._origin = origin
        self.redfish_session_pool = None
        self.redfish_session = None
        self.redfish_connector = None
        self.redfish_auth = None
        self._collector_controller_views: set[Any] = set()

    def __getattr__(self, name: str) -> Any:
        """
        Borrow the configured limits, TLS helpers and logger from the owner.

        Mutable session and cache methods are explicitly implemented on this
        view, so delegating policy reads cannot select the default session pool.

        Args:
            name: Configuration field or policy helper required by the transport.

        Returns:
            The original DUT's configuration value or bound policy helper.
        """

        return getattr(self._origin, name)

    def get_redfish_connection_info(self) -> dict[str, Any]:
        """
        Resolve the current verified BMC route and its own credentials.

        Rechecking on every request preserves live proxy ownership checks and
        lets the existing session boundary detect changed endpoint identities.

        Returns:
            Validated Host BMC connection information.
        """

        return self._origin.get_bmc_redfish_connection_info()

    def normalize_redfish_uri(self, uri: str) -> str:
        """
        Apply the BMC service root without consulting HMC resource heuristics.

        The existing URI validator still rejects unsafe request targets. Root
        selection follows the chosen controller even for an advertised HGX link.

        Args:
            uri: Registry request target or controller-advertised resource URI.

        Returns:
            The request target rebased to the configured BMC service root.
        """

        return self._origin._replace_catalog_service_root(
            uri,
            self._origin._get_catalog_redfish_service_root(),
            self.get_redfish_connection_info()["service_root"],
        )

    def _has_cached_response(self, uri: str) -> bool:
        """
        Disable default-controller cache lookups inside the BMC view.

        Registry discovery and its advertised payload must come from this
        controller, even if an HMC request previously used the same URI.

        Args:
            uri: Request target whose response would otherwise be reused.

        Returns:
            False because this short-lived controller scope does not cache data.
        """

        return False

    def _get_cached_response(self, uri: str) -> None:
        """
        Return no cached response for the collector's independent endpoint.

        This also preserves compatibility with callers that do not use the
        explicit cache-presence check before looking up a response.

        Args:
            uri: Request target supplied by the shared transport engine.
        """

        return None

    def _cache_response(self, uri: str, response: Any, **kwargs: Any) -> bool:
        """
        Decline cache publication across the controller ownership boundary.

        Collected content still reaches the normal artifact publisher; only
        cross-request caching is disabled for this independent controller.

        Args:
            uri: Completed request target.
            response: Response owned by the current request.
            kwargs: Cache size metadata supplied by the response handler.

        Returns:
            False because no cache entry was retained.
        """

        return False

    async def initialize_redfish_session_pool(self) -> bool:
        """
        Initialize a pool bound to this BMC's endpoint and authentication policy.

        The existing session owner serializes initialization and enforces the
        configured token policy, including required-session failure behavior.

        Returns:
            Whether this independent controller pool initialized successfully.
        """

        return await initialize_redfish_session_pool(self)

    async def _create_fallback_session(self, connection_info: dict[str, Any]) -> bool:
        """
        Apply the normal fallback policy using only this view's HTTP handles.

        Required session authentication continues to forbid Basic fallback.
        Failed probes close this view's resources without touching the DUT pool.

        Args:
            connection_info: Validated BMC endpoint and authentication settings.

        Returns:
            Whether the configured fallback established a working connection.
        """

        return await create_fallback_redfish_session(self, connection_info)

    async def close_redfish_session(self) -> None:
        """
        Close and observe all HTTP resources owned by the collector view.

        Failed handles remain attached for the parent DUT's final cleanup retry.
        No default/HMC handle is reachable through the view's owned attributes.
        """

        await close_redfish_session(self)


@asynccontextmanager
async def redfish_controller_scope(dut: Any, controller: str) -> AsyncIterator[None]:
    """
    Own a collector's controller selection through initialization and cleanup.

    Context variables isolate concurrent collectors. BMC sessions are registered
    with the DUT before initialization so failed cleanup retains a finalization
    owner; successful cleanup removes that registration. Nested default scopes
    leave their enclosing controller selection unchanged.

    Args:
        dut: Original DUT whose BMC route, TLS and authentication policy are used.
        controller: Validated default or BMC selection from the catalog.

    Yields:
        Control after the selected controller has an authenticated session.

    Raises:
        ValueError: If an unsupported controller name is supplied.
        RuntimeError: If the BMC session cannot be established.
        TimeoutError: If controller initialization exceeds the DUT session timeout.
    """

    if controller == "default":
        yield
        return
    if controller != "bmc":
        raise ValueError("Unsupported collector Redfish controller")
    view = _BmcControllerView(dut)
    owners = getattr(dut, "_collector_controller_views", None)
    if owners is None:
        owners = dut._collector_controller_views = set()
    owners.add(view)
    token = _ACTIVE_CONTROLLER.set((dut, view))
    try:
        async with asyncio.timeout(dut.redfish_session_timeout):
            await dut.ensure_bmc_redfish_proxy_route()
            if not await create_redfish_session(view):
                raise RuntimeError("Host BMC Redfish session initialization failed")
        yield
    finally:
        try:
            await view.close_redfish_session()
            owners.discard(view)
        finally:
            _ACTIVE_CONTROLLER.reset(token)
