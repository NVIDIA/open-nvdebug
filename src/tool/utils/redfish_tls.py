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
Redfish TLS trust-policy primitives shared by all HTTP paths.

This module owns the redfish tls boundary and exposes
``normalize_sha256_fingerprint``, ``_normalize_legacy_verify``, and
``RedfishTLSPolicy``. Keeping those contracts together gives importers one
source of truth for their validation, lifecycle, and compatibility behavior.
"""

import re
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

import aiohttp

REDFISH_TLS_MODES = frozenset({"system_ca", "custom_ca", "fingerprint", "insecure"})
INSECURE_REDFISH_TRANSPORT_WARNING_MESSAGE = (
    "SECURITY WARNING: Redfish server authentication is not active for one or "
    "more configured endpoints (plaintext HTTP or insecure TLS); use an isolated "
    "trusted management network or configure HTTPS with system_ca, custom_ca, or "
    "fingerprint verification. Otherwise credentials and responses are vulnerable "
    "to man-in-the-middle attacks."
)


def normalize_sha256_fingerprint(value: Optional[str]) -> Optional[str]:
    """
    Return a canonical lowercase SHA-256 certificate fingerprint.

    The implementation uses ``value`` to produce a canonical lowercase SHA-256
    certificate fingerprint. If the function cannot produce a canonical
    lowercase SHA-256 certificate fingerprint, its exception reaches the caller
    instead of being converted into a successful result.

    Args:
        value: Text supplied as value in the format accepted by this function.

    Returns:
        The validated ``normalized``, or ``None`` when no value qualifies.

    Raises:
        ValueError: If redfish SHA-256 fingerprint must contain exactly 64
            hexadecimal digits.
    """

    if value is None:
        return None
    normalized = re.sub(r"[:\s]", "", str(value)).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", normalized):
        raise ValueError(
            "Redfish SHA-256 fingerprint must contain exactly 64 hexadecimal digits"
        )
    return normalized


def _normalize_legacy_verify(value: Any) -> Optional[bool]:
    """
    Normalize a legacy verification boolean without string truthiness.

    The implementation uses ``value`` to normalize a legacy verification boolean
    without string truthiness. The source value keeps its ownership while the
    normalized representation is returned separately. If the function cannot
    normalize a legacy verification boolean without string truthiness, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        value: Value object whose ``strip`` state is read while performing
            legacy verification boolean without string truthiness.

    Returns:
        Whether the legacy verification boolean without string truthiness
        operation succeeds, or ``None`` when the decision is unavailable.

    Raises:
        ValueError: If the redfish ssl_verify is not true or false.
    """

    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    raise ValueError("Redfish ssl_verify must be true or false")


@dataclass(frozen=True)
class RedfishTLSPolicy:
    """
    Validated Redfish server-authentication policy.

    The immutable record keeps ``mode``, ``ca_file``, ``fingerprint_sha256``,
    and ``server_name`` together so consumers observe one Redfish TLS policy
    state. Construction validates cross-field invariants before the instance is
    exposed.

    Attributes:
        mode: Canonical text used as mode.
        ca_file: Canonical text used as ca file.
        fingerprint_sha256: Lowercase SHA-256 digest binding the fingerprint
            content.
        server_name: Canonical text used as server name.
    """

    mode: str = "insecure"
    ca_file: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    server_name: Optional[str] = None

    def __post_init__(self) -> None:
        """
        Validate and finalize the initialized RedfishTLSPolicy state.

        The hook checks cross-field invariants after generated initialization
        and rejects inconsistent state before the instance becomes visible to
        callers. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path.

        Raises:
            ValueError: If the redfish tls mode is not system_ca, custom_ca,
                fingerprint, or insecure; redfish custom_ca tls mode lacks
                ca_file; redfish fingerprint tls mode lacks fingerprint_sha256;
                or redfish ca_file lacks custom_ca TLS mode; or another input
                invariant is violated.
        """
        mode = str(self.mode or "insecure").strip().lower()
        if mode not in REDFISH_TLS_MODES:
            raise ValueError(
                "Redfish TLS mode must be system_ca, custom_ca, fingerprint, "
                "or insecure"
            )
        object.__setattr__(self, "mode", mode)
        object.__setattr__(
            self,
            "fingerprint_sha256",
            normalize_sha256_fingerprint(self.fingerprint_sha256),
        )

        if mode == "custom_ca" and not self.ca_file:
            raise ValueError("Redfish custom_ca TLS mode requires ca_file")
        if mode == "fingerprint" and not self.fingerprint_sha256:
            raise ValueError("Redfish fingerprint TLS mode requires fingerprint_sha256")
        if mode != "custom_ca" and self.ca_file:
            raise ValueError("Redfish ca_file requires custom_ca TLS mode")
        if mode != "fingerprint" and self.fingerprint_sha256:
            raise ValueError("Redfish fingerprint_sha256 requires fingerprint TLS mode")

    @classmethod
    def from_session_config(
        cls, config: Optional[Mapping[str, Any]]
    ) -> "RedfishTLSPolicy":
        """
        Build a policy from canonical or legacy session configuration.

        Omission preserves the documented compatibility default and resolves
        to non-verifying ``insecure`` mode. An explicit canonical mode of
        ``system_ca``, ``custom_ca``, or ``fingerprint`` (or an explicit true
        legacy verification value) opts into Redfish server authentication.

        Args:
            config: Config governing policy from canonical or legacy session
                configuration.

        Returns:
            A ``RedfishTLSPolicy`` initialized from session config.

        Raises:
            ValueError: If the redfish ssl_verify is not true or false.
        """

        values = dict(config or {})
        mode = values.get("tls_mode")
        if not mode:
            legacy_present = "ssl_verify" in values or "ssl" in values
            legacy_verify = _normalize_legacy_verify(
                values.get("ssl_verify", values.get("ssl"))
            )
            if legacy_present and legacy_verify is None:
                raise ValueError("Redfish ssl_verify must be true or false")
            # Omission preserves the accepted v2.1 password-only behavior on a
            # trusted management network. An explicit true value opts into the
            # operating-system CA trust store.
            mode = "system_ca" if legacy_verify is True else "insecure"
        return cls(
            mode=mode,
            ca_file=values.get("ca_file"),
            fingerprint_sha256=values.get("fingerprint_sha256"),
            server_name=values.get("server_name"),
        )

    def as_dict(self) -> Dict[str, Optional[str]]:
        """
        Return the as dict.

        The implementation uses current instance state to produce the as dict.

        Returns:
            A mapping containing the ``tls_mode``, ``ca_file``,
            ``fingerprint_sha256``, and ``server_name`` fields.
        """
        return {
            "tls_mode": self.mode,
            "ca_file": self.ca_file,
            "fingerprint_sha256": self.fingerprint_sha256,
            "server_name": self.server_name,
        }

    def build_ssl_parameter(self, *, use_https: bool = True) -> Any:
        """
        Build the aiohttp SSL argument without fallback or downgrade.

        The implementation uses ``use_https`` to build the aiohttp SSL argument
        without fallback or downgrade.

        Args:
            use_https: Whether use HTTPS is enabled or required for this
                operation.

        Returns:
            The ssl parameter value selected by the operation.
        """

        if not use_https:
            return False
        if self.mode == "system_ca":
            return ssl.create_default_context()
        if self.mode == "custom_ca":
            return ssl.create_default_context(cafile=str(Path(self.ca_file)))
        if self.mode == "fingerprint":
            return aiohttp.Fingerprint(bytes.fromhex(self.fingerprint_sha256))
        return False

    def is_verified(self, *, use_https: bool = True) -> bool:
        """
        Return the effective transport posture, including the URL scheme.

        The implementation uses ``use_https`` to produce the effective transport
        posture, including the URL scheme.

        Args:
            use_https: Whether use HTTPS is enabled or required for this
                operation.

        Returns:
            Whether the effective transport posture, including the URL scheme
            operation succeeds.
        """

        return bool(use_https) and self.mode in {
            "system_ca",
            "custom_ca",
            "fingerprint",
        }

    def require_compatible_transport(
        self, *, use_https: bool, endpoint_name: str = "Redfish"
    ) -> None:
        """
        Reject applying a verifying TLS policy to plaintext transport.

        The implementation uses ``use_https`` and ``endpoint_name`` to reject
        applying a verifying TLS policy to plaintext transport. Every required
        invariant is checked before a successful value is returned; invalid
        input follows the function's explicit exception path.

        Args:
            use_https: Whether use HTTPS is enabled or required for this
                operation.
            endpoint_name: Validated remote resource identifier used for
                endpoint name.

        Raises:
            ValueError: If the redfish use_https are not true or false; or a
                verifying redfish tls policy lacks HTTPS for the active
                ``endpoint_name`` endpoint.
        """

        if not isinstance(use_https, bool):
            raise ValueError("Redfish use_https must be true or false")
        if not use_https and self.mode != "insecure":
            raise ValueError(
                "A verifying Redfish TLS policy requires HTTPS for the active "
                f"{endpoint_name} endpoint"
            )

    def request_kwargs(
        self, ssl_parameter: Any, *, use_https: bool = True
    ) -> Dict[str, Any]:
        """
        Return consistent aiohttp TLS keyword arguments for a request.

        The implementation uses ``ssl_parameter`` and ``use_https`` to produce
        consistent aiohttp TLS keyword arguments for a request.

        Args:
            ssl_parameter: Ssl parameter consumed while the function attempts to
                produce consistent aiohttp TLS keyword arguments for a request.
            use_https: Whether use HTTPS is enabled or required for this
                operation.

        Returns:
            The validated ``kwargs``.
        """

        self.require_compatible_transport(use_https=use_https)

        kwargs: Dict[str, Any] = {
            "ssl": ssl_parameter if use_https else False,
        }
        if use_https and self.server_name:
            kwargs["server_hostname"] = self.server_name
        return kwargs
