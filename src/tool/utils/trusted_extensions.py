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
Fail-closed access to optional trusted runtime extensions.

The public source distribution intentionally does not include the internal
extension package. Core code therefore treats its absence as normal until a
namespaced extension is explicitly enabled. Product configuration, legacy
aliases, and implementation details remain owned by the installed package.
"""

from __future__ import annotations

import copy
import importlib
import importlib.util
import sys
from importlib.machinery import PathFinder
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping

TRUSTED_EXTENSION_PACKAGE = "nvdebug_internal_extensions"


class TrustedExtensionError(RuntimeError):
    """
    Raised when an installed trusted extension boundary is malformed.

    Callers receive this exception when the trusted extension error invariant
    prevents the requested operation from completing. The distinct type lets
    them handle that boundary without parsing an error message.
    """


def _trusted_extension_roots() -> tuple[Path, ...]:
    """
    Return install roots derived from this already-trusted host module.

    Editable source installs keep ``tool`` below ``src/`` while the private
    package is a sibling of that directory. This path is still anchored to this
    module's location, never to the process working directory.

    Returns:
        The trusted extension roots returned in operation-defined order.
    """

    host_import_root = Path(__file__).resolve().parents[2]
    roots = [host_import_root / TRUSTED_EXTENSION_PACKAGE]
    # Editable source installs keep ``tool`` below ``src/`` while the private
    # package is a sibling of that directory. This path is still anchored to
    # this module's location, never to the process working directory.
    if host_import_root.name == "src":
        roots.append(host_import_root.parent / TRUSTED_EXTENSION_PACKAGE)
    return tuple(root.resolve() for root in roots)


def _find_trusted_spec(module_name: str) -> Any:
    """
    Resolve an extension spec using only host-anchored search locations.

    The normal import finder searches every entry in ``sys.path``. That is too
    broad for this boundary and also lets an editable private checkout leak
    into a copied public runtime. The package lookup is therefore limited to
    the parents of the approved package roots. Child lookups use only the
    already-validated parent package paths.

    Args:
        module_name: Trusted-extension package or descendant to resolve.

    Returns:
        The anchored import spec, or ``None`` when no approved package or child
        exists.

    Raises:
        TrustedExtensionError: If a child package exposes an unapproved search
            location or the requested name is outside the trusted namespace.
    """

    if module_name != TRUSTED_EXTENSION_PACKAGE and not module_name.startswith(
        f"{TRUSTED_EXTENSION_PACKAGE}."
    ):
        raise TrustedExtensionError("Trusted extension module is outside its namespace")

    if module_name == TRUSTED_EXTENSION_PACKAGE:
        search_paths = []
        for root in _trusted_extension_roots():
            parent = root.parent
            if parent.is_dir() and str(parent) not in search_paths:
                search_paths.append(str(parent))
        return PathFinder.find_spec(module_name, search_paths)

    parent_name = module_name.rpartition(".")[0]
    parent = sys.modules.get(parent_name)
    if parent is None:
        return None
    _assert_trusted_origin(parent_name, parent)
    package_paths = getattr(parent, "__path__", None)
    if package_paths is None:
        return None

    search_paths = []
    approved_roots = _trusted_extension_roots()
    for raw_path in package_paths:
        try:
            resolved = Path(raw_path).resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise TrustedExtensionError(
                "Trusted extension package has an invalid search path"
            ) from error
        if not resolved.is_dir() or not any(
            resolved == root or resolved.is_relative_to(root) for root in approved_roots
        ):
            raise TrustedExtensionError(
                "Trusted extension package has an unapproved search path"
            )
        search_paths.append(str(resolved))
    return PathFinder.find_spec(module_name, search_paths)


def _assert_trusted_origin(module_name: str, subject: Any) -> None:
    """
    Require a module/spec to originate in the host-anchored package root.

    The implementation uses ``module_name`` and ``subject`` to require a
    module/spec to originate in the host-anchored package root. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path. Filesystem effects remain
    confined to the caller-selected paths and the owning resource lifecycle.

    Args:
        module_name: Stable module name used for lookup and operator-facing
            diagnostics.
        subject: Subject consumed while the function attempts to require a
            module/spec to originate in the host-anchored package root.

    Raises:
        TrustedExtensionError: If trusted extension module is outside its
            namespace; trusted extension module has no filesystem origin;
            trusted extension module has no valid filesystem origin; or trusted
            extension module origin is not a regular file; or another input
            invariant is violated.
    """

    if module_name != TRUSTED_EXTENSION_PACKAGE and not module_name.startswith(
        f"{TRUSTED_EXTENSION_PACKAGE}."
    ):
        raise TrustedExtensionError("Trusted extension module is outside its namespace")
    origin = getattr(subject, "origin", None) or getattr(subject, "__file__", None)
    if not isinstance(origin, str) or not origin:
        raise TrustedExtensionError("Trusted extension module has no filesystem origin")
    try:
        resolved = Path(origin).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise TrustedExtensionError(
            "Trusted extension module has no valid filesystem origin"
        ) from error
    if not resolved.is_file():
        raise TrustedExtensionError(
            "Trusted extension module origin is not a regular file"
        )
    if not any(
        resolved == root or resolved.is_relative_to(root)
        for root in _trusted_extension_roots()
    ):
        raise TrustedExtensionError("Trusted extension module has an unapproved origin")


def _execute_trusted_spec(module_name: str, spec: Any) -> Any:
    """
    Execute the exact validated import spec with rollback on every failure.

    A pre-existing module is revalidated before reuse. New modules are made
    visible only for normal circular-import semantics while their selected
    loader runs; any exception or terminal origin mismatch removes the exact
    provisional entry so a later import cannot inherit partial state.

    Args:
        module_name: Trusted-extension namespace selected by the caller.
        spec: Import spec whose origin has already passed the anchored check.

    Returns:
        The revalidated cached module or module produced by the exact spec.

    Raises:
        TrustedExtensionError: If the cached module has an unapproved origin,
            the spec has no loader, or the loaded module changes origin.
        BaseException: Any loader control or initialization failure after the
            provisional module entry has been rolled back.

    Side effects:
        Temporarily registers a new module in ``sys.modules`` while its trusted
        loader executes.
    """

    cached = sys.modules.get(module_name)
    if cached is not None:
        _assert_trusted_origin(module_name, cached)
        return cached
    loader = getattr(spec, "loader", None)
    if loader is None:
        raise TrustedExtensionError("Trusted extension module has no loader")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        loader.exec_module(module)
        _assert_trusted_origin(module_name, module)
    except BaseException:
        if sys.modules.get(module_name) is module:
            del sys.modules[module_name]
        raise
    return module


def import_trusted_extension_module(module_name: str) -> Any:
    """
    Resolve and import a private module only from the anchored package root.

    The implementation uses ``module_name`` to resolve and import a private
    module only from the anchored package root. If the function cannot resolve
    and import a private module only from the anchored package root, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        module_name: Stable module name used for lookup and operator-facing
            diagnostics.

    Returns:
        The validated ``module``.

    Raises:
        TrustedExtensionError: If trusted extension module is outside its
            namespace; trusted extension module cannot be resolved; or the
            trusted extension module could not be initialized.
    """

    if module_name != TRUSTED_EXTENSION_PACKAGE and not module_name.startswith(
        f"{TRUSTED_EXTENSION_PACKAGE}."
    ):
        raise TrustedExtensionError("Trusted extension module is outside its namespace")
    if module_name != TRUSTED_EXTENSION_PACKAGE:
        parent_name = module_name.rpartition(".")[0]
        if parent_name == TRUSTED_EXTENSION_PACKAGE:
            if _load_package() is None:
                raise TrustedExtensionError(
                    "Trusted extension module cannot be resolved"
                )
        else:
            import_trusted_extension_module(parent_name)
    cached = sys.modules.get(module_name)
    if cached is not None:
        _assert_trusted_origin(module_name, cached)
        return cached
    try:
        spec = _find_trusted_spec(module_name)
    except (ImportError, ModuleNotFoundError, ValueError) as error:
        raise TrustedExtensionError(
            "Trusted extension module cannot be resolved"
        ) from error
    if spec is None:
        raise TrustedExtensionError("Trusted extension module cannot be resolved")
    _assert_trusted_origin(module_name, spec)
    try:
        module = _execute_trusted_spec(module_name, spec)
    except TrustedExtensionError:
        raise
    except Exception as error:
        raise TrustedExtensionError(
            "The trusted extension module could not be initialized"
        ) from error
    _assert_trusted_origin(module_name, module)
    return module


def _load_package() -> Any:
    """
    Load package.

    The implementation uses current instance state to load package. Parsing or
    I/O must finish before the validated representation is made available to the
    caller. If the function cannot load package, its exception reaches the
    caller instead of being converted into a successful result.

    Returns:
        The validated ``package``.

    Raises:
        TrustedExtensionError: If the trusted extension package has an
            unavailable dependency; or the trusted extension package could not
            be initialized.
    """
    cached = sys.modules.get(TRUSTED_EXTENSION_PACKAGE)
    if cached is not None:
        _assert_trusted_origin(TRUSTED_EXTENSION_PACKAGE, cached)
        return cached
    try:
        spec = _find_trusted_spec(TRUSTED_EXTENSION_PACKAGE)
        if spec is None:
            return None
        _assert_trusted_origin(TRUSTED_EXTENSION_PACKAGE, spec)
        package = _execute_trusted_spec(TRUSTED_EXTENSION_PACKAGE, spec)
        return package
    except ModuleNotFoundError as error:
        if error.name == TRUSTED_EXTENSION_PACKAGE:
            return None
        raise TrustedExtensionError(
            "The trusted extension package has an unavailable dependency"
        ) from error
    except TrustedExtensionError:
        raise
    except Exception as error:
        raise TrustedExtensionError(
            "The trusted extension package could not be initialized"
        ) from error


def call_optional_config_hook(name: str, values: Mapping[str, Any]) -> Dict[str, Any]:
    """
    Apply one installed-package configuration hook to a defensive copy.

    The implementation uses ``name`` and ``values`` to apply one
    installed-package configuration hook to a defensive copy. If the function
    cannot apply one installed-package configuration hook to a defensive copy,
    its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        name: Stable name used for lookup and operator-facing diagnostics.
        values: Mapping supplying fields for apply one installed-package
            configuration hook to a defensive copy.

    Returns:
        A mapping containing call optional config hook.

    Raises:
        TrustedExtensionError: If trusted configuration hook ``name`` is
            invalid; or trusted configuration hook ``name`` returned a
            non-mapping.
    """

    normalized = copy.deepcopy(dict(values))
    package = _load_package()
    if package is None:
        return normalized
    hook = getattr(package, name, None)
    if hook is None:
        return normalized
    if not callable(hook):
        raise TrustedExtensionError(f"Trusted configuration hook {name!r} is invalid")
    result = hook(normalized)
    if not isinstance(result, dict):
        raise TrustedExtensionError(
            f"Trusted configuration hook {name!r} returned a non-mapping"
        )
    return result


def sanitize_optional_config_text(text: str, replacement: str) -> str:
    """
    Let the installed package redact legacy extension configuration text.

    The implementation uses ``text`` and ``replacement`` to let the installed
    package redact legacy extension configuration text. If the function cannot
    let the installed package redact legacy extension configuration text, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        text: Text supplied as text in the format accepted by this function.
        replacement: Text supplied as replacement in the format accepted by this
            function.

    Returns:
        The canonical optional config text.

    Raises:
        TrustedExtensionError: If trusted sanitization hook is invalid; or
            trusted sanitization hook returned non-text.
    """

    package = _load_package()
    if package is None:
        return text
    hook = getattr(package, "sanitize_config_text", None)
    if hook is None:
        return text
    if not callable(hook):
        raise TrustedExtensionError("Trusted sanitization hook is invalid")
    result = hook(text, replacement)
    if not isinstance(result, str):
        raise TrustedExtensionError("Trusted sanitization hook returned non-text")
    return result


def redact_optional_config_mapping(
    values: Mapping[str, Any], replacement: str
) -> Dict[str, Any]:
    """
    Let the installed package redact bounded legacy mapping shapes.

    The implementation uses ``values`` and ``replacement`` to let the installed
    package redact bounded legacy mapping shapes. If the function cannot let the
    installed package redact bounded legacy mapping shapes, its exception
    reaches the caller instead of being converted into a successful result.

    Args:
        values: Mapping supplying fields for let the installed package redact
            bounded legacy mapping shapes.
        replacement: Text supplied as replacement in the format accepted by this
            function.

    Returns:
        A mapping containing redact optional config mapping.

    Raises:
        TrustedExtensionError: If trusted mapping-redaction hook is invalid; or
            trusted mapping-redaction hook returned a non-mapping.
    """

    normalized = copy.deepcopy(dict(values))
    package = _load_package()
    if package is None:
        return normalized
    hook = getattr(package, "redact_config_mapping", None)
    if hook is None:
        return normalized
    if not callable(hook):
        raise TrustedExtensionError("Trusted mapping-redaction hook is invalid")
    result = hook(normalized, replacement)
    if not isinstance(result, dict):
        raise TrustedExtensionError(
            "Trusted mapping-redaction hook returned a non-mapping"
        )
    return result


def lifecycle_descriptors() -> Iterable[Mapping[str, Any]]:
    """
    Return installed lifecycle descriptors without importing their modules.

    The implementation uses current instance state to produce installed
    lifecycle descriptors without importing their modules. If the function
    cannot produce installed lifecycle descriptors without importing their
    modules, its exception reaches the caller instead of being converted into a
    successful result.

    Returns:
        The canonical lifecycle descriptors text.

    Raises:
        TrustedExtensionError: If trusted lifecycle descriptor hook is invalid;
            or the trusted lifecycle descriptors are not a sequence.
    """

    package = _load_package()
    if package is None:
        return ()
    hook = getattr(package, "get_lifecycle_extension_descriptors", None)
    if hook is None:
        return ()
    if not callable(hook):
        raise TrustedExtensionError("Trusted lifecycle descriptor hook is invalid")
    result = hook()
    if not isinstance(result, (list, tuple)):
        raise TrustedExtensionError("Trusted lifecycle descriptors must be a sequence")
    return tuple(result)


def legacy_extension_results(dut_dir: Path, dut_id: str) -> tuple[Dict[str, Any], ...]:
    """
    Load bounded legacy result locations owned by the installed package.

    The implementation uses ``dut_dir`` and ``dut_id`` to load bounded legacy
    result locations owned by the installed package. Parsing or I/O must finish
    before the validated representation is made available to the caller. If the
    function cannot load bounded legacy result locations owned by the installed
    package, its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        dut_dir: filesystem location used as the DUT dir for this operation.
        dut_id: Stable DUT identifier used to correlate configuration, logs, and
            results.

    Returns:
        The legacy extension results returned in operation-defined order.

    Raises:
        TrustedExtensionError: If trusted legacy-result hook is invalid; or
            trusted legacy-result hook returned an invalid result sequence.
    """

    package = _load_package()
    if package is None:
        return ()
    hook = getattr(package, "get_legacy_extension_results", None)
    if hook is None:
        return ()
    if not callable(hook):
        raise TrustedExtensionError("Trusted legacy-result hook is invalid")
    result = hook(dut_dir, dut_id)
    if not isinstance(result, (list, tuple)) or not all(
        isinstance(item, dict) for item in result
    ):
        raise TrustedExtensionError(
            "Trusted legacy-result hook returned an invalid result sequence"
        )
    return tuple(copy.deepcopy(result))
