#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
Lightweight Excel reader backed by openpyxl.

Replaces the pandas pd.read_excel / pd.notna subset used in this codebase
without pulling in pandas + numpy (~40-50 MB in a PyInstaller binary).
"""

import math
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple, Union

import openpyxl
from openpyxl import load_workbook

from . import run_limits


def notna(value: Any) -> bool:
    """
    Return True unless *value* is None or float NaN.

    Drop-in replacement for ``pd.notna()`` for the subset of behavior used in
    this codebase (cell values read from openpyxl).

    Args:
        value: Value evaluated while performing true unless *value* is None or
            float NaN.

    Returns:
        Whether the true unless *value* is None or float NaN operation succeeds.
    """
    if value is None:
        return False
    try:
        if isinstance(value, float) and math.isnan(value):
            return False
    except (TypeError, ValueError):
        pass
    return True


class _ColumnAccessor:
    """
    Implement the column accessor boundary used by the NVDebug runtime.

    The type gives the column accessor responsibility a stable runtime boundary.
    Callers use the declared Python protocol instead of depending on its
    representation.
    """

    __slots__ = ("_rows", "_column")

    def __init__(self, rows: List[Dict[str, Any]], column: str) -> None:
        """
        Initialize a ``_ColumnAccessor`` instance.

        The initializer records ``_column`` and ``_rows`` for later operations
        and establishes the instance invariants before any public method runs.

        Args:
            rows: Mapping supplying fields for initialize a ``_ColumnAccessor``
                instance.
            column: Text supplied as column in the format accepted by this
                function.
        """
        self._rows = rows
        self._column = column

    def __eq__(self, value: object) -> List[bool]:  # type: ignore[override]
        """
        Return whether another value represents the same state.

        The implementation uses ``value`` to determine whether another value
        represents the same state.

        Args:
            value: Value evaluated while performing another value represents the
                same state.

        Returns:
            The eq returned in operation-defined order.
        """
        return [row.get(self._column) == value for row in self._rows]


class _RowAccessor(dict):
    """
    Dict subclass whose ``.get()`` default mirrors a pandas Series.

    The type coordinates ``get`` and retains the state those operations share
    between calls. Resource ownership remains inside the instance until the
    matching close, exit, or cleanup operation completes.
    """

    def get(self, key: str, default: Any = "") -> Any:
        """
        Return get.

        After applying local validation, the function forwards ``key`` and
        ``default`` to ``get`` and preserves its return and exception contract.

        Args:
            key: Stable key used for lookup and operator-facing diagnostics.
            default: Fallback used when the requested value is absent or
                invalid.

        Returns:
            Get selected by this operation.
        """
        return super().get(key, default)


class SheetData:
    """
    Provide the minimal read-only table used by spreadsheet consumers.

    The wrapper implements row count, column lookup, row iteration, Boolean-mask
    filtering, and mapping-style access required by this codebase. It
    deliberately does not emulate the rest of the pandas DataFrame API.
    """

    __slots__ = ("_rows", "_columns")

    def __init__(self, rows: List[Dict[str, Any]], columns: List[str]) -> None:
        """
        Initialize a ``SheetData`` instance.

        The initializer records ``_columns`` and ``_rows`` for later operations
        and establishes the instance invariants before any public method runs.

        Args:
            rows: Mapping supplying fields for initialize a ``SheetData``
                instance.
            columns: Entries supplied as ``columns`` without transferring
                container ownership.
        """
        self._rows = rows
        self._columns = columns

    @property
    def columns(self) -> List[str]:
        """
        Return the columns.

        Each access computes the value from ``_columns`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            The columns returned in operation-defined order.
        """
        return list(self._columns)

    def __len__(self) -> int:
        """
        Return the number of entries owned by the SheetData.

        After applying local validation, the function forwards current instance
        state to ``len`` and preserves its return and exception contract.

        Returns:
            The numeric len value.
        """
        return len(self._rows)

    def __getitem__(self, key: Any) -> Any:
        """
        Return the requested value from the SheetData.

        The implementation uses ``key`` to produce the requested value from the
        SheetData. If the function cannot produce the requested value from the
        SheetData, its exception reaches the caller instead of being converted
        into a successful result.

        Args:
            key: Stable key used for lookup and operator-facing diagnostics.

        Returns:
            The requested value from the SheetData.

        Raises:
            TypeError: If the supplied input cannot be used to produce the
                requested value from the SheetData.
        """
        if isinstance(key, str):
            return _ColumnAccessor(self._rows, key)
        if isinstance(key, list):
            return SheetData(
                [row for row, keep in zip(self._rows, key) if keep],
                self._columns,
            )
        raise TypeError(f"Unsupported index type: {type(key)}")

    def iterrows(self) -> Iterator[Tuple[int, _RowAccessor]]:
        """
        Return the iterrows.

        The implementation uses current instance state to produce the iterrows.

        Yields:
            Each iterrows admitted by the operation, in deterministic iteration
            order.
        """
        for idx, row in enumerate(self._rows):
            yield idx, _RowAccessor(row)


_PANDAS_NA_STRINGS = frozenset(
    {"", "NA", "N/A", "#N/A", "NaN", "nan", "null", "NULL", "None", "#NA", "<NA>"}
)


def _read_excel_source(
    source: Any,
    sheet_name: str,
    keep_default_na: bool,
    *,
    source_label: str,
    maximum_rows: int = run_limits.MAX_CATALOG_SHEET_ROWS,
    maximum_cells: int = run_limits.MAX_CATALOG_SHEET_CELLS,
) -> SheetData:
    """
    Read one sheet from a path or an already-pinned workbook stream.

    The implementation uses ``source``, ``sheet_name``, ``keep_default_na``, and
    ``source_label`` to read one sheet from a path or an already-pinned workbook
    stream. Parsing or I/O must finish before the validated representation is
    made available to the caller. If the function cannot read one sheet from a
    path or an already-pinned workbook stream, its exception reaches the caller
    instead of being converted into a successful result. Cleanup in the
    ``finally`` path runs for successful, failed, and cancelled execution.

    Args:
        source: Source consumed while the function attempts to read one sheet
            from a path or an already-pinned workbook stream.
        sheet_name: Stable sheet name used for lookup and operator-facing
            diagnostics.
        keep_default_na: Whether keep default na is enabled or required for this
            operation.
        source_label: Text supplied as source label in the format accepted by
            this function.
        maximum_rows: Maximum data rows that may be materialized from the sheet.
        maximum_cells: Maximum header and data cells that may be inspected.

    Returns:
        A ``SheetData`` representing excel source.

    Raises:
        ValueError: If a limit is invalid, the requested sheet is absent, or
            the sheet exceeds its row/cell or unique-header contract.
        RuntimeError: If the defused XML backend required for catalog parsing is
            unavailable.
    """

    if (
        isinstance(maximum_rows, bool)
        or not isinstance(maximum_rows, int)
        or not 1 <= maximum_rows <= run_limits.MAX_CATALOG_SHEET_ROWS
    ):
        raise ValueError(
            "maximum catalog sheet rows must be between 1 and "
            f"{run_limits.MAX_CATALOG_SHEET_ROWS}"
        )
    if (
        isinstance(maximum_cells, bool)
        or not isinstance(maximum_cells, int)
        or not 1 <= maximum_cells <= run_limits.MAX_CATALOG_SHEET_CELLS
    ):
        raise ValueError(
            "maximum catalog sheet cells must be between 1 and "
            f"{run_limits.MAX_CATALOG_SHEET_CELLS}"
        )
    if getattr(openpyxl, "DEFUSEDXML", False) is not True:
        raise RuntimeError(
            "Telemetry Catalog parsing requires defusedxml for bounded XML handling"
        )

    wb = load_workbook(source, read_only=True, data_only=True)
    try:
        try:
            ws = wb[sheet_name]
        except KeyError:
            raise ValueError(
                f"Sheet '{sheet_name}' not found in {source_label}"
            ) from None

        rows_iter = ws.iter_rows(values_only=True)

        header_tuple = next(rows_iter, None)
        if header_tuple is None:
            return SheetData([], [])
        observed_cells = len(header_tuple)
        if observed_cells > maximum_cells:
            raise ValueError(
                f"Sheet '{sheet_name}' in {source_label} exceeds the "
                f"{maximum_cells}-cell runtime limit"
            )

        columns = [
            str(cell) if cell is not None else f"Unnamed_{i}"
            for i, cell in enumerate(header_tuple)
        ]
        duplicate_columns = sorted(
            {column for column in columns if columns.count(column) > 1}
        )
        if duplicate_columns:
            raise ValueError(
                f"Sheet '{sheet_name}' in {source_label} has duplicate columns: "
                + ", ".join(duplicate_columns)
            )

        data: List[Dict[str, Any]] = []
        for row_count, raw in enumerate(rows_iter, start=1):
            if row_count > maximum_rows:
                raise ValueError(
                    f"Sheet '{sheet_name}' in {source_label} exceeds the "
                    f"{maximum_rows}-row runtime limit"
                )
            observed_cells += len(raw)
            if observed_cells > maximum_cells:
                raise ValueError(
                    f"Sheet '{sheet_name}' in {source_label} exceeds the "
                    f"{maximum_cells}-cell runtime limit"
                )
            row_dict: Dict[str, Any] = {}
            for col_name, cell_value in zip(columns, raw):
                if (
                    keep_default_na
                    and isinstance(cell_value, str)
                    and cell_value.strip() in _PANDAS_NA_STRINGS
                ):
                    row_dict[col_name] = None
                else:
                    row_dict[col_name] = cell_value
            data.append(row_dict)

        return SheetData(data, columns)
    finally:
        wb.close()


def _read_excel_bytes(
    content: bytes,
    sheet_name: str,
    keep_default_na: bool = True,
    *,
    source_label: str = "loaded catalog snapshot",
    maximum_rows: int = run_limits.MAX_CATALOG_SHEET_ROWS,
    maximum_cells: int = run_limits.MAX_CATALOG_SHEET_CELLS,
) -> SheetData:
    """
    Read one sheet from immutable bytes owned by a catalog snapshot.

    After applying local validation, the function forwards ``content``,
    ``sheet_name``, ``keep_default_na``, and ``source_label`` to
    ``_read_excel_source`` and preserves its return and exception contract.
    Parsing or I/O must finish before the validated representation is made
    available to the caller.

    Args:
        content: Bounded byte sequence supplied as content.
        sheet_name: Stable sheet name used for lookup and operator-facing
            diagnostics.
        keep_default_na: Whether keep default na is enabled or required for this
            operation.
        source_label: Text supplied as source label in the format accepted by
            this function.
        maximum_rows: Maximum data rows that may be materialized from the sheet.
        maximum_cells: Maximum header and data cells that may be inspected.

    Returns:
        A ``SheetData`` representing excel bytes.
    """

    with BytesIO(content) as stream:
        return _read_excel_source(
            stream,
            sheet_name,
            keep_default_na,
            source_label=source_label,
            maximum_rows=maximum_rows,
            maximum_cells=maximum_cells,
        )


def read_excel(
    path: Union[str, Path],
    sheet_name: str,
    keep_default_na: bool = True,
    *,
    maximum_rows: int = run_limits.MAX_CATALOG_SHEET_ROWS,
    maximum_cells: int = run_limits.MAX_CATALOG_SHEET_CELLS,
) -> SheetData:
    """
    Read a single Excel sheet into a :class:`SheetData`.

    Parameters ---------- path: Path to an ``.xlsx`` file. sheet_name: Worksheet
    name. keep_default_na: When *True* (the default, matching pandas), strings
    that look like NA values (``""``, ``"N/A"``, ``"NaN"``, …) are converted to
    ``None``. Set to *False* to keep them as literal strings (used when
    ``"N/A"`` has domain meaning).

    Args:
        path: filesystem location used as the path for this operation.
        sheet_name: Stable sheet name used for lookup and operator-facing
            diagnostics.
        keep_default_na: Whether keep default na is enabled or required for this
            operation.
        maximum_rows: Maximum data rows that may be materialized from the sheet.
        maximum_cells: Maximum header and data cells that may be inspected.

    Returns:
        A ``SheetData`` representing excel.
    """
    from .catalog_snapshot import read_catalog_snapshot

    snapshot = read_catalog_snapshot(path)
    return snapshot.read_excel(
        sheet_name=sheet_name,
        keep_default_na=keep_default_na,
        maximum_rows=maximum_rows,
        maximum_cells=maximum_cells,
    )
