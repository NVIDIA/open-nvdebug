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
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple, Union

from openpyxl import load_workbook


def notna(value: Any) -> bool:
    """Return True unless *value* is None or float NaN.

    Drop-in replacement for ``pd.notna()`` for the subset of behavior used
    in this codebase (cell values read from openpyxl).
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
    """Returned by ``SheetData["column"]``; supports ``== value`` to build a boolean mask."""

    __slots__ = ("_rows", "_column")

    def __init__(self, rows: List[Dict[str, Any]], column: str) -> None:
        self._rows = rows
        self._column = column

    def __eq__(self, value: object) -> List[bool]:  # type: ignore[override]
        return [row.get(self._column) == value for row in self._rows]


class _RowAccessor(dict):
    """Dict subclass whose ``.get()`` default mirrors a pandas Series."""

    def get(self, key: str, default: Any = "") -> Any:
        return super().get(key, default)


class SheetData:
    """Minimal read-only table returned by :func:`read_excel`.

    Supports the DataFrame operations actually used in the codebase:

    * ``len(sheet)``
    * ``sheet.columns``
    * ``sheet.iterrows()``
    * ``sheet[sheet["col"] == value]``  (boolean-mask filtering)
    """

    __slots__ = ("_rows", "_columns")

    def __init__(self, rows: List[Dict[str, Any]], columns: List[str]) -> None:
        self._rows = rows
        self._columns = columns

    @property
    def columns(self) -> List[str]:
        return list(self._columns)

    def __len__(self) -> int:
        return len(self._rows)

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, str):
            return _ColumnAccessor(self._rows, key)
        if isinstance(key, list):
            return SheetData(
                [row for row, keep in zip(self._rows, key) if keep],
                self._columns,
            )
        raise TypeError(f"Unsupported index type: {type(key)}")

    def iterrows(self) -> Iterator[Tuple[int, _RowAccessor]]:
        for idx, row in enumerate(self._rows):
            yield idx, _RowAccessor(row)


_PANDAS_NA_STRINGS = frozenset(
    {"", "NA", "N/A", "#N/A", "NaN", "nan", "null", "NULL", "None", "#NA", "<NA>"}
)


def read_excel(
    path: Union[str, Path],
    sheet_name: str,
    keep_default_na: bool = True,
) -> SheetData:
    """Read a single Excel sheet into a :class:`SheetData`.

    Parameters
    ----------
    path:
        Path to an ``.xlsx`` file.
    sheet_name:
        Worksheet name.
    keep_default_na:
        When *True* (the default, matching pandas), strings that look like NA
        values (``""``, ``"N/A"``, ``"NaN"``, …) are converted to ``None``.
        Set to *False* to keep them as literal strings (used when ``"N/A"``
        has domain meaning).
    """
    wb = load_workbook(str(path), read_only=True, data_only=True)
    try:
        ws = wb[sheet_name]
    except KeyError:
        wb.close()
        raise ValueError(f"Sheet '{sheet_name}' not found in {path}")

    rows_iter = ws.iter_rows(values_only=True)

    header_tuple = next(rows_iter, None)
    if header_tuple is None:
        wb.close()
        return SheetData([], [])

    columns = [
        str(cell) if cell is not None else f"Unnamed_{i}"
        for i, cell in enumerate(header_tuple)
    ]

    data: List[Dict[str, Any]] = []
    for raw in rows_iter:
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

    wb.close()
    return SheetData(data, columns)
