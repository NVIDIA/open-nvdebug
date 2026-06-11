"""
Safe command construction utilities for open-nvdebugtool.

Prevents shell command injection by providing:
- quote_arg(): Shell-safe argument quoting via shlex.quote
- build_remote_cmd(): Build quoted commands for SSH remote execution
- build_local_cmd(): Build argument lists for subprocess (no shell)
- safe_subprocess_run(): subprocess.run wrapper that forbids shell=True
"""

import shlex
import subprocess
from typing import Any, List, Optional


def quote_arg(value: str) -> str:
    """
    Quote a single argument for safe shell interpolation.
    Uses shlex.quote which wraps the value in single quotes.

    Raises:
        TypeError: If value is not a string.
    """
    if not isinstance(value, str):
        raise TypeError(f"quote_arg requires a string, got {type(value).__name__}")
    return shlex.quote(value)


def build_remote_cmd(template: str, **kwargs: str) -> str:
    """
    Build a shell command string for remote (SSH) execution with all
    interpolated values safely quoted via shlex.quote.

    Example:
        >>> build_remote_cmd("cat {path}", path="/var/log/syslog")
        "cat '/var/log/syslog'"
    """
    quoted_kwargs = {k: quote_arg(str(v)) for k, v in kwargs.items()}
    return template.format(**quoted_kwargs)


def build_local_cmd(template_args: List[str], **kwargs: str) -> List[str]:
    """
    Build a command argument list for local subprocess execution.
    No quoting needed — subprocess with shell=False treats each element as literal.

    Example:
        >>> build_local_cmd(["xxd", "-g", "1", "{file}"], file="/tmp/dump.bin")
        ["xxd", "-g", "1", "/tmp/dump.bin"]
    """
    return [arg.format(**kwargs) for arg in template_args]


def safe_subprocess_run(
    cmd: List[str],
    timeout: Optional[int] = 120,
    capture_output: bool = True,
    text: bool = True,
    check: bool = False,
    **kwargs: Any,
) -> subprocess.CompletedProcess:
    """
    Safe wrapper around subprocess.run that forbids shell=True.

    Raises:
        TypeError: If cmd is not a list.
        ValueError: If shell=True is passed.
    """
    if not isinstance(cmd, list):
        raise TypeError(
            f"cmd must be a list of arguments, got {type(cmd).__name__}. "
            "Use build_local_cmd() to construct the argument list."
        )
    if kwargs.get("shell", False):
        raise ValueError(
            "shell=True is not allowed. Use build_local_cmd() to construct "
            "a safe argument list for subprocess.run(shell=False)."
        )
    kwargs.pop("shell", None)
    return subprocess.run(
        cmd,
        timeout=timeout,
        capture_output=capture_output,
        text=text,
        check=check,
        **kwargs,
    )
