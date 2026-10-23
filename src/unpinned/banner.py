"""The wordmark unpinned prints when it starts in a terminal: the logo's broken padlock over the P, in its colours."""

from __future__ import annotations

import os
import shutil
import sys
from importlib import metadata

WORDMARK = """\
                   ▄█▀▀▀█▄  ▗ ▘
                   ██    ▀ ▖  ▝
██╗   ██╗███╗   ██╗██████╗ ██╗███╗   ██╗███╗   ██╗███████╗██████╗
██║   ██║████╗  ██║██╔══██╗██║████╗  ██║████╗  ██║██╔════╝██╔══██╗
██║   ██║██╔██╗ ██║██████╔╝██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║  ██║
██║   ██║██║╚██╗██║██╔═══╝ ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║  ██║
╚██████╔╝██║ ╚████║██║     ██║██║ ╚████║██║ ╚████║███████╗██████╔╝
 ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═════╝"""
HEAT = (229, 226, 220, 214, 208, 202, 196, 160)  # 256-colour codes, white-hot shackle down to red, one per line
WIDTH = max(len(line) for line in WORDMARK.splitlines())


def version() -> str:
    try:
        return metadata.version("unpinned")
    except metadata.PackageNotFoundError:
        return "dev"


def render(color: bool = True) -> str:
    lines = WORDMARK.splitlines()
    if color:
        lines = [f"\033[38;5;{c}m{line}\033[0m" for line, c in zip(lines, HEAT, strict=True)]
    tagline = f"drop in an APK, get its traffic  ·  v{version()}"
    lines.append(f"\033[2m{tagline:>{WIDTH}}\033[0m" if color else f"{tagline:>{WIDTH}}")
    return "\n".join(lines) + "\n"


def show() -> None:
    """Only for a person at a terminal wide enough for it, never into a pipe or a file."""
    if not sys.stdout.isatty() or shutil.get_terminal_size().columns < WIDTH:
        return
    print(render(color="NO_COLOR" not in os.environ), flush=True)
