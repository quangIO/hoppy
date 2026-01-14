"""
Joern installer module for Hoppy.

This module provides automatic installation of Joern to a well-known directory.
Joern is installed on-demand when Hoppy runs and Joern is not found in PATH.
"""

import logging
import os
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    DownloadColumn,
    MofNCompleteColumn,
    Progress,
    TaskID,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)
from rich.text import Text

logger = logging.getLogger(__name__)

# Default Joern version
DEFAULT_JOERN_VERSION = "v4.0.460"

# Base URL for Joern releases
JOERN_RELEASE_BASE = "https://github.com/joernio/joern/releases/download"


def get_joern_version() -> str:
    """Get the Joern version to install."""
    return os.environ.get("HOPPY_JOERN_VERSION", DEFAULT_JOERN_VERSION)


def get_install_dir() -> Path:
    """Get the installation directory for Joern."""
    home = Path.home()

    # Platform-specific defaults (no root required)
    # Use ~/.joern for all platforms
    return home / ".joern"


def get_joern_executable() -> Path | None:
    """
    Get the path to the Joern executable.

    Returns:
        Path to joern if found, None otherwise

    This checks:
    1. joern in PATH (via shutil.which)
    2. The well-known installation directory (~/.joern)
    """
    # First check PATH
    joern_path = shutil.which("joern")
    if joern_path:
        return Path(joern_path).resolve()

    # Then check the well-known installation directory
    install_dir = get_install_dir()
    # Joern executable is at joern-cli/joern (NOT joern-cli/bin/joern)
    joern_script = install_dir / "joern-cli" / "joern"

    if joern_script.exists():
        return joern_script

    return None


def is_joern_available(joern_path: Path | None = None) -> bool:
    """
    Check if Joern is installed and accessible.

    Args:
        joern_path: Path to joern script. If None, searches for it.

    Returns:
        True if Joern is installed and working, False otherwise
    """
    if joern_path is None:
        joern_path = get_joern_executable()
        if joern_path is None:
            return False

    if not joern_path.exists():
        return False

    # Try to run joern to verify it works
    try:
        result = subprocess.run(
            [str(joern_path), "--version"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


class DownloadProgressBar:
    """Wrapper around rich Progress for tracking downloads."""

    def __init__(self, console: Console, description: str = "Downloading"):
        self.console = console
        self.description = description
        self.progress = Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            DownloadColumn(),
            TransferSpeedColumn(),
            TimeRemainingColumn(),
            console=console,
        )
        self.task_id: TaskID | None = None

    def __enter__(self):
        self.progress.__enter__()
        self.task_id = self.progress.add_task(self.description, total=None)
        return self

    def __exit__(self, *args):
        self.progress.__exit__(*args)

    def update(self, block_num, block_size, total_size):
        """Update progress from urllib.request.urlretrieve callback."""
        if self.task_id is None:
            return
        if total_size > 0:
            if self.progress.tasks[self.task_id].total is None:
                self.progress.update(self.task_id, total=total_size)
            downloaded = block_num * block_size
            self.progress.update(self.task_id, completed=min(downloaded, total_size))


def download_file(url: str, dest: Path, console: Console) -> None:
    """Download a file from URL to destination path with rich progress."""
    filename = Path(url).name
    with DownloadProgressBar(console, f"Downloading {filename}") as progress:
        urllib.request.urlretrieve(url, dest, reporthook=progress.update)


def install_joern(console: Console | None = None) -> Path:
    """
    Install Joern to the well-known directory.

    Downloads joern-cli.zip and extracts it to ~/.joern (or platform equivalent).

    Args:
        console: Rich console for output. If None, creates a new one.

    Returns:
        Path to the installed joern script

    Raises:
        RuntimeError: If installation fails
    """
    if console is None:
        console = Console()

    version = get_joern_version()
    install_dir = get_install_dir()
    zip_url = f"{JOERN_RELEASE_BASE}/{version}/joern-cli.zip"

    # Show header
    console.print()
    console.print(
        Panel(
            Text.from_markup(
                f"[bold cyan]Joern Installation[/bold cyan]\n\n"
                f"Version: [bold]{version}[/bold]\n"
                f"Directory: [bold]{install_dir}[/bold]"
            ),
            title="[Setup]",
            border_style="cyan",
        )
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        zip_file = tmpdir_path / "joern-cli.zip"

        # Download the zip file
        try:
            download_file(zip_url, zip_file, console)
        except Exception as e:
            raise RuntimeError(f"Failed to download Joern: {e}")

        # Create the installation directory
        install_dir.mkdir(parents=True, exist_ok=True)

        # Remove existing installation if present
        existing_cli = install_dir / "joern-cli"
        if existing_cli.exists():
            console.print("[yellow]Removing existing installation...[/yellow]")
            shutil.rmtree(existing_cli)

        # Extract the zip file with progress, preserving Unix permissions
        with zipfile.ZipFile(zip_file, "r") as zip_ref:
            file_count = len(zip_ref.infolist())
            with Progress(
                TextColumn("[bold blue]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
                TimeRemainingColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Extracting files", total=file_count)
                for member in zip_ref.infolist():
                    # Extract with permissions preserved from zip
                    zip_ref.extract(member, install_dir)
                    # Ensure Unix execute permission is set for files that should be executable
                    # (zipfile should preserve this, but we ensure it as a safety measure)
                    extracted_path = install_dir / member.filename
                    if member.external_attr >> 16 & 0o111:  # Has execute bit in zip
                        extracted_path.chmod(0o755)
                    progress.update(task, advance=1)

    # The joern script is in joern-cli/joern
    joern_script = install_dir / "joern-cli" / "joern"

    if not joern_script.exists():
        raise RuntimeError(f"Installation completed but joern script not found at {joern_script}")

    # Show success
    console.print(
        Panel(
            Text.from_markup(
                f"[bold green]✓ Joern installed successfully![/bold green]\n\n"
                f"Location: {joern_script}"
            ),
            border_style="green",
        )
    )
    console.print()

    return joern_script


def ensure_joern_installed(console: Console | None = None) -> Path:
    """
    Ensure Joern is installed, installing it if necessary.

    Args:
        console: Rich console for output. If None, creates a new one.

    Returns:
        Path to the joern executable

    Raises:
        RuntimeError: If installation fails
    """
    joern_path = get_joern_executable()

    if joern_path and is_joern_available(joern_path):
        return joern_path

    # Joern not found, install it
    return install_joern(console=console)
