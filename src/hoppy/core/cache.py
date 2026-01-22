import hashlib
import os
import shutil
from pathlib import Path

def get_directory_fingerprint(path: str) -> str:
    """
    Generates a fingerprint for a directory based on file names, sizes, and modification times.
    This is faster than hashing all content.
    """
    path_obj = Path(path)
    if not path_obj.exists():
        return ""

    if path_obj.is_file():
        stats = path_obj.stat()
        return hashlib.md5(f"{path_obj.name}:{stats.st_size}:{stats.st_mtime}".encode()).hexdigest()

    # For directories, we list all files and their stats
    files_info = []
    # Using a limited depth or ignoring common noise might be good, 
    # but for now let's keep it simple.
    for root, dirs, files in os.walk(path):
        # Sort to ensure stable fingerprint
        dirs.sort()
        files.sort()
        
        # Skip hidden and ignored directories if needed, 
        # but let's just use what's there for now.
        if ".git" in dirs:
            dirs.remove(".git")
        if "__pycache__" in dirs:
            dirs.remove("__pycache__")
        if "node_modules" in dirs:
            dirs.remove("node_modules")

        for f in files:
            full_path = Path(root) / f
            try:
                stats = full_path.stat()
                files_info.append(f"{full_path.relative_to(path)}:{stats.st_size}:{stats.st_mtime}")
            except OSError:
                continue

    return hashlib.md5("\n".join(files_info).encode()).hexdigest()

class CpgCache:
    def __init__(self, cache_dir: str | None = None):
        if cache_dir:
            self.cache_root = Path(cache_dir)
        else:
            # Default to ~/.hoppy/cache
            self.cache_root = Path.home() / ".hoppy" / "cache"
        
        self.cache_root.mkdir(parents=True, exist_ok=True)

    def get_cpg_path(self, source_path: str, language: str | None = None, joern_args: list[str] | None = None) -> Path:
        fingerprint = get_directory_fingerprint(source_path)
        # Include language and args in the key to avoid collisions
        key_parts = [fingerprint, language or "any"]
        if joern_args:
            key_parts.append("-".join(sorted(joern_args)))
        
        key = hashlib.md5(":".join(key_parts).encode()).hexdigest()
        return self.cache_root / f"{key}.cpg.bin.zip"

    def has(self, source_path: str, language: str | None = None, joern_args: list[str] | None = None) -> bool:
        return self.get_cpg_path(source_path, language, joern_args).exists()

    def get(self, source_path: str, language: str | None = None, joern_args: list[str] | None = None) -> str | None:
        path = self.get_cpg_path(source_path, language, joern_args)
        if path.exists():
            return str(path)
        return None

    def put(self, source_path: str, cpg_bin_path: str, language: str | None = None, joern_args: list[str] | None = None):
        target_path = self.get_cpg_path(source_path, language, joern_args)
        shutil.copy2(cpg_bin_path, target_path)
        return str(target_path)
