#!/usr/bin/env python3
import argparse
import fcntl
import hashlib
import http.client
import lzma
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import sys
import tarfile
import tempfile
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parent
PAYLOAD = ROOT / "runtime"
PANEL_NAME = "ariaatashin-linux-amd64"
ENGINE_VERSION = "3.8.5"
ENGINE_ARCHIVE = "x-ui-linux-amd64.tar.gz"
ENGINE_URL = (
    "https://github.com/MHSanaei/3x-ui/releases/download/"
    f"v{ENGINE_VERSION}/{ENGINE_ARCHIVE}"
)
ENGINE_DIGEST = "6a85c110a04a727613c933c54ae602b8d37dab8876c6e20a6d46623010dd9d3c"
ENGINE_PROGRAMS = ("x-ui", "bin/xray-linux-amd64")
ENGINE_FILES = (*ENGINE_PROGRAMS, "bin/geoip.dat", "bin/geosite.dat")
CHUNK_SIZE = 1024 * 1024
MAX_ENGINE_ARCHIVE = 140 * CHUNK_SIZE
MAX_ENGINE_FILES = 650 * CHUNK_SIZE
MAX_PANEL_FILE = 120 * CHUNK_SIZE


def digest_stream(source, output=None, limit=None):
    digest = hashlib.sha256()
    size = 0
    for chunk in iter(lambda: source.read(CHUNK_SIZE), b""):
        size += len(chunk)
        if limit is not None and size > limit:
            raise RuntimeError("The runtime file exceeds its size limit.")
        digest.update(chunk)
        if output is not None:
            output.write(chunk)
    return digest.hexdigest()


def sha256(path):
    with path.open("rb") as source:
        return digest_stream(source)


def panel_ready(path, expected):
    return path.is_file() and os.access(path, os.X_OK) and sha256(path) == expected


def prepare_panel(runtime, destination, expected):
    with tempfile.TemporaryDirectory(prefix=".panel-", dir=runtime) as staging:
        binary = Path(staging) / PANEL_NAME
        with lzma.open(PAYLOAD / f"{PANEL_NAME}.xz", "rb") as source, binary.open("xb") as out:
            if digest_stream(source, out, MAX_PANEL_FILE) != expected:
                raise RuntimeError("The packaged panel checksum did not match.")
        binary.chmod(0o700)
        binary.replace(destination)


def check_engine(path):
    for name in ENGINE_FILES:
        file = path / name
        if not file.is_file() or file.stat().st_size == 0:
            raise RuntimeError(f"Engine v{ENGINE_VERSION} is missing {name}.")
    for name in ENGINE_PROGRAMS:
        if not os.access(path / name, os.X_OK):
            raise RuntimeError(f"The host cannot execute {path / name}.")


def unpack_engine(archive, output):
    total_size = 0
    with tarfile.open(archive, mode="r:gz") as source:
        for member in source:
            path = PurePosixPath(member.name)
            if not path.parts or path.parts[0] != "x-ui" or ".." in path.parts:
                raise RuntimeError("Unexpected path in the 3x-ui archive.")
            if member.isdir():
                (output.joinpath(*path.parts[1:])).mkdir(parents=True, exist_ok=True)
                continue
            if len(path.parts) < 2 or not member.isfile():
                raise RuntimeError("Unexpected entry in the 3x-ui archive.")
            total_size += member.size
            if member.size < 0 or total_size > MAX_ENGINE_FILES:
                raise RuntimeError("The 3x-ui archive exceeds its extraction limit.")
            file = output.joinpath(*path.parts[1:])
            file.parent.mkdir(parents=True, exist_ok=True)
            with source.extractfile(member) as entry, file.open("xb") as target:
                shutil.copyfileobj(entry, target)
            file.chmod(0o700 if member.mode & 0o111 else 0o600)


def prepare_engine(runtime, engine, env):
    override = env.get("ARIA_ENGINE_ARCHIVE")
    local_archive = Path(override).expanduser() if override else PAYLOAD / ENGINE_ARCHIVE
    with tempfile.TemporaryDirectory(prefix=".engine-", dir=runtime) as staging:
        staging = Path(staging)
        verified_archive = staging / ENGINE_ARCHIVE
        if override or local_archive.is_file():
            source = local_archive.open("rb")
        else:
            print(f"Downloading pinned 3x-ui v{ENGINE_VERSION} from GitHub.", flush=True)
            try:
                source = urlopen(ENGINE_URL, timeout=35)
            except OSError as error:
                raise RuntimeError(
                    "Unable to download the official 3x-ui engine. "
                    f"Place {ENGINE_ARCHIVE} in runtime/ and try again."
                ) from error
        with source, verified_archive.open("xb") as target:
            if digest_stream(source, target, MAX_ENGINE_ARCHIVE) != ENGINE_DIGEST:
                raise RuntimeError("The official 3x-ui archive checksum did not match.")

        extracted = staging / "engine"
        extracted.mkdir()
        unpack_engine(verified_archive, extracted)
        check_engine(extracted)
        extracted.replace(engine)


def prepare_runtime(env):
    runtime = Path(env.get("ARIA_RUNTIME_DIR") or ROOT / ".aria-runtime").expanduser().resolve()
    panel = runtime / PANEL_NAME
    provided_engine = env.get("ARIA_ENGINE_DIR") or env.get("ATIA_ENGINE_DIR")
    engine = Path(provided_engine).expanduser().resolve() if provided_engine else runtime / f"engine-{ENGINE_VERSION}"
    tools = runtime / "bin"
    sqlite = tools / "sqlite3"
    expected = (PAYLOAD / f"{PANEL_NAME}.sha256").read_text(encoding="ascii").strip()
    if provided_engine or engine.exists():
        check_engine(engine)
        if panel_ready(panel, expected) and sqlite.is_file() and os.access(sqlite, os.X_OK):
            return panel, engine, tools

    runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (runtime / "prepare.lock").open("ab") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not panel_ready(panel, expected):
            prepare_panel(runtime, panel, expected)
        if not provided_engine and not engine.exists():
            prepare_engine(runtime, engine, env)
        check_engine(engine)
        tools.mkdir(mode=0o700, exist_ok=True)
        if not sqlite.is_file() or not os.access(sqlite, os.X_OK):
            with tempfile.TemporaryDirectory(prefix=".sqlite-", dir=runtime) as staging:
                shim = Path(staging) / "sqlite3"
                shutil.copyfile(PAYLOAD / "sqlite3-shim", shim)
                shim.chmod(0o700)
                shim.replace(sqlite)
    return panel, engine, tools


def main():
    parser = argparse.ArgumentParser(description="Run the ariaatashin 4.11.1 panel with Python.")
    parser.add_argument("--prepare", action="store_true", help="Prepare the Linux runtime without starting the panel.")
    args = parser.parse_args()
    if sys.platform != "linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise RuntimeError("This package requires a Linux x86_64 host.")

    env = os.environ.copy()
    if not args.prepare:
        password = env.get("ARIA_ADMIN_PASSWORD") or env.get("ATIA_ADMIN_PASSWORD", "")
        if len(password.strip()) < 12 or len(password.encode()) > 256:
            raise RuntimeError("Set ARIA_ADMIN_PASSWORD to a private password of at least 12 characters and at most 256 UTF-8 bytes.")

    panel, engine, tools = prepare_runtime(env)
    if args.prepare:
        print("Panel and 3x-ui runtime are ready.", flush=True)
        return

    env["ARIA_ENGINE_DIR"] = str(engine)
    env["ARIA_SQLITE_PYTHON"] = sys.executable
    env["ARIA_SQLITE_HELPER"] = str(PAYLOAD / "sqlite_helper.py")
    env["PATH"] = os.pathsep.join((str(tools), env.get("PATH") or os.defpath))
    for binary, key in (("sing-box", "ARIA_SING_BOX_BIN"), ("ookla-speedtest", "ARIA_SPEEDTEST_BIN")):
        local = PAYLOAD / binary
        if local.is_file():
            env.setdefault(key, str(local))
    os.execve(panel, [str(panel)], env)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, lzma.LZMAError, tarfile.TarError, http.client.HTTPException) as error:
        print(f"ariaatashin: {error}", file=sys.stderr)
        sys.exit(1)
