"""The host side of interception: mitmweb on localhost (or a proxy you already run), the CA it signs with, a
config.js filled in for this run, the frida command that spawns the app with every hook, and scrcpy."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import time
from pathlib import Path

from unpinned import assets, env


def mitm_dir() -> Path:
    """unpinned's own mitmproxy config directory: its own CA (not your main ~/.mitmproxy one) and the web UI
    password, in a private config.yaml rather than on the command line where `ps` would show it."""
    d = env.home() / "mitmproxy"
    d.mkdir(mode=0o700, exist_ok=True)
    return d


def mitm_ca() -> Path:
    return mitm_dir() / "mitmproxy-ca-cert.pem"


class InterceptError(RuntimeError):
    pass


def _state_file() -> Path:
    return env.home() / "state.json"


def state() -> dict:
    try:
        return json.loads(_state_file().read_text())
    except (OSError, ValueError):
        return {}


def save_state(**kw) -> None:
    s = state() | kw
    _state_file().write_text(json.dumps(s, indent=2))


def listening(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def _alive(pid: int | None, name: str) -> bool:
    """pid is running and is `name` (a stale pid in the state file may have been reused by something else)."""
    if not pid:
        return False
    r = subprocess.run(["/bin/ps", "-p", str(int(pid)), "-o", "command="], capture_output=True, text=True, check=False)
    return r.returncode == 0 and name in r.stdout


def free_port(preferred: int) -> int:
    """preferred when nothing listens there, else one the OS picks (something else, e.g. a container, may own it)."""
    if not listening(preferred):
        return preferred
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_mitmweb(insecure_upstream: bool = False) -> tuple[int, str]:
    """mitmweb on 127.0.0.1 only → (proxy port, web UI URL with its access token). Reuses the mitmweb unpinned started
    earlier; never takes a port something else already listens on for a proxy."""
    st = state()
    if _alive(st.get("mitmweb_pid"), "mitmweb") and st.get("proxy_port") and listening(st["proxy_port"]):
        if bool(st.get("insecure_upstream")) == insecure_upstream:
            return st["proxy_port"], st.get("mitmweb_url") or ""
        os.kill(st["mitmweb_pid"], signal.SIGTERM)  # started with the other upstream setting
        time.sleep(1)
    mitmweb = shutil.which("mitmweb")
    if not mitmweb:
        raise InterceptError("mitmweb not found (brew install mitmproxy), or run your own proxy and pass --proxy-port")
    port = free_port(env.PROXY_PORT)
    web_port = free_port(env.WEB_PORT if env.WEB_PORT != port else env.WEB_PORT + 1)
    token = secrets.token_hex(16)
    conf = mitm_dir() / "config.yaml"
    conf.unlink(missing_ok=True)
    fd = os.open(conf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(f"web_password: '{token}'\n")
    log_path = env.home() / "mitmweb.log"
    log = open(log_path, "wb")
    p = subprocess.Popen(
        [
            mitmweb,
            "--set",
            f"confdir={mitm_dir()}",
            "--listen-host",
            "127.0.0.1",
            "--listen-port",
            str(port),
            "--web-host",
            "127.0.0.1",
            "--web-port",
            str(web_port),
            "--set",
            "web_open_browser=false",
            *(["--set", "ssl_insecure=true"] if insecure_upstream else []),
        ],
        stdout=log,
        stderr=log,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and p.poll() is None and not (listening(port) and listening(web_port)):
        time.sleep(0.5)
    if p.poll() is not None or not listening(port):
        raise InterceptError(f"mitmweb didn't start (see {log_path})")
    url = f"http://127.0.0.1:{web_port}/?token={token}"
    save_state(mitmweb_pid=p.pid, mitmweb_url=url, proxy_port=port, insecure_upstream=insecure_upstream)
    return port, url


def ca_pem(path: Path | None = None) -> str:
    p = Path(path) if path else mitm_ca()
    deadline = time.monotonic() + 10  # mitmproxy writes its CA on first start
    while not p.is_file() and time.monotonic() < deadline:
        time.sleep(0.5)
    if not p.is_file():
        raise InterceptError(f"no CA certificate at {p} (start mitmproxy once, or pass --ca)")
    return p.read_text()


def write_config(ca: str, host: str, port: int, run_dir: Path) -> Path:
    template = (assets.scripts_dir() / "config.js").read_text()
    out = run_dir / "config.js"
    run_dir.mkdir(parents=True, exist_ok=True)
    out.write_text(assets.render_config(template, ca, host, port))
    return out


def frida_command(serial: str, package: str, config: Path, extra: list[str] | None = None) -> list[str]:
    """frida spawns the app with config.js first, then every hook, and leaves you in its REPL."""
    d = assets.scripts_dir()
    cmd = [env.frida_bin(), "-D", serial, "-l", str(config)]
    for rel in assets.SCRIPTS:
        if rel != "config.js":
            cmd += ["-l", str(d / rel)]
    for script in extra or []:
        cmd += ["-l", str(script)]
    return [*cmd, "-f", package]


def start_hooks(cmd: list[str], log_path: Path) -> subprocess.Popen:
    """Run frida (spawning the app with the hooks) in the background. Its stdin is a FIFO it holds open itself, so the
    REPL never sees end-of-input and the hooks stay loaded after unpinned exits, until `unpinned stop`."""
    fifo = log_path.with_suffix(".stdin")
    fifo.unlink(missing_ok=True)
    os.mkfifo(fifo, 0o600)
    stdin = os.open(fifo, os.O_RDWR)
    log = open(log_path, "wb")
    try:
        p = subprocess.Popen(cmd, stdin=stdin, stdout=log, stderr=log, start_new_session=True)
    finally:
        os.close(stdin)
    save_state(frida_pid=p.pid)
    return p


def wait_for(log_path: Path, needle: str, timeout: float, proc: subprocess.Popen | None = None) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if needle in log_path.read_text(errors="replace"):
            return True
        if proc is not None and proc.poll() is not None:
            return False
        time.sleep(0.5)
    return False


def start_scrcpy(serial: str, title: str) -> None:
    scrcpy = shutil.which("scrcpy")
    if not scrcpy:
        return
    log = open(env.home() / "scrcpy.log", "wb")
    p = subprocess.Popen(
        [scrcpy, "-s", serial, "--window-title", title, "--stay-awake"],
        stdout=log,
        stderr=log,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )
    save_state(scrcpy_pid=p.pid)


def stop_host_processes() -> list[str]:
    stopped = []
    s = state()
    for key, name in (("frida_pid", "frida"), ("scrcpy_pid", "scrcpy"), ("mitmweb_pid", "mitmweb")):
        pid = s.get(key)
        if _alive(pid, name):
            os.kill(pid, signal.SIGTERM)
            stopped.append(key.removesuffix("_pid"))
    save_state(frida_pid=None, scrcpy_pid=None, mitmweb_pid=None, mitmweb_url=None, proxy_port=None)
    return stopped
