#!/usr/bin/env python3
"""Fido Fidelis workflows.

``fido.py config`` turns a profile from ``tools/generate_profile.py`` into the
firmware config that ``build`` consumes.  ``fido.py build`` compiles firmware
for a profile, board and payload, then exits.  ``fido.py root`` serves the
stage-two installer to a target running firmware from ``build --payload
root-ssh`` and verifies that root SSH came up.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import ipaddress
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tools"))

import gen_descriptors  # noqa: E402
import payload  # noqa: E402
import profile_data  # noqa: E402


DEFAULT_CONFIG = ROOT / "firmware.json"
DEFAULT_INSTALLER = ROOT / "payloads" / "persist_root_ssh.sh"
DEFAULT_TARGET = "192.168.123.161"
DEFAULT_PORT = 8000
DEFAULT_BOARD = "pico2"
BOARD_BOOTSEL_VOLUMES = {
    "pico": "RPI-RP2",
    "pico2": "RP2350",
}
COMPLETION_PATH = "/.fido-fidelis-complete"
GENERATED_CONFIG_NAME = "firmware.json"
BUILD_HINT = "fido.py build --payload root-ssh"
# Measured on the bench Go2; retune with --drain/--neighbours for another dog.
DEFAULT_DRAIN = 23
DEFAULT_NEIGHBOURS = [1, 2]
# The robot's eth0 is a /24 (192.168.123.161, netmask 255.255.255.0).
LINK_PREFIX = 24


class WorkflowError(ValueError):
    pass


@dataclass
class StageEvents:
    fetched: threading.Event = field(default_factory=threading.Event)
    completed: threading.Event = field(default_factory=threading.Event)
    result: str = ""


def detect_callback_host(target_host: str) -> str:
    """Return this machine's address on the robot's directly connected subnet.

    Connecting a datagram socket sends no packets; it asks the kernel which
    local address it would use to reach ``target_host``.  An address reached
    through the default gateway lands outside the robot's /24, so a Wi-Fi
    answer is rejected here rather than being compiled into the firmware.
    Nothing but ``target_host`` is ever probed.
    """
    try:
        link = ipaddress.ip_network(f"{target_host}/{LINK_PREFIX}", strict=False)
    except ValueError as exc:
        raise WorkflowError(
            f"--target-host must be an IPv4 address, not {target_host!r}"
        ) from exc

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((target_host, 9))
            address = sock.getsockname()[0]
    except OSError as exc:
        raise WorkflowError(f"no route to {target_host}: {exc}") from exc

    if ipaddress.ip_address(address) not in link:
        raise WorkflowError(
            f"detected {address}, which is not on {link}; connect the Ethernet "
            f"cable to the robot and give this machine a static address on "
            f"{link}, or pass --callback-host"
        )
    return address


def normalize_callback_host(value: str) -> str:
    value = value.strip()
    if not value or value == "localhost" or "://" in value or "/" in value:
        raise WorkflowError("--callback-host must be a target-reachable host or IP")
    literal = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    try:
        address = ipaddress.ip_address(literal)
    except ValueError:
        return value
    if address.is_unspecified or address.is_loopback:
        raise WorkflowError("--callback-host must be reachable from the target")
    if address.version == 6 and not value.startswith("["):
        return f"[{value}]"
    return value


def validate_path(value: str) -> str:
    if not value.startswith("/") or urlsplit(value).path != value:
        raise WorkflowError("--path must be an absolute URL path without a query or fragment")
    if value == COMPLETION_PATH:
        raise WorkflowError(f"--path is reserved: {COMPLETION_PATH}")
    return value


def _config_filename(name: str) -> str:
    """Turn a profile name into the build-config filename it gets by default."""
    value = re.sub(r"[^a-zA-Z0-9._+-]+", "-", name).strip("-.")
    if not value:
        raise WorkflowError(f"profile name {name!r} has no usable filename")
    return value + ".json"


def resolve_config_profile(selector: str):
    """Resolve a profile by name, or by path to one installed in profiles/."""
    candidate = Path(selector).expanduser()
    if candidate.suffix == ".json" or os.sep in selector:
        if not candidate.is_file():
            raise WorkflowError(f"no profile file at {candidate}")
        try:
            raw = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise WorkflowError(f"cannot read profile {candidate}: {exc}") from exc
        selector = profile_data.parse_profile(raw, str(candidate)).name
    return profile_data.resolve_profile(selector).profile


def build_config_document(profile, drain: int, neighbours, msc: bool) -> dict:
    """Assemble a build config. ``build`` replaces payload and msc from its flags."""
    document = {
        "profile": profile.name,
        "payload": {"type": "default", "path": payload.DEFAULT_FILE_PATH},
        "drain": drain,
        "neighbours": neighbours,
        "msc": msc,
    }
    # Normalises neighbours to a list and rejects a bad drain.
    gen_descriptors._validate_config(document)
    return document


def write_config_document(document: dict, output: Path, force: bool) -> Path:
    if output == DEFAULT_CONFIG:
        raise WorkflowError(f"refusing to overwrite {DEFAULT_CONFIG.name}")
    if output.exists() and not force:
        raise WorkflowError(f"{output} exists; pass --force to replace it")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return output


def write_firmware_config(
    base_config: Path,
    output: Path,
    payload_spec: dict,
) -> dict:
    try:
        config = json.loads(base_config.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkflowError(f"cannot read {base_config}: {exc}") from exc
    if not isinstance(config, dict):
        raise WorkflowError(f"{base_config} must contain a JSON object")

    payload.build(payload_spec)
    config["payload"] = payload_spec
    config["msc"] = True

    rendered = json.dumps(config, indent=2) + "\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    if not output.exists() or output.read_text(encoding="utf-8") != rendered:
        output.write_text(rendered, encoding="utf-8")
    return config


def load_root_build(build_dir: Path):
    """Recover the callback endpoint and path that ``build`` compiled in.

    ``build`` and ``root`` read the same generated config, so the address the
    robot curls and the address this machine serves on cannot disagree.
    """
    generated = build_dir / GENERATED_CONFIG_NAME
    try:
        config = json.loads(generated.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise WorkflowError(
            f"no firmware build at {generated}; run '{BUILD_HINT}' first"
        ) from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkflowError(f"cannot read {generated}: {exc}") from exc

    spec = config.get("payload") if isinstance(config, dict) else None
    if not isinstance(spec, dict) or spec.get("type") != "persistent-root-ssh":
        raise WorkflowError(
            f"{generated} is not a root-ssh build; rebuild with '{BUILD_HINT}'"
        )
    payload.build(spec)

    endpoint = spec["callback_host"]
    _, separator, port_text = endpoint.rpartition(":")
    if not separator or not port_text.isdigit():
        raise WorkflowError(f"{generated} has no callback port in {endpoint!r}")
    return endpoint, spec["callback_path"], int(port_text)


def build_firmware(config: Path, build_dir: Path, board: str) -> Path:
    environment = os.environ.copy()
    cache = build_dir / "CMakeCache.txt"
    if cache.is_file():
        try:
            cached_board = next(
                (
                    line.removeprefix("PICO_BOARD:STRING=")
                    for line in cache.read_text(encoding="utf-8").splitlines()
                    if line.startswith("PICO_BOARD:STRING=")
                ),
                None,
            )
        except OSError as exc:
            raise WorkflowError(f"cannot read {cache}: {exc}") from exc
        if cached_board and cached_board != board:
            raise WorkflowError(
                f"{build_dir} is configured for {cached_board}, not {board}; "
                "choose a different --build-dir"
            )
    elif not environment.get("PICO_SDK_PATH"):
        raise WorkflowError("set PICO_SDK_PATH to a Raspberry Pi Pico SDK checkout")

    configure = [
        "cmake",
        "-S", str(ROOT),
        "-B", str(build_dir),
        "-G", environment.get("CMAKE_GENERATOR", "Ninja"),
        "-DCMAKE_BUILD_TYPE=Release",
        f"-DFIDO_FIDELIS_CONFIG={config}",
        f"-DPICO_BOARD={board}",
    ]
    subprocess.run(configure, cwd=ROOT, env=environment, check=True)
    subprocess.run(
        ["cmake", "--build", str(build_dir)], cwd=ROOT, env=environment, check=True
    )
    uf2 = build_dir / "fido-fidelis.uf2"
    if not uf2.is_file():
        raise WorkflowError(f"build completed without producing {uf2}")
    return uf2


def flash_firmware(uf2: Path, mount: Path, board: str) -> Path:
    mount = _resolve(mount)
    if not mount.is_dir():
        raise WorkflowError(f"BOOTSEL mount does not exist: {mount}")

    expected = BOARD_BOOTSEL_VOLUMES[board]
    identity = mount.name.upper()
    info = mount / "INFO_UF2.TXT"
    if info.is_file():
        try:
            identity += "\n" + info.read_text(encoding="utf-8").upper()
        except OSError as exc:
            raise WorkflowError(f"cannot read {info}: {exc}") from exc
    if expected not in identity:
        raise WorkflowError(
            f"{mount} is not the expected {expected} BOOTSEL volume for "
            f"--board {board}"
        )

    destination = mount / uf2.name
    shutil.copyfile(uf2, destination)
    return destination


def _completion_script(callback_endpoint: str) -> bytes:
    completion_url = f"http://{callback_endpoint}{COMPLETION_PATH}"
    return (
        "\nif [ -f /unitree/var/data/fido-fidelis/status ]; then\n"
        "    { cat /unitree/var/data/fido-fidelis/status; /usr/bin/id; } | "
        f"/usr/bin/curl -fsS --max-time 5 --data-binary @- {completion_url} "
        ">/dev/null 2>&1 || true\n"
        "fi\n"
    ).encode("ascii")


class PayloadHandler(BaseHTTPRequestHandler):
    """Serve one stage payload at one path and 404 everything else.

    ``create_stage_server`` sets these two attributes on its subclass before
    the server starts; the empty defaults match no request path, so an
    unconfigured handler serves nothing.
    """

    payload = b""
    payload_path = ""

    def _send_payload(self, include_body):
        if urlsplit(self.path).path != self.payload_path:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/x-shellscript")
        self.send_header("Content-Length", str(len(self.payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if include_body:
            self.wfile.write(self.payload)

    def do_GET(self):
        self._send_payload(include_body=True)

    def do_HEAD(self):
        self._send_payload(include_body=False)


def create_stage_server(
    bind_host: str,
    port: int,
    callback_endpoint: str,
    callback_path: str,
    installer: Path = DEFAULT_INSTALLER,
):
    stage = installer.read_bytes() + _completion_script(callback_endpoint)
    events = StageEvents()

    class WorkflowHandler(PayloadHandler):
        completion_path = COMPLETION_PATH

        def do_GET(self):
            requested_path = urlsplit(self.path).path
            super().do_GET()
            if requested_path == self.payload_path:
                if not events.fetched.is_set():
                    print("[2/3] Target fetched the root-SSH installer", flush=True)
                events.fetched.set()

        def do_POST(self):
            if urlsplit(self.path).path != self.completion_path:
                self.send_error(404)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400)
                return
            if length <= 0 or length > 8192:
                self.send_error(413)
                return
            body = self.rfile.read(length)
            if b"installed" not in body or b"uid=0(" not in body:
                self.send_error(422, "installer did not report installed root access")
                return
            events.result = body.decode("utf-8", errors="replace").strip()
            events.completed.set()
            self.send_response(204)
            self.end_headers()

        def log_message(self, fmt, *args):
            pass

    WorkflowHandler.payload = stage
    WorkflowHandler.payload_path = callback_path
    server = ThreadingHTTPServer((bind_host, port), WorkflowHandler)
    return server, events


def wait_for_ssh(target_host: str, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((target_host, 22), timeout=2):
                return True
        except OSError:
            time.sleep(1)
    return False


def _resolve(path: Path) -> Path:
    return path.expanduser().resolve()


def _positive_port(value: str) -> int:
    port = int(value)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def _positive_seconds(value: str) -> float:
    seconds = float(value)
    if seconds <= 0:
        raise argparse.ArgumentTypeError("timeout must be greater than zero")
    return seconds


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build and run Fido Fidelis firmware workflows"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    config = commands.add_parser(
        "config",
        help="write the build config for a profile from tools/generate_profile.py",
    )
    config.add_argument(
        "--profile",
        required=True,
        metavar="NAME_OR_PATH",
        help="profile name, or path to a profile JSON installed in profiles/",
    )
    config.add_argument(
        "-o",
        "--output",
        type=Path,
        help="config to write (default: <profile name>.json beside fido.py)",
    )
    config.add_argument(
        "--drain",
        type=int,
        default=DEFAULT_DRAIN,
        help=f"grooming drain (default: {DEFAULT_DRAIN}, measured on the bench Go2)",
    )
    config.add_argument(
        "--neighbours",
        default=",".join(str(index) for index in DEFAULT_NEIGHBOURS),
        help=(
            "comma-separated neighbour indices (default: "
            f"{','.join(str(index) for index in DEFAULT_NEIGHBOURS)}, "
            "measured on the bench Go2)"
        ),
    )
    msc_group = config.add_mutually_exclusive_group()
    msc_group.add_argument("--msc", dest="msc", action="store_true")
    msc_group.add_argument("--no-msc", dest="msc", action="store_false")
    config.set_defaults(msc=True)
    config.add_argument(
        "--force", action="store_true", help="replace an existing output file"
    )

    build = commands.add_parser(
        "build",
        help="build firmware for the selected profile, board and payload",
    )
    build.add_argument(
        "--payload",
        choices=("default", "root-ssh", "command"),
        default="default",
        help="payload compiled into the firmware (default: default)",
    )
    build.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    build.add_argument(
        "--board",
        choices=tuple(BOARD_BOOTSEL_VOLUMES),
        default=DEFAULT_BOARD,
        help="target board (default: pico2; non-W boards only)",
    )
    build.add_argument(
        "--build-dir",
        type=Path,
        help="build directory (default: build-<payload>-<board>)",
    )
    build.add_argument(
        "--flash-to",
        type=Path,
        metavar="BOOTSEL_MOUNT",
        help="copy the completed UF2 to this board's mounted BOOTSEL volume",
    )
    build.add_argument(
        "--target-host",
        default=DEFAULT_TARGET,
        help="robot address, used to pick this machine's Ethernet IP (root-ssh)",
    )
    build.add_argument(
        "--callback-host",
        help="this machine's Ethernet IP (root-ssh; default: auto-detect)",
    )
    build.add_argument("--port", type=_positive_port, default=DEFAULT_PORT)
    build.add_argument("--path", default=payload.DEFAULT_CALLBACK_PATH)
    build.add_argument(
        "--pattern",
        metavar="CORE_PATTERN",
        help="exact pipe-form core_pattern to compile in (--payload command)",
    )

    root = commands.add_parser(
        "root",
        help=f"serve the installer to a target built by '{BUILD_HINT}'",
    )
    root.add_argument(
        "--board",
        choices=tuple(BOARD_BOOTSEL_VOLUMES),
        default=DEFAULT_BOARD,
        help="board the firmware was built for (default: pico2)",
    )
    root.add_argument(
        "--build-dir",
        type=Path,
        help="build directory to read (default: build-root-ssh-<board>)",
    )
    root.add_argument("--target-host", default=DEFAULT_TARGET)
    root.add_argument("--bind", default="0.0.0.0", help="stage-server bind address")
    root.add_argument("--installer", type=Path, default=DEFAULT_INSTALLER)
    root.add_argument(
        "--timeout",
        type=_positive_seconds,
        default=300,
        help="seconds to wait for installer completion (default: 300)",
    )
    root.add_argument(
        "--ssh-timeout",
        type=_positive_seconds,
        default=30,
        help="seconds to wait for TCP port 22 after completion (default: 30)",
    )
    return parser


def _build_dir_for(args) -> Path:
    if args.build_dir is not None:
        return _resolve(args.build_dir)
    return ROOT / f"build-{getattr(args, 'payload', 'root-ssh')}-{args.board}"


def _publish_uf2(uf2: Path) -> Path:
    """Copy the build artifact to the repo root, where you flash it from."""
    published = ROOT / uf2.name
    if published != uf2:
        shutil.copyfile(uf2, published)
    return published


def _report_firmware(args, uf2: Path) -> None:
    if args.flash_to:
        print(f"      Flashed: {flash_firmware(uf2, args.flash_to, args.board)}")
        return

    volume = BOARD_BOOTSEL_VOLUMES[args.board]
    print(f"      Hold BOOTSEL, connect the {args.board}, then copy:")
    print(f"        {uf2}")
    print(f"      to the mounted {volume} volume.")


def _root_ssh_spec(args) -> dict:
    callback_path = validate_path(args.path)
    callback_host = normalize_callback_host(
        args.callback_host or detect_callback_host(args.target_host)
    )
    return {
        "type": "persistent-root-ssh",
        "callback_host": f"{callback_host}:{args.port}",
        "callback_path": callback_path,
    }


def _payload_spec(args) -> dict:
    if args.pattern is not None and args.payload != "command":
        raise WorkflowError("--pattern requires --payload command")
    if args.payload == "root-ssh":
        return _root_ssh_spec(args)
    if args.payload == "command":
        if not args.pattern:
            raise WorkflowError("--payload command requires --pattern")
        return {"type": "command", "pattern": args.pattern}
    return {"type": "default", "path": payload.DEFAULT_FILE_PATH}


def run_config(args) -> int:
    profile = resolve_config_profile(args.profile)
    document = build_config_document(profile, args.drain, args.neighbours, args.msc)
    output = _resolve(args.output) if args.output else ROOT / _config_filename(profile.name)
    write_config_document(document, output, args.force)

    print(f"wrote {output}")
    print(f"  profile  {profile.name}")
    print(f"  kernel   {profile.kernel_release}")
    print(
        f"  shaping  drain {document['drain']}, "
        f"neighbours {document['neighbours']}"
    )
    print(f"  payload  {document['payload']['path']}")
    print()
    reference = output.name if output.parent == ROOT else output
    print(f"Next: ./fido.py build --config {reference} --board {DEFAULT_BOARD}")
    return 0


def run_build(args) -> int:
    spec = _payload_spec(args)

    build_dir = _build_dir_for(args)
    generated_config = build_dir / GENERATED_CONFIG_NAME
    config = write_firmware_config(_resolve(args.config), generated_config, spec)

    print(f"Board:    {args.board}")
    print(f"Profile:  {config.get('profile', '<missing>')}")
    if args.payload == "root-ssh":
        print(f"Callback: http://{spec['callback_host']}{spec['callback_path']}")
    elif args.payload == "command":
        print(f"Pattern:  {spec['pattern']}")
    else:
        print(f"Payload:  {spec['path']}")
    print(f"[1/2] Building {args.payload} firmware", flush=True)
    uf2 = _publish_uf2(build_firmware(generated_config, build_dir, args.board))
    print(f"[2/2] Firmware ready: {uf2}", flush=True)
    _report_firmware(args, uf2)
    if args.payload == "root-ssh":
        print()
        print("Next: flash the board, then run 'fido.py root' before powering the robot.")
    return 0


def run_root(args) -> int:
    build_dir = _build_dir_for(args)
    callback_endpoint, callback_path, port = load_root_build(build_dir)
    installer = _resolve(args.installer)

    server, events = create_stage_server(
        args.bind, port, callback_endpoint, callback_path, installer
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        print(f"Target:   {args.target_host}")
        print(f"Build:    {build_dir}")
        print(f"[1/3] Serving installer at http://{callback_endpoint}{callback_path}")
        print("      Attach the Pico to the robot, then power it on.")
        print(f"      Waiting up to {int(args.timeout)}s for completion...", flush=True)

        if not events.completed.wait(args.timeout):
            if events.fetched.is_set():
                raise WorkflowError("target fetched the installer but did not report completion")
            raise WorkflowError("target did not fetch the installer before the timeout")

        print("[3/3] Installer reported:")
        for line in events.result.splitlines():
            print(f"      {line}")
        if not wait_for_ssh(args.target_host, args.ssh_timeout):
            raise WorkflowError(
                f"installer completed, but {args.target_host}:22 did not become reachable"
            )
        print()
        print("Root SSH is ready:")
        print(f"  ssh root@{args.target_host}")
        print("  password: unleash")
        return 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "config":
            return run_config(args)
        if args.command == "build":
            return run_build(args)
        return run_root(args)
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)
        return 130
    except subprocess.CalledProcessError as exc:
        print(f"firmware build failed with exit status {exc.returncode}", file=sys.stderr)
        return exc.returncode or 1
    except (OSError, ValueError, profile_data.ProfileError) as exc:
        print(f"fido workflow failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
