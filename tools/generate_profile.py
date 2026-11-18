#!/usr/bin/env python3
"""Create a firmware profile from a live Go2 over SSH."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import profile_data

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PROFILES = ROOT / "profiles"
_SYMBOL_RE = re.compile(r"^([0-9a-fA-F]{16})\s+(\S)\s+(.+)$")
_EXPECTED_TEXT = 0xFFFFFFC010000000  # kernel-profile-lint: allow-sentinel (VA base)
_REMOTE_KALLSYMS = r"""set -eu
printf 'kptr_restrict='
cat /proc/sys/kernel/kptr_restrict
printf '__FIDO_FIDELIS_KALLSYMS__\n'
cat /proc/kallsyms
"""
REQUIREMENTS = """Profile information required:
- profile name
- kernel release
- core_name_size virtual address
- core_pattern virtual address
- core_pattern_end virtual address
Assumed defaults unless the firmware differs:
- stock core_pattern: /tmp/core.%e.%p
- core_pattern size and initial core_name_size: 128
- kmalloc object size: 256
- kmalloc freelist offset: 128
- UVC interval write offset: 196
"""


def _parse_kallsyms(lines, source: str):
    symbols = {}
    for line_number, line in enumerate(lines, 1):
        match = _SYMBOL_RE.fullmatch(line.strip())
        if not match:
            if line.strip():
                raise ValueError(f"{source}:{line_number}: malformed kallsyms line")
            continue
        address = int(match.group(1), 16)
        name = match.group(3)
        symbols.setdefault(name, []).append(address)
    if not symbols:
        raise ValueError(f"kallsyms source {source} is empty")
    return symbols


def _unique_symbol(symbols, name: str) -> int:
    values = sorted(set(symbols.get(name, ())))
    if not values:
        raise ValueError(f"kallsyms does not contain {name}")
    if len(values) != 1:
        rendered = ", ".join(f"0x{value:016x}" for value in values)
        raise ValueError(f"kallsyms has ambiguous {name} addresses: {rendered}")
    return values[0]


def _query_live_kallsyms(target: str, timeout: float):
    if target == "local":
        command = ["sh", "-c", _REMOTE_KALLSYMS]
    else:
        command = [
            "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", target,
            _REMOTE_KALLSYMS,
        ]
    try:
        result = subprocess.run(
            command, check=False, capture_output=True, text=True, timeout=timeout
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"cannot read kallsyms from {target}: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or f"exit {result.returncode}"
        raise ValueError(f"kallsyms probe failed for {target}: {detail}")
    marker = "__FIDO_FIDELIS_KALLSYMS__\n"
    try:
        metadata, kallsyms = result.stdout.split(marker, 1)
    except ValueError as exc:
        raise ValueError(f"kallsyms probe from {target} omitted its output marker") from exc
    if not metadata.startswith("kptr_restrict="):
        raise ValueError(f"kallsyms probe from {target} returned malformed metadata")
    kptr_restrict = metadata.removeprefix("kptr_restrict=").strip()
    if kptr_restrict not in {"0", "1", "2"}:
        raise ValueError(f"kallsyms probe returned invalid kptr_restrict={kptr_restrict!r}")
    return _parse_kallsyms(kallsyms.splitlines(), f"{target}:/proc/kallsyms")


def _safe_filename(name: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9._+-]+", "-", name).strip("-.")
    if not value:
        raise ValueError("profile name does not contain a usable filename")
    return value + ".json"


def _write_profile(path: Path, document, force: bool):
    content = json.dumps(document, indent=2, sort_keys=False) + "\n"
    if path.exists() and not force:
        raise ValueError(f"output {path} exists; pass --force to replace it")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        temporary.write_text(content, encoding="utf-8")
        os.replace(temporary, path)
    except OSError as exc:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise ValueError(f"cannot write profile {path}: {exc}") from exc


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--target-host",
        help="SSH host from which to collect the profile",
    )
    mode.add_argument(
        "--requirements",
        action="store_true",
        help="print the required SSH access and exit",
    )
    parser.add_argument("--name", help="profile name (required with --target-host)")
    parser.add_argument("--ssh-timeout", type=float, default=30.0)
    parser.add_argument("--core-pattern-size", type=int, default=128)
    parser.add_argument("--kmalloc-object-size", type=int, default=256)
    parser.add_argument("--kmalloc-freeptr-offset", type=int, default=128)
    parser.add_argument("--uvc-interval-write-offset", type=int, default=196)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--force", action="store_true")
    return parser


def main(argv=None):
    parser = _parser()
    args = parser.parse_args(argv)
    if args.requirements:
        print(REQUIREMENTS, end="")
        return 0
    if not args.name:
        parser.error("--name is required with --target-host")

    try:
        if args.ssh_timeout <= 0:
            raise ValueError("--ssh-timeout must be positive")
        live = profile_data.query_live_target(
            args.target_host, timeout=args.ssh_timeout
        )
        if live.core_pattern.startswith("|"):
            raise ValueError(
                "live core_pattern is a pipe handler and appears modified; "
                "refusing to record it as the stock observable"
            )
        symbols = _query_live_kallsyms(args.target_host, args.ssh_timeout)
        text_address = _unique_symbol(symbols, "_text")
        if text_address == 0:
            raise ValueError("/proc/kallsyms addresses are hidden")
        if text_address != _EXPECTED_TEXT:
            raise ValueError(
                f"live _text is 0x{text_address:016x}, expected "
                f"0x{_EXPECTED_TEXT:016x}; refusing a reboot-unstable KASLR profile"
            )

        core_name_size = _unique_symbol(symbols, "core_name_size")
        core_pattern = _unique_symbol(symbols, "core_pattern")
        if core_pattern - core_name_size != 8:
            raise ValueError(
                f"core_pattern - core_name_size is {core_pattern - core_name_size}, expected 8"
            )
        if args.core_pattern_size <= 0:
            raise ValueError("--core-pattern-size must be positive")
        core_pattern_end = core_pattern + args.core_pattern_size
        boundary_names = sorted(
            name for name, addresses in symbols.items() if core_pattern_end in addresses
        )
        if not boundary_names:
            next_addresses = sorted({
                address
                for addresses in symbols.values()
                for address in addresses
                if address > core_pattern
            })
            nearest = f"0x{next_addresses[0]:016x}" if next_addresses else "none"
            raise ValueError(
                f"no kallsyms symbol starts at expected core_pattern end "
                f"0x{core_pattern_end:016x}; nearest later symbol is {nearest}"
            )

        document = {
            "name": args.name,
            "kernel_release": live.kernel_release,
            "symbols": {
                "core_name_size": f"0x{core_name_size:016x}",
                "core_pattern": f"0x{core_pattern:016x}",
                "core_pattern_end": f"0x{core_pattern_end:016x}",
            },
            "layout": {
                "core_name_size_initial": args.core_pattern_size,
                "core_pattern_size": args.core_pattern_size,
                "kmalloc_256_object_size": args.kmalloc_object_size,
                "kmalloc_256_freeptr_offset": args.kmalloc_freeptr_offset,
                "uvc_interval_write_offset": args.uvc_interval_write_offset,
            },
            "observables": {"core_pattern": live.core_pattern},
        }
        profile_data.parse_profile(document, "generated profile")
        output = args.output or DEFAULT_PROFILES / _safe_filename(args.name)
        _write_profile(output, document, args.force)
    except (ValueError, profile_data.ProfileError) as exc:
        parser.error(str(exc))

    print(f"wrote {output}")
    print(f"  core_name_size    0x{core_name_size:016x}")
    print(f"  core_pattern      0x{core_pattern:016x}")
    print(f"  core_pattern_end  0x{core_pattern_end:016x} ({', '.join(boundary_names)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
