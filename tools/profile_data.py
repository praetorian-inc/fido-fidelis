#!/usr/bin/env python3
"""Load and validate firmware profiles used by the Pico descriptor generator."""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Sequence

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PROFILE_DIR = ROOT / "profiles"
DEFAULT_TARGET = os.environ.get("GO2_TARGET", "go2")
_REMOTE_PROBE = r"""set -eu
printf 'kernel_release='
uname -r
printf 'core_pattern='
cat /proc/sys/kernel/core_pattern
"""


class ProfileError(RuntimeError):
    """A profile is missing, malformed, or does not match the target."""


@dataclass(frozen=True)
class KernelSymbols:
    core_name_size: int
    core_pattern: int
    core_pattern_end: int


@dataclass(frozen=True)
class KernelLayout:
    core_name_size_initial: int
    core_pattern_size: int
    kmalloc_256_object_size: int
    kmalloc_256_freeptr_offset: int
    uvc_interval_write_offset: int


@dataclass(frozen=True)
class KernelProfile:
    name: str
    kernel_release: str
    symbols: KernelSymbols
    layout: KernelLayout
    core_pattern_observable: str

    @property
    def core_name_size(self) -> int:
        return self.symbols.core_name_size

    @property
    def core_pattern(self) -> int:
        return self.symbols.core_pattern

    @property
    def core_pattern_end(self) -> int:
        return self.symbols.core_pattern_end


@dataclass(frozen=True)
class LiveTargetData:
    kernel_release: str
    core_pattern: str


@dataclass(frozen=True)
class ResolvedProfile:
    profile: KernelProfile
    live: Optional[LiveTargetData]


def _object(value: object, where: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ProfileError(f"{where} must be a JSON object")
    return value


def _required(
    value: object,
    fields: Sequence[str],
    where: str,
) -> Mapping[str, object]:
    obj = _object(value, where)
    required = set(fields)
    missing = sorted(required - set(obj))
    if missing:
        raise ProfileError(f"{where} is incomplete; missing: {', '.join(missing)}")
    unknown = sorted(set(obj) - required)
    if unknown:
        raise ProfileError(f"{where} has unknown fields: {', '.join(unknown)}")
    return obj


def _address(value: object, where: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{16}", value):
        raise ProfileError(f"{where} must be a 16-digit hexadecimal string")
    address = int(value, 16)
    if address >> 32 != 0xFFFFFFC0:
        raise ProfileError(f"{where} is outside the Go2 arm64 kernel VA range: {value}")
    return address


def _positive_int(value: object, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ProfileError(f"{where} must be a positive integer")
    return value


def parse_profile(raw: object, source: str = "profile") -> KernelProfile:
    obj = _required(
        raw,
        (
            "name",
            "kernel_release",
            "symbols",
            "layout",
            "observables",
        ),
        source,
    )
    name = obj["name"]
    release = obj["kernel_release"]
    if not isinstance(name, str) or not name:
        raise ProfileError(f"{source}.name must be a non-empty string")
    if not isinstance(release, str) or not release:
        raise ProfileError(f"{source}.kernel_release must be a non-empty string")

    symbols = _required(
        obj["symbols"],
        ("core_name_size", "core_pattern", "core_pattern_end"),
        f"{source}.symbols",
    )
    layout = _required(
        obj["layout"],
        (
            "core_name_size_initial",
            "core_pattern_size",
            "kmalloc_256_object_size",
            "kmalloc_256_freeptr_offset",
            "uvc_interval_write_offset",
        ),
        f"{source}.layout",
    )
    observables = _required(obj["observables"], ("core_pattern",), f"{source}.observables")
    observable = observables["core_pattern"]
    if not isinstance(observable, str) or not observable:
        raise ProfileError(f"{source}.observables.core_pattern must be a non-empty string")

    profile = KernelProfile(
        name=name,
        kernel_release=release,
        symbols=KernelSymbols(**{
            key: _address(symbols[key], f"{source}.symbols.{key}")
            for key in ("core_name_size", "core_pattern", "core_pattern_end")
        }),
        layout=KernelLayout(**{
            key: _positive_int(layout[key], f"{source}.layout.{key}")
            for key in (
                "core_name_size_initial",
                "core_pattern_size",
                "kmalloc_256_object_size",
                "kmalloc_256_freeptr_offset",
                "uvc_interval_write_offset",
            )
        }),
        core_pattern_observable=observable,
    )
    validate_geometry(profile)
    return profile


def validate_geometry(profile: KernelProfile) -> None:
    symbols = profile.symbols
    layout = profile.layout
    if symbols.core_pattern - symbols.core_name_size != 8:
        raise ProfileError(f"profile {profile.name}: core_name_size must be core_pattern - 8")
    if symbols.core_pattern_end - symbols.core_pattern != layout.core_pattern_size:
        raise ProfileError(
            f"profile {profile.name}: core_pattern_end gap does not match core_pattern_size"
        )
    if layout.core_name_size_initial != layout.core_pattern_size:
        raise ProfileError(
            f"profile {profile.name}: core_name_size_initial must match core_pattern_size"
        )
    if layout.kmalloc_256_freeptr_offset >= layout.kmalloc_256_object_size:
        raise ProfileError(f"profile {profile.name}: freelist offset is outside kmalloc-256")
    if layout.uvc_interval_write_offset % 4:
        raise ProfileError(f"profile {profile.name}: UVC interval offset is not u32-aligned")
    freeptr_offset = (
        symbols.core_name_size
        + layout.kmalloc_256_freeptr_offset
        - symbols.core_pattern
    )
    if not 0 <= freeptr_offset < layout.core_pattern_size:
        raise ProfileError(f"profile {profile.name}: freelist read is outside core_pattern")
    if freeptr_offset < len(profile.core_pattern_observable) + 1:
        raise ProfileError(
            f"profile {profile.name}: freelist read overlaps the expected core_pattern string"
        )


def load_profiles(directory: Path = DEFAULT_PROFILE_DIR) -> Mapping[str, KernelProfile]:
    directory = Path(directory)
    try:
        paths = sorted(directory.glob("*.json"))
    except OSError as exc:
        raise ProfileError(f"cannot list profile directory {directory}: {exc}") from exc
    if not paths:
        raise ProfileError(f"profile directory {directory} contains no JSON profiles")
    profiles = {}
    for path in paths:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProfileError(f"cannot load profile {path}: {exc}") from exc
        profile = parse_profile(raw, str(path))
        if profile.name in profiles:
            raise ProfileError(f"duplicate profile name {profile.name!r}")
        profiles[profile.name] = profile
    return profiles


def resolve_profile(selector: str, directory: Path = DEFAULT_PROFILE_DIR) -> ResolvedProfile:
    profiles = load_profiles(directory)
    profile = profiles.get(selector.strip())
    if profile is None:
        known = ", ".join(sorted(profiles)) or "none"
        raise ProfileError(f"unknown profile {selector!r}; known profiles: {known}")
    return ResolvedProfile(profile=profile, live=None)




def query_live_target(target: str = DEFAULT_TARGET, timeout: float = 30.0) -> LiveTargetData:
    if target == "local":
        command = ["sh", "-c", _REMOTE_PROBE]
    else:
        command = [
            "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", target,
            _REMOTE_PROBE,
        ]
    try:
        result = subprocess.run(
            command, check=False, capture_output=True, text=True, timeout=timeout
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProfileError(f"cannot query live target {target}: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or f"exit {result.returncode}"
        raise ProfileError(f"live target probe failed for {target}: {detail}")
    values = {}
    for line in result.stdout.splitlines():
        if "=" not in line:
            raise ProfileError(f"malformed live probe output from {target}: {line!r}")
        key, value = line.split("=", 1)
        if key not in ("kernel_release", "core_pattern") or key in values:
            raise ProfileError(f"unexpected live probe field from {target}: {key!r}")
        values[key] = value
    missing = sorted({"kernel_release", "core_pattern"} - set(values))
    if missing:
        raise ProfileError(f"live probe from {target} omitted: {', '.join(missing)}")
    return LiveTargetData(
        kernel_release=values["kernel_release"],
        core_pattern=values["core_pattern"],
    )


def resolve_live(target: str, directory: Path = DEFAULT_PROFILE_DIR) -> ResolvedProfile:
    """Match a live target to a profile by kernel release."""
    live = query_live_target(target)
    profile = next(
        (
            value
            for value in load_profiles(directory).values()
            if value.kernel_release == live.kernel_release
        ),
        None,
    )
    if profile is None:
        raise ProfileError(f"no profile for live kernel_release {live.kernel_release!r}")
    if profile.core_pattern_observable != live.core_pattern:
        raise ProfileError(
            f"live target {target} does not match profile {profile.name}: "
            f"core_pattern expected {profile.core_pattern_observable!r}, "
            f"got {live.core_pattern!r}"
        )
    return ResolvedProfile(profile=profile, live=live)
