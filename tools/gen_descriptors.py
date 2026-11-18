#!/usr/bin/env python3
"""Generate Fido Fidelis descriptor firmware from a selected Go2 profile.

The default invocation reads ``firmware.json`` and writes
``generated/descriptors.h``. CMake invokes this command before compiling, so a
profile or payload change cannot leave stale descriptor bytes in the UF2.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

import payload
import profile_data
import uvc_descriptors

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = ROOT / "firmware.json"
DEFAULT_OUTPUT = ROOT / "generated" / "descriptors.h"
MSC_CLASS, MSC_SUBCLASS, MSC_PROTOCOL = 0x08, 0x06, 0x50
MSC_EP_OUT, MSC_EP_IN, MSC_EP_SIZE = 0x02, 0x82, 64
_ALLOWED_CONFIG_KEYS = {"profile", "payload", "drain", "neighbours", "msc"}


def _load_config(path: Path):
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load firmware config {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"firmware config {path} must be a JSON object")
    unknown = sorted(set(raw) - _ALLOWED_CONFIG_KEYS)
    if unknown:
        raise ValueError(f"firmware config {path} has unknown keys: {', '.join(unknown)}")
    missing = sorted(_ALLOWED_CONFIG_KEYS - set(raw))
    if missing:
        raise ValueError(f"firmware config {path} is incomplete: {', '.join(missing)}")
    return raw


def _parse_neighbours(value):
    if isinstance(value, str):
        try:
            result = [int(item) for item in value.split(",") if item.strip()]
        except ValueError as exc:
            raise ValueError("neighbours must be comma-separated integers") from exc
    elif isinstance(value, list) and all(isinstance(item, int) and not isinstance(item, bool) for item in value):
        result = list(value)
    else:
        raise ValueError("neighbours must be a JSON list or comma-separated integers")
    if not result or any(item <= 0 for item in result):
        raise ValueError("neighbours must contain positive indices")
    return result


def _validate_config(config):
    if not isinstance(config["profile"], str) or not config["profile"]:
        raise ValueError("profile must be a non-empty string")
    pattern = payload.build(config["payload"])
    if isinstance(config["drain"], bool) or not isinstance(config["drain"], int) or config["drain"] < 0:
        raise ValueError("drain must be a non-negative integer")
    if not isinstance(config["msc"], bool):
        raise ValueError("msc must be true or false")
    config["neighbours"] = _parse_neighbours(config["neighbours"])
    return pattern


def build_blob(profile, pattern: str) -> bytes:
    """Build the exact bmaControls bytes written at core_name_size."""
    maximum = profile.layout.core_pattern_size
    raw = pattern.encode("latin-1") + b"\x00"
    if len(raw) > maximum:
        raise ValueError(f"pattern + NUL is {len(raw)} bytes, over {maximum}")

    body = bytearray(struct.pack("<i", profile.layout.core_name_size_initial))
    # These four bytes occupy compiler alignment between core_name_size and
    # core_pattern. They are don't-care bytes, so use deterministic filler.
    body += uvc_descriptors.filler(4)
    body += raw
    body += uvc_descriptors.filler(maximum - len(raw))
    expected = 8 + maximum
    if len(body) != expected or expected != uvc_descriptors.BMA_SIZE:
        raise ValueError(
            f"profile produces a {len(body)}-byte blob; firmware geometry requires "
            f"{uvc_descriptors.BMA_SIZE} bytes"
        )
    return bytes(body)


def _check_geometry(profile, live_core_pattern: str):
    problems = []
    target = profile.core_name_size
    end = target + uvc_descriptors.BMA_SIZE
    if end != profile.core_pattern_end:
        problems.append(
            f"write ends at 0x{end:016x}, not core_pattern_end "
            f"0x{profile.core_pattern_end:016x}"
        )
    freeptr = target + profile.layout.kmalloc_256_freeptr_offset
    offset = freeptr - profile.core_pattern
    if not 0 <= offset < profile.layout.core_pattern_size:
        problems.append("freelist read is outside core_pattern")
    elif offset < len(live_core_pattern) + 1:
        problems.append(
            f"freelist read lands at core_pattern[{offset}], inside "
            f"{live_core_pattern!r}"
        )
    if (target & 0xFFFFFFFF) == 0 or (target >> 32) == 0:
        problems.append(f"target 0x{target:016x} has a zero u32 half")
    return problems


def _build_msc_function(interface_number: int) -> bytes:
    interface = bytes([
        9, 0x04, interface_number, 0, 2,
        MSC_CLASS, MSC_SUBCLASS, MSC_PROTOCOL, 0,
    ])

    def endpoint(address):
        return struct.pack("<BBBBHB", 7, 0x05, address, 0x02, MSC_EP_SIZE, 0)

    return interface + endpoint(MSC_EP_OUT) + endpoint(MSC_EP_IN)


def _append_msc(configuration: bytes):
    interface_number = configuration[4]
    result = bytearray(configuration)
    result += _build_msc_function(interface_number)
    result[2:4] = len(result).to_bytes(2, "little")
    result[4] = interface_number + 1
    if result[4] > 32:
        raise ValueError(
            f"bNumInterfaces {result[4]} exceeds Linux USB_MAXINTERFACES (32)"
        )
    return bytes(result), interface_number


def _c_array(name: str, data: bytes, per_line: int = 12) -> str:
    output = [f"static const uint8_t {name}[{len(data)}] = {{"]
    for offset in range(0, len(data), per_line):
        chunk = data[offset:offset + per_line]
        output.append(
            "    " + " ".join(f"0x{byte:02x}," for byte in chunk) + f"   /* {offset:4d} */"
        )
    output.append("};")
    return "\n".join(output)


def _render_header(profile, pattern, config, descriptors, configuration, msc_interface):
    digest = hashlib.sha256(configuration).hexdigest()
    safe_pattern = pattern.replace("*/", "* /")
    if msc_interface is None:
        msc_block = "#define HAVE_MSC_FUNCTION     0"
        msc_note = ""
    else:
        msc_block = "#define HAVE_MSC_FUNCTION     1"
        msc_note = (
            f" *   msc interface    : {msc_interface}, endpoints "
            f"0x{MSC_EP_OUT:02x}/0x{MSC_EP_IN:02x}\n"
        )
    return f"""/* GENERATED by gen_descriptors.py -- DO NOT EDIT.
 *
 *   profile           : {profile.name}
 *   payload           : {safe_pattern}
 *   config descriptor : {len(configuration)} bytes
 *   sha256            : {digest}
 *   interfaces        : {configuration[4]} total, {descriptors.configuration[4]} arm
 *   payload interfaces: {list(descriptors.payload_interfaces)}
 *   shaping           : drain {config['drain']}, neighbours {config['neighbours']}
{msc_note} */

#ifndef FIDO_FIDELIS_DESCRIPTORS_H
#define FIDO_FIDELIS_DESCRIPTORS_H

#include <stdint.h>

#define ARM_CONFIG_DESC_LEN   {len(configuration)}
#define ARM_NUM_INTERFACES    {descriptors.configuration[4]}
#define ARM_PAYLOAD_ITF_A     {descriptors.payload_interfaces[0]}
#define ARM_PAYLOAD_ITF_B     {descriptors.payload_interfaces[1]}

{msc_block}

{_c_array('arm_device_desc', descriptors.device)}

{_c_array('arm_config_desc', configuration)}

#endif /* FIDO_FIDELIS_DESCRIPTORS_H */
"""


def _write_if_changed(path: Path, content: str):
    try:
        if path.read_text(encoding="utf-8") == content:
            return False
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise ValueError(f"cannot read output {path}: {exc}") from exc
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
        raise ValueError(f"cannot write output {path}: {exc}") from exc
    return True


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--profiles", type=Path, default=profile_data.DEFAULT_PROFILE_DIR)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--profile", help="exact profile name")
    source.add_argument("--target-host", help="resolve and validate a live target over SSH")
    parser.add_argument("--drain", type=int, help="override the grooming drain")
    parser.add_argument("--neighbours", help="override comma-separated neighbour indices")
    msc = parser.add_mutually_exclusive_group()
    msc.add_argument("--msc", dest="msc", action="store_true")
    msc.add_argument("--no-msc", dest="msc", action="store_false")
    parser.set_defaults(msc=None)
    parser.add_argument("-o", "--out", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--list-profiles", action="store_true")
    return parser


def main(argv=None):
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.list_profiles:
            for profile in profile_data.load_profiles(args.profiles).values():
                print(f"{profile.name}  {profile.kernel_release}")
            return 0

        config = _load_config(args.config)
        if args.profile is not None:
            config["profile"] = args.profile
        if args.drain is not None:
            config["drain"] = args.drain
        if args.neighbours is not None:
            config["neighbours"] = args.neighbours
        if args.msc is not None:
            config["msc"] = args.msc
        pattern = _validate_config(config)

        if args.target_host:
            resolved = profile_data.resolve_live(args.target_host, args.profiles)
        else:
            resolved = profile_data.resolve_profile(config["profile"], args.profiles)
        profile = resolved.profile
        live_pattern = (
            resolved.live.core_pattern if resolved.live else profile.core_pattern_observable
        )
        problems = _check_geometry(profile, live_pattern)
        if problems:
            raise ValueError("unsafe profile geometry: " + "; ".join(problems))
        if not payload.report(
            pattern, profile.layout.core_pattern_size, stream=sys.stderr
        ):
            raise ValueError("payload validation failed")

        blob = build_blob(profile, pattern)
        descriptors = uvc_descriptors.build(
            profile, blob, config["drain"], config["neighbours"]
        )
        configuration = descriptors.configuration
        msc_interface = None
        if config["msc"]:
            configuration, msc_interface = _append_msc(configuration)
        header = _render_header(
            profile, pattern, config, descriptors, configuration, msc_interface
        )
        changed = _write_if_changed(args.out, header)
    except (ValueError, profile_data.ProfileError) as exc:
        parser.error(str(exc))

    digest = hashlib.sha256(configuration).hexdigest()
    print(f"{'wrote' if changed else 'unchanged'} {args.out}")
    print(f"  profile {profile.name}")
    print(f"  config  {len(configuration)} bytes, sha256 {digest}")
    print(
        f"  ifaces  {configuration[4]} total ({descriptors.configuration[4]} arm), "
        f"payload at {list(descriptors.payload_interfaces)}"
    )
    print(f"  shaping drain {config['drain']}, neighbours {config['neighbours']}")
    if msc_interface is not None:
        print(f"  msc     interface {msc_interface}, ep 0x02/0x82")
    return 0


if __name__ == "__main__":
    sys.exit(main())
