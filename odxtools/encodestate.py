# SPDX-License-Identifier: MIT
import struct
import warnings
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .encoding import Encoding, get_string_encoding
from .exceptions import EncodeError, OdxWarning, odxassert, odxraise
from .odxtypes import AtomicOdxType, BytesTypes, DataType, ParameterValue

if TYPE_CHECKING:
    from .parameters.parameter import Parameter


@dataclass
class EncodeState:
    """Utility class to holding the state variables needed for encoding a message.
    """

    coded_message: bytearray = field(default_factory=bytearray)
    used_mask: bytearray = field(default_factory=bytearray)
    origin_byte_position: int = 0
    cursor_byte_position: int = 0
    cursor_bit_position: int = 0
    triggering_request: bytes | None = None
    length_keys: dict[str, int] = field(default_factory=dict)
    table_keys: dict[str, str] = field(default_factory=dict)
    key_pos: dict[str, int] = field(default_factory=dict)
    is_end_of_pdu: bool = True
    journal: list[tuple["Parameter", ParameterValue | None]] = field(default_factory=list)
    allow_unknown_parameters = False

    def __post_init__(self) -> None:
        if len(self.coded_message) > len(self.used_mask):
            self.used_mask += b'\xff' * (len(self.coded_message) - len(self.used_mask))
        if len(self.coded_message) < len(self.used_mask):
            odxraise(f"The specified bit mask 0x{self.used_mask.hex()} for used bits "
                     f"is not suitable for representing the coded_message "
                     f"0x{self.coded_message.hex()}")
            self.used_mask = self.used_mask[:len(self.coded_message)]

    def emplace_atomic_value(
        self,
        *,
        internal_value: AtomicOdxType,
        bit_length: int,
        base_data_type: DataType,
        base_type_encoding: Encoding | None,
        is_highlow_byte_order: bool,
        used_mask: bytes | None,
    ) -> None:
        """Convert the internal_value to bytes and emplace this into the PDU"""

        raw_value: AtomicOdxType

        if base_data_type == DataType.A_BYTEFIELD:
            if not isinstance(internal_value, BytesTypes):
                odxraise(f"{internal_value!r} is not a bytefield", EncodeError)
                return
            odxassert(
                base_type_encoding in (None, Encoding.NONE, Encoding.BCD_P, Encoding.BCD_UP),
                f"Illegal encoding '{base_type_encoding}' for A_BYTEFIELD")
            raw_value = bytes(internal_value)
            if 8 * len(raw_value) > bit_length:
                odxraise(
                    f"The value '{internal_value!r}' cannot be encoded using "
                    f"{bit_length} bits.", EncodeError)
                raw_value = raw_value[0:bit_length // 8]

        elif base_data_type in (DataType.A_UTF8STRING, DataType.A_ASCIISTRING,
                                DataType.A_UNICODE2STRING):
            if not isinstance(internal_value, str):
                odxraise(f"The internal value '{internal_value!r}' is not a string", EncodeError)
                internal_value = str(internal_value)
            str_encoding = get_string_encoding(base_data_type, base_type_encoding,
                                               is_highlow_byte_order)
            if str_encoding is not None:
                raw_value = internal_value.encode(str_encoding)
            else:
                raw_value = b""
            if 8 * len(raw_value) > bit_length:
                odxraise(
                    f"The value '{internal_value!r}' cannot be encoded using "
                    f"{bit_length} bits.", EncodeError)
                raw_value = raw_value[0:bit_length // 8]

        elif base_data_type == DataType.A_INT32:
            if not isinstance(internal_value, int):
                odxraise(
                    f"Internal value must be of integer type, not {type(internal_value).__name__}",
                    EncodeError)
                internal_value = int(internal_value)
            if base_type_encoding == Encoding.ONEC:
                if internal_value >= 0:
                    raw_value = internal_value
                else:
                    mask = (1 << bit_length) - 1
                    raw_value = mask + internal_value
            elif base_type_encoding in (None, Encoding.TWOC):
                if internal_value >= 0:
                    raw_value = internal_value
                else:
                    mask = (1 << bit_length) - 1
                    raw_value = mask + internal_value + 1
            elif base_type_encoding == Encoding.SM:
                if internal_value >= 0:
                    raw_value = internal_value
                else:
                    raw_value = (1 << (bit_length - 1)) + abs(internal_value)
            else:
                odxraise(
                    f"Illegal encoding ({base_type_encoding and base_type_encoding.value}) specified for "
                    f"{base_data_type.value}")
                if base_type_encoding == Encoding.BCD_P:
                    raw_value = self.__encode_bcd_p(abs(internal_value))
                elif base_type_encoding == Encoding.BCD_UP:
                    raw_value = self.__encode_bcd_up(abs(internal_value))
                else:
                    raw_value = internal_value
            if not isinstance(raw_value, int):
                odxraise(f"Expected integer raw value for A_INT32, got {type(raw_value).__name__}",
                         EncodeError)
            if raw_value.bit_length() > bit_length:
                odxraise(
                    f"The value '{internal_value!r}' cannot be encoded using "
                    f"{bit_length} bits.", EncodeError)
                raw_value &= (1 << bit_length) - 1

        elif base_data_type == DataType.A_UINT32:
            if not isinstance(internal_value, int) or internal_value < 0:
                odxraise(f"Internal value must be a positive integer, not {internal_value!r}")
                internal_value = abs(int(internal_value))
            if base_type_encoding == Encoding.BCD_P:
                raw_value = self.__encode_bcd_p(internal_value)
            elif base_type_encoding == Encoding.BCD_UP:
                raw_value = self.__encode_bcd_up(internal_value)
            elif base_type_encoding in (None, Encoding.NONE):
                raw_value = internal_value
            else:
                odxraise(f"Illegal encoding ({base_type_encoding}) specified for "
                         f"{base_data_type.value}")
                raw_value = internal_value
            if not isinstance(raw_value, int):
                odxraise(f"Expected integer raw value for A_UINT32, got {type(raw_value).__name__}",
                         EncodeError)
            if raw_value.bit_length() > bit_length:
                odxraise(
                    f"The value '{internal_value!r}' cannot be encoded using "
                    f"{bit_length} bits.", EncodeError)
                raw_value &= (1 << bit_length) - 1

        else:
            odxassert(base_data_type in (DataType.A_FLOAT32, DataType.A_FLOAT64))
            odxassert(base_type_encoding in (None, Encoding.NONE))
            if base_data_type == DataType.A_FLOAT32 and bit_length != 32:
                odxraise(f"Illegal bit length for a float32 object ({bit_length})")
                bit_length = 32
            elif base_data_type == DataType.A_FLOAT64 and bit_length != 64:
                odxraise(f"Illegal bit length for a float64 object ({bit_length})")
                bit_length = 64
            raw_value = float(internal_value)

        if bit_length == 0:
            self.emplace_bytes(b'')
            return

        # === NATIVE BIT-SHIFTING ENCODE ===
        total_bits = self.cursor_bit_position + bit_length
        byte_length = (total_bits + 7) // 8

        if base_data_type in (DataType.A_UINT32, DataType.A_INT32):
            if isinstance(raw_value, int):
                masked = raw_value & ((1 << bit_length) - 1)
                shifted = masked << self.cursor_bit_position
                coded = shifted.to_bytes(byte_length, "big")
            else:
                odxraise(f"Expected integer, got {type(raw_value).__name__}", EncodeError)
                coded = b"\x00" * byte_length

        elif base_data_type == DataType.A_FLOAT32:
            float_bytes = struct.pack(">f", float(raw_value))
            float_val = int.from_bytes(float_bytes, "big")
            shifted = float_val << self.cursor_bit_position
            coded = shifted.to_bytes(byte_length, "big")

        elif base_data_type == DataType.A_FLOAT64:
            float_bytes = struct.pack(">d", float(raw_value))
            float_val = int.from_bytes(float_bytes, "big")
            shifted = float_val << self.cursor_bit_position
            coded = shifted.to_bytes(byte_length, "big")

        elif base_data_type == DataType.A_BYTEFIELD:
            if isinstance(raw_value, (bytes, bytearray)):
                raw_int = int.from_bytes(raw_value, "big")
                shifted = raw_int << self.cursor_bit_position
                coded = shifted.to_bytes(byte_length, "big")
            else:
                odxraise(f"Expected bytes, got {type(raw_value).__name__}", EncodeError)
                coded = b"\x00" * byte_length

        elif base_data_type in (DataType.A_ASCIISTRING, DataType.A_UTF8STRING, DataType.A_UNICODE2STRING):
            if isinstance(raw_value, str):
                if base_data_type == DataType.A_ASCIISTRING:
                    raw_value = raw_value.encode("ascii")
                elif base_data_type == DataType.A_UTF8STRING:
                    raw_value = raw_value.encode("utf-8")
                else:
                    raw_value = raw_value.encode("utf-16-be")
            if isinstance(raw_value, (bytes, bytearray)):
                raw_int = int.from_bytes(raw_value, "big")
                shifted = raw_int << self.cursor_bit_position
                coded = shifted.to_bytes(byte_length, "big")
            else:
                odxraise(f"Expected bytes, got {type(raw_value).__name__}", EncodeError)
                coded = b"\x00" * byte_length

        else:
            odxraise(f"Unsupported base data type: {base_data_type}", EncodeError)
            coded = b"\x00" * byte_length

        # Create used mask
        used_mask_raw = used_mask
        if used_mask_raw is None:
            used_mask_raw = ((1 << bit_length) - 1).to_bytes((bit_length + 7) // 8, "big")

        if self.cursor_bit_position != 0:
            tmp = int.from_bytes(used_mask_raw, "big")
            tmp <<= self.cursor_bit_position
            used_mask_raw = tmp.to_bytes((self.cursor_bit_position + bit_length + 7) // 8, "big")

        if not is_highlow_byte_order and base_data_type in [
                DataType.A_INT32, DataType.A_UINT32, DataType.A_FLOAT32, DataType.A_FLOAT64
        ]:
            coded = coded[::-1]
            used_mask_raw = used_mask_raw[::-1]

        self.cursor_bit_position = 0
        self.emplace_bytes(coded, obj_used_mask=used_mask_raw)

    def emplace_bytes(self,
                      new_data: bytes,
                      obj_name: str | None = None,
                      obj_used_mask: bytes | None = None) -> None:
        if self.cursor_bit_position != 0:
            odxraise("EncodeState.emplace_bytes can only be called "
                     "for a bit position of 0!", RuntimeError)

        pos = self.cursor_byte_position
        min_length = pos + len(new_data)
        if len(self.coded_message) < min_length:
            pad = b'\x00' * (min_length - len(self.coded_message))
            self.coded_message += pad
            self.used_mask += pad

        if obj_used_mask is None:
            n = len(new_data)
            if self.used_mask[pos:pos + n] != b'\x00' * n:
                warnings.warn(
                    f"Overlapping objects detected in between bytes {pos} and "
                    f"{pos+n}",
                    OdxWarning,
                    stacklevel=1,
                )
            self.coded_message[pos:pos + n] = new_data
            self.used_mask[pos:pos + n] = b'\xff' * n
        else:
            for i in range(len(new_data)):
                if self.used_mask[pos + i] & obj_used_mask[i] != 0:
                    warnings.warn(
                        f"Overlapping objects detected at position {pos + i}",
                        OdxWarning,
                        stacklevel=1,
                    )
                self.coded_message[pos + i] &= ~obj_used_mask[i]
                self.coded_message[pos + i] |= new_data[i] & obj_used_mask[i]
                self.used_mask[pos + i] |= obj_used_mask[i]

        self.cursor_byte_position += len(new_data)

    @staticmethod
    def __encode_bcd_p(value: int) -> int:
        result = 0
        shift = 0
        while value > 0:
            result |= (value % 10) << shift
            shift += 4
            value //= 10
        return result

    @staticmethod
    def __encode_bcd_up(value: int) -> int:
        result = 0
        shift = 0
        while value > 0:
            result |= (value % 10) << shift
            shift += 8
            value //= 10
        return result
