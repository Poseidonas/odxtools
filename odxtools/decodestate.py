# SPDX-License-Identifier: MIT
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .encoding import Encoding, get_string_encoding
from .exceptions import DecodeError, odxassert, odxraise, strict_mode
from .odxtypes import AtomicOdxType, DataType, ParameterValue

if TYPE_CHECKING:
    from .parameters.parameter import Parameter
    from .tablerow import TableRow


@dataclass
class DecodeState:
    """Utility class to be used while decoding a message."""

    coded_message: bytes | bytearray
    origin_byte_position: int = 0
    cursor_byte_position: int = 0
    cursor_bit_position: int = 0
    length_keys: dict[str, int] = field(default_factory=dict)
    table_keys: dict[str, "TableRow"] = field(default_factory=dict)
    journal: list[tuple["Parameter", ParameterValue | None]] = field(default_factory=list)

    def extract_atomic_value(
        self,
        *,
        bit_length: int,
        base_data_type: DataType,
        base_type_encoding: Encoding | None,
        is_highlow_byte_order: bool,
    ) -> AtomicOdxType:
        """Extract an internal value from a blob of raw bytes."""
        if bit_length == 0:
            return base_data_type.python_type()

        if base_data_type == DataType.A_FLOAT32 and bit_length != 32:
            odxraise("The bit length of FLOAT32 values must be 32 bits")
            bit_length = 32
        elif base_data_type == DataType.A_FLOAT64 and bit_length != 64:
            odxraise("The bit length of FLOAT64 values must be 64 bits")
            bit_length = 64

        byte_length = (bit_length + self.cursor_bit_position + 7) // 8
        if self.cursor_byte_position + byte_length > len(self.coded_message):
            raise DecodeError(f"Expected a longer message.")
        extracted_bytes = self.coded_message[self.cursor_byte_position:self.cursor_byte_position +
                                             byte_length]

        if not is_highlow_byte_order and base_data_type in [
                DataType.A_INT32,
                DataType.A_UINT32,
                DataType.A_FLOAT32,
                DataType.A_FLOAT64,
        ]:
            extracted_bytes = extracted_bytes[::-1]

        # === NATIVE BIT-SHIFTING DECODE ===
        tmp = int.from_bytes(extracted_bytes, "big")
        tmp >>= self.cursor_bit_position
        raw_value = tmp & ((1 << bit_length) - 1)

        if base_data_type == DataType.A_FLOAT32:
            raw_value = struct.unpack(">f", raw_value.to_bytes(4, "big"))[0]
        elif base_data_type == DataType.A_FLOAT64:
            raw_value = struct.unpack(">d", raw_value.to_bytes(8, "big"))[0]
        elif base_data_type == DataType.A_BYTEFIELD:
            byte_len = (bit_length + 7) // 8
            raw_value = raw_value.to_bytes(byte_len, "big")
        elif base_data_type in (DataType.A_ASCIISTRING, DataType.A_UTF8STRING, DataType.A_UNICODE2STRING):
            byte_len = (bit_length + 7) // 8
            raw_value = raw_value.to_bytes(byte_len, "big")

        internal_value: AtomicOdxType

        if base_data_type == DataType.A_BYTEFIELD:
            odxassert(
                base_type_encoding in (None, Encoding.NONE, Encoding.BCD_P, Encoding.BCD_UP),
                f"Illegal encoding '{base_type_encoding}' for A_BYTEFIELD")
            internal_value = raw_value

        elif base_data_type in (DataType.A_UTF8STRING, DataType.A_ASCIISTRING,
                                DataType.A_UNICODE2STRING):
            text_errors = 'strict' if strict_mode else 'replace'
            str_encoding = get_string_encoding(base_data_type, base_type_encoding,
                                               is_highlow_byte_order)
            if str_encoding is not None:
                if not isinstance(raw_value, (bytes, bytearray)):
                    odxraise(f"Expected bytes for string decoding, got {type(raw_value).__name__}")
                internal_value = raw_value.decode(str_encoding, errors=text_errors)
            else:
                internal_value = "ERROR"

        elif base_data_type == DataType.A_INT32:
            if not isinstance(raw_value, int):
                odxraise(f"Expected integer raw value for A_INT32, got {type(raw_value).__name__}")
            if base_type_encoding == Encoding.ONEC:
                sign_bit = 1 << (bit_length - 1)
                if raw_value < sign_bit:
                    internal_value = raw_value
                else:
                    internal_value = -((1 << bit_length) - raw_value - 1)
            elif base_type_encoding in (None, Encoding.TWOC):
                sign_bit = 1 << (bit_length - 1)
                if raw_value < sign_bit:
                    internal_value = raw_value
                else:
                    internal_value = -((1 << bit_length) - raw_value)
            elif base_type_encoding == Encoding.SM:
                sign_bit = 1 << (bit_length - 1)
                if raw_value < sign_bit:
                    internal_value = raw_value
                else:
                    internal_value = -(raw_value - sign_bit)
            else:
                odxraise(f"Illegal encoding ({base_type_encoding}) specified for "
                         f"{base_data_type.value}")
                if base_type_encoding == Encoding.BCD_P:
                    internal_value = self.__decode_bcd_p(raw_value)
                elif base_type_encoding == Encoding.BCD_UP:
                    internal_value = self.__decode_bcd_up(raw_value)
                else:
                    internal_value = raw_value

        elif base_data_type == DataType.A_UINT32:
            if not isinstance(raw_value, int):
                odxraise(f"Expected integer raw value for A_UINT32, got {type(raw_value).__name__}")
            if base_type_encoding == Encoding.BCD_P:
                internal_value = self.__decode_bcd_p(raw_value)
            elif base_type_encoding == Encoding.BCD_UP:
                internal_value = self.__decode_bcd_up(raw_value)
            elif base_type_encoding in (None, Encoding.NONE):
                internal_value = raw_value
            else:
                odxraise(f"Illegal encoding ({base_type_encoding}) specified for "
                         f"{base_data_type.value}")
                internal_value = raw_value

        else:
            odxassert(base_data_type in (DataType.A_FLOAT32, DataType.A_FLOAT64))
            odxassert(
                base_type_encoding in (None, Encoding.NONE),
                f"Specified illegal encoding '{base_type_encoding}' for float object")
            internal_value = float(raw_value)

        self.cursor_byte_position += byte_length
        self.cursor_bit_position = 0

        return internal_value

    @staticmethod
    def __decode_bcd_p(value: int) -> int:
        result = 0
        factor = 1
        while value > 0:
            result += (value & 0xf) * factor
            factor *= 10
            value >>= 4
        return result

    @staticmethod
    def __decode_bcd_up(value: int) -> int:
        result = 0
        factor = 1
        while value > 0:
            result += (value & 0xf) * factor
            factor *= 10
            value >>= 8
        return result
