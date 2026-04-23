import struct

import pytest

from rscp_lib.RscpFrame import RscpFrame
from rscp_lib.RscpValue import RscpValue


def _none_value():
    return RscpValue().withTagName("TAG_EMS_REQ_POWER_PV", None)


def test_pack_single_value_has_magic():
    data = RscpFrame().packFrame(_none_value())
    assert data[0:2] == struct.pack("<H", 0xDCE3)


def test_pack_list_of_values_has_magic():
    values = [
        _none_value(),
        RscpValue().withTagName("TAG_EMS_REQ_POWER_BAT", None),
    ]
    data = RscpFrame().packFrame(values)
    assert data[0:2] == struct.pack("<H", 0xDCE3)


def test_roundtrip_single_value():
    data = RscpFrame().packFrame(_none_value())
    f = RscpFrame()
    f.unpack(data)
    values = f.getRscpValues()
    assert len(values) == 1
    assert values[0].getTagName() == "TAG_EMS_REQ_POWER_PV"


def test_roundtrip_list_of_values():
    values = [
        _none_value(),
        RscpValue().withTagName("TAG_EMS_REQ_POWER_BAT", None),
    ]
    data = RscpFrame().packFrame(values)
    f = RscpFrame()
    f.unpack(data)
    out = f.getRscpValues()
    assert [v.getTagName() for v in out] == [
        "TAG_EMS_REQ_POWER_PV",
        "TAG_EMS_REQ_POWER_BAT",
    ]


def test_get_frame_length_matches_buffer():
    data = RscpFrame().packFrame(_none_value())
    assert RscpFrame.getFrameLength(data) == len(data)


def test_get_frame_length_buffer_too_small():
    with pytest.raises(ValueError):
        RscpFrame.getFrameLength(b"\x00")


def test_unpack_bad_magic():
    data = b"\x00" * 18
    with pytest.raises(ValueError):
        RscpFrame().unpack(data)


def test_unpack_buffer_too_small_for_header():
    with pytest.raises(ValueError):
        RscpFrame().unpack(b"\x00")


def test_unpack_buffer_smaller_than_full_frame():
    data = RscpFrame().packFrame(_none_value())
    # keep only the header; declared data_length will exceed remaining bytes
    header = data[: struct.calcsize("<HHQIH")]
    with pytest.raises(ValueError):
        RscpFrame().unpack(header)


def test_unpack_buffer_with_trailing_bytes_is_truncated():
    data = RscpFrame().packFrame(_none_value()) + b"\xAA\xBB\xCC"
    f = RscpFrame()
    f.unpack(data)
    assert f.getRscpValues()[0].getTagName() == "TAG_EMS_REQ_POWER_PV"
