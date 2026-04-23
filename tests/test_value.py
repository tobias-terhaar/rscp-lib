import struct

import pytest

from rscp_lib import RscpTags
from rscp_lib.RscpValue import RscpValue


def _find_tag_of_type(type_name, require_no_variable=True):
    for name, tag in RscpTags.rscpTags.items():
        if tag["type"] != type_name:
            continue
        if require_no_variable and tag.get("type_variable"):
            continue
        return name
    raise RuntimeError(f"no tag of type {type_name}")


# --- Scalar round-trips ----------------------------------------------------


@pytest.mark.parametrize(
    "type_name,value",
    [
        ("Bool", True),
        ("Char8", -5),
        ("UChar8", 100),
        ("Int16", -1234),
        ("UInt16", 65000),
        ("Int32", -123456),
        ("Uint32", 123456),
        ("Int64", -1234567890),
        ("Uint64", 1234567890),
        ("Double64", 2.71828),
        ("Bitfield", 15),
    ],
)
def test_scalar_roundtrip(type_name, value):
    tag_name = _find_tag_of_type(type_name)
    packed = RscpValue().withTagName(tag_name, value).pack()
    v = RscpValue().withBuffer(packed)
    assert v.getTagName() == tag_name
    assert v.getValue() == value


def test_float32_roundtrip():
    tag_name = _find_tag_of_type("Float32")
    packed = RscpValue().withTagName(tag_name, 3.5).pack()
    v = RscpValue().withBuffer(packed)
    assert abs(v.getValue() - 3.5) < 1e-6


def test_cstring_roundtrip():
    packed = (
        RscpValue().withTagName("TAG_RSCP_AUTHENTICATION_USER", "alice").pack()
    )
    v = RscpValue().withBuffer(packed)
    assert v.getValue() == "alice"


def test_none_type_roundtrip():
    packed = RscpValue().withTagName("TAG_EMS_REQ_POWER_PV", None).pack()
    v = RscpValue().withBuffer(packed)
    assert v.getValue() is None


# --- Container -------------------------------------------------------------


def _auth_container():
    user = RscpValue().withTagName("TAG_RSCP_AUTHENTICATION_USER", "alice")
    pw = RscpValue().withTagName("TAG_RSCP_AUTHENTICATION_PASSWORD", "secret")
    return RscpValue().withTagName("TAG_RSCP_REQ_AUTHENTICATION", [user, pw])


def test_container_roundtrip_and_helpers():
    packed = _auth_container().pack()
    v = RscpValue().withBuffer(packed)
    assert v.is_container()
    assert v.has_child_tag("TAG_RSCP_AUTHENTICATION_USER")
    assert not v.has_child_tag("TAG_NOT_A_CHILD")
    assert v.get_child("TAG_RSCP_AUTHENTICATION_USER").getValue() == "alice"
    assert v.get_child("TAG_NOT_A_CHILD") is None
    assert len(v.get_childs("TAG_RSCP_AUTHENTICATION_USER")) == 1


def test_container_requires_list():
    with pytest.raises(ValueError):
        RscpValue().withTagName("TAG_RSCP_REQ_AUTHENTICATION", "bad").pack()


def test_non_container_helpers_return_empty():
    leaf = RscpValue().withTagName("TAG_RSCP_AUTHENTICATION_USER", "alice")
    assert not leaf.is_container()
    assert not leaf.has_child_tag("anything")
    assert leaf.get_child("anything") is None
    assert leaf.get_childs("anything") == []


def test_construct_rscp_value_builds_nested():
    v = RscpValue.construct_rscp_value(
        "TAG_RSCP_REQ_AUTHENTICATION",
        [
            ["TAG_RSCP_AUTHENTICATION_USER", "alice"],
            ["TAG_RSCP_AUTHENTICATION_PASSWORD", "secret"],
        ],
    )
    assert v.is_container()
    assert v.get_child("TAG_RSCP_AUTHENTICATION_USER").getValue() == "alice"


def test_construct_rscp_value_leaf():
    v = RscpValue.construct_rscp_value("TAG_RSCP_AUTHENTICATION_USER", "alice")
    assert v.getValue() == "alice"


# --- Tag identity helpers --------------------------------------------------


def test_is_tag_and_getters():
    v = RscpValue().withTagName("TAG_RSCP_AUTHENTICATION_USER", "alice")
    assert v.isTag("TAG_RSCP_AUTHENTICATION_USER")
    assert not v.isTag("TAG_OTHER")
    assert v.getTagName() == "TAG_RSCP_AUTHENTICATION_USER"
    assert v.getValue() == "alice"


# --- Filter / path navigation ---------------------------------------------


def _pvi_containers():
    def make(idx):
        index = RscpValue().withTagName("TAG_PVI_INDEX", idx)
        other = RscpValue().withTagName("TAG_PVI_INDEX", 999)  # second child
        return RscpValue().withTagName("TAG_PVI_DATA", [index, other])

    return [make(0), make(1)]


def test_get_rscp_value_by_filter_simple_match():
    values = [RscpValue().withTagName("TAG_PVI_INDEX", 7)]
    found = RscpValue.get_RscpValue_by_filter(values, "TAG_PVI_INDEX")
    assert found.getValue() == 7


def test_get_rscp_value_by_filter_no_match():
    values = [RscpValue().withTagName("TAG_PVI_INDEX", 7)]
    assert (
        RscpValue.get_RscpValue_by_filter(values, "TAG_RSCP_AUTHENTICATION_USER")
        is None
    )


def test_get_rscp_value_by_filter_container_subfilter():
    values = _pvi_containers()
    found = RscpValue.get_RscpValue_by_filter(values, "TAG_PVI_DATA(TAG_PVI_INDEX==1)")
    assert found is not None
    assert found.get_child("TAG_PVI_INDEX").getValue() == 1


def test_get_rscp_value_by_filter_container_subfilter_miss():
    values = _pvi_containers()
    found = RscpValue.get_RscpValue_by_filter(
        values, "TAG_PVI_DATA(TAG_PVI_INDEX==99)"
    )
    assert found is None


def test_get_tag_by_path_simple():
    values = [_auth_container()]
    v = RscpValue.get_tag_by_path(values, "TAG_RSCP_REQ_AUTHENTICATION")
    assert v.is_container()


def test_get_tag_by_path_nested():
    values = [_auth_container()]
    v = RscpValue.get_tag_by_path(
        values, "TAG_RSCP_REQ_AUTHENTICATION/TAG_RSCP_AUTHENTICATION_USER"
    )
    assert v.getValue() == "alice"


def test_get_tag_by_path_with_filter_chain():
    values = _pvi_containers()
    v = RscpValue.get_tag_by_path(
        values, "TAG_PVI_DATA(TAG_PVI_INDEX==1)/TAG_PVI_INDEX"
    )
    assert v is not None
    assert v.getValue() == 1


def test_get_tag_by_path_not_found():
    values = [_auth_container()]
    assert (
        RscpValue.get_tag_by_path(values, "TAG_RSCP_AUTHENTICATION_USER/TAG_NONE")
        is None
    )


# --- toString / print ------------------------------------------------------


def test_toString_leaf_and_container(capsys):
    leaf = RscpValue().withTagName("TAG_RSCP_AUTHENTICATION_USER", "alice")
    assert "TAG_RSCP_AUTHENTICATION_USER" in leaf.toString()

    container = _auth_container()
    text = container.toString()
    assert "==>>" in text
    assert "TAG_RSCP_AUTHENTICATION_USER" in text


def test_print_leaf_and_container(capsys):
    leaf = RscpValue().withTagName("TAG_RSCP_AUTHENTICATION_USER", "alice")
    leaf.print()
    captured = capsys.readouterr().out
    assert "TAG_RSCP_AUTHENTICATION_USER" in captured

    _auth_container().print()
    captured = capsys.readouterr().out
    assert "Container" in captured


# --- Wire-level edge cases ------------------------------------------------


def _pack_header(tag_code, type_id, data_length):
    return struct.pack("<IBH", tag_code, type_id, data_length)


def test_unpack_unknown_tag_raises():
    buf = _pack_header(0xDEADBEEF, 0x00, 0)
    with pytest.raises(ValueError):
        RscpValue().withBuffer(buf)


def test_unpack_error8_tag():
    tag_code = RscpTags.rscpTags["TAG_RSCP_GENERAL_ERROR"]["tagvalue"]
    buf = _pack_header(tag_code, 0xFF, 1) + struct.pack("<B", 7)
    v = RscpValue().withBuffer(buf)
    assert v.isError
    assert v.getValue() == 7


def test_unpack_error32_tag():
    tag_code = RscpTags.rscpTags["TAG_RSCP_GENERAL_ERROR"]["tagvalue"]
    buf = _pack_header(tag_code, 0xFF, 4) + struct.pack("<I", 0xCAFEBABE)
    v = RscpValue().withBuffer(buf)
    assert v.isError
    assert v.getValue() == 0xCAFEBABE


def test_unpack_error_tag_bad_length_raises():
    tag_code = RscpTags.rscpTags["TAG_RSCP_GENERAL_ERROR"]["tagvalue"]
    buf = _pack_header(tag_code, 0xFF, 2) + b"\x00\x00"
    with pytest.raises(ValueError):
        RscpValue().withBuffer(buf)


def test_unpack_error_tag_logging_enabled():
    # Turn on error-tag logging to cover the conditional log.error lines.
    # Need the module (not the re-exported class) — see conftest.
    from tests.conftest import value_module
    RscpValueModule = value_module()

    saved = RscpValueModule.log_error_tags
    RscpValueModule.log_error_tags = True
    try:
        tag_code = RscpTags.rscpTags["TAG_RSCP_GENERAL_ERROR"]["tagvalue"]
        # Error8 path
        buf = _pack_header(tag_code, 0xFF, 1) + struct.pack("<B", 1)
        v = RscpValue().withBuffer(buf)
        assert v.isError
        # Error32 path also exercises the trailing log.error branch
        buf = _pack_header(tag_code, 0xFF, 4) + struct.pack("<I", 42)
        v = RscpValue().withBuffer(buf)
        assert v.isError
    finally:
        RscpValueModule.log_error_tags = saved


def test_unpack_authentication_failure_uses_int32():
    # TAG_RSCP_AUTHENTICATION declared UChar8; on failure comes back as Int32.
    tag_code = RscpTags.rscpTags["TAG_RSCP_AUTHENTICATION"]["tagvalue"]
    buf = _pack_header(tag_code, 0x06, 4) + struct.pack("<i", -1)
    v = RscpValue().withBuffer(buf)
    assert v.getValue() == -1


def test_unpack_type_variable_overrides_declared_type():
    # TAG_EMS_SET_POWER is Int32 with type_variable=True.
    # Send as Int16 on the wire and verify it unpacks correctly.
    tag_code = RscpTags.rscpTags["TAG_EMS_SET_POWER"]["tagvalue"]
    buf = _pack_header(tag_code, 0x04, 2) + struct.pack("<h", 1234)
    v = RscpValue().withBuffer(buf)
    assert v.getValue() == 1234


def test_unpack_type_mismatch_raises():
    # TAG_RSCP_AUTHENTICATION_USER is CString (0x0D). Send with wrong type byte.
    tag_code = RscpTags.rscpTags["TAG_RSCP_AUTHENTICATION_USER"]["tagvalue"]
    buf = _pack_header(tag_code, 0x01, 1) + b"\x01"
    with pytest.raises(ValueError):
        RscpValue().withBuffer(buf)


def test_unpack_error_declared_type_on_non_error_wire_raises():
    # TAG_RSCP_GENERAL_ERROR declares type "Error" which is not in RscpTypes.
    # If the wire type is NOT 0xFF we take the else-branch that KeyErrors.
    tag_code = RscpTags.rscpTags["TAG_RSCP_GENERAL_ERROR"]["tagvalue"]
    buf = _pack_header(tag_code, 0x01, 1) + b"\x00"
    with pytest.raises(ValueError):
        RscpValue().withBuffer(buf)


def test_unpack_bytearray_raises_not_implemented():
    # ByteArray has fmt 's' but is neither CString nor Container — should raise.
    tag_code = RscpTags.rscpTags["TAG_RSCP_AUTH_CHALLENGE_DATA"]["tagvalue"]
    buf = _pack_header(tag_code, 0x10, 3) + b"abc"
    with pytest.raises(NotImplementedError):
        RscpValue().withBuffer(buf)


def test_pack_bytearray_raises_not_implemented():
    v = RscpValue().withTagName("TAG_RSCP_AUTH_CHALLENGE_DATA", b"abc")
    with pytest.raises(NotImplementedError):
        v.pack()


def test_unpack_timestamp_returns_seconds():
    # Timestamp fmt "QI"; the current unpack only returns the first element.
    tag_code = RscpTags.rscpTags["TAG_EMS_EPTEST_NEXT_TESTSTART"]["tagvalue"]
    payload = struct.pack("<QI", 1_700_000_000, 12345)
    buf = _pack_header(tag_code, 0x0F, len(payload)) + payload
    v = RscpValue().withBuffer(buf)
    assert v.getValue() == 1_700_000_000


def test_get_packed_data_size_matches_pack_length():
    v = _auth_container()
    assert v.getPackedDataSize() == len(v.pack())


def test_get_header_size_and_data_length_helpers():
    v = RscpValue().withTagName("TAG_RSCP_AUTHENTICATION_USER", "abc")
    packed = v.pack()
    assert RscpValue.getHeaderSize() == struct.calcsize("<IBH")
    assert RscpValue.getDataLength(packed) == 3
