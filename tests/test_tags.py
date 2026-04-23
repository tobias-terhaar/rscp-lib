from rscp_lib import RscpTags


def test_find_tag_value_known():
    result = RscpTags.findTagValue(RscpTags.rscpTags["TAG_RSCP_AUTHENTICATION"]["tagvalue"])
    assert result is not None
    assert list(result.keys())[0] == "TAG_RSCP_AUTHENTICATION"


def test_find_tag_value_unknown():
    assert RscpTags.findTagValue(0xDEADBEEF) is None


def test_tags_dict_nonempty():
    assert len(RscpTags.rscpTags) > 100
