import lakers


def test_ead_items():
    short = repr(lakers.EADItem(label=42, is_critical=True))
    assert "42" in short
    assert ", critical," in short
    assert "no value" in short

    long = repr(lakers.EADItem(label=23, is_critical=False, value=b"........"))
    assert ", not critical," in long
    assert "(8 byte)" in long
