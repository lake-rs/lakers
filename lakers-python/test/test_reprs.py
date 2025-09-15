import lakers

from test_lakers import R, CRED_R


def test_ead_items():
    short = repr(lakers.EADItem(label=42, is_critical=True))
    assert "42" in short
    assert ", critical," in short
    assert "no value" in short

    long = repr(lakers.EADItem(label=23, is_critical=False, value=b"........"))
    assert ", not critical," in long
    assert "(8 byte)" in long


def test_initiator():
    i = repr(lakers.EdhocInitiator())
    assert " in state Start" in i


def test_responder():
    r = repr(lakers.EdhocResponder(R, CRED_R))
    assert " in state Start" in r
