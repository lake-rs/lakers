import io
import logging
import lakers
import cbor2
import pytest
from lakers import CredentialTransfer, EdhocInitiator, EdhocResponder, EADItem

# This needs to be early, thus top-level: Once Lakers objects are created, the
# log level is fixed.
LOGSTREAM = io.StringIO()
logging.basicConfig(stream=LOGSTREAM, level=0, force=True)

# values from RFC9529, but CRED_I shortened so that passing by value is possible in a 256 byte message
CRED_I = bytes.fromhex("A202617808A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8")
I = bytes.fromhex("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b")
R = bytes.fromhex("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac")
CRED_R = bytes.fromhex("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072")
CONTEXT = [0xa0, 0x11, 0x58, 0xfd, 0xb8, 0x20, 0x89, 0x0c, 0xd6, 0xbe, 0x16, 0x96, 0x02, 0xb8, 0xbc, 0xea]

def test_gen_keys():
    priv, pub = lakers.p256_generate_key_pair()
    assert len(priv) == 32
    assert len(pub) == 32

def test_initiator():
    initiator = EdhocInitiator()
    message_1 = initiator.prepare_message_1(c_i=None)
    assert type(message_1) == bytes

def test_responder():
    responder = EdhocResponder(R, CRED_R)

def test_ccs_consruction():
    # The main crednetials we use can be parsed as they are:
    cred_r = lakers.Credential(CRED_R)

    # We can also parse them on our own and construct an equivalent credential:
    parsed_cred_r = cbor2.loads(CRED_R)
    public_key = parsed_cred_r[8][1][-2]
    kid = [ord(parsed_cred_r[8][1][2])]
    cred_r_manual = lakers.Credential(CRED_R, public_key=public_key, kid=kid)

    # No equality is useful, but the reprs are comprehensive
    assert repr(cred_r_manual) == repr(cred_r)

    # Both forms are accepted for constructing equivalent responders
    _ = EdhocResponder(R, CRED_R)
    _ = EdhocResponder(R, cred_r_manual)

def _test_handshake(cred_r_transfer, cred_i_transfer):
    initiator = EdhocInitiator()
    responder = EdhocResponder(R, CRED_R)

    # initiator
    message_1 = initiator.prepare_message_1(c_i=None)

    # responder
    _c_i, ead_1 = responder.process_message_1(message_1)
    assert not ead_1
    message_2 = responder.prepare_message_2(cred_r_transfer, None, [EADItem(10, False, None)])
    assert type(message_2) == bytes

    # initiator
    c_r, id_cred_r, ead_2 = initiator.parse_message_2(message_2)
    assert len(ead_2) == 1
    assert ead_2[0].value() == None
    assert ead_2[0].label() == 10
    assert ead_2[0].is_critical() == False
    valid_cred_r = lakers.credential_check_or_fetch(id_cred_r, CRED_R)
    initiator.verify_message_2(I, CRED_I, valid_cred_r)
    message_3, i_prk_out = initiator.prepare_message_3(cred_i_transfer, [EADItem(1000, True, b"..."), EADItem(0, False, b"")])
    assert type(message_3) == bytes

    # responder
    id_cred_i, ead_3 = responder.parse_message_3(message_3)
    assert len(ead_3) == 2
    assert ead_3[0].label() == 1000
    assert ead_3[0].is_critical() == True
    assert ead_3[0].value() == b"..."
    assert ead_3[1].label() == 0
    valid_cred_i = lakers.credential_check_or_fetch(id_cred_i, CRED_I)
    r_prk_out = responder.verify_message_3(valid_cred_i)
    message_4 = responder.prepare_message_4()

    assert i_prk_out == r_prk_out

    # initiator
    ead_4 = initiator.parse_message_4(message_4)
    initiator.verify_message_4()

    i_oscore_secret = initiator.edhoc_exporter(0, [], 16)
    i_oscore_salt = initiator.edhoc_exporter(1, [], 8)
    r_oscore_secret = responder.edhoc_exporter(0, [], 16)
    r_oscore_salt = responder.edhoc_exporter(1, [], 8)
    assert i_oscore_secret == r_oscore_secret
    assert i_oscore_salt == r_oscore_salt

    # test key update with context from RFC9529
    i_prk_out_new = initiator.edhoc_key_update(CONTEXT)
    r_prk_out_new = responder.edhoc_key_update(CONTEXT)
    assert i_prk_out_new == r_prk_out_new

def test_edhoc_error():
    responder = EdhocResponder(R, CRED_R)
    with pytest.raises(ValueError) as err:
        _ = responder.process_message_1([1, 2, 3])
    assert str(err.value) == "EDHOCError::ParsingError"

def test_buffer_error():
    initiator = EdhocInitiator()
    initiator.prepare_message_1()
    with pytest.raises(ValueError) as err:
        _ = initiator.parse_message_2(cbor2.dumps(bytes([1] * 10000)))
    assert str(err.value) == "Message 2 too long (EdhocBufferError::SliceTooLong)"

def test_state_missing_step():
    initiator = EdhocInitiator()
    with pytest.raises(RuntimeError) as err:
        initiator.prepare_message_3(CredentialTransfer.ByReference)
    assert str(err.value).startswith("State machine is just at Start, but this operation requires it to have progressed to ProcessedM2")

def test_state_no_going_back():
    initiator = EdhocInitiator()
    message_1 = initiator.prepare_message_1(c_i=None)

    responder = EdhocResponder(R, CRED_R)
    assert "Start" in repr(responder), f"Expected state to be reported in repr, found {responder!r}"
    responder.process_message_1(message_1)
    assert "ProcessingM1" in repr(responder), f"Expected state to be reported in repr, found {responder!r}"
    with pytest.raises(RuntimeError) as err:
        responder.process_message_1(message_1)
    assert str(err.value).startswith("State machine has progressed beyond expected Start, is already at ProcessingM1"), str(err.value)

def test_logging():
    LOGSTREAM.truncate(0)
    LOGSTREAM.seek(0)

    test_handshake_credential_transfer_by(CredentialTransfer.ByValue, CredentialTransfer.ByValue)

    # So far we don't test much, but that is currently in it an shows that log messages get through.
    assert 'Initializing EdhocInitiator' in LOGSTREAM.getvalue()

@pytest.mark.parametrize("cred_r_transfer", [CredentialTransfer.ByReference, CredentialTransfer.ByValue])
@pytest.mark.parametrize("cred_i_transfer", [CredentialTransfer.ByReference, CredentialTransfer.ByValue])
def test_handshake_credential_transfer_by(cred_r_transfer, cred_i_transfer):
    _test_handshake(cred_r_transfer, cred_i_transfer)
