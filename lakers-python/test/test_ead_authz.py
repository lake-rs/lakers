import lakers

# values from traces-zeroconf.ipynb
ID_U = bytes.fromhex("a104412b")
G_W = bytes.fromhex("FFA4F102134029B3B156890B88C9D9619501196574174DCB68A07DB0588E4D41")
LOC_W = "coap://enrollment.server"
W = bytes.fromhex("4E5E15AB35008C15B89E91F9F329164D4AACD53D9923672CE0019F9ACD98573F")
KID_I = 0x2b
CRED_I = bytes.fromhex("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8")
I = bytes.fromhex("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b")
CRED_V = bytes.fromhex("a2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072")
V = bytes.fromhex("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac")
EAD_1_VALUE = bytes.fromhex("58287818636f61703a2f2f656e726f6c6c6d656e742e7365727665724dda9784962883c96ed01ff122c3")
MESSAGE_1_WITH_EAD = bytes.fromhex("0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6370158287818636f61703a2f2f656e726f6c6c6d656e742e7365727665724dda9784962883c96ed01ff122c3")
VOUCHER_RESPONSE = bytes.fromhex("8258520382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6370158287818636f61703a2f2f656e726f6c6c6d656e742e7365727665724dda9784962883c96ed01ff122c34948c783671337f75bd5")
EAD_2_VALUE = bytes.fromhex("48c783671337f75bd5")

def test_authenticator_and_server():
    authenticator = lakers.AuthzAutenticator()
    enrollment_server = lakers.AuthzEnrollmentServer(
            W,
            CRED_V,
            [KID_I],
    )

    ead_1 = lakers.EADItem(1, True, EAD_1_VALUE)
    loc_w, voucher_request = authenticator.process_ead_1(ead_1, MESSAGE_1_WITH_EAD)
    assert type(loc_w) == str
    voucher_response = enrollment_server.handle_voucher_request(voucher_request)
    assert type(voucher_response) == bytes

    ead_2 = authenticator.prepare_ead_2(voucher_response)
    assert ead_2.label() == lakers.consts.EAD_AUTHZ_LABEL
    assert ead_2.is_critical() == True
    assert ead_2.value() == EAD_2_VALUE

def test_authenticator_and_server():
    VOUCHER_REQUEST_TV = bytes.fromhex("8158520382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6370158287818636f61703a2f2f656e726f6c6c6d656e742e7365727665724dda9784962883c96ed01ff122c3")
    enrollment_server = lakers.AuthzServerUserAcl(W, CRED_V)

    id_u = enrollment_server.decode_voucher_request(VOUCHER_REQUEST_TV)
    assert id_u == ID_U
    voucher_response = enrollment_server.prepare_voucher(VOUCHER_REQUEST_TV)
    assert type(voucher_response) == bytes

def test_handshake_with_authz():
    initiator = lakers.EdhocInitiator()
    responder = lakers.EdhocResponder(CRED_V, V)

    device = lakers.AuthzDevice(
        ID_U,
        G_W,
        LOC_W,
    )
    authenticator = lakers.AuthzAutenticator()
    enrollment_server = lakers.AuthzEnrollmentServer(
            W,
            CRED_V,
            [KID_I],
    )

    # initiator
    #
    # Because we can, we're treating them as a list.
    ead_1 = [device.prepare_ead_1(
        initiator.compute_ephemeral_secret(device.get_g_w()),
        initiator.selected_cipher_suite(),
    )]

    message_1 = initiator.prepare_message_1(c_i=None, ead_1=ead_1)
    device.set_h_message_1(initiator.get_h_message_1())

    # responder
    _c_i, ead_1 = responder.process_message_1(message_1)
    [ead_1] = ead_1
    loc_w, voucher_request = authenticator.process_ead_1(ead_1, message_1)
    voucher_response = enrollment_server.handle_voucher_request(voucher_request)
    # Because we can, we're treating them as tuple. (Python conversion
    # tolerates this, it is also a PySequence).
    ead_2 = (authenticator.prepare_ead_2(voucher_response),)
    message_2 = responder.prepare_message_2(lakers.CredentialTransfer.ByReference, None, ead_2)
    assert type(message_2) == bytes

    # initiator
    c_r, id_cred_r, ead_2 = initiator.parse_message_2(message_2)
    valid_cred_r = lakers.credential_check_or_fetch(id_cred_r, CRED_V)
    [ead_2] = ead_2
    assert device.process_ead_2(ead_2, CRED_V) # voucher is valid!
    initiator.verify_message_2(I, CRED_I, valid_cred_r)
    # No EAD items in this message
    message_3, i_prk_out = initiator.prepare_message_3(lakers.CredentialTransfer.ByReference)
    assert type(message_3) == bytes

    # responder
    id_cred_i, ead_3 = responder.parse_message_3(message_3)
    for ead in ead_3:
        assert ead.is_critical() == False
        assert ead.value() == None
        
    valid_cred_i = lakers.credential_check_or_fetch(id_cred_i, CRED_I)
    r_prk_out = responder.verify_message_3(valid_cred_i)

    assert i_prk_out == r_prk_out
