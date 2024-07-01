pub use crate::edhoc::*;
use hexlit::hex;
use lakers_shared::*;

//#[derive(Clone, Copy, Debug)]

// Function compute_prk_3e2m
pub fn compute_prk_3e2m_psk(
    crypto: &mut impl CryptoTrait,
    salt_3e2m: &BytesHashLen,
    cred_psk: &BytesP256ElemLen, //TODO: what is the psk type? len?
) -> BytesHashLen {
    crypto.hkdf_extract(salt_3e2m, cred_psk)
}

// Function compute_prk_4e3m that calls compute_prk_3e2m
pub fn compute_prk_4e3m(
    crypto: &mut impl CryptoTrait,
    salt_4e3m: &BytesHashLen,
    cred_psk: &BytesP256ElemLen,
) -> BytesHashLen {
    compute_prk_3e2m(crypto, salt_4e3m, cred_psk)
}

// Function compute_mac_2
pub fn compute_mac_2(
    crypto: &mut impl CryptoTrait,
    prk_3e2m: &BytesHashLen,
    c_r: ConnId,
    id_cred_psk: &BytesIdCredPSK, //TODO
    cred_psk: &[u8],
    th_2: &BytesHashLen,
    ead_2: &Option<EADItem>,
) -> BytesMac2 {
    // compute MAC_2
    let (context, context_len) = encode_kdf_context(Some(c_r), id_cred_psk, th_2, cred_psk, ead_2);

    // MAC_2 = EDHOC-KDF( PRK_3e2m, 2, context_2, mac_length_2 )
    // context_2 = << c_r, id_cred_psk, th_2, ? ead_2 >>
    let mut mac_2: BytesMac2 = [0x00; MAC_LENGTH_2];
    mac_2[..].copy_from_slice(
        &edhoc_kdf(crypto, prk_3e2m, 2_u8, &context, context_len, MAC_LENGTH_2)[..MAC_LENGTH_2],
    );

    mac_2
}

use super::*;
// Define a tests module
#[cfg(test)]
mod tests {
    use super::*;
    use lakers_crypto::default_crypto;
    pub const ID_CRED_PSK: [u8; 4] = hex!("a104412b");
    pub const CRED_PSK : [u8; 107] = hex!("a2027734322d35302d33312d46462d45462d33372d33322d333908a101a5010202412b2001215820ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb62258206e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8");
    //const G_XY_TV: BytesP256ElemLen = hex!("2f0cb7e860ba538fbf5c8bded009f6259b4b628fe1eb7dbe9378e5ecf7a824ba");
    //const G_X_TV: BytesP256ElemLen = hex!("8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6");
    // Example usage test function
    #[test]
    fn test_example_usage() {
        let mut crypto = default_crypto();
        let psk: BytesP256ElemLen = [1; P256_ELEM_LEN]; // Example psk
                                                        //let h_message_1: BytesHashLen = [0; SHA256_DIGEST_LEN]; // TODO
        let h_message_1: BytesHashLen =
            hex!("ca02cabda5a8902749b42f711050bb4dbd52153e87527594b39f50cdf019888c");
        let g_y: BytesP256ElemLen =
            hex!("419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5");
        let x: BytesP256ElemLen =
            hex!("368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525");

        let th_2 = compute_th_2(&mut crypto, &g_y, &h_message_1);
        //let th_2: BytesHashLen = [0; SHA256_DIGEST_LEN]; // Example th_2

        // Calling compute prk_2e
        let prk_2e = compute_prk_2e(&mut crypto, &x, &g_y, &th_2);
        println!("PRK 2e: {:?}", prk_2e);

        // Calling salt_3e2m
        let salt_3e2m = compute_salt_3e2m(&mut crypto, &prk_2e, &th_2);
        println!("SALT 3e2m: {:?}", salt_3e2m);

        // Calling compute_prk_3e2m
        let prk_3e2m = compute_prk_3e2m(&mut crypto, &salt_3e2m, &psk);
        println!("PRK 3e2m: {:?}", prk_3e2m);

        // Calling compute_prk_4e3m
        let prk_4e3m = compute_prk_4e3m(&mut crypto, &salt_3e2m, &psk);
        println!("PRK 4e3m: {:?}", prk_4e3m);

        // Example values for compute_mac_2
        let c_r = generate_connection_identifier_cbor(&mut crypto);
        let cred_psk: &[u8] = &CRED_PSK; //&[];
        let id_cred_psk: BytesIdCredPSK = ID_CRED_PSK;
        let th_2: BytesHashLen = [0; SHA256_DIGEST_LEN]; // Example th_2
        let ead_2: Option<EADItem> = None; // Example ead_2

        // Compute MAC 2
        let mac_2 = compute_mac_2(
            &mut crypto,
            &prk_3e2m,
            c_r,
            &id_cred_psk,
            &cred_psk,
            &th_2,
            &ead_2,
        );
        println!("MAC 2: {:?}", mac_2);

        // Add assertions to validate the results if needed
        //assert!(true); // Placeholder assertion, replace with actual assertions
    }
}
