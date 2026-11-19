#![no_std]

mod authenticator;
mod device;
mod server;
mod shared;
#[cfg(test)]
mod test_vectors;

pub use authenticator::{ZeroTouchAuthenticator, ZeroTouchAuthenticatorWaitVoucherResp};
pub use device::{ZeroTouchDevice, ZeroTouchDeviceDone, ZeroTouchDeviceWaitEAD2};
pub use server::{ZeroTouchServer, ZeroTouchServerUserAcl};

pub mod consts {
    pub const EAD_AUTHZ_LABEL: u16 = 0x1; // NOTE: in lake-authz-draft-01 it is still TBD1
    pub const EAD_AUTHZ_INFO_K_1_LABEL: u8 = 0x0;
    pub const EAD_AUTHZ_INFO_IV_1_LABEL: u8 = 0x1;
    pub const EAD_AUTHZ_ENC_STRUCTURE_LEN: usize = 2 + 8 + 3;
}

#[derive(PartialEq, Debug)]
#[repr(C)]
pub enum ZeroTouchError {
    InvalidEADLabel,
    EmptyEADValue,
    VoucherVerificationFailed,
}

#[cfg(test)]
mod test_authz {
    use crate::{
        authenticator::ZeroTouchAuthenticator, device::ZeroTouchDevice, server::ZeroTouchServer,
        test_vectors::*,
    };
    use lakers_crypto::default_crypto;
    use lakers_shared::LAKEError;

    #[test]
    fn test_complete_flow() {
        let device = ZeroTouchDevice::new(
            ID_U_TV.try_into().unwrap(),
            G_W_TV.try_into().unwrap(),
            LOC_W_TV.try_into().unwrap(),
        );
        let authenticator = ZeroTouchAuthenticator::default();
        let server = ZeroTouchServer::new(
            W_TV.try_into().unwrap(),
            CRED_V_TV.try_into().unwrap(),
            Some(ACL_TV.try_into().unwrap()),
        );

        // using .unwrap below since detailed errors are tested in each entity's tests

        let (mut device, ead_1) =
            device.prepare_ead_1(&mut default_crypto(), G_XW_TV.try_into().unwrap(), SS_TV);
        device.set_h_message_1(H_MESSAGE_1_TV.try_into().unwrap());

        // ead_1 will be transported within message_1

        let (authenticator, _loc_w, voucher_request) = authenticator
            .process_ead_1(&ead_1, &MESSAGE_1_WITH_EAD_TV.try_into().unwrap())
            .unwrap();

        // network request would be: let Ok(voucher_response) = auth_client.post(loc_w, voucher_request)

        let voucher_response = server
            .handle_voucher_request(&mut default_crypto(), &voucher_request)
            .unwrap();

        let ead_2 = authenticator.prepare_ead_2(&voucher_response).unwrap();

        // ead_2 will be transported within message_2

        let result = device.process_ead_2(&mut default_crypto(), &ead_2, CRED_V_TV);
        assert!(result.is_ok());
    }

    #[test]
    fn test_complete_flow_unauthorized() {
        let device = ZeroTouchDevice::new(
            ID_U_TV.try_into().unwrap(),
            G_W_TV.try_into().unwrap(),
            LOC_W_TV.try_into().unwrap(),
        );
        let authenticator = ZeroTouchAuthenticator::default();
        let server = ZeroTouchServer::new(
            W_TV.try_into().unwrap(),
            CRED_V_TV.try_into().unwrap(),
            Some(ACL_INVALID_TV.try_into().unwrap()),
        );

        let (mut device, ead_1) =
            device.prepare_ead_1(&mut default_crypto(), G_XW_TV.try_into().unwrap(), SS_TV);
        device.set_h_message_1(H_MESSAGE_1_TV.try_into().unwrap());

        let (_authenticator, _loc_w, voucher_request) = authenticator
            .process_ead_1(&ead_1, &MESSAGE_1_WITH_EAD_TV.try_into().unwrap())
            .unwrap();

        let voucher_response =
            server.handle_voucher_request(&mut default_crypto(), &voucher_request);
        assert_eq!(voucher_response.unwrap_err(), LAKEError::AccessDenied);
    }
}
