use lakers::*;
use lakers_ead_authz::*;
use log::trace;
use pyo3::{
    prelude::*,
    types::{PyBytes, PyString},
};

#[pyclass(name = "AuthzAutenticator")]
pub struct PyAuthzAutenticator {
    authenticator: ZeroTouchAuthenticator,
    authenticator_wait: ZeroTouchAuthenticatorWaitVoucherResp,
}

#[pymethods]
impl PyAuthzAutenticator {
    #[new]
    fn new() -> Self {
        trace!("Initializing AuthzAutenticator");
        Self {
            authenticator: ZeroTouchAuthenticator::default(),
            authenticator_wait: ZeroTouchAuthenticatorWaitVoucherResp::default(),
        }
    }

    pub fn process_ead_1<'a>(
        &mut self,
        py: Python<'a>,
        ead_1: EADItem,
        message_1: Vec<u8>,
    ) -> PyResult<(Bound<'a, PyString>, Bound<'a, PyBytes>)> {
        let message_1 = LakeBuffer::new_from_slice(message_1.as_slice())?;
        let (state, loc_w, voucher_request) =
            self.authenticator.process_ead_1(&ead_1, &message_1)?;
        self.authenticator_wait = state;
        let loc_w = std::str::from_utf8(loc_w.as_slice()).unwrap();
        Ok((
            PyString::new(py, loc_w),
            PyBytes::new(py, voucher_request.as_slice()),
        ))
    }

    pub fn prepare_ead_2(&self, voucher_response: Vec<u8>) -> PyResult<EADItem> {
        let voucher_response = EdhocMessageBuffer::new_from_slice(voucher_response.as_slice())?;
        Ok(self.authenticator_wait.prepare_ead_2(&voucher_response)?)
    }
}
