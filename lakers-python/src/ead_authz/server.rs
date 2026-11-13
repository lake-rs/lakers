use lakers::*;
use lakers_crypto::default_crypto;
use lakers_ead_authz::*;
use log::trace;
use pyo3::{prelude::*, types::PyBytes};

#[pyclass(name = "AuthzEnrollmentServer")]
pub struct PyAuthzEnrollmentServer {
    server: ZeroTouchServer,
}

#[pymethods]
impl PyAuthzEnrollmentServer {
    #[new]
    #[pyo3(signature = (w, cred_v, acl=None))]
    pub fn new(w: Vec<u8>, cred_v: Vec<u8>, acl: Option<Vec<u8>>) -> Self {
        trace!("Initializing AuthzEnrollmentServer");
        let mut w_arr = BytesP256ElemLen::default();
        w_arr.copy_from_slice(&w.as_slice());
        let acl = if let Some(acl) = acl {
            Some(LakeMessageBuffer::new_from_slice(acl.as_slice()).unwrap())
        } else {
            None
        };

        Self {
            server: ZeroTouchServer::new(w_arr, cred_v.as_slice(), acl),
        }
    }

    fn handle_voucher_request<'a>(
        &self,
        py: Python<'a>,
        vreq: Vec<u8>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let vreq = LakeMessageBuffer::new_from_slice(vreq.as_slice()).unwrap();
        match self
            .server
            .handle_voucher_request(&mut default_crypto(), &vreq)
        {
            Ok(voucher_response) => Ok(PyBytes::new(py, voucher_response.as_slice())),
            Err(error) => Err(error.into()),
        }
    }
}

#[pyclass(name = "AuthzServerUserAcl")]
pub struct PyAuthzServerUserAcl {
    server: ZeroTouchServerUserAcl,
}

#[pymethods]
impl PyAuthzServerUserAcl {
    #[new]
    pub fn new(w: Vec<u8>, cred_v: Vec<u8>) -> Self {
        trace!("Initializing AuthzServerUserAcl");
        let mut w_arr = BytesP256ElemLen::default();
        w_arr.copy_from_slice(&w.as_slice());

        Self {
            server: ZeroTouchServerUserAcl::new(w_arr, cred_v.as_slice()),
        }
    }

    fn decode_voucher_request<'a>(
        &self,
        py: Python<'a>,
        vreq: Vec<u8>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let vreq = LakeMessageBuffer::new_from_slice(vreq.as_slice()).unwrap();
        match self
            .server
            .decode_voucher_request(&mut default_crypto(), &vreq)
        {
            Ok(id_u) => Ok(PyBytes::new(py, id_u.as_slice())),
            Err(error) => Err(error.into()),
        }
    }

    fn prepare_voucher<'a>(&self, py: Python<'a>, vreq: Vec<u8>) -> PyResult<Bound<'a, PyBytes>> {
        let vreq = LakeMessageBuffer::new_from_slice(vreq.as_slice()).unwrap();
        match self.server.prepare_voucher(&mut default_crypto(), &vreq) {
            Ok(voucher_response) => Ok(PyBytes::new(py, voucher_response.as_slice())),
            Err(error) => Err(error.into()),
        }
    }
}
