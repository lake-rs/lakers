use lakers::*;
use lakers_crypto::default_crypto;
use lakers_ead_authz::*;
use log::trace;
use pyo3::{exceptions::PyBaseException, prelude::*, types::PyBytes};

#[pyclass(name = "AuthzDevice")]
pub struct PyAuthzDevice {
    device: ZeroTouchDevice,
    device_wait: ZeroTouchDeviceWaitEAD2,
    device_done: ZeroTouchDeviceDone,
}

#[pymethods]
impl PyAuthzDevice {
    #[new]
    fn new(id_u: Vec<u8>, g_w: Vec<u8>, loc_w: &str) -> Self {
        trace!("Initializing AuthzDevice");
        let id_u = LakeMessageBuffer::new_from_slice(id_u.as_slice()).unwrap();
        let loc_w = LakeMessageBuffer::new_from_slice(loc_w.as_bytes()).unwrap();
        let mut g_w_arr = BytesP256ElemLen::default();
        g_w_arr.copy_from_slice(&g_w[..]);
        Self {
            device: ZeroTouchDevice {
                id_u,
                g_w: g_w_arr,
                loc_w,
            },
            device_wait: ZeroTouchDeviceWaitEAD2::default(),
            device_done: ZeroTouchDeviceDone::default(),
        }
    }

    pub fn prepare_ead_1(&mut self, secret: Vec<u8>, ss: u8) -> PyResult<EADItem> {
        let mut secret_arr = BytesP256ElemLen::default();
        secret_arr.copy_from_slice(&secret[..]);
        let (device_wait, ead_1) = self
            .device
            .prepare_ead_1(&mut default_crypto(), secret_arr, ss);
        self.device_wait = device_wait;
        Ok(ead_1)
    }

    pub fn process_ead_2(&mut self, ead_2: &EADItem, cred_v: &[u8]) -> PyResult<bool> {
        match self
            .device_wait
            .process_ead_2(&mut default_crypto(), ead_2, cred_v)
        {
            Ok(device_done) => {
                self.device_done = device_done;
                Ok(true)
            }
            Err(error) => Err(PyBaseException::new_err(error as i8)),
        }
    }

    pub fn set_h_message_1(&mut self, h_message_1: Vec<u8>) {
        let mut h_message_1_arr = BytesHashLen::default();
        h_message_1_arr.copy_from_slice(&h_message_1[..]);
        self.device_wait.set_h_message_1(h_message_1_arr);
    }

    pub fn get_g_w<'a>(&self, py: Python<'a>) -> PyResult<Bound<'a, PyBytes>> {
        Ok(PyBytes::new(py, &self.device.g_w[..]))
    }
}
