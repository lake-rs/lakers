use lakers::*;
use lakers_crypto::{default_crypto, CryptoTrait};
use log::trace;
use pyo3::{prelude::*, types::PyBytes};

use super::{ErrExt as _, StateMismatch};

/// An implementation of the EDHOC protocol for the initiator side.
#[pyclass(name = "EdhocInitiator")]
pub struct PyEdhocInitiator {
    cred_i: Option<Credential>,
    // FIXME: This does *not* get taken out, so some data stays available for longer than it needs
    // to be -- but that is apparently needed in selected_cipher_suite and
    // compute_ephemeral_secret.
    start: InitiatorStart,
    wait_m2: Option<WaitM2>,
    processing_m2: Option<ProcessingM2>,
    processed_m2: Option<ProcessedM2>,
    wait_m4: Option<WaitM4>,
    completed: Option<Completed>,
}

/// Summary of a [`PyEdhocInitiator`]'s state.
///
/// This is sorted along the typical (and, really, only) sequence of operations so that if the
/// expected state is greater than the current state, the user forgot to do something, whereas the
/// other way round, the user already did something and can't do that again.
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum PyEdhocInitiatorSummary {
    Start,
    WaitM2,
    ProcessingM2,
    ProcessedM2,
    WaitM4,
    Completed,
    /// This is the last item because there is always something that happened before this and that
    /// broke things.
    Invalid,
}

#[pymethods]
impl PyEdhocInitiator {
    #[new]
    fn new() -> Self {
        trace!("Initializing EdhocInitiator");
        let mut crypto = default_crypto();
        let suites_i =
            prepare_suites_i(&crypto.supported_suites(), EDHOCSuite::CipherSuite2.into()).unwrap();
        let (x, g_x) = crypto.p256_generate_key_pair();

        Self {
            cred_i: None,
            start: InitiatorStart {
                x,
                g_x,
                method: EDHOCMethod::StatStat,
                suites_i,
            },
            wait_m2: None,
            processing_m2: None,
            processed_m2: None,
            wait_m4: None,
            completed: None,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "<lakers.EdhocInitiator at {:p} in state {:?}>",
            self,
            self.summarize()
        )
    }

    /// Generates message 1.
    ///
    /// At this point, a ``C_I`` (connection identifier) may be provided, as well as additonal EAD
    /// data.
    #[pyo3(signature = (c_i=None, ead_1=EadItems::new()))]
    fn prepare_message_1<'a>(
        &mut self,
        py: Python<'a>,
        c_i: Option<Vec<u8>>,
        ead_1: EadItems,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let c_i = match c_i {
            Some(c_i) => ConnId::from_slice(c_i.as_slice())
                .with_cause(py, "Connection identifier C_I out of range")?,
            None => generate_connection_identifier_cbor(&mut default_crypto()),
        };
        let ead_1 = ead_1.try_into()?;

        let (state, message_1) =
            i_prepare_message_1(&self.start, &mut default_crypto(), c_i, &ead_1)?;
        self.wait_m2 = Some(state);
        Ok(PyBytes::new(py, message_1.as_slice()))
    }

    /// Process message 2.
    ///
    /// This produces both the ``C_R`` and the ``ID_CRED_R``, and maybe additional EAD data sent by
    /// the responder, but does not verify them yet: They are only verified when the application
    /// provides the expanded credential ``CRED_R`` (typically based on the information in
    /// ``ID_CRED_R``) in :meth:`.verify_message_2()`.
    pub fn parse_message_2<'a>(
        &mut self,
        py: Python<'a>,
        message_2: Vec<u8>,
    ) -> PyResult<(Bound<'a, PyBytes>, Bound<'a, PyBytes>, EadItems)> {
        let message_2 = EdhocMessageBuffer::new_from_slice(message_2.as_slice())
            .with_cause(py, "Message 2 too long")?;

        let (state, c_r, details) =
            i_parse_message_2(&self.take_wait_m2()?, &mut default_crypto(), &message_2)?;
        let (id_cred_r, ead_2) = match details {
            ParsedMessage2Details::StatStat { id_cred_r, ead_2 } => (id_cred_r, ead_2),
            // ParsedMessage2Details::Psk { ead_2 } => (IdCred::new(), ead_2),
        };
        self.processing_m2 = Some(state);
        Ok((
            PyBytes::new(py, c_r.as_slice()),
            PyBytes::new(py, id_cred_r.bytes.as_slice()),
            ead_2,
        ))
    }

    /// Verifies the previously inserted message 2.
    ///
    /// At this point, the initiator's private key ``I`` as well as the initiator's identity ``CRED_I``
    /// needs to be provided, as well as the peer's credential ``CRED_R`` (as looked up by its
    /// ``ID_CRED_R`` from the preceeding :meth:`parse_message_2()` output).
    pub fn verify_message_2(
        &mut self,
        py: Python<'_>,
        i: Vec<u8>,
        cred_i: super::AutoCredential,
        valid_cred_r: super::AutoCredential,
    ) -> PyResult<()> {
        let cred_i = cred_i
            .to_credential()
            .with_cause(py, "Failed to ingest CRED_I")?;
        let valid_cred_r = valid_cred_r
            .to_credential()
            .with_cause(py, "Failed to ingest CRED_R")?;

        let state = i_verify_message_2(
            &self.take_processing_m2()?,
            &mut default_crypto(),
            valid_cred_r,
            Some(
                i.as_slice()
                    .try_into()
                    .expect("Wrong length of initiator private key"),
            ),
        )?;
        self.processed_m2 = Some(state);
        self.cred_i = Some(cred_i);
        Ok(())
    }

    /// Generates a message 3.
    ///
    /// Input influences whether the credential previously provided in :meth:`verify_message_2()` is
    /// sent by value or reference, and whether any additional EAD data is to be sent.
    #[pyo3(signature = (cred_transfer, ead_3=EadItems::new()))]
    pub fn prepare_message_3<'a>(
        &mut self,
        py: Python<'a>,
        cred_transfer: CredentialTransfer,
        ead_3: EadItems,
    ) -> PyResult<(Bound<'a, PyBytes>, Bound<'a, PyBytes>)> {
        let ead_3 = ead_3.try_into()?;
        let (state, message_3, prk_out) = i_prepare_message_3(
            &mut self.take_processed_m2()?,
            &mut default_crypto(),
            // FIXME: take as reference rather than cloning
            self.cred_i.as_ref().unwrap().clone(),
            cred_transfer,
            &ead_3,
        )?;
        self.wait_m4 = Some(state);
        Ok((
            PyBytes::new(py, message_3.as_slice()),
            PyBytes::new(py, prk_out.as_slice()),
        ))
    }

    /// Declares the protocol to have completed without the need of a message 4.
    ///
    /// Key material can be extracted after this point, but some properties of the protocol only
    /// hold when non-EDHOC messages protected with the extracted key material are received from
    /// the peer.
    pub fn completed_without_message_4<'a>(&mut self) -> PyResult<()> {
        let state = i_complete_without_message_4(&self.take_wait_m4()?)?;
        self.completed = Some(state);
        Ok(())
    }

    /// Processes and verifies message 4.
    ///
    /// This produces EAD data if the peer sent any.
    pub fn process_message_4<'a>(
        &mut self,
        py: Python<'a>,
        message_4: Vec<u8>,
    ) -> PyResult<EadItems> {
        let message_4 = EdhocMessageBuffer::new_from_slice(message_4.as_slice())
            .with_cause(py, "Message 4 too long")?;
        let (state, ead_4) =
            i_process_message_4(&mut self.take_wait_m4()?, &mut default_crypto(), &message_4)?;
        self.completed = Some(state);
        Ok(ead_4)
    }

    /// Exports key material.
    pub fn edhoc_exporter<'a>(
        &mut self,
        py: Python<'a>,
        label: u8,
        context: Vec<u8>,
        length: usize,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let completed = self.as_mut_completed()?;
        PyBytes::new_with(py, length, |output| {
            Ok(edhoc_exporter(
                completed,
                &mut default_crypto(),
                label,
                context.as_slice(),
                output,
            ))
        })
    }

    /// Performs the key update procedure, enabling the production of new key material.
    pub fn edhoc_key_update<'a>(
        &mut self,
        py: Python<'a>,
        context: Vec<u8>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let res = edhoc_key_update(
            self.as_mut_completed()?,
            &mut default_crypto(),
            context.as_slice(),
        );
        Ok(PyBytes::new(py, &res[..SHA256_DIGEST_LEN]))
    }

    pub fn get_h_message_1<'a>(&self, py: Python<'a>) -> PyResult<Bound<'a, PyBytes>> {
        Ok(PyBytes::new(py, &self.as_ref_wait_m2()?.h_message_1[..]))
    }

    pub fn compute_ephemeral_secret<'a>(
        &self,
        py: Python<'a>,
        g_a: Vec<u8>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let mut g_a_arr = BytesP256ElemLen::default();
        g_a_arr.copy_from_slice(&g_a[..]);
        let secret = default_crypto().p256_ecdh(&self.start.x, &g_a_arr);
        Ok(PyBytes::new(py, &secret[..]))
    }

    /// The cipher suite that is agreed on by the exchange.
    pub fn selected_cipher_suite(&self) -> PyResult<u8> {
        Ok(self.start.suites_i[self.start.suites_i.len() - 1])
    }
}

/// Tools for generating useful and readable reprs and errors.
///
/// See [`StateMismatch`] for some more context.
impl PyEdhocInitiator {
    fn summarize(&self) -> PyEdhocInitiatorSummary {
        let wait_m2 = self.wait_m2.is_some();
        let processing_m2 = self.processing_m2.is_some();
        let processed_m2 = self.processed_m2.is_some();
        let wait_m4 = self.wait_m4.is_some();
        let completed = self.completed.is_some();
        match (wait_m2, processing_m2, processed_m2, wait_m4, completed) {
            (false, false, false, false, false) => PyEdhocInitiatorSummary::Start,
            (true, false, false, false, false) => PyEdhocInitiatorSummary::WaitM2,
            (false, true, false, false, false) => PyEdhocInitiatorSummary::ProcessingM2,
            (false, false, true, false, false) => PyEdhocInitiatorSummary::ProcessedM2,
            (false, false, false, true, false) => PyEdhocInitiatorSummary::WaitM4,
            (false, false, false, false, true) => PyEdhocInitiatorSummary::Completed,
            _ => PyEdhocInitiatorSummary::Invalid,
        }
    }

    // FIXME: Those should be generated, or the PyEdhocInitiator type changed to something more
    // annotated-enum-ish

    fn take_wait_m2(&mut self) -> Result<WaitM2, StateMismatch<PyEdhocInitiatorSummary>> {
        let summary = self.summarize();
        match self.wait_m2.take() {
            Some(o) => Ok(o),
            None => Err(StateMismatch::new(PyEdhocInitiatorSummary::WaitM2, summary)),
        }
    }

    fn as_ref_wait_m2(&self) -> Result<&WaitM2, StateMismatch<PyEdhocInitiatorSummary>> {
        let summary = self.summarize();
        match self.wait_m2.as_ref() {
            Some(o) => Ok(o),
            None => Err(StateMismatch::new(PyEdhocInitiatorSummary::WaitM2, summary)),
        }
    }

    fn take_processing_m2(
        &mut self,
    ) -> Result<ProcessingM2, StateMismatch<PyEdhocInitiatorSummary>> {
        let summary = self.summarize();
        match self.processing_m2.take() {
            Some(o) => Ok(o),
            None => Err(StateMismatch::new(
                PyEdhocInitiatorSummary::ProcessingM2,
                summary,
            )),
        }
    }

    fn take_processed_m2(&mut self) -> Result<ProcessedM2, StateMismatch<PyEdhocInitiatorSummary>> {
        let summary = self.summarize();
        match self.processed_m2.take() {
            Some(o) => Ok(o),
            None => Err(StateMismatch::new(
                PyEdhocInitiatorSummary::ProcessedM2,
                summary,
            )),
        }
    }

    fn take_wait_m4(&mut self) -> Result<WaitM4, StateMismatch<PyEdhocInitiatorSummary>> {
        let summary = self.summarize();
        match self.wait_m4.take() {
            Some(o) => Ok(o),
            None => Err(StateMismatch::new(PyEdhocInitiatorSummary::WaitM4, summary)),
        }
    }

    fn as_mut_completed(
        &mut self,
    ) -> Result<&mut Completed, StateMismatch<PyEdhocInitiatorSummary>> {
        let summary = self.summarize();
        match self.completed.as_mut() {
            Some(o) => Ok(o),
            None => Err(StateMismatch::new(
                PyEdhocInitiatorSummary::Completed,
                summary,
            )),
        }
    }
}
