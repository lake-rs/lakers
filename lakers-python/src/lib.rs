/// This file implements the python bindings for the lakers library.
/// Note that this module is not restricted by no_std.
use lakers::*;
// use lakers_ead_authz::consts::*;
use lakers_crypto::{default_crypto, CryptoTrait};
use pyo3::wrap_pyfunction;
use pyo3::{prelude::*, types::PyBytes};

mod ead_authz;
mod initiator;
mod responder;

/// Error raised when operations on a Python object did not happen in the sequence in which they
/// were intended.
///
/// This carries data purely for the purpose of guiding the user towards an understanding of how
/// things went wrong; for less powerful error reporting, this could be a ZSTs, and all its
/// constructors, the `.summarize()` methods and the detailed `.take_…()`/`.as_ref_…()` methods
/// could be plain `.take()`/`.as_ref()` on their fields.
#[derive(Debug)]
pub(crate) struct StateMismatch<S> {
    expected: S,
    found: S,
}

impl<S> StateMismatch<S> {
    pub(crate) fn new(expected: S, found: S) -> Self {
        Self { expected, found }
    }
}

trait ErrExt {
    type T;
    fn with_cause(self, py: Python<'_>, cause: &str) -> Result<Self::T, PyErr>;
}

impl<T> ErrExt for Option<T> {
    type T = T;
    fn with_cause(self, _py: Python<'_>, cause: &str) -> Result<T, PyErr> {
        self.ok_or_else(|| pyo3::exceptions::PyValueError::new_err(format!("{}", cause)))
    }
}

impl<T, E: core::fmt::Display> ErrExt for Result<T, E> {
    type T = T;
    fn with_cause(self, _py: Python<'_>, cause: &str) -> Result<T, PyErr> {
        self.map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{} ({})", cause, e)))
    }
}

impl<S: Ord + core::fmt::Debug> std::error::Error for StateMismatch<S> {}
impl<S: Ord + core::fmt::Debug> std::fmt::Display for StateMismatch<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.expected < self.found {
            write!(
                f,
                "State machine has progressed beyond expected {:?}, is already at {:?}",
                self.expected, self.found
            )
        } else {
            write!(f, "State machine is just at {:?}, but this operation requires it to have progressed to {:?}", self.found, self.expected)
        }
    }
}
impl<S: Ord + core::fmt::Debug> From<StateMismatch<S>> for PyErr {
    #[track_caller]
    fn from(err: StateMismatch<S>) -> PyErr {
        let location = std::panic::Location::caller();
        // It would be nice to inject something more idiomatic on the Python side, eg. setting a
        // cause with a Rust file and line number, but to create such an object we'd need the GIL,
        // and that'd required doing a lot of things custom, eg. by creating a custom class where
        // we pass that extra info in extra arguments, or re-implementing PyErr's lazy state (which
        // we can't hook into because that's private) -- having the location in the text is the
        // second best option.
        pyo3::exceptions::PyRuntimeError::new_err(format!("{} (internally {})", err, location))
    }
}

// NOTE: throughout this implementation, we use Vec<u8> for incoming byte lists and PyBytes for outgoing byte lists.
// This is because the incoming lists of bytes are automatically converted to `Vec<u8>` by pyo3,
// but the outgoing ones must be explicitly converted to `PyBytes`.

// NOTE: using inverted parameters from rust version (credential_check_or_fetch)
// since, in Python, parameters that can be None come later
#[pyfunction(name = "credential_check_or_fetch")]
#[pyo3(signature = (id_cred_received, cred_expected=None))]
pub fn py_credential_check_or_fetch<'a>(
    py: Python<'a>,
    id_cred_received: Vec<u8>,
    cred_expected: Option<AutoCredential>,
) -> PyResult<Bound<'a, PyBytes>> {
    let cred_expected = cred_expected.map(|c| c.to_public()).transpose()?;
    let valid_cred = credential_check_or_fetch(
        cred_expected,
        IdCred::from_full_value(id_cred_received.as_slice())?,
    )?;

    Ok(PyBytes::new(py, valid_cred.bytes.as_slice()))
}

/// this function is useful to test the python bindings
#[pyfunction]
fn p256_generate_key_pair<'a>(
    py: Python<'a>,
) -> PyResult<(Bound<'a, PyBytes>, Bound<'a, PyBytes>)> {
    let (x, g_x) = default_crypto().p256_generate_key_pair();
    Ok((
        PyBytes::new(py, x.as_slice()),
        PyBytes::new(py, g_x.as_slice()),
    ))
}

/// Helper for PyO3 converted functions that take a credential argument.
///
/// The resulting function accepts either a bytes-ish object, parsed as a CCS according to what the
/// call site asks for, or a [`PublicCredential`] the caller already holds. There is no variant for
/// an existing [`PskCredential`]: that class exposes no constructor to Python yet, so Python cannot
/// hold one.
///
/// The `annotation` strings appear in the `TypeError` Python sees when an argument matches no
/// variant, so they name the Python-visible types.
#[derive(FromPyObject)]
pub enum AutoCredential {
    #[pyo3(transparent, annotation = "bytes")]
    Parse(Vec<u8>),
    #[pyo3(transparent, annotation = "PublicCredential")]
    ExistingPublic(PublicCredential),
}

impl AutoCredential {
    /// Resolve to a credential carrying an asymmetric public key.
    pub fn to_public(self) -> Result<PublicCredential, EDHOCError> {
        use AutoCredential::*;
        Ok(match self {
            ExistingPublic(e) => e,
            Parse(v) => PublicCredential::parse_ccs(v.as_slice())?,
        })
    }

    /// Resolve to a credential carrying a pre-shared key.
    ///
    /// Only bytes can produce one, since Python cannot construct a [`PskCredential`]. A credential
    /// object passed here is a public one: well-formed, but the wrong kind.
    pub fn to_psk(self) -> Result<PskCredential, EDHOCError> {
        use AutoCredential::*;
        Ok(match self {
            Parse(v) => PskCredential::parse_ccs(v.as_slice())?,
            ExistingPublic(_) => return Err(EDHOCError::WrongCredentialType),
        })
    }
}

/// Build the credential expected of the peer, parsed according to the negotiated EDHOC method.
///
/// The same Python API accepts both stat-stat CCS credentials and PSK CCS credentials, so the
/// method decides which parser runs and which [`PeerCredential`] variant results. Call sites that
/// need their *own* credential, to build an identity, use [`AutoCredential::to_public`] or
/// [`AutoCredential::to_psk`] instead: they want the concrete type rather than this enum.
pub(crate) fn parse_peer_credential(
    method: EDHOCMethod,
    credential: AutoCredential,
) -> Result<PeerCredential, EDHOCError> {
    Ok(match method {
        EDHOCMethod::StatStat => PeerCredential::StatStat(Some(credential.to_public()?)),
        EDHOCMethod::PSK => PeerCredential::Psk(credential.to_psk()?),
        _ => return Err(EDHOCError::UnsupportedMethod),
    })
}

/// The :class:`EdhocInitiator` and :class:`EdhocResponder` are entry points to this module. Both
/// provided classes that represent one side of the EDHOC exchange, and are updated with and
/// produce messages and information through a series of method calls on the object.
///
/// Operations in this module produce logging entries on the ``lakers.initiator`` and
/// ``lakers.responder`` logger names. Due to implementation details of ``pyo3_log``, Python's log
/// levels are cached in the Rust implementation. It is recommended that the full logging
/// is configured before creating Lakers objects. A setup with ``logging.basicConfig(loglevel=5)``
/// will also show Lakers' trace level log messages, which have no equivalent Python level.
#[pymodule]
// this name must match `lib.name` in `Cargo.toml`
#[pyo3(name = "lakers")]
fn lakers_python(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // initialize the logger once when the module is imported
    if let Err(e) = pyo3_log::Logger::new(py, pyo3_log::Caching::LoggersAndLevels)?
        .filter(log::LevelFilter::Trace)
        .install()
    {
        // Not logging anything in the successful case (see module level docs)
        log::error!("lakers-python failed to set up: {e}");
    }

    m.add_function(wrap_pyfunction!(p256_generate_key_pair, m)?)?;
    m.add_function(wrap_pyfunction!(py_credential_check_or_fetch, m)?)?;
    // edhoc items
    m.add_class::<initiator::PyEdhocInitiator>()?;
    m.add_class::<responder::PyEdhocResponder>()?;
    m.add_class::<lakers::CredentialTransfer>()?;
    m.add_class::<lakers::EADItem>()?;
    m.add_class::<lakers::PublicCredential>()?;
    // ead-authz items
    m.add_class::<ead_authz::PyAuthzDevice>()?;
    m.add_class::<ead_authz::PyAuthzAutenticator>()?;
    m.add_class::<ead_authz::PyAuthzEnrollmentServer>()?;
    m.add_class::<ead_authz::PyAuthzServerUserAcl>()?;

    let submodule = PyModule::new(py, "consts")?;
    submodule.add("EAD_AUTHZ_LABEL", lakers_ead_authz::consts::EAD_AUTHZ_LABEL)?;
    m.add_submodule(&submodule)?;
    Ok(())
}
