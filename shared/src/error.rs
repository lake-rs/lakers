use core::num::NonZeroI16;
#[derive(PartialEq, Debug)]
#[non_exhaustive]
pub enum EDHOCError {
    /// In an exchange, a credential was set as "expected", but the credential configured by the
    /// peer did not match what was presented. This is more an application internal than an EDHOC
    /// error: When the application sets the expected credential, that process should be informed
    /// by the known details.
    UnexpectedCredential,
    MissingIdentity,
    IdentityAlreadySet,
    MacVerificationFailed,
    UnsupportedMethod,
    UnsupportedCipherSuite,
    ParsingError,
    EncodingError,
    CredentialTooLongError,
    EadLabelTooLongError,
    EadTooLongError,
    /// An EAD was received that was either not known (and critical), or not understood, or
    /// otherwise erroneous.
    EADUnprocessable,
    /// The credential or EADs could be processed (possibly by a third party), but the decision
    /// based on that was to not to continue the EDHOC session.
    ///
    /// See also
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-lake-authz#name-edhoc-error-access-denied>
    AccessDenied,
}

impl EDHOCError {
    /// The ERR_CODE corresponding to the error
    ///
    /// Errors that refer to internal limitations (such as EadTooLongError) are treated the same
    /// way as parsing errors, and return an unspecified error: Those are equivalent to limitations
    /// of the parser, and a constrained system can not be expected to differentiate between "the
    /// standard allows this but my number space is too small" and "this violates the standard".
    ///
    /// If an EDHOCError is returned through EDHOC, it will use this in its EDHOC error message.
    ///
    /// Note that this on its own is insufficient to create an error message: Additional ERR_INFO
    /// is needed, which may or may not be available with the EDHOCError alone.
    ///
    /// TODO: Evolve the EDHOCError type such that all information needed is available.
    pub fn err_code(&self) -> ErrCode {
        use EDHOCError::*;
        match self {
            UnexpectedCredential => ErrCode::UNSPECIFIED,
            MissingIdentity => ErrCode::UNSPECIFIED,
            IdentityAlreadySet => ErrCode::UNSPECIFIED,
            MacVerificationFailed => ErrCode::UNSPECIFIED,
            UnsupportedMethod => ErrCode::UNSPECIFIED,
            UnsupportedCipherSuite => ErrCode::WRONG_SELECTED_CIPHER_SUITE,
            ParsingError => ErrCode::UNSPECIFIED,
            EncodingError => ErrCode::UNSPECIFIED,
            CredentialTooLongError => ErrCode::UNSPECIFIED,
            EadLabelTooLongError => ErrCode::UNSPECIFIED,
            EadTooLongError => ErrCode::UNSPECIFIED,
            EADUnprocessable => ErrCode::UNSPECIFIED,
            AccessDenied => ErrCode::ACCESS_DENIED,
        }
    }
}

/// Representation of an EDHOC ERR_CODE
#[repr(C)]
pub struct ErrCode(pub NonZeroI16);

impl ErrCode {
    pub const UNSPECIFIED: Self = ErrCode(NonZeroI16::new(1).unwrap());
    pub const WRONG_SELECTED_CIPHER_SUITE: Self = ErrCode(NonZeroI16::new(2).unwrap());
    pub const UNKNOWN_CREDENTIAL: Self = ErrCode(NonZeroI16::new(3).unwrap());
    // Code requested in https://datatracker.ietf.org/doc/html/draft-ietf-lake-authz
    pub const ACCESS_DENIED: Self = ErrCode(NonZeroI16::new(3333).unwrap());
}
