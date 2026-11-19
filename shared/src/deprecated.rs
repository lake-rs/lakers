use crate::*;

#[deprecated(since = "0.9.0", note = "renamed to `LakeBuffer`")]
pub type EdhocBuffer<const N: usize> = LakeBuffer<N>;

#[deprecated(since = "0.9.0", note = "renamed to `LakeBufferError`")]
pub type EdhocBufferError = LakeBufferError;

#[deprecated(since = "0.9.0", note = "renamed to `LakeMessageBuffer`")]
pub type EdhocMessageBuffer = LakeMessageBuffer;

#[deprecated(since = "0.9.0", note = "renamed to `LAKEError`")]
pub type EDHOCError = LAKEError;

#[deprecated(since = "0.9.0", note = "renamed to `LAKEMethod`")]
pub type EDHOCMethod = LAKEMethod;

#[deprecated(since = "0.9.0", note = "renamed to `LAKESuite`")]
pub type EDHOCSuite = LAKESuite;

#[deprecated(since = "0.9.0", note = "renamed to `LAKE_METHOD`")]
pub const EDHOC_METHOD: u8 = LAKE_METHOD;

#[deprecated(since = "0.9.0", note = "renamed to `LAKE_SUITES`")]
pub const EDHOC_SUITES: BytesSuites = LAKE_SUITES;

#[deprecated(since = "0.9.0", note = "renamed to `LAKE_SUPPORTED_SUITES`")]
pub const EDHOC_SUPPORTED_SUITES: BytesSupportedSuites = LAKE_SUPPORTED_SUITES;
