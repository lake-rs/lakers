//! EDHOC crypto backend backed by the [`embedded-cal`](embedded_cal) Cryptographic Abstraction
//! Layer.
//!
//! [`Crypto`] is generic over any [`embedded_cal::Cal`] instance. This lets lakers use
//! hardware-accelerated crypto on microcontrollers that ship an embedded-cal backend (e.g.
//! nRF54L15, STM32WBA55), while falling back to a software `Cal` elsewhere. "Use hardware if
//! available" is expressed by *which concrete `Cal` the caller constructs*, not by cfg flags here.
#![cfg_attr(not(test), no_std)]

/// A [`lakers_shared::Crypto`] implementation that forwards to an embedded-cal [`Cal`] instance.
///
/// Construct it with [`Crypto::new`], passing a fully-wired `Cal` (for hardware backends, typically
/// an `embedded_cal_software_demo::Extender` wrapping the hardware `Cal`, so that SHA-256, HMAC and
/// therefore HKDF are available on top of the hardware's raw primitives).
pub struct Crypto<C> {
    cal: C,
}

impl<C> Crypto<C> {
    /// Wraps an embedded-cal [`Cal`](embedded_cal::Cal) instance as a lakers crypto backend.
    pub const fn new(cal: C) -> Self {
        Self { cal }
    }
}

// Hand-written so we do not require `C: Debug`; most `Cal` types do not implement it, but the
// `lakers_shared::Crypto` trait requires the backend to be `Debug`.
impl<C> core::fmt::Debug for Crypto<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("lakers_crypto_embedded_cal::Crypto")
            .field("cal", &core::any::type_name::<C>())
            .finish()
    }
}
