//! LAKE crypto backed by the [`embedded-cal`](embedded_cal) Cryptographic Abstraction Layer.
//!
//! [`Crypto`] is generic over any [`embedded_cal::Cal`] instance. This lets lakers use
//! hardware-accelerated crypto on microcontrollers that ship an embedded-cal backend (e.g.
//! nRF52840, nRF5340, nRF54L15, STM32WBA55), while falling back to a software `Cal` elsewhere. "Use
//! hardware if available" is expressed by *which concrete `Cal` the caller constructs*, not by cfg
//! flags here.
#![no_std]

use embedded_cal::Cal;

/// A [`Cal`] that forwards to another [`Cal`] instance, and can also be used by mutable reference.
///
/// Construct it with [`Crypto::new`], passing a fully-wired `Cal` (for hardware backends, typically
/// an `embedded_cal_software_demo::Extender` wrapping the hardware `Cal`, so that SHA-256, HMAC and
/// therefore HKDF are available on top of the hardware's raw primitives).
pub struct Crypto<C> {
    cal: C,
}

impl<C> Crypto<C> {
    /// Wraps an embedded-cal [`Cal`](embedded_cal::Cal) instance for use with lakers.
    pub const fn new(cal: C) -> Self {
        Self { cal }
    }
}

impl<C> core::fmt::Debug for Crypto<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("lakers_crypto_embedded_cal::Crypto")
            .field("cal", &core::any::type_name::<C>())
            .finish()
    }
}

impl<C: Cal> Cal for Crypto<C> {
    type DhProvider = C::DhProvider;
    type AeadProvider = C::AeadProvider;
    type HashProvider = C::HashProvider;
    type HmacProvider = C::HmacProvider;
    type SignProvider = C::SignProvider;

    fn dh(&mut self) -> &mut Self::DhProvider {
        self.cal.dh()
    }

    fn aead(&mut self) -> &mut Self::AeadProvider {
        self.cal.aead()
    }

    fn hash(&mut self) -> &mut Self::HashProvider {
        self.cal.hash()
    }

    fn hmac(&mut self) -> &mut Self::HmacProvider {
        self.cal.hmac()
    }

    fn sign(&mut self) -> &mut Self::SignProvider {
        self.cal.sign()
    }
}

// TODO: update if https://github.com/lake-rs/embedded-cal/pull/159 is merged
impl<C: Cal> Cal for &mut Crypto<C> {
    type DhProvider = C::DhProvider;
    type AeadProvider = C::AeadProvider;
    type HashProvider = C::HashProvider;
    type HmacProvider = C::HmacProvider;
    type SignProvider = C::SignProvider;

    fn dh(&mut self) -> &mut Self::DhProvider {
        self.cal.dh()
    }

    fn aead(&mut self) -> &mut Self::AeadProvider {
        self.cal.aead()
    }

    fn hash(&mut self) -> &mut Self::HashProvider {
        self.cal.hash()
    }

    fn hmac(&mut self) -> &mut Self::HmacProvider {
        self.cal.hmac()
    }

    fn sign(&mut self) -> &mut Self::SignProvider {
        self.cal.sign()
    }
}

impl<C: rand_core::TryRng> rand_core::TryRng for Crypto<C> {
    type Error = C::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.cal.try_next_u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.cal.try_next_u64()
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.cal.try_fill_bytes(dst)
    }
}

impl<C: rand_core::TryCryptoRng> rand_core::TryCryptoRng for Crypto<C> {}
