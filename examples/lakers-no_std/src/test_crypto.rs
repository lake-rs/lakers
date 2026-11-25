use core::convert::Infallible;
use core::sync::atomic::{AtomicU32, Ordering};

use embedded_cal::empty::EmptyCal;
use embedded_cal_rand::WithRng;
use embedded_cal_rustcrypto::RustcryptoCalExtender;
pub use lakers::CryptoTrait;

static STATE: AtomicU32 = AtomicU32::new(0x2545_f491);

/// Predictable numbers for running the tests on targets without an entropy source.
///
/// Never use this outside of tests: every key generated from it is known to everyone.
pub struct TestRng;

impl rand_core::TryRng for TestRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut x = STATE.load(Ordering::Relaxed);
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        STATE.store(x, Ordering::Relaxed);
        Ok(x)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok((u64::from(self.try_next_u32()?) << 32) | u64::from(self.try_next_u32()?))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(4) {
            chunk.copy_from_slice(&self.try_next_u32()?.to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for TestRng {}

pub type TestCal = RustcryptoCalExtender<WithRng<EmptyCal, TestRng>>;

pub fn default_crypto() -> lakers_crypto_embedded_cal::Crypto<TestCal> {
    lakers_crypto_embedded_cal::Crypto::new(RustcryptoCalExtender::new_extending(WithRng::new(
        EmptyCal, TestRng,
    )))
}
