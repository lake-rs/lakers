use crate::{EdhocBuffer, EdhocBufferError, MAX_PSK_LEN, MIN_PSK_LEN};

/// A pre-shared key for the EDHOC PSK method.
///
/// This wraps an [`EdhocBuffer`] rather than being an alias for one, so that the key material is
/// covered by two guarantees that a bare buffer cannot give:
///
/// * **It is at least [`MIN_PSK_LEN`] bytes long.** The only way to obtain a value of this type is
///   [`BufferPsk::new_from_slice`], which rejects anything shorter, so no code path can produce a
///   PSK with insufficient entropy.
/// * **It does not reveal the key material.** A derived `Debug` would let the key leak into logs
///   and panic messages, so `Debug` is implemented by hand and prints only a redaction marker. A
///   derived `PartialEq` would compare the key in non-constant time, leaking it through a timing
///   side channel, so it is not implemented at all. The inner buffer is private so that neither
///   can be reached through it. `Clone` *is* implemented: duplicating a key reveals nothing, it
///   only affects how many copies are in memory. Do not turn the other two into derives.
///
/// Note that this type does not yet erase the key material when it is dropped, so the key remains
/// readable in memory afterwards (in as many places as it was cloned into). See the TODO below.

// TODO: BufferPsk does not erase key material on drop, and Clone can leave multiple copies in memory.
// Fix with zeroize.
#[derive(Clone)]
#[repr(C)]
pub struct BufferPsk {
    inner: EdhocBuffer<MAX_PSK_LEN>,
}
impl BufferPsk {
    pub const fn new_from_slice(slice: &[u8]) -> Result<Self, EdhocBufferError> {
        if slice.len() < MIN_PSK_LEN {
            return Err(EdhocBufferError::SliceTooShort);
        }
        match EdhocBuffer::new_from_slice(slice) {
            Ok(inner) => Ok(Self { inner }),
            Err(e) => Err(e),
        }
    }
    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_slice()
    }
}

impl core::fmt::Debug for BufferPsk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BufferPsk(<redacted>)")
    }
}
