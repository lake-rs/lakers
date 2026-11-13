use crate::*;

#[deprecated(since = "0.9.0", note = "renamed to `LakeInitiator`")]
pub type EdhocInitiator<Crypto> = LakeInitiator<Crypto>;

#[deprecated(since = "0.9.0", note = "renamed to `LakeInitiatorWaitM2`")]
pub type EdhocInitiatorWaitM2<Crypto> = LakeInitiatorWaitM2<Crypto>;

#[deprecated(since = "0.9.0", note = "renamed to `LakeInitiatorProcessingM2`")]
pub type EdhocInitiatorProcessingM2<Crypto> = LakeInitiatorProcessingM2<Crypto>;

#[deprecated(since = "0.9.0", note = "renamed to `LakeInitiatorProcessedM2`")]
pub type EdhocInitiatorProcessedM2<Crypto> = LakeInitiatorProcessedM2<Crypto>;

#[deprecated(since = "0.9.0", note = "renamed to `LakeInitiatorWaitM4`")]
pub type EdhocInitiatorWaitM4<Crypto> = LakeInitiatorWaitM4<Crypto>;

#[deprecated(since = "0.9.0", note = "renamed to `LakeInitiatorDone`")]
pub type EdhocInitiatorDone<Crypto> = LakeInitiatorDone<Crypto>;

#[deprecated(since = "0.9.0", note = "renamed to `LakeResponder`")]
pub type EdhocResponder<Crypto> = LakeResponder<Crypto>;

#[deprecated(since = "0.9.0", note = "renamed to `LakeResponderProcessedM1`")]
pub type EdhocResponderProcessedM1<Crypto> = LakeResponderProcessedM1<Crypto>;

#[deprecated(since = "0.9.0", note = "renamed to `LakeResponderWaitM3`")]
pub type EdhocResponderWaitM3<Crypto> = LakeResponderWaitM3<Crypto>;

#[deprecated(since = "0.9.0", note = "renamed to `LakeResponderProcessingM3`")]
pub type EdhocResponderProcessingM3<Crypto> = LakeResponderProcessingM3<Crypto>;

#[deprecated(since = "0.9.0", note = "renamed to `LakeResponderProcessedM3`")]
pub type EdhocResponderProcessedM3<Crypto> = LakeResponderProcessedM3<Crypto>;

#[deprecated(since = "0.9.0", note = "renamed to `LakeResponderDone`")]
pub type EdhocResponderDone<Crypto> = LakeResponderDone<Crypto>;

#[deprecated(since = "0.9.0", note = "renamed to `lake_exporter`")]
pub fn edhoc_exporter(
    state: &Completed,
    crypto: &mut impl CryptoTrait,
    label: u8,
    context: &[u8],
    result: &mut [u8],
) {
    lake_exporter(state, crypto, label, context, result)
}

#[deprecated(since = "0.9.0", note = "renamed to `lake_key_update`")]
pub fn edhoc_key_update(
    state: &mut Completed,
    crypto: &mut impl CryptoTrait,
    context: &[u8],
) -> BytesHashLen {
    lake_key_update(state, crypto, context)
}

impl<Crypto: CryptoTrait> LakeInitiatorDone<Crypto> {
    #[deprecated(since = "0.9.0", note = "renamed to `lake_exporter`")]
    pub fn edhoc_exporter(&mut self, label: u8, context: &[u8], result: &mut [u8]) {
        self.lake_exporter(label, context, result)
    }

    #[deprecated(since = "0.9.0", note = "renamed to `lake_key_update`")]
    pub fn edhoc_key_update(&mut self, context: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
        self.lake_key_update(context)
    }
}

impl<Crypto: CryptoTrait> LakeResponderDone<Crypto> {
    #[deprecated(since = "0.9.0", note = "renamed to `lake_exporter`")]
    pub fn edhoc_exporter(&mut self, label: u8, context: &[u8], result: &mut [u8]) {
        self.lake_exporter(label, context, result)
    }

    #[deprecated(since = "0.9.0", note = "renamed to `lake_key_update`")]
    pub fn edhoc_key_update(&mut self, context: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
        self.lake_key_update(context)
    }
}
