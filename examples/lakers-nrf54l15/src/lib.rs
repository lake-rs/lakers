#![no_std]

//! Shared support code for the nRF54L15 EDHOC example
//! As of today is no `embassy-nrf` BLE driver for the nRF54L15
//! So re are rolling our own to test the handshake with another board (nRF54L15 and nRF52840)

use core::sync::atomic::{compiler_fence, Ordering};

use hexlit::hex;
use nrf_pac::radio::vals::{Crcstatus, Endian, Len, Mode, Plen, Skipaddr, Txpower};

pub const MAX_PDU: usize = 258;
pub const FREQ: u32 = 2408;
pub const ADV_ADDRESS: u32 = 0x12345678;
pub const ADV_CRC_INIT: u32 = 0xffff;
pub const CRC_POLY: u32 = 0x00065b;

pub const CRED_I: &[u8] = &hex!("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
pub const I: &[u8] = &hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
pub const R: &[u8] = &hex!("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");
pub const CRED_R: &[u8] = &hex!("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");

/// Builds the hardware `Crypto`: the nRF54L15 `Cal` (hardware AEAD / DH / RNG + raw SHA-2 plumbing)
/// wrapped in the software `Extender` that adds the high-level SHA-256 / HMAC / HKDF layer.
///
/// The nRF54L15 has a single CRACEN, so only one hardware `Crypto` may be alive at a time. Each of
/// the two binaries drives only one EDHOC party, so this is called once per handshake.
pub fn hardware_crypto() -> lakers_crypto::Crypto {
    let cal = embedded_cal_software_demo::Extender::<lakers_crypto::Nrf54l15ExtConfig>::new(
        embedded_cal_nrf54l15::Nrf54l15Cal::new(nrf_pac::CRACEN_S, nrf_pac::CRACENCORE_S),
    );
    lakers_crypto::Crypto::new(cal)
}

#[derive(Debug)]
pub enum PacketError {
    SliceTooLong,
    SliceTooShort,
    ParsingError,
    TimeoutError,
    RadioError,
}

pub struct Packet {
    // total length that gets transmitted over the air, equals length of pdu + 1, for pdu_header
    pub len: usize,
    // 1-byte application-level header, used for filtering the packets
    pub pdu_header: Option<u8>,
    // application-level payload
    pub pdu: [u8; MAX_PDU],
}

impl Default for Packet {
    fn default() -> Self {
        Packet {
            len: 0,
            pdu_header: None,
            pdu: [0u8; MAX_PDU],
        }
    }
}

impl Packet {
    pub fn new() -> Self {
        Packet {
            len: 0,
            pdu_header: None,
            pdu: [0u8; MAX_PDU],
        }
    }

    pub fn new_from_slice(slice: &[u8], header: Option<u8>) -> Result<Self, PacketError> {
        let mut buffer = Self::new();
        if buffer.fill_with_slice(slice, header).is_ok() {
            Ok(buffer)
        } else {
            Err(PacketError::SliceTooLong)
        }
    }

    pub fn fill_with_slice(&mut self, slice: &[u8], header: Option<u8>) -> Result<(), PacketError> {
        if slice.len() <= self.pdu.len() {
            self.len = slice.len();
            self.pdu_header = header;
            self.pdu[..self.len].copy_from_slice(slice);
            Ok(())
        } else {
            Err(PacketError::SliceTooLong)
        }
    }

    pub fn as_bytes(&mut self) -> &[u8] {
        let (offset, len) = if self.pdu_header.is_some() {
            (3, self.len + 1)
        } else {
            (2, self.len)
        };
        self.pdu.copy_within(..self.len, offset);
        self.pdu[0] = 0x00;
        self.pdu[1] = len as u8;

        if let Some(header) = self.pdu_header {
            self.pdu[2] = header;
        }
        &self.pdu[..len]
    }
}

impl TryInto<Packet> for &[u8] {
    type Error = ();

    fn try_into(self) -> Result<Packet, Self::Error> {
        let mut packet: Packet = Default::default();

        if self.len() > 1 {
            packet.len = self[1] as usize;
            packet.pdu[..packet.len].copy_from_slice(&self[2..2 + packet.len]);
            Ok(packet)
        } else {
            Err(())
        }
    }
}

pub struct Radio {
    r: nrf_pac::radio::Radio,
}

impl Default for Radio {
    fn default() -> Self {
        Self::new()
    }
}

impl Radio {
    /// Starts the high-frequency crystal oscillator (the radio PLL needs it) and programs the
    /// radio for the same on-air BLE 1 Mbit format the nRF52840 example uses.
    pub fn new() -> Self {
        // The radio PLL runs off the HFXO; start it and wait until it is running.
        let clock = nrf_pac::CLOCK_S;
        clock.events_xostarted().write_value(0);
        clock.tasks_xostart().write_value(1);
        while clock.events_xostarted().read() == 0 {}

        let r = nrf_pac::RADIO_S;

        r.mode().write(|w| w.set_mode(Mode::BLE_1MBIT));

        // S0 = 1 byte (application header flags), LENGTH = 8 bits, no S1 field, 8-bit preamble.
        r.pcnf0().write(|w| {
            w.set_plen(Plen::_8BIT);
            w.set_s0len(true);
            w.set_lflen(8);
            w.set_s1len(0);
        });

        // 3-byte base address (+1 prefix = 4-byte access address), little-endian, whitening on.
        // MAXLEN caps the DMA so the radio never reads/writes past the packet buffer.
        r.pcnf1().write(|w| {
            w.set_maxlen(255);
            w.set_statlen(0);
            w.set_balen(3);
            w.set_endian(Endian::LITTLE);
            w.set_whiteen(true);
        });

        // BLE data whitening: 9-bit IV (channel index | 0x40) and the x^7 + x^4 + 1 polynomial.
        // Unlike the nRF52, the nRF54L15 makes the polynomial configurable, so set it explicitly.
        // Both boards use the same values, so whitening is symmetric.
        r.datawhite().write(|w| {
            w.set_iv(0x40);
            w.set_poly(0x89);
        });

        // 24-bit CRC computed over the PDU only (address field skipped), as in BLE.
        r.crccnf().write(|w| {
            w.set_len(Len::THREE);
            w.set_skipaddr(Skipaddr::SKIP);
        });
        r.crcpoly().write(|w| w.set_crcpoly(CRC_POLY & 0x00ff_ffff));
        r.crcinit()
            .write(|w| w.set_crcinit(ADV_CRC_INIT & 0x00ff_ffff));

        // Access address 0xAA_BB_CC_DD -> BASE0 = 0xBB_CC_DD_00 (truncated to 3 bytes), PREFIX = 0xAA.
        r.base0().write_value(ADV_ADDRESS << 8);
        r.prefix0().write(|w| w.set_ap0((ADV_ADDRESS >> 24) as u8));
        r.txaddress().write(|w| w.set_txaddress(0));
        r.rxaddresses().write(|w| w.set_addr0(true));

        // 2400 MHz + (FREQ - 2400) offset.
        r.frequency().write(|w| {
            w.set_map(false);
            w.set_frequency((FREQ - 2400) as u8);
        });
        r.txpower().write(|w| w.set_txpower(Txpower::_0_DBM));

        Self { r }
    }

    /// Send one packet, blocking until transmission completes.
    pub fn transmit(&mut self, mut packet: Packet) {
        let ptr = packet.as_bytes().as_ptr() as u32;
        self.run(ptr, false);
    }

    /// Send one packet, then block until a CRC-valid packet whose header matches `filter` arrives.
    pub fn transmit_and_wait_response(&mut self, packet: Packet, filter: Option<u8>) -> Packet {
        self.transmit(packet);
        self.receive_and_filter(filter)
    }

    /// Send one packet without waiting for a reply.
    pub fn transmit_without_response(&mut self, packet: Packet) {
        self.transmit(packet);
    }

    /// Block until a CRC-valid packet is received; if `header` is `Some`, keep receiving until the
    /// packet's application header byte matches (packets that fail CRC or filtering are dropped).
    pub fn receive_and_filter(&mut self, header: Option<u8>) -> Packet {
        loop {
            let mut buffer = [0u8; MAX_PDU];
            let crc_ok = self.run(buffer.as_mut_ptr() as u32, true);
            if !crc_ok {
                continue;
            }
            if let Ok(packet) = <&[u8] as TryInto<Packet>>::try_into(&buffer[..]) {
                match header {
                    Some(h) if packet.pdu[0] != h => continue,
                    _ => return packet,
                }
            }
        }
    }

    /// Ramp the radio up (TX or RX), fire the single-shot transfer, wait for END, then disable.
    /// Returns whether the CRC was valid (only meaningful for RX).
    fn run(&self, packetptr: u32, rx: bool) -> bool {
        let r = self.r;

        r.events_ready().write_value(0);
        r.events_end().write_value(0);
        r.events_disabled().write_value(0);
        r.packetptr().write_value(packetptr);

        compiler_fence(Ordering::SeqCst);

        if rx {
            r.tasks_rxen().write_value(1);
        } else {
            r.tasks_txen().write_value(1);
        }
        while r.events_ready().read() == 0 {}
        r.events_ready().write_value(0);

        r.tasks_start().write_value(1);
        while r.events_end().read() == 0 {}
        r.events_end().write_value(0);

        compiler_fence(Ordering::SeqCst);

        let crc_ok = r.crcstatus().read().crcstatus() == Crcstatus::CRCOK;

        r.tasks_disable().write_value(1);
        while r.events_disabled().read() == 0 {}
        r.events_disabled().write_value(0);

        crc_ok
    }
}
