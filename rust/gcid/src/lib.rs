//! GCIDv2 encoder and decoder.
//!
//! GCIDv2 strings have the shape `<prefix>_<base58-payload>`. The payload is a
//! four-byte clear header followed by AES-256-GCM-SIV ciphertext and tag. The
//! visible prefix and header are authenticated as associated data.

use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use thiserror::Error;

pub const VERSION: u8 = 0x02;
pub const SUITE_AES_256_GCM_SIV: u8 = 0x01;
pub const SCHEMA_SEQ64_LOC56: u8 = 0x01;
pub const DEFAULT_KEY_ID: u8 = 0x00;

pub const HEADER_LEN: usize = 4;
pub const LOCATION_LEN: usize = 7;
pub const SEQUENCE_LEN: usize = 8;
pub const PLAINTEXT_LEN: usize = LOCATION_LEN + SEQUENCE_LEN;
pub const TAG_LEN: usize = 16;
pub const PAYLOAD_LEN: usize = HEADER_LEN + PLAINTEXT_LEN + TAG_LEN;

const AAD_DOMAIN: &[u8] = b"GCIDv2";
const NONCE_BYTES: [u8; 12] = [0; 12];

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Gcid {
    value: String,
    prefix_len: usize,
}

impl Gcid {
    pub fn new(value: impl Into<String>) -> Result<Self, GcidError> {
        let value = value.into();
        let (prefix, _) = split_gcid(&value)?;
        let prefix_len = prefix.len();
        Ok(Self::from_validated(value, prefix_len))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.value[..self.prefix_len]
    }

    fn from_validated(value: String, prefix_len: usize) -> Self {
        Self { value, prefix_len }
    }
}

impl AsRef<str> for Gcid {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for Gcid {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Display for Gcid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Gcid {
    type Err = GcidError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for Gcid {
    type Error = GcidError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for Gcid {
    type Error = GcidError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Gcid> for String {
    fn from(value: Gcid) -> Self {
        value.value
    }
}

impl PartialEq<&str> for Gcid {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<Gcid> for &str {
    fn eq(&self, other: &Gcid) -> bool {
        *self == other.as_str()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LocationPartition([u8; LOCATION_LEN]);

impl LocationPartition {
    pub const ZERO: Self = Self([0; LOCATION_LEN]);

    #[must_use]
    pub fn from_bytes(bytes: [u8; LOCATION_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; LOCATION_LEN] {
        &self.0
    }

    #[must_use]
    pub fn into_bytes(self) -> [u8; LOCATION_LEN] {
        self.0
    }

    #[must_use]
    pub fn as_u64(&self) -> u64 {
        let mut bytes = [0_u8; 8];
        bytes[1..].copy_from_slice(&self.0);
        u64::from_be_bytes(bytes)
    }
}

impl From<[u8; LOCATION_LEN]> for LocationPartition {
    fn from(bytes: [u8; LOCATION_LEN]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl TryFrom<u64> for LocationPartition {
    type Error = GcidError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value >= (1_u64 << 56) {
            return Err(GcidError::LocationOutOfRange(value));
        }

        let bytes = value.to_be_bytes();
        let mut location = [0_u8; LOCATION_LEN];
        location.copy_from_slice(&bytes[1..]);
        Ok(Self(location))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedGcid {
    pub prefix: String,
    pub sequence: u64,
    pub location: LocationPartition,
    pub header: [u8; HEADER_LEN],
    pub key_id: u8,
}

impl DecodedGcid {
    #[must_use]
    pub fn location_u64(&self) -> u64 {
        self.location.as_u64()
    }
}

#[derive(Clone)]
pub struct GcidCodec {
    cipher: Aes256GcmSiv,
    key_id: u8,
}

impl GcidCodec {
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self::with_key_id(key, DEFAULT_KEY_ID)
    }

    pub fn try_from_key_slice(key: &[u8]) -> Result<Self, GcidError> {
        Self::try_with_key_id_from_slice(key, DEFAULT_KEY_ID)
    }

    #[must_use]
    pub fn with_key_id(key: [u8; 32], key_id: u8) -> Self {
        let cipher =
            Aes256GcmSiv::new_from_slice(&key).expect("AES-256-GCM-SIV accepts 32-byte keys");
        Self { cipher, key_id }
    }

    pub fn try_with_key_id_from_slice(key: &[u8], key_id: u8) -> Result<Self, GcidError> {
        let key: [u8; 32] = key.try_into().map_err(|_| GcidError::InvalidKeyLength {
            expected: 32,
            actual: key.len(),
        })?;
        Ok(Self::with_key_id(key, key_id))
    }

    pub fn encode(&self, prefix: &str, sequence: u64) -> Result<Gcid, GcidError> {
        self.encode_with_location(prefix, sequence, 0)
    }

    pub fn encode_with_location(
        &self,
        prefix: &str,
        sequence: u64,
        location: u64,
    ) -> Result<Gcid, GcidError> {
        self.encode_with_location_partition(prefix, sequence, location.try_into()?)
    }

    pub fn encode_with_location_bytes(
        &self,
        prefix: &str,
        sequence: u64,
        location: [u8; LOCATION_LEN],
    ) -> Result<Gcid, GcidError> {
        self.encode_with_location_partition(prefix, sequence, location.into())
    }

    pub fn encode_with_location_partition(
        &self,
        prefix: &str,
        sequence: u64,
        location: LocationPartition,
    ) -> Result<Gcid, GcidError> {
        validate_prefix(prefix)?;

        let header = self.header();
        let aad = associated_data(prefix, &header);
        let mut plaintext = [0_u8; PLAINTEXT_LEN];
        plaintext[..LOCATION_LEN].copy_from_slice(location.as_bytes());
        plaintext[LOCATION_LEN..].copy_from_slice(&sequence.to_be_bytes());

        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&NONCE_BYTES),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| GcidError::Encrypt)?;

        let mut payload = Vec::with_capacity(PAYLOAD_LEN);
        payload.extend_from_slice(&header);
        payload.extend_from_slice(&ciphertext);

        let encoded_payload = bs58::encode(payload).into_string();
        let mut value = String::with_capacity(prefix.len() + 1 + encoded_payload.len());
        value.push_str(prefix);
        value.push('_');
        value.push_str(&encoded_payload);

        Ok(Gcid::from_validated(value, prefix.len()))
    }

    pub fn decode(
        &self,
        expected_prefix: &str,
        gcid: impl AsRef<str>,
    ) -> Result<DecodedGcid, GcidError> {
        validate_prefix(expected_prefix)?;
        let (prefix, payload) = decode_parts(gcid.as_ref())?;

        if prefix != expected_prefix {
            return Err(GcidError::UnexpectedPrefix {
                expected: expected_prefix.to_owned(),
                actual: prefix.to_owned(),
            });
        }

        self.decode_payload(prefix, &payload)
    }

    pub fn decode_any(&self, gcid: impl AsRef<str>) -> Result<DecodedGcid, GcidError> {
        let (prefix, payload) = decode_parts(gcid.as_ref())?;
        self.decode_payload(prefix, &payload)
    }

    fn decode_payload(&self, prefix: &str, payload: &[u8]) -> Result<DecodedGcid, GcidError> {
        if payload.len() != PAYLOAD_LEN {
            return Err(GcidError::InvalidPayloadLength {
                expected: PAYLOAD_LEN,
                actual: payload.len(),
            });
        }

        let header: [u8; HEADER_LEN] = payload[..HEADER_LEN]
            .try_into()
            .expect("slice length is checked");
        validate_header(header, self.key_id)?;

        let aad = associated_data(prefix, &header);
        let plaintext = self
            .cipher
            .decrypt(
                Nonce::from_slice(&NONCE_BYTES),
                Payload {
                    msg: &payload[HEADER_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| GcidError::Authentication)?;
        if plaintext.len() != PLAINTEXT_LEN {
            return Err(GcidError::InvalidPlaintextLength {
                expected: PLAINTEXT_LEN,
                actual: plaintext.len(),
            });
        }

        let location: [u8; LOCATION_LEN] = plaintext[..LOCATION_LEN]
            .try_into()
            .expect("slice length is checked");
        let sequence = u64::from_be_bytes(
            plaintext[LOCATION_LEN..]
                .try_into()
                .expect("slice length is checked"),
        );

        Ok(DecodedGcid {
            prefix: prefix.to_owned(),
            sequence,
            location: location.into(),
            header,
            key_id: header[3],
        })
    }

    #[must_use]
    pub fn header(&self) -> [u8; HEADER_LEN] {
        [
            VERSION,
            SUITE_AES_256_GCM_SIV,
            SCHEMA_SEQ64_LOC56,
            self.key_id,
        ]
    }
}

#[derive(Clone)]
pub struct GcidKeyring {
    codecs: Vec<Option<GcidCodec>>,
    default_key_id: Option<u8>,
}

impl Default for GcidKeyring {
    fn default() -> Self {
        Self {
            codecs: vec![None; 256],
            default_key_id: None,
        }
    }
}

impl GcidKeyring {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_key(key: [u8; 32]) -> Self {
        Self::new().add_key(DEFAULT_KEY_ID, key)
    }

    pub fn add_key(mut self, key_id: u8, key: [u8; 32]) -> Self {
        self.default_key_id.get_or_insert(key_id);
        self.codecs[usize::from(key_id)] = Some(GcidCodec::with_key_id(key, key_id));
        self
    }

    pub fn try_add_key_slice(mut self, key_id: u8, key: &[u8]) -> Result<Self, GcidError> {
        self.default_key_id.get_or_insert(key_id);
        self.codecs[usize::from(key_id)] =
            Some(GcidCodec::try_with_key_id_from_slice(key, key_id)?);
        Ok(self)
    }

    pub fn encode(&self, prefix: &str, sequence: u64) -> Result<Gcid, GcidError> {
        self.default_codec()?.encode(prefix, sequence)
    }

    pub fn encode_with_location(
        &self,
        prefix: &str,
        sequence: u64,
        location: u64,
    ) -> Result<Gcid, GcidError> {
        self.default_codec()?
            .encode_with_location(prefix, sequence, location)
    }

    pub fn decode(
        &self,
        expected_prefix: &str,
        gcid: impl AsRef<str>,
    ) -> Result<DecodedGcid, GcidError> {
        validate_prefix(expected_prefix)?;
        let (prefix, payload) = decode_parts(gcid.as_ref())?;
        if prefix != expected_prefix {
            return Err(GcidError::UnexpectedPrefix {
                expected: expected_prefix.to_owned(),
                actual: prefix.to_owned(),
            });
        }
        self.decode_payload(prefix, &payload)
    }

    pub fn decode_any(&self, gcid: impl AsRef<str>) -> Result<DecodedGcid, GcidError> {
        let (prefix, payload) = decode_parts(gcid.as_ref())?;
        self.decode_payload(prefix, &payload)
    }

    fn decode_payload(&self, prefix: &str, payload: &[u8]) -> Result<DecodedGcid, GcidError> {
        if payload.len() < HEADER_LEN {
            return Err(GcidError::InvalidPayloadLength {
                expected: PAYLOAD_LEN,
                actual: payload.len(),
            });
        }
        let key_id = payload[3];
        let codec = self
            .codecs
            .get(usize::from(key_id))
            .and_then(Option::as_ref)
            .ok_or(GcidError::UnknownKeyId(key_id))?;
        codec.decode_payload(prefix, payload)
    }

    fn default_codec(&self) -> Result<&GcidCodec, GcidError> {
        let key_id = self.default_key_id.ok_or(GcidError::EmptyKeyring)?;
        self.codecs[usize::from(key_id)]
            .as_ref()
            .ok_or(GcidError::EmptyKeyring)
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum GcidError {
    #[error("key must be {expected} bytes, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("prefix must be non-empty visible ASCII and must not contain '_'")]
    InvalidPrefix,
    #[error("location must fit in 56 bits: {0}")]
    LocationOutOfRange(u64),
    #[error("GCID must have exactly one '_' separator")]
    InvalidFormat,
    #[error("expected prefix {expected:?}, got {actual:?}")]
    UnexpectedPrefix { expected: String, actual: String },
    #[error("invalid Base58 payload")]
    InvalidBase58,
    #[error("invalid payload length: expected {expected}, got {actual}")]
    InvalidPayloadLength { expected: usize, actual: usize },
    #[error("unsupported GCID version: {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported crypto suite: {0}")]
    UnsupportedSuite(u8),
    #[error("unsupported payload schema: {0}")]
    UnsupportedSchema(u8),
    #[error("unsupported key id: expected {expected}, got {actual}")]
    UnsupportedKeyId { expected: u8, actual: u8 },
    #[error("unknown key id: {0}")]
    UnknownKeyId(u8),
    #[error("keyring is empty")]
    EmptyKeyring,
    #[error("encryption failed")]
    Encrypt,
    #[error("authentication failed")]
    Authentication,
    #[error("invalid plaintext length: expected {expected}, got {actual}")]
    InvalidPlaintextLength { expected: usize, actual: usize },
}

fn split_gcid(value: &str) -> Result<(&str, &str), GcidError> {
    let Some(separator) = value.bytes().position(|byte| byte == b'_') else {
        return Err(GcidError::InvalidFormat);
    };
    let prefix = &value[..separator];
    let encoded_payload = &value[separator + 1..];
    if encoded_payload.bytes().any(|byte| byte == b'_') {
        return Err(GcidError::InvalidFormat);
    }
    validate_prefix(prefix)?;
    if encoded_payload.is_empty() {
        return Err(GcidError::InvalidFormat);
    }
    Ok((prefix, encoded_payload))
}

fn decode_parts(value: &str) -> Result<(&str, Vec<u8>), GcidError> {
    let (prefix, encoded_payload) = split_gcid(value)?;
    let payload = bs58::decode(encoded_payload)
        .into_vec()
        .map_err(|_| GcidError::InvalidBase58)?;
    Ok((prefix, payload))
}

fn validate_prefix(prefix: &str) -> Result<(), GcidError> {
    let valid = !prefix.is_empty()
        && prefix
            .bytes()
            .all(|byte| (0x21..=0x7e).contains(&byte) && byte != b'_');
    if !valid {
        return Err(GcidError::InvalidPrefix);
    }
    Ok(())
}

fn validate_header(header: [u8; HEADER_LEN], expected_key_id: u8) -> Result<(), GcidError> {
    if header[0] != VERSION {
        return Err(GcidError::UnsupportedVersion(header[0]));
    }
    if header[1] != SUITE_AES_256_GCM_SIV {
        return Err(GcidError::UnsupportedSuite(header[1]));
    }
    if header[2] != SCHEMA_SEQ64_LOC56 {
        return Err(GcidError::UnsupportedSchema(header[2]));
    }
    if header[3] != expected_key_id {
        return Err(GcidError::UnsupportedKeyId {
            expected: expected_key_id,
            actual: header[3],
        });
    }
    Ok(())
}

fn associated_data(prefix: &str, header: &[u8; HEADER_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 1 + prefix.len() + 1 + header.len());
    aad.extend_from_slice(AAD_DOMAIN);
    aad.push(0);
    aad.extend_from_slice(prefix.as_bytes());
    aad.push(0);
    aad.extend_from_slice(header);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEV_KEY: [u8; 32] = *b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
    const ALT_KEY: [u8; 32] = *b"YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY";

    #[test]
    fn encodes_spec_vectors() {
        let codec = GcidCodec::new(DEV_KEY);

        assert_eq!(
            codec.encode("prf", 123).unwrap(),
            "prf_Cbds1yPUh73MNg2g2H3cdADCRuF7USjteUEdqeEAQPC7whQ"
        );
        assert_eq!(
            codec.encode("asset", 456).unwrap(),
            "asset_Cbds3PQ1ZC2vzDFLB7qWod4hHnAuFwt4uqFH6NbKL1ZBCvT"
        );
        assert_eq!(
            codec.encode_with_location("asset", 123, 42).unwrap(),
            "asset_CbdrzuzUWxA1FkCVjXXNP92ZT5cpu2DrP23ioGdJ5GPWj2M"
        );
        assert_eq!(
            codec.encode("prf", 0).unwrap(),
            "prf_Cbds4CmMHP4273kXPwFQ8DQCPu3sd4CSAmhYDA7RzkTEGmb"
        );
        assert_eq!(
            codec.encode("prf", u64::MAX).unwrap(),
            "prf_Cbdrze8v48sf8q2jPwrCf3TMB4Gs3YiHcnki91GDYsBwmxp"
        );
    }

    #[test]
    fn decodes_spec_vectors() {
        let codec = GcidCodec::new(DEV_KEY);
        let decoded = codec
            .decode(
                "asset",
                "asset_CbdrzuzUWxA1FkCVjXXNP92ZT5cpu2DrP23ioGdJ5GPWj2M",
            )
            .unwrap();

        assert_eq!(decoded.prefix, "asset");
        assert_eq!(decoded.sequence, 123);
        assert_eq!(decoded.location_u64(), 42);
        assert_eq!(
            decoded.header,
            [
                VERSION,
                SUITE_AES_256_GCM_SIV,
                SCHEMA_SEQ64_LOC56,
                DEFAULT_KEY_ID,
            ]
        );
    }

    #[test]
    fn rejects_prefix_relabeling() {
        let codec = GcidCodec::new(DEV_KEY);
        let relabeled = codec
            .encode("prf", 123)
            .unwrap()
            .replacen("prf_", "asset_", 1);

        assert_eq!(
            codec.decode("asset", &relabeled),
            Err(GcidError::Authentication)
        );
    }

    #[test]
    fn rejects_wrong_expected_prefix_before_authentication() {
        let codec = GcidCodec::new(DEV_KEY);
        let gcid = codec.encode("prf", 123).unwrap();

        assert_eq!(
            codec.decode("asset", &gcid),
            Err(GcidError::UnexpectedPrefix {
                expected: "asset".to_owned(),
                actual: "prf".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_bad_prefixes() {
        let codec = GcidCodec::new(DEV_KEY);

        assert_eq!(codec.encode("", 1), Err(GcidError::InvalidPrefix));
        assert_eq!(codec.encode("bad_prefix", 1), Err(GcidError::InvalidPrefix));
        assert_eq!(codec.encode("bad prefix", 1), Err(GcidError::InvalidPrefix));
        assert_eq!(codec.encode("caf\u{e9}", 1), Err(GcidError::InvalidPrefix));
    }

    #[test]
    fn rejects_out_of_range_location() {
        let codec = GcidCodec::new(DEV_KEY);

        assert_eq!(
            codec.encode_with_location("asset", 1, 1_u64 << 56),
            Err(GcidError::LocationOutOfRange(1_u64 << 56))
        );
    }

    #[test]
    fn rejects_unsupported_header_values() {
        let codec = GcidCodec::new(DEV_KEY);
        let gcid = codec.encode("prf", 123).unwrap();
        let (prefix, payload) = gcid.split_once('_').unwrap();
        let mut raw = bs58::decode(payload).into_vec().unwrap();
        raw[0] = 3;
        let gcid = format!("{prefix}_{}", bs58::encode(raw).into_string());

        assert_eq!(
            codec.decode("prf", &gcid),
            Err(GcidError::UnsupportedVersion(3))
        );
    }

    #[test]
    fn supports_decode_any_and_gcid_newtype() {
        let codec = GcidCodec::new(DEV_KEY);
        let id = codec.encode("asset", 456).unwrap();
        let parsed: Gcid = id.as_str().parse().unwrap();

        assert_eq!(parsed, id);
        assert_eq!(id.prefix(), "asset");

        let decoded = codec.decode_any(&id).unwrap();
        assert_eq!(decoded.prefix, "asset");
        assert_eq!(decoded.sequence, 456);
    }

    #[test]
    fn supports_slice_keys_and_keyrings() {
        let codec = GcidCodec::try_with_key_id_from_slice(&DEV_KEY, 7).unwrap();
        let id = codec.encode("prf", 99).unwrap();

        let keyring = GcidKeyring::new()
            .add_key(1, ALT_KEY)
            .try_add_key_slice(7, &DEV_KEY)
            .unwrap();
        let decoded = keyring.decode_any(&id).unwrap();

        assert_eq!(decoded.key_id, 7);
        assert_eq!(decoded.sequence, 99);
        assert_eq!(keyring.decode("prf", &id).unwrap().sequence, 99);
        assert!(matches!(
            GcidCodec::try_from_key_slice(&DEV_KEY[..31]),
            Err(GcidError::InvalidKeyLength {
                expected: 32,
                actual: 31,
            })
        ));
    }

    #[test]
    fn keyring_reports_missing_keys_cleanly() {
        let codec = GcidCodec::with_key_id(DEV_KEY, 7);
        let id = codec.encode("prf", 99).unwrap();

        assert_eq!(
            GcidKeyring::with_key(ALT_KEY).decode_any(&id),
            Err(GcidError::UnknownKeyId(7))
        );
        assert_eq!(
            GcidKeyring::new().encode("prf", 99),
            Err(GcidError::EmptyKeyring)
        );
    }

    #[test]
    fn supports_location_partition_type() {
        let location = LocationPartition::try_from(42).unwrap();
        assert_eq!(location.as_u64(), 42);
        assert_eq!(location.as_bytes(), &[0, 0, 0, 0, 0, 0, 42]);

        let codec = GcidCodec::new(DEV_KEY);
        let id = codec
            .encode_with_location_partition("asset", 123, location)
            .unwrap();
        assert_eq!(codec.decode("asset", &id).unwrap().location, location);
    }

    #[test]
    fn gcid_newtype_rejects_invalid_shapes() {
        assert_eq!(
            Gcid::new("prf_payload_extra"),
            Err(GcidError::InvalidFormat)
        );
        assert_eq!(Gcid::new("prf_"), Err(GcidError::InvalidFormat));
        assert_eq!(Gcid::new("_payload"), Err(GcidError::InvalidPrefix));
    }
}
