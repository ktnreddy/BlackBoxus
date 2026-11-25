//! Vault items: content encoding, padding and encrypted envelopes
//! (spec section 6).

use zeroize::{Zeroize, Zeroizing};

use crate::aead::{self, NONCE_LEN, TAG_LEN};
use crate::error::{Error, Result};
use crate::key::{KEY_LEN, SymmetricKey};
use crate::random;

/// Length of vault and item IDs in bytes.
pub const ID_LEN: usize = 16;

/// Maximum number of fields in an item.
pub const MAX_FIELDS: usize = 256;

/// Maximum length of a field label in bytes.
pub const MAX_LABEL_BYTES: usize = 256;

/// Maximum length of a field value in bytes.
pub const MAX_VALUE_BYTES: usize = 16_384;

/// Padding buckets for encrypted content, in bytes.
pub const PADDING_BUCKETS: [usize; 8] = [256, 512, 1024, 2048, 4096, 8192, 16_384, 32_768];

/// Smallest possible envelope, in bytes.
pub const MIN_ENVELOPE_LEN: usize = 410;

/// Largest possible envelope, in bytes.
pub const MAX_ENVELOPE_LEN: usize = 32_922;

const FORMAT_VERSION: u16 = 1;
const SCHEMA_VERSION: u8 = 1;
const HEADER_LEN: usize = 42;
const WRAPPED_KEY_LEN: usize = 72;
const LABEL_ITEM_KEY: &[u8] = b"BlackBoxus v1 item-key";
const LABEL_ITEM: &[u8] = b"BlackBoxus v1 item";

macro_rules! id_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; ID_LEN]);

        impl $name {
            /// Generates a new random ID.
            ///
            /// # Errors
            ///
            /// Returns [`Error::RandomUnavailable`] if the generator fails.
            pub fn generate() -> Result<Self> {
                random::bytes().map(Self)
            }

            /// Wraps ID bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; ID_LEN]) -> Self {
                Self(bytes)
            }

            /// The ID bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
                &self.0
            }
        }
    };
}

id_type!(
    /// Identifies a vault. Not secret.
    VaultId
);
id_type!(
    /// Identifies an item within a vault. Not secret.
    ItemId
);

/// The kind of item (spec section 6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ItemType {
    /// A website or app login.
    Login,
    /// A free-form secure note.
    SecureNote,
    /// A payment card.
    Card,
    /// Personal identity details.
    Identity,
    /// An API key or other credential.
    ApiCredential,
    /// The vault's own details: its name in the title, and an optional
    /// description in the notes. Stored only under [`VAULT_DETAILS_ITEM`];
    /// clients do not list it as an item.
    VaultDetails,
}

/// The reserved item ID of a vault's details (spec section 6.3). Item IDs
/// are otherwise random, so no ordinary item has it.
pub const VAULT_DETAILS_ITEM: ItemId = ItemId::from_bytes([0; ID_LEN]);

impl ItemType {
    const fn code(self) -> u8 {
        match self {
            Self::Login => 1,
            Self::SecureNote => 2,
            Self::Card => 3,
            Self::Identity => 4,
            Self::ApiCredential => 5,
            Self::VaultDetails => 6,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Login),
            2 => Some(Self::SecureNote),
            3 => Some(Self::Card),
            4 => Some(Self::Identity),
            5 => Some(Self::ApiCredential),
            6 => Some(Self::VaultDetails),
            _ => None,
        }
    }
}

/// The kind of a field (spec section 6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FieldKind {
    /// The item's title.
    Title,
    /// A username or email used to sign in.
    Username,
    /// A password.
    Password,
    /// A website address.
    Url,
    /// Free-form notes.
    Notes,
    /// A TOTP secret for one-time codes.
    TotpSecret,
    /// The name on a payment card.
    CardholderName,
    /// A payment card number.
    CardNumber,
    /// A payment card expiry date.
    CardExpiry,
    /// A payment card security code.
    CardSecurityCode,
    /// User-defined text.
    CustomText,
    /// User-defined text hidden by default.
    CustomConcealed,
}

impl FieldKind {
    const fn code(self) -> u8 {
        match self {
            Self::Title => 1,
            Self::Username => 2,
            Self::Password => 3,
            Self::Url => 4,
            Self::Notes => 5,
            Self::TotpSecret => 6,
            Self::CardholderName => 7,
            Self::CardNumber => 8,
            Self::CardExpiry => 9,
            Self::CardSecurityCode => 10,
            Self::CustomText => 11,
            Self::CustomConcealed => 12,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Title),
            2 => Some(Self::Username),
            3 => Some(Self::Password),
            4 => Some(Self::Url),
            5 => Some(Self::Notes),
            6 => Some(Self::TotpSecret),
            7 => Some(Self::CardholderName),
            8 => Some(Self::CardNumber),
            9 => Some(Self::CardExpiry),
            10 => Some(Self::CardSecurityCode),
            11 => Some(Self::CustomText),
            12 => Some(Self::CustomConcealed),
            _ => None,
        }
    }

    /// Whether clients should hide this field's value until revealed.
    #[must_use]
    pub const fn is_concealed(self) -> bool {
        matches!(
            self,
            Self::Password
                | Self::TotpSecret
                | Self::CardNumber
                | Self::CardSecurityCode
                | Self::CustomConcealed
        )
    }
}

/// One field of an item. The value is erased on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct Field {
    /// The field's kind.
    pub kind: FieldKind,
    /// An optional label, usually empty.
    pub label: String,
    /// The field's value.
    pub value: Zeroizing<String>,
}

impl Field {
    /// Creates a field with no label.
    #[must_use]
    pub fn new(kind: FieldKind, value: &str) -> Self {
        Self {
            kind,
            label: String::new(),
            value: Zeroizing::new(value.to_owned()),
        }
    }

    /// Creates a field with a label.
    #[must_use]
    pub fn labelled(kind: FieldKind, label: &str, value: &str) -> Self {
        Self {
            kind,
            label: label.to_owned(),
            value: Zeroizing::new(value.to_owned()),
        }
    }
}

impl core::fmt::Debug for Field {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Field")
            .field("kind", &self.kind)
            .field("label", &self.label)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// A decrypted vault item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// The item's type.
    pub item_type: ItemType,
    /// Creation time, Unix milliseconds.
    pub created_ms: u64,
    /// Last modification time, Unix milliseconds.
    pub modified_ms: u64,
    /// Fields in display order.
    pub fields: Vec<Field>,
}

impl Item {
    /// Encodes the content (spec section 6.3), without padding.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ItemTooLarge`] if a limit is exceeded.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        if self.fields.len() > MAX_FIELDS {
            return Err(Error::ItemTooLarge);
        }
        let mut out = Zeroizing::new(Vec::with_capacity(PADDING_BUCKETS[0]));
        out.push(SCHEMA_VERSION);
        out.push(self.item_type.code());
        out.extend_from_slice(&self.created_ms.to_be_bytes());
        out.extend_from_slice(&self.modified_ms.to_be_bytes());
        let count = u16::try_from(self.fields.len()).map_err(|_| Error::ItemTooLarge)?;
        out.extend_from_slice(&count.to_be_bytes());
        for field in &self.fields {
            if field.label.len() > MAX_LABEL_BYTES || field.value.len() > MAX_VALUE_BYTES {
                return Err(Error::ItemTooLarge);
            }
            let label_len = u16::try_from(field.label.len()).map_err(|_| Error::ItemTooLarge)?;
            let value_len = u32::try_from(field.value.len()).map_err(|_| Error::ItemTooLarge)?;
            out.push(field.kind.code());
            out.extend_from_slice(&label_len.to_be_bytes());
            out.extend_from_slice(field.label.as_bytes());
            out.extend_from_slice(&value_len.to_be_bytes());
            out.extend_from_slice(field.value.as_bytes());
        }
        Ok(out)
    }

    /// Parses content produced by [`Item::encode`]. Strict: unknown codes,
    /// over-limit lengths, invalid UTF-8 and trailing bytes are rejected.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader(bytes);
        let version = r.u8()?;
        if version > SCHEMA_VERSION {
            // Authentic (it decrypted), just newer: callers keep it as it
            // is instead of treating the whole vault as unreadable.
            return Err(Error::NewerItemFormat);
        }
        if version != SCHEMA_VERSION {
            return Err(Error::MalformedMessage);
        }
        let item_type = ItemType::from_code(r.u8()?).ok_or(Error::MalformedMessage)?;
        let created_ms = r.u64()?;
        let modified_ms = r.u64()?;
        let count = usize::from(r.u16()?);
        if count > MAX_FIELDS {
            return Err(Error::MalformedMessage);
        }
        let mut fields = Vec::with_capacity(count);
        for _ in 0..count {
            let kind = FieldKind::from_code(r.u8()?).ok_or(Error::MalformedMessage)?;
            let label_len = usize::from(r.u16()?);
            if label_len > MAX_LABEL_BYTES {
                return Err(Error::MalformedMessage);
            }
            let label = core::str::from_utf8(r.take(label_len)?)
                .map_err(|_| Error::MalformedMessage)?
                .to_owned();
            let value_len = usize::try_from(r.u32()?).map_err(|_| Error::MalformedMessage)?;
            if value_len > MAX_VALUE_BYTES {
                return Err(Error::MalformedMessage);
            }
            let value =
                core::str::from_utf8(r.take(value_len)?).map_err(|_| Error::MalformedMessage)?;
            fields.push(Field {
                kind,
                label,
                value: Zeroizing::new(value.to_owned()),
            });
        }
        if !r.0.is_empty() {
            return Err(Error::MalformedMessage);
        }
        Ok(Self {
            item_type,
            created_ms,
            modified_ms,
            fields,
        })
    }
}

/// Reads big-endian values from a byte slice without panicking.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(Error::MalformedMessage);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| Error::MalformedMessage)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(u8::from_be_bytes(self.array()?))
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
}

/// Pads content to the smallest bucket (spec section 6.3).
pub(crate) fn pad(content: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let needed = content.len().checked_add(1).ok_or(Error::ItemTooLarge)?;
    let bucket = PADDING_BUCKETS
        .iter()
        .copied()
        .find(|&b| b >= needed)
        .ok_or(Error::ItemTooLarge)?;
    let mut out = Zeroizing::new(Vec::with_capacity(bucket));
    out.extend_from_slice(content);
    out.push(0x80);
    out.resize(bucket, 0);
    Ok(out)
}

/// Removes padding added by [`pad`].
pub(crate) fn unpad(padded: &[u8]) -> Result<&[u8]> {
    if !PADDING_BUCKETS.contains(&padded.len()) {
        return Err(Error::MalformedMessage);
    }
    let end = padded
        .iter()
        .rposition(|&b| b != 0)
        .ok_or(Error::MalformedMessage)?;
    let (content, marker) = padded.split_at(end);
    if marker.first() != Some(&0x80) {
        return Err(Error::MalformedMessage);
    }
    Ok(content)
}

fn aad(label: &[u8], vault_id: &VaultId, item_id: &ItemId, revision: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(label.len().saturating_add(HEADER_LEN));
    out.extend_from_slice(label);
    out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(vault_id.as_bytes());
    out.extend_from_slice(item_id.as_bytes());
    out.extend_from_slice(&revision.to_be_bytes());
    out
}

/// Encrypts an item revision into an envelope (spec section 6.4).
///
/// # Errors
///
/// Returns [`Error::ItemTooLarge`] if the item exceeds the limits,
/// [`Error::RandomUnavailable`], or [`Error::Encryption`].
pub fn seal_item(
    item: &Item,
    vault_key: &SymmetricKey,
    vault_id: &VaultId,
    item_id: &ItemId,
    revision: u64,
) -> Result<Vec<u8>> {
    let item_key = SymmetricKey::from_bytes(random::bytes()?);
    let nonces: [[u8; NONCE_LEN]; 2] = [random::bytes()?, random::bytes()?];
    seal_item_deterministic(
        item, vault_key, vault_id, item_id, revision, &item_key, &nonces,
    )
}

#[doc(hidden)]
/// Deterministic sealing for test vectors only. A key and nonce pair must
/// never be reused: real code uses [`seal_item`].
///
/// # Errors
///
/// As [`seal_item`].
pub fn seal_item_deterministic(
    item: &Item,
    vault_key: &SymmetricKey,
    vault_id: &VaultId,
    item_id: &ItemId,
    revision: u64,
    item_key: &SymmetricKey,
    nonces: &[[u8; NONCE_LEN]; 2],
) -> Result<Vec<u8>> {
    let [key_nonce, content_nonce] = nonces;
    let padded = pad(&item.encode()?)?;

    let wrapped_key = aead::seal_with_nonce(
        vault_key,
        key_nonce,
        item_key.as_bytes(),
        &aad(LABEL_ITEM_KEY, vault_id, item_id, revision),
    )?;
    let sealed = aead::seal_with_nonce(
        item_key,
        content_nonce,
        &padded,
        &aad(LABEL_ITEM, vault_id, item_id, revision),
    )?;

    let mut out = Vec::with_capacity(
        HEADER_LEN
            .saturating_add(wrapped_key.len())
            .saturating_add(sealed.len()),
    );
    out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(vault_id.as_bytes());
    out.extend_from_slice(item_id.as_bytes());
    out.extend_from_slice(&revision.to_be_bytes());
    out.extend_from_slice(&wrapped_key);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// A decrypted item revision.
#[derive(Debug)]
pub struct OpenedItem {
    /// The item's ID.
    pub item_id: ItemId,
    /// The revision number, to be checked against the revision log.
    pub revision: u64,
    /// The decrypted item.
    pub item: Item,
}

/// Decrypts an envelope (spec section 6.5).
///
/// `vault_id` is the vault the client is reading. Pass `expected_item` when a
/// specific item was requested. The returned revision must still be checked
/// against the signed revision log before the item is shown or used.
///
/// # Errors
///
/// Returns [`Error::MalformedMessage`] for a bad length, version or
/// encoding, [`Error::WrongItem`] if the vault or item ID does not match, or
/// [`Error::Decryption`] if the key is wrong or the envelope was modified.
pub fn open_item(
    envelope: &[u8],
    vault_key: &SymmetricKey,
    vault_id: &VaultId,
    expected_item: Option<&ItemId>,
) -> Result<OpenedItem> {
    if envelope.len() < MIN_ENVELOPE_LEN || envelope.len() > MAX_ENVELOPE_LEN {
        return Err(Error::MalformedMessage);
    }
    let mut r = Reader(envelope);
    if r.u16()? != FORMAT_VERSION {
        return Err(Error::MalformedMessage);
    }
    let envelope_vault = VaultId(r.array()?);
    let item_id = ItemId(r.array()?);
    let revision = r.u64()?;
    if envelope_vault != *vault_id || expected_item.is_some_and(|id| *id != item_id) {
        return Err(Error::WrongItem);
    }
    let wrapped_key = r.take(WRAPPED_KEY_LEN)?;
    let sealed = r.0;
    let content_len = sealed
        .len()
        .checked_sub(NONCE_LEN.saturating_add(TAG_LEN))
        .ok_or(Error::MalformedMessage)?;
    if !PADDING_BUCKETS.contains(&content_len) {
        return Err(Error::MalformedMessage);
    }

    let mut key_bytes = aead::open(
        vault_key,
        wrapped_key,
        &aad(LABEL_ITEM_KEY, vault_id, &item_id, revision),
    )?;
    let key_array: [u8; KEY_LEN] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Decryption)?;
    key_bytes.zeroize();
    let item_key = SymmetricKey::from_bytes(key_array);

    let padded = aead::open(
        &item_key,
        sealed,
        &aad(LABEL_ITEM, vault_id, &item_id, revision),
    )?;
    let item = Item::decode(unpad(&padded)?)?;
    Ok(OpenedItem {
        item_id,
        revision,
        item,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Item {
        Item {
            item_type: ItemType::Login,
            created_ms: 1_762_000_000_000,
            modified_ms: 1_762_000_500_000,
            fields: vec![
                Field::new(FieldKind::Title, "Example"),
                Field::labelled(FieldKind::Username, "Work email", "alice@example.com"),
                Field::new(FieldKind::Password, "correct horse battery staple"),
                Field::new(FieldKind::Url, "https://example.com/login"),
            ],
        }
    }

    fn keys() -> (SymmetricKey, VaultId, ItemId) {
        (
            SymmetricKey::from_bytes([1; KEY_LEN]),
            VaultId::from_bytes([2; ID_LEN]),
            ItemId::from_bytes([3; ID_LEN]),
        )
    }

    #[test]
    fn encode_decode_round_trip() {
        let item = sample();
        let encoded = item.encode().unwrap();
        assert_eq!(Item::decode(&encoded).unwrap(), item);
    }

    #[test]
    fn decode_rejects_bad_content() {
        let encoded = item_bytes();
        // Trailing byte.
        let mut extra = encoded.clone();
        extra.push(0);
        assert!(Item::decode(&extra).is_err());
        // Truncation at every length.
        for len in 0..encoded.len() {
            assert!(Item::decode(&encoded[..len]).is_err(), "len {len}");
        }
        // Unknown schema, type and field kind.
        for (pos, value) in [(0, 2), (1, 99), (20, 99)] {
            let mut bad = encoded.clone();
            bad[pos] = value;
            assert!(Item::decode(&bad).is_err(), "pos {pos}");
        }
    }

    #[test]
    fn a_newer_schema_is_told_apart_from_damage() {
        let mut newer = item_bytes();
        newer[0] = SCHEMA_VERSION + 1;
        assert!(matches!(Item::decode(&newer), Err(Error::NewerItemFormat)));
        let mut older = item_bytes();
        older[0] = 0;
        assert!(matches!(Item::decode(&older), Err(Error::MalformedMessage)));
    }

    fn item_bytes() -> Vec<u8> {
        sample().encode().unwrap().to_vec()
    }

    #[test]
    fn decode_rejects_invalid_utf8() {
        let item = Item {
            fields: vec![Field::new(FieldKind::Notes, "ab")],
            ..sample()
        };
        let mut encoded = item.encode().unwrap().to_vec();
        let last = encoded.len() - 1;
        encoded[last] = 0xFF;
        assert!(Item::decode(&encoded).is_err());
    }

    #[test]
    fn limits_are_enforced() {
        let too_many = Item {
            fields: vec![Field::new(FieldKind::Notes, ""); MAX_FIELDS + 1],
            ..sample()
        };
        assert_eq!(too_many.encode().unwrap_err(), Error::ItemTooLarge);
        let long_value = Item {
            fields: vec![Field::new(
                FieldKind::Notes,
                &"a".repeat(MAX_VALUE_BYTES + 1),
            )],
            ..sample()
        };
        assert_eq!(long_value.encode().unwrap_err(), Error::ItemTooLarge);
        let long_label = Item {
            fields: vec![Field::labelled(
                FieldKind::Notes,
                &"a".repeat(MAX_LABEL_BYTES + 1),
                "",
            )],
            ..sample()
        };
        assert_eq!(long_label.encode().unwrap_err(), Error::ItemTooLarge);
    }

    #[test]
    fn padding_uses_buckets() {
        assert_eq!(pad(&[]).unwrap().len(), 256);
        assert_eq!(pad(&[1; 255]).unwrap().len(), 256);
        assert_eq!(pad(&[1; 256]).unwrap().len(), 512);
        assert_eq!(pad(&[1; 32_767]).unwrap().len(), 32_768);
        assert_eq!(pad(&[1; 32_768]).unwrap_err(), Error::ItemTooLarge);
        for content in [&[][..], &[0, 0, 0][..], &[0x80, 0][..], &[5; 300][..]] {
            assert_eq!(unpad(&pad(content).unwrap()).unwrap(), content);
        }
    }

    #[test]
    fn unpad_rejects_bad_padding() {
        assert!(unpad(&[0; 256]).is_err());
        let mut no_marker = vec![0; 256];
        no_marker[10] = 0x7F;
        assert!(unpad(&no_marker).is_err());
        assert!(unpad(&[0x80; 300]).is_err());
    }

    #[test]
    fn seal_open_round_trip() {
        let (vk, vault, id) = keys();
        let envelope = seal_item(&sample(), &vk, &vault, &id, 7).unwrap();
        assert_eq!(envelope.len(), MIN_ENVELOPE_LEN);
        let opened = open_item(&envelope, &vk, &vault, Some(&id)).unwrap();
        assert_eq!(opened.item_id, id);
        assert_eq!(opened.revision, 7);
        assert_eq!(opened.item, sample());
    }

    #[test]
    fn every_revision_uses_fresh_keys() {
        let (vk, vault, id) = keys();
        let a = seal_item(&sample(), &vk, &vault, &id, 1).unwrap();
        let b = seal_item(&sample(), &vk, &vault, &id, 1).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_wrong_vault_item_or_key() {
        let (vk, vault, id) = keys();
        let envelope = seal_item(&sample(), &vk, &vault, &id, 1).unwrap();
        let other_vault = VaultId::from_bytes([9; ID_LEN]);
        let other_item = ItemId::from_bytes([9; ID_LEN]);
        assert_eq!(
            open_item(&envelope, &vk, &other_vault, None).unwrap_err(),
            Error::WrongItem
        );
        assert_eq!(
            open_item(&envelope, &vk, &vault, Some(&other_item)).unwrap_err(),
            Error::WrongItem
        );
        let other_key = SymmetricKey::from_bytes([8; KEY_LEN]);
        assert_eq!(
            open_item(&envelope, &other_key, &vault, None).unwrap_err(),
            Error::Decryption
        );
    }

    #[test]
    fn server_cannot_relabel_or_move_envelopes() {
        let (vk, vault, id) = keys();
        let envelope = seal_item(&sample(), &vk, &vault, &id, 1).unwrap();

        // Claim a newer revision.
        let mut newer = envelope.clone();
        newer[41] = 2;
        assert_eq!(
            open_item(&newer, &vk, &vault, None).unwrap_err(),
            Error::Decryption
        );

        // Move the ciphertext to another item ID.
        let mut moved = envelope.clone();
        moved[18] ^= 1;
        assert_eq!(
            open_item(&moved, &vk, &vault, None).unwrap_err(),
            Error::Decryption
        );

        // Splice another item's content under this item's wrapped key.
        let other = seal_item(&sample(), &vk, &vault, &ItemId::from_bytes([4; ID_LEN]), 1).unwrap();
        let mut spliced = envelope[..HEADER_LEN + WRAPPED_KEY_LEN].to_vec();
        spliced.extend_from_slice(&other[HEADER_LEN + WRAPPED_KEY_LEN..]);
        assert_eq!(
            open_item(&spliced, &vk, &vault, None).unwrap_err(),
            Error::Decryption
        );
    }

    #[test]
    fn any_bit_flip_is_detected() {
        let (vk, vault, id) = keys();
        let envelope = seal_item(&sample(), &vk, &vault, &id, 1).unwrap();
        for pos in (0..envelope.len()).step_by(7) {
            let mut bad = envelope.clone();
            bad[pos] ^= 0x40;
            assert!(open_item(&bad, &vk, &vault, None).is_err(), "pos {pos}");
        }
    }

    #[test]
    fn rejects_bad_lengths() {
        let (vk, vault, _) = keys();
        assert!(open_item(&[], &vk, &vault, None).is_err());
        assert!(open_item(&vec![0; MIN_ENVELOPE_LEN - 1], &vk, &vault, None).is_err());
        assert!(open_item(&vec![0; MAX_ENVELOPE_LEN + 1], &vk, &vault, None).is_err());
        let (vk, vault, id) = keys();
        let mut envelope = seal_item(&sample(), &vk, &vault, &id, 1).unwrap();
        envelope.push(0);
        assert_eq!(
            open_item(&envelope, &vk, &vault, None).unwrap_err(),
            Error::MalformedMessage
        );
    }

    #[test]
    fn largest_item_fits() {
        let (vk, vault, id) = keys();
        // Two maximum-size values plus headers fill the largest bucket.
        let big = Item {
            fields: vec![
                Field::new(FieldKind::Notes, &"a".repeat(MAX_VALUE_BYTES)),
                Field::new(FieldKind::Notes, &"b".repeat(MAX_VALUE_BYTES - 100)),
            ],
            ..sample()
        };
        let envelope = seal_item(&big, &vk, &vault, &id, 1).unwrap();
        assert_eq!(envelope.len(), MAX_ENVELOPE_LEN);
        assert_eq!(open_item(&envelope, &vk, &vault, None).unwrap().item, big);
    }

    #[test]
    fn debug_hides_values() {
        let shown = format!("{:?}", Field::new(FieldKind::Password, "hunter2"));
        assert!(!shown.contains("hunter2"));
    }
}
