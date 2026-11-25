//! Encrypted exports: a copy of the user's vaults in one file, opened with
//! a password chosen for it, so it can be kept as a backup or moved to a
//! new account without the Secret Key (spec section 6.9).
//!
//! ```text
//! file    = MAGIC ‖ u32be(memory_kib) ‖ u32be(iterations) ‖ u32be(parallelism)
//!         ‖ salt(16) ‖ nonce(24) ‖ XChaCha20-Poly1305(key, content, aad = header)
//! key     = Argon2id(password, salt, params)
//! content = u16be(vault_count)
//!         ‖ (u16be(len) ‖ name ‖ u32be(item_count) ‖ (u32be(len) ‖ item)*)*
//! ```
//!
//! `header` is everything before the nonce, so the parameters and salt
//! can't be changed without the file failing to open. Items use the item
//! encoding (spec section 6.3).

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::aead;
use crate::error::{Error, Result};
use crate::item::Item;
use crate::kdf::{KdfParams, SALT_LEN};
use crate::key::{KEY_LEN, SymmetricKey};
use crate::password::MasterPassword;
use crate::random;

/// The first bytes of every export file.
pub const EXPORT_MAGIC: &[u8; 8] = b"BBXEXP\x00\x01";

/// Most vaults and items in one export, and the longest vault name.
const MAX_VAULTS: usize = 1_000;
const MAX_ITEMS: usize = 100_000;
const MAX_NAME_BYTES: usize = 1_024;

const HEADER_LEN: usize = EXPORT_MAGIC.len() + 12 + SALT_LEN;

/// One vault in an export: its name and items.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedVault {
    /// The vault's name.
    pub name: String,
    /// Its items, without the vault's details item.
    pub items: Vec<Item>,
}

fn derive(password: &MasterPassword, salt: &[u8], params: &KdfParams) -> Result<SymmetricKey> {
    params.validate()?;
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| Error::KeyDerivation)?;
    let mut key = SymmetricKey::zeroed();
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params)
        .hash_password_into(password.as_bytes(), salt, key.as_mut_bytes())
        .map_err(|_| Error::KeyDerivation)?;
    Ok(key)
}

/// Encrypts `vaults` into an export file opened with `password`.
///
/// # Errors
///
/// Returns [`Error::ItemTooLarge`] if there are too many vaults or items or
/// an item can't be encoded, or a key derivation or random failure.
pub fn seal_export(
    password: &MasterPassword,
    vaults: &[ExportedVault],
    params: &KdfParams,
) -> Result<Vec<u8>> {
    if vaults.len() > MAX_VAULTS || vaults.iter().map(|v| v.items.len()).sum::<usize>() > MAX_ITEMS
    {
        return Err(Error::ItemTooLarge);
    }
    let mut content = Zeroizing::new(Vec::new());
    content.extend_from_slice(
        &u16::try_from(vaults.len())
            .map_err(|_| Error::ItemTooLarge)?
            .to_be_bytes(),
    );
    for vault in vaults {
        if vault.name.len() > MAX_NAME_BYTES {
            return Err(Error::ItemTooLarge);
        }
        let name_len = u16::try_from(vault.name.len()).map_err(|_| Error::ItemTooLarge)?;
        content.extend_from_slice(&name_len.to_be_bytes());
        content.extend_from_slice(vault.name.as_bytes());
        let count = u32::try_from(vault.items.len()).map_err(|_| Error::ItemTooLarge)?;
        content.extend_from_slice(&count.to_be_bytes());
        for item in &vault.items {
            let encoded = item.encode()?;
            let len = u32::try_from(encoded.len()).map_err(|_| Error::ItemTooLarge)?;
            content.extend_from_slice(&len.to_be_bytes());
            content.extend_from_slice(&encoded);
        }
    }

    let salt: [u8; SALT_LEN] = random::bytes()?;
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(EXPORT_MAGIC);
    header.extend_from_slice(&params.memory_kib.to_be_bytes());
    header.extend_from_slice(&params.iterations.to_be_bytes());
    header.extend_from_slice(&params.parallelism.to_be_bytes());
    header.extend_from_slice(&salt);
    let key = derive(password, &salt, params)?;
    let sealed = aead::seal(&key, &content, &header)?;
    header.extend_from_slice(&sealed);
    Ok(header)
}

/// Whether `bytes` look like an export file (by their first bytes only).
#[must_use]
pub fn is_export(bytes: &[u8]) -> bool {
    bytes.starts_with(EXPORT_MAGIC)
}

/// Opens an export file made by [`seal_export`].
///
/// # Errors
///
/// Returns [`Error::Decryption`] for a wrong password or a changed file,
/// [`Error::KdfParamOutOfRange`] for parameters outside the accepted range
/// (checked before any work), and [`Error::MalformedMessage`] or
/// [`Error::NewerItemFormat`] for content this version can't read.
pub fn open_export(password: &MasterPassword, bytes: &[u8]) -> Result<Vec<ExportedVault>> {
    if bytes.len() < HEADER_LEN || !is_export(bytes) {
        return Err(Error::MalformedMessage);
    }
    let (header, sealed) = bytes.split_at(HEADER_LEN);
    let word = |at: usize| -> Result<u32> {
        let slice = header
            .get(at..at.saturating_add(4))
            .ok_or(Error::MalformedMessage)?;
        Ok(u32::from_be_bytes(
            slice.try_into().map_err(|_| Error::MalformedMessage)?,
        ))
    };
    let params = KdfParams {
        memory_kib: word(8)?,
        iterations: word(12)?,
        parallelism: word(16)?,
    };
    let salt = header.get(20..).ok_or(Error::MalformedMessage)?;
    let key = derive(password, salt, &params)?;
    let content = aead::open(&key, sealed, header)?;
    parse(&content)
}

fn parse(content: &[u8]) -> Result<Vec<ExportedVault>> {
    let mut rest = content;
    let mut take = |n: usize| -> Result<&[u8]> {
        if rest.len() < n {
            return Err(Error::MalformedMessage);
        }
        let (head, tail) = rest.split_at(n);
        rest = tail;
        Ok(head)
    };
    let mut vaults = Vec::new();
    let count = usize::from(u16::from_be_bytes(
        take(2)?.try_into().map_err(|_| Error::MalformedMessage)?,
    ));
    if count > MAX_VAULTS {
        return Err(Error::MalformedMessage);
    }
    let mut total = 0_usize;
    for _ in 0..count {
        let name_len = usize::from(u16::from_be_bytes(
            take(2)?.try_into().map_err(|_| Error::MalformedMessage)?,
        ));
        if name_len > MAX_NAME_BYTES {
            return Err(Error::MalformedMessage);
        }
        let name = core::str::from_utf8(take(name_len)?)
            .map_err(|_| Error::MalformedMessage)?
            .to_owned();
        let items_len = usize::try_from(u32::from_be_bytes(
            take(4)?.try_into().map_err(|_| Error::MalformedMessage)?,
        ))
        .map_err(|_| Error::MalformedMessage)?;
        total = total.saturating_add(items_len);
        if total > MAX_ITEMS {
            return Err(Error::MalformedMessage);
        }
        let mut items = Vec::with_capacity(items_len.min(1_024));
        for _ in 0..items_len {
            let len = usize::try_from(u32::from_be_bytes(
                take(4)?.try_into().map_err(|_| Error::MalformedMessage)?,
            ))
            .map_err(|_| Error::MalformedMessage)?;
            items.push(Item::decode(take(len)?)?);
        }
        vaults.push(ExportedVault { name, items });
    }
    if !rest.is_empty() {
        return Err(Error::MalformedMessage);
    }
    Ok(vaults)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{Field, FieldKind, ItemType};

    /// Fast parameters for tests only; real exports use the defaults.
    const TEST: KdfParams = KdfParams::MIN;

    fn vaults() -> Vec<ExportedVault> {
        vec![
            ExportedVault {
                name: "Personal".into(),
                items: vec![Item {
                    item_type: ItemType::Login,
                    created_ms: 1,
                    modified_ms: 2,
                    fields: vec![
                        Field::new(FieldKind::Title, "GitHub"),
                        Field::new(FieldKind::Password, "tusk-orbit-lantern"),
                    ],
                }],
            },
            ExportedVault {
                name: "Empty".into(),
                items: vec![],
            },
        ]
    }

    #[test]
    fn round_trip_and_wrong_password() {
        let pw = MasterPassword::new("export password here").unwrap();
        let file = seal_export(&pw, &vaults(), &TEST).unwrap();
        assert!(is_export(&file));
        assert_eq!(open_export(&pw, &file).unwrap(), vaults());
        let wrong = MasterPassword::new("not the export password").unwrap();
        assert!(matches!(open_export(&wrong, &file), Err(Error::Decryption)));
    }

    #[test]
    fn any_change_is_caught() {
        let pw = MasterPassword::new("export password here").unwrap();
        let file = seal_export(&pw, &vaults(), &TEST).unwrap();
        // Salt and ciphertext: no longer opens.
        for at in [HEADER_LEN - 1, HEADER_LEN + 30, file.len() - 1] {
            let mut bad = file.clone();
            bad[at] ^= 1;
            assert!(open_export(&pw, &bad).is_err(), "byte {at}");
        }
        // Weakened parameters are refused before any work.
        let mut weak = file.clone();
        weak[8..12].copy_from_slice(&1_u32.to_be_bytes());
        assert!(matches!(
            open_export(&pw, &weak),
            Err(Error::KdfParamOutOfRange { .. })
        ));
        assert!(open_export(&pw, &file[..HEADER_LEN]).is_err());
        assert!(open_export(&pw, b"not an export").is_err());
    }
}
