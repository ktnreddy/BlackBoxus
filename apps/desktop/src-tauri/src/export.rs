//! Exporting the vaults: an encrypted file opened with a password chosen
//! for it (spec section 6.9), or a plain CSV file for moving to another
//! password manager.

use vault_core::export::ExportedVault;
use vault_core::{FieldKind, Item, ItemType};
use zeroize::Zeroizing;

use crate::error::AppError;
use crate::import::Preview;

/// The CSV columns, in the order most password managers read them.
const COLUMNS: [&str; 8] = [
    "folder", "type", "name", "username", "password", "url", "notes", "totp",
];

fn first(item: &Item, kind: FieldKind) -> &str {
    item.fields
        .iter()
        .find(|f| f.kind == kind && !f.value.is_empty())
        .map_or("", |f| f.value.as_str())
}

/// Every value of `kind`, one per line.
fn all(item: &Item, kind: FieldKind) -> String {
    item.fields
        .iter()
        .filter(|f| f.kind == kind && !f.value.is_empty())
        .map(|f| f.value.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

/// The notes column: the notes, then every field without a column of its
/// own, as `label: value` lines, so nothing is lost.
fn notes(item: &Item) -> Zeroizing<String> {
    let mut out = Zeroizing::new(all(item, FieldKind::Notes));
    for field in &item.fields {
        let name = match field.kind {
            FieldKind::CardholderName => "Name on card",
            FieldKind::CardNumber => "Card number",
            FieldKind::CardExpiry => "Expires",
            FieldKind::CardSecurityCode => "Security code",
            FieldKind::CustomText | FieldKind::CustomConcealed => {
                if field.label.is_empty() {
                    "Field"
                } else {
                    field.label.as_str()
                }
            }
            _ => continue,
        };
        if field.value.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(name);
        out.push_str(": ");
        out.push_str(&field.value);
    }
    out
}

/// The vaults as a CSV file.
///
/// # Errors
///
/// Returns [`AppError::Internal`] if writing fails, which it shouldn't.
pub fn csv(vaults: &[ExportedVault]) -> Result<Zeroizing<Vec<u8>>, AppError> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer
        .write_record(COLUMNS)
        .map_err(|_| AppError::Internal)?;
    for vault in vaults {
        for item in &vault.items {
            let kind = match item.item_type {
                ItemType::Login => "login",
                ItemType::SecureNote => "note",
                ItemType::Card => "card",
                ItemType::Identity => "identity",
                ItemType::ApiCredential => "api",
                _ => continue,
            };
            let notes = notes(item);
            let urls = Zeroizing::new(all(item, FieldKind::Url));
            writer
                .write_record([
                    vault.name.as_str(),
                    kind,
                    first(item, FieldKind::Title),
                    first(item, FieldKind::Username),
                    first(item, FieldKind::Password),
                    urls.as_str(),
                    notes.as_str(),
                    first(item, FieldKind::TotpSecret),
                ])
                .map_err(|_| AppError::Internal)?;
        }
    }
    writer
        .into_inner()
        .map(Zeroizing::new)
        .map_err(|_| AppError::Internal)
}

/// What an opened export holds, for the import preview. Each item is
/// tagged with its vault's name, like a folder in other apps' exports.
pub fn preview(vaults: &[ExportedVault]) -> (Vec<Item>, Preview) {
    let mut items = Vec::new();
    let mut sample = Vec::new();
    let (mut logins, mut notes) = (0_usize, 0_usize);
    for vault in vaults {
        for item in &vault.items {
            match item.item_type {
                ItemType::Login => logins = usize::saturating_add(logins, 1),
                ItemType::VaultDetails => continue,
                _ => notes = usize::saturating_add(notes, 1),
            }
            if sample.len() < 5 {
                sample.push(first(item, FieldKind::Title).to_owned());
            }
            let mut item = item.clone();
            if vaults.len() > 1 && !vault.name.is_empty() {
                item.fields.push(vault_core::Field::labelled(
                    FieldKind::CustomText,
                    "Folder",
                    &vault.name,
                ));
            }
            items.push(item);
        }
    }
    let preview = Preview {
        source: "BlackBoxus",
        logins,
        notes,
        skipped: 0,
        folders: if vaults.len() > 1 { vaults.len() } else { 0 },
        custom_fields: 0,
        sample,
    };
    (items, preview)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::Field;

    #[test]
    fn csv_keeps_every_field() {
        let vaults = vec![ExportedVault {
            name: "Personal".into(),
            items: vec![
                Item {
                    item_type: ItemType::Login,
                    created_ms: 0,
                    modified_ms: 0,
                    fields: vec![
                        Field::new(FieldKind::Title, "GitHub, Inc."),
                        Field::new(FieldKind::Username, "alex"),
                        Field::new(FieldKind::Password, "p\"w"),
                        Field::new(FieldKind::Url, "https://github.com"),
                        Field::labelled(FieldKind::CustomConcealed, "PIN", "1234"),
                    ],
                },
                Item {
                    item_type: ItemType::Card,
                    created_ms: 0,
                    modified_ms: 0,
                    fields: vec![
                        Field::new(FieldKind::Title, "Visa"),
                        Field::new(FieldKind::CardNumber, "4242"),
                    ],
                },
            ],
        }];
        let out = csv(&vaults).unwrap();
        let text = core::str::from_utf8(&out).unwrap();
        assert!(text.starts_with("folder,type,name,username,password,url,notes,totp\n"));
        assert!(text.contains(
            "Personal,login,\"GitHub, Inc.\",alex,\"p\"\"w\",https://github.com,PIN: 1234,"
        ));
        assert!(text.contains("Personal,card,Visa,,,,Card number: 4242,"));
        // And our own import reads it back.
        let parsed = crate::import::parse(&out, 0).unwrap();
        assert_eq!(parsed.items.len(), 2);
    }
}
