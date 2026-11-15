//! Items as the window sees them. Concealed values (passwords, card
//! numbers and the like) are never sent with an item: the window asks for
//! one with `reveal_field` when the user clicks the eye, or has it copied
//! straight to the clipboard from Rust.

use serde::{Deserialize, Serialize};
use vault_core::{Field, FieldKind, Item, ItemId, ItemType};
use zeroize::Zeroizing;

use crate::error::AppError;

/// Item types by name.
const TYPES: [(&str, ItemType); 5] = [
    ("login", ItemType::Login),
    ("note", ItemType::SecureNote),
    ("card", ItemType::Card),
    ("identity", ItemType::Identity),
    ("api", ItemType::ApiCredential),
];

/// Field kinds by name, and whether each is concealed.
const KINDS: [(&str, FieldKind, bool); 12] = [
    ("title", FieldKind::Title, false),
    ("username", FieldKind::Username, false),
    ("password", FieldKind::Password, true),
    ("url", FieldKind::Url, false),
    ("notes", FieldKind::Notes, false),
    ("totp", FieldKind::TotpSecret, true),
    ("cardholder", FieldKind::CardholderName, false),
    ("card_number", FieldKind::CardNumber, true),
    ("card_expiry", FieldKind::CardExpiry, false),
    ("card_code", FieldKind::CardSecurityCode, true),
    ("text", FieldKind::CustomText, false),
    ("concealed", FieldKind::CustomConcealed, true),
];

fn type_name(t: ItemType) -> &'static str {
    TYPES
        .iter()
        .find(|(_, v)| *v == t)
        .map_or("login", |(n, _)| n)
}

fn kind_info(k: FieldKind) -> (&'static str, bool) {
    KINDS
        .iter()
        .find(|(_, v, _)| *v == k)
        .map_or(("text", false), |(n, _, c)| (n, *c))
}

fn first(item: &Item, kind: FieldKind) -> Option<&str> {
    item.fields
        .iter()
        .find(|f| f.kind == kind && !f.value.is_empty())
        .map(|f| f.value.as_str())
}

/// An item in the list: no secrets.
#[derive(Debug, Clone, Serialize)]
pub struct ItemSummary {
    /// The item ID, base64url.
    pub id: String,
    /// The item type.
    #[serde(rename = "type")]
    pub item_type: &'static str,
    /// The title.
    pub title: String,
    /// A second line: username, website or type.
    pub subtitle: String,
    /// Last change, Unix milliseconds.
    pub modified_ms: u64,
}

/// One field of an item, as shown.
#[derive(Debug, Clone, Serialize)]
pub struct FieldView {
    /// The field kind.
    pub kind: &'static str,
    /// The field's label, if it has its own.
    pub label: String,
    /// The value, or `None` while concealed.
    pub value: Option<String>,
    /// Whether the value is concealed.
    pub concealed: bool,
}

/// An item, as shown.
#[derive(Debug, Clone, Serialize)]
pub struct ItemView {
    /// The item ID.
    pub id: String,
    /// The item type.
    #[serde(rename = "type")]
    pub item_type: &'static str,
    /// The title.
    pub title: String,
    /// Fields in order, the title excluded.
    pub fields: Vec<FieldView>,
    /// Creation time, Unix milliseconds.
    pub created_ms: u64,
    /// Last change, Unix milliseconds.
    pub modified_ms: u64,
}

/// A field as typed into the edit form.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldInput {
    /// The field kind.
    pub kind: String,
    /// The field's label.
    #[serde(default)]
    pub label: String,
    /// The value.
    pub value: Zeroizing<String>,
}

/// An item as typed into the edit form.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemInput {
    /// The item type.
    #[serde(rename = "type")]
    pub item_type: String,
    /// The title.
    pub title: String,
    /// The other fields.
    pub fields: Vec<FieldInput>,
}

/// The list entry for an item.
pub fn summary(id: &ItemId, item: &Item) -> ItemSummary {
    let subtitle = first(item, FieldKind::Username)
        .or_else(|| first(item, FieldKind::Url))
        .or_else(|| first(item, FieldKind::CardholderName))
        .map(str::to_owned)
        .unwrap_or_else(|| match item.item_type {
            ItemType::SecureNote => "Secure note".into(),
            ItemType::Card => "Card".into(),
            ItemType::Identity => "Identity".into(),
            ItemType::ApiCredential => "API credential".into(),
            _ => "Login".into(),
        });
    ItemSummary {
        id: wire::b64(id.as_bytes()),
        item_type: type_name(item.item_type),
        title: first(item, FieldKind::Title)
            .unwrap_or("Untitled")
            .to_owned(),
        subtitle,
        modified_ms: item.modified_ms,
    }
}

/// The detail view of an item, concealed values left out.
pub fn view(id: &ItemId, item: &Item) -> ItemView {
    let mut title_seen = false;
    let fields = item
        .fields
        .iter()
        .filter(|f| {
            // The first title is the heading; any others are shown as fields.
            let heading = f.kind == FieldKind::Title && !title_seen;
            title_seen |= f.kind == FieldKind::Title;
            !heading
        })
        .map(|f| {
            let (kind, concealed) = kind_info(f.kind);
            FieldView {
                kind,
                label: f.label.clone(),
                value: (!concealed).then(|| f.value.to_string()),
                concealed,
            }
        })
        .collect();
    ItemView {
        id: wire::b64(id.as_bytes()),
        item_type: type_name(item.item_type),
        title: first(item, FieldKind::Title)
            .unwrap_or("Untitled")
            .to_owned(),
        fields,
        created_ms: item.created_ms,
        modified_ms: item.modified_ms,
    }
}

/// The field at `index` in [`view`]'s order.
///
/// # Errors
///
/// Returns [`AppError::NotFound`] if there is no such field.
pub fn field_at(item: &Item, index: usize) -> Result<&Field, AppError> {
    let heading = item.fields.iter().position(|f| f.kind == FieldKind::Title);
    item.fields
        .iter()
        .enumerate()
        .filter(|(i, _)| Some(*i) != heading)
        .map(|(_, f)| f)
        .nth(index)
        .ok_or(AppError::NotFound)
}

/// Builds an item from the edit form. Empty fields are dropped.
///
/// # Errors
///
/// Returns [`AppError::InvalidItem`] for an unknown type or field kind, or
/// a missing title.
pub fn build(input: &ItemInput, created_ms: u64, now_ms: u64) -> Result<Item, AppError> {
    let item_type = TYPES
        .iter()
        .find(|(n, _)| *n == input.item_type)
        .map(|(_, t)| *t)
        .ok_or(AppError::InvalidItem)?;
    let title = input.title.trim();
    if title.is_empty() {
        return Err(AppError::InvalidItem);
    }
    let mut fields = vec![Field::new(FieldKind::Title, title)];
    for f in &input.fields {
        let kind = KINDS
            .iter()
            .find(|(n, _, _)| *n == f.kind)
            .map(|(_, k, _)| *k)
            .ok_or(AppError::InvalidItem)?;
        if f.value.trim().is_empty() {
            continue;
        }
        if kind == FieldKind::TotpSecret {
            crate::totp::Totp::parse(&f.value)?;
        }
        fields.push(Field::labelled(kind, f.label.trim(), &f.value));
    }
    Ok(Item {
        item_type,
        created_ms,
        modified_ms: now_ms,
        fields,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login() -> Item {
        Item {
            item_type: ItemType::Login,
            created_ms: 1,
            modified_ms: 2,
            fields: vec![
                Field::new(FieldKind::Title, "Northwind Bank"),
                Field::new(FieldKind::Username, "alex.r@example.com"),
                Field::new(FieldKind::Password, "Xq7#vL0o-Wd2!kO1"),
                Field::new(FieldKind::Url, "https://northwind.example"),
            ],
        }
    }

    #[test]
    fn views_never_carry_concealed_values() {
        let id = ItemId::from_bytes([1; 16]);
        let v = view(&id, &login());
        assert_eq!(v.title, "Northwind Bank");
        assert_eq!(v.fields.len(), 3);
        let password = v.fields.iter().find(|f| f.kind == "password");
        assert!(password.is_some_and(|f| f.concealed && f.value.is_none()));
        let json = serde_json::to_string(&v).unwrap_or_default();
        assert!(!json.contains("Xq7#"));

        let s = summary(&id, &login());
        assert_eq!(s.subtitle, "alex.r@example.com");
    }

    #[test]
    fn field_indexes_match_the_view() -> Result<(), AppError> {
        let item = login();
        assert_eq!(field_at(&item, 1)?.value.as_str(), "Xq7#vL0o-Wd2!kO1");
        assert_eq!(field_at(&item, 3), Err(AppError::NotFound));
        Ok(())
    }

    #[test]
    fn building_from_the_form() -> Result<(), AppError> {
        let input = ItemInput {
            item_type: "login".into(),
            title: "  Mail ".into(),
            fields: vec![
                FieldInput {
                    kind: "username".into(),
                    label: String::new(),
                    value: Zeroizing::new("alex".into()),
                },
                FieldInput {
                    kind: "url".into(),
                    label: String::new(),
                    value: Zeroizing::new("  ".into()),
                },
            ],
        };
        let item = build(&input, 5, 9)?;
        assert_eq!(item.fields.len(), 2);
        assert_eq!(item.fields.first().map(|f| f.value.as_str()), Some("Mail"));
        assert_eq!(item.created_ms, 5);

        let bad = ItemInput {
            item_type: "spaceship".into(),
            title: "x".into(),
            fields: vec![],
        };
        assert_eq!(build(&bad, 0, 0).err(), Some(AppError::InvalidItem));
        Ok(())
    }
}
