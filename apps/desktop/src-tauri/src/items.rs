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
    /// It has a one-time code secret.
    pub has_code: bool,
    /// The website's host name, such as "gmail.com", if it has one.
    pub site: Option<String>,
    /// A change made offline and not yet sent: "new", "edited" or
    /// "conflict".
    pub pending: Option<&'static str>,
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
    let subtitle = card_line(item)
        .or_else(|| first(item, FieldKind::Username).map(str::to_owned))
        .or_else(|| first(item, FieldKind::Url).map(str::to_owned))
        .or_else(|| first(item, FieldKind::CardholderName).map(str::to_owned))
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
        has_code: first(item, FieldKind::TotpSecret).is_some(),
        site: website(item).as_deref().and_then(host),
        pending: None,
    }
}

/// The host name of a web link, without "www.", a port or sign-in details.
fn host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let name = authority.split(':').next().unwrap_or_default();
    let name = name.strip_prefix("www.").unwrap_or(name);
    (!name.is_empty()).then(|| name.to_ascii_lowercase())
}

/// A card's list line: the last four digits and the expiry, like the
/// card itself shows.
fn card_line(item: &Item) -> Option<String> {
    if item.item_type != ItemType::Card {
        return None;
    }
    let digits: Vec<char> = first(item, FieldKind::CardNumber)?
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    let last4: String = digits.iter().skip(digits.len().saturating_sub(4)).collect();
    if last4.is_empty() {
        return None;
    }
    Some(match first(item, FieldKind::CardExpiry) {
        Some(expiry) => format!("•••• {last4} · expires {expiry}"),
        None => format!("•••• {last4}"),
    })
}

/// The item's website as a link to open: http or https only, with
/// `https://` added when no scheme is given.
pub fn website(item: &Item) -> Option<String> {
    let text = first(item, FieldKind::Url)?.trim();
    if text.is_empty() || text.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("https://") || lower.starts_with("http://") {
        Some(text.to_owned())
    } else if text.contains("://") || lower.starts_with("javascript:") || lower.starts_with("data:")
    {
        None
    } else {
        Some(format!("https://{text}"))
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
    fn websites_open_only_as_web_links() {
        let with = |url: &str| Item {
            fields: vec![Field::new(FieldKind::Url, url)],
            ..login()
        };
        assert_eq!(
            website(&login()).as_deref(),
            Some("https://northwind.example")
        );
        assert_eq!(
            website(&with("github.com")).as_deref(),
            Some("https://github.com")
        );
        assert_eq!(
            website(&with("http://intranet.local")).as_deref(),
            Some("http://intranet.local")
        );
        assert_eq!(website(&with("javascript:alert(1)")), None);
        assert_eq!(website(&with("file:///etc/passwd")), None);
        assert_eq!(website(&with("intent://scan#Intent;end")), None);
        assert_eq!(website(&with("a b.com")), None);
        assert_eq!(
            host("https://www.Gmail.com/inbox?x=1").as_deref(),
            Some("gmail.com")
        );
        assert_eq!(
            host("https://me:pw@intranet.local:8443#a").as_deref(),
            Some("intranet.local")
        );
        assert_eq!(host("https://"), None);
    }

    #[test]
    fn cards_list_their_last_four_digits() {
        let card = Item {
            item_type: ItemType::Card,
            created_ms: 1,
            modified_ms: 2,
            fields: vec![
                Field::new(FieldKind::Title, "Visa debit"),
                Field::new(FieldKind::CardholderName, "Alex Rivera"),
                Field::new(FieldKind::CardNumber, "4242 4242 4242 4242"),
                Field::new(FieldKind::CardExpiry, "08/29"),
            ],
        };
        let s = summary(&ItemId::from_bytes([2; 16]), &card);
        assert_eq!(s.subtitle, "•••• 4242 · expires 08/29");
        assert!(!s.has_code);
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
