//! Reads CSV exports from other password managers.
//!
//! The format is recognised from the header row, so files from Bitwarden,
//! 1Password, Chrome, Edge, Firefox, Safari, LastPass, KeePass, KeePassXC,
//! Dashlane, NordPass, Proton Pass and similar exports all work. Folders
//! and tags are kept as labelled fields, and Bitwarden's custom fields as
//! hidden fields. Every value is held in memory that is wiped when dropped,
//! and nothing from the file goes to the window except titles and counts.

use std::collections::BTreeSet;

use serde::Serialize;
use vault_core::{Field, FieldKind, Item, ItemType, MAX_LABEL_BYTES, MAX_VALUE_BYTES};
use zeroize::Zeroizing;

use crate::error::AppError;

/// Largest file accepted.
pub const MAX_FILE_BYTES: u64 = 20 << 20;
/// Most rows accepted.
const MAX_ROWS: usize = 10_000;

/// Header names for each field, lowercase, in order of preference.
const TITLE: &[&str] = &["title", "name"];
const USERNAME: &[&str] = &["username", "login_username", "login", "email", "username2"];
const PASSWORD: &[&str] = &["password", "login_password"];
const URL: &[&str] = &["url", "login_uri", "website", "uri", "web site", "hostname"];
const NOTES: &[&str] = &["notes", "note", "extra", "comments"];
const TOTP: &[&str] = &[
    "totp",
    "login_totp",
    "otpauth",
    "otpsecret",
    "otp",
    "one-time password",
];
const TYPE: &[&str] = &["type"];
const FOLDER: &[&str] = &[
    "folder",
    "grouping",
    "group",
    "category",
    "collection",
    "vault",
];
const TAGS: &[&str] = &["tags", "tag", "labels"];
/// Bitwarden's custom fields: one `name: value` per line.
const CUSTOM: &[&str] = &["fields"];

/// Folder names that mean "no folder".
const NO_FOLDER: &[&str] = &["(none)", "root", "none", "unfiled"];

/// Most custom fields kept from one row.
const MAX_CUSTOM: usize = 50;

/// What an import file holds, shown before anything is saved.
#[derive(Debug, Clone, Serialize)]
pub struct Preview {
    /// The app the file most likely came from.
    pub source: &'static str,
    /// Logins found.
    pub logins: usize,
    /// Secure notes found.
    pub notes: usize,
    /// Rows left out because they were empty or unreadable.
    pub skipped: usize,
    /// Different folders found, kept as a "Folder" field on each item.
    pub folders: usize,
    /// Custom fields found, kept as hidden fields.
    pub custom_fields: usize,
    /// The first few titles, so the user can check it is the right file.
    pub sample: Vec<String>,
}

/// A parsed file: the items and the preview.
pub struct Parsed {
    /// Items to import.
    pub items: Vec<Item>,
    /// What to show the user.
    pub preview: Preview,
}

impl core::fmt::Debug for Parsed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Parsed")
            .field("preview", &self.preview)
            .finish_non_exhaustive()
    }
}

fn find(headers: &[String], names: &[&str]) -> Option<usize> {
    names
        .iter()
        .find_map(|n| headers.iter().position(|h| h == n))
}

fn source(headers: &[String]) -> &'static str {
    let has = |h: &str| headers.iter().any(|x| x == h);
    if has("login_uri") && has("login_password") {
        "Bitwarden"
    } else if has("otpauth") && has("archived") {
        "1Password"
    } else if has("httprealm") || has("formactionorigin") {
        "Firefox"
    } else if has("grouping") && has("extra") {
        "LastPass"
    } else if has("group") && has("title") && has("last modified") {
        "KeePass or KeePassXC"
    } else if has("username2") || has("otpsecret") {
        "Dashlane"
    } else if has("vault") && has("createtime") {
        "Proton Pass"
    } else if has("name") && has("url") && has("note") && headers.len() <= 5 {
        "Chrome, Edge or Brave"
    } else if has("title") && has("otpauth") {
        "Safari"
    } else {
        "a CSV file"
    }
}

/// A host name to use as the title when a row has none.
fn host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let host = rest.split(['/', '?', '#', ':']).next()?.trim();
    let host = host.strip_prefix("www.").unwrap_or(host);
    (!host.is_empty()).then(|| host.to_owned())
}

/// Cuts `v` to at most `max` bytes, at a character boundary.
fn cut(v: &str, max: usize) -> &str {
    let mut end = v.len().min(max);
    while !v.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    v.get(..end).unwrap_or_default()
}

/// Reads Bitwarden's custom fields, one `name: value` per line.
fn custom_fields(text: &str) -> Vec<Field> {
    text.lines()
        .filter_map(|line| {
            let (name, value) = line.split_once(": ").or_else(|| line.split_once(':'))?;
            let (name, value) = (name.trim(), value.trim());
            (!name.is_empty() && !value.is_empty()).then(|| {
                Field::labelled(
                    FieldKind::CustomConcealed,
                    cut(name, MAX_LABEL_BYTES),
                    cut(value, MAX_VALUE_BYTES),
                )
            })
        })
        .take(MAX_CUSTOM)
        .collect()
}

fn value(record: &csv::StringRecord, index: Option<usize>) -> Option<Zeroizing<String>> {
    // Values longer than an item allows are cut at a character boundary.
    let v = cut(record.get(index?)?.trim(), MAX_VALUE_BYTES);
    (!v.is_empty()).then(|| Zeroizing::new(v.to_owned()))
}

/// Parses a CSV export.
///
/// # Errors
///
/// Returns [`AppError::ImportUnreadable`] if it is not a CSV file with a
/// password or notes column, or [`AppError::ImportTooLarge`].
pub fn parse(bytes: &[u8], now_ms: u64) -> Result<Parsed, AppError> {
    let text = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::None)
        .from_reader(text);
    let headers: Vec<String> = reader
        .headers()
        .map_err(|_| AppError::ImportUnreadable)?
        .iter()
        .map(|h| h.trim().to_lowercase())
        .collect();
    let col = |names| find(&headers, names);
    let (title, username, password, url, notes, totp, kind) = (
        col(TITLE),
        col(USERNAME),
        col(PASSWORD),
        col(URL),
        col(NOTES),
        col(TOTP),
        col(TYPE),
    );
    let (folder, tags, custom) = (col(FOLDER), col(TAGS), col(CUSTOM));
    let mut folders = BTreeSet::new();
    let mut custom_count = 0_usize;
    if password.is_none() && notes.is_none() {
        return Err(AppError::ImportUnreadable);
    }

    let mut items = Vec::new();
    let mut skipped = 0_usize;
    let mut record = csv::StringRecord::new();
    loop {
        match reader.read_record(&mut record) {
            Ok(false) => break,
            Ok(true) => {}
            Err(_) => {
                skipped = skipped.saturating_add(1);
                continue;
            }
        }
        if items.len() >= MAX_ROWS {
            return Err(AppError::ImportTooLarge);
        }
        let get = |i| value(&record, i);
        let (pw, user, link, note, code) = (
            get(password),
            get(username),
            get(url),
            get(notes),
            get(totp),
        );
        let is_note = get(kind).is_some_and(|k| {
            matches!(
                k.to_lowercase().as_str(),
                "note" | "securenote" | "secure note" | "2"
            )
        }) || (pw.is_none() && user.is_none() && link.is_none() && note.is_some());
        let heading = get(title)
            .map(|t| t.to_string())
            .or_else(|| link.as_deref().and_then(|l| host(l)))
            .or_else(|| user.as_ref().map(|u| u.to_string()));
        let Some(heading) = heading else {
            skipped = skipped.saturating_add(1);
            continue;
        };
        if pw.is_none() && note.is_none() && user.is_none() {
            skipped = skipped.saturating_add(1);
            continue;
        }
        let mut fields = vec![Field::new(FieldKind::Title, &heading)];
        for (kind, v) in [
            (FieldKind::Username, user),
            (FieldKind::Password, pw),
            (FieldKind::Url, link),
            (FieldKind::TotpSecret, code),
            (FieldKind::Notes, note),
        ] {
            if let Some(v) = v {
                fields.push(Field::new(kind, &v));
            }
        }
        let extra = get(custom).map(|c| custom_fields(&c)).unwrap_or_default();
        custom_count = custom_count.saturating_add(extra.len());
        fields.extend(extra);
        if let Some(f) = get(folder).filter(|f| !NO_FOLDER.contains(&f.to_lowercase().as_str())) {
            fields.push(Field::labelled(FieldKind::CustomText, "Folder", &f));
            folders.insert(f.to_string());
        }
        if let Some(t) = get(tags) {
            fields.push(Field::labelled(FieldKind::CustomText, "Tags", &t));
        }
        items.push(Item {
            item_type: if is_note {
                ItemType::SecureNote
            } else {
                ItemType::Login
            },
            created_ms: now_ms,
            modified_ms: now_ms,
            fields,
        });
    }
    if items.is_empty() {
        return Err(AppError::ImportUnreadable);
    }

    let notes_count = items
        .iter()
        .filter(|i| i.item_type == ItemType::SecureNote)
        .count();
    let sample = items
        .iter()
        .take(5)
        .filter_map(|i| i.fields.first().map(|f| f.value.to_string()))
        .collect();
    Ok(Parsed {
        preview: Preview {
            source: source(&headers),
            logins: items.len().saturating_sub(notes_count),
            notes: notes_count,
            skipped,
            folders: folders.len(),
            custom_fields: custom_count,
            sample,
        },
        items,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(item: &Item, kind: FieldKind) -> Option<&str> {
        item.fields
            .iter()
            .find(|f| f.kind == kind)
            .map(|f| f.value.as_str())
    }

    fn labelled<'a>(item: &'a Item, label: &str) -> Option<(&'a str, FieldKind)> {
        item.fields
            .iter()
            .find(|f| f.label == label)
            .map(|f| (f.value.as_str(), f.kind))
    }

    #[test]
    fn folders_tags_and_custom_fields() -> Result<(), AppError> {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                   Work,,login,VPN,,\"PIN: 4321\nRegion: eu-west\",0,https://vpn.example,alex,pw,\n\
                   ,,login,Mail,,,0,https://mail.example,alex,pw2,\n\
                   Work,,login,Wiki,,bad line,0,https://wiki.example,alex,pw3,\n";
        let p = parse(csv.as_bytes(), 7)?;
        assert_eq!((p.preview.folders, p.preview.custom_fields), (1, 2));
        let vpn = p.items.first().ok_or(AppError::Internal)?;
        assert_eq!(
            labelled(vpn, "Folder"),
            Some(("Work", FieldKind::CustomText))
        );
        assert_eq!(
            labelled(vpn, "PIN"),
            Some(("4321", FieldKind::CustomConcealed))
        );
        assert_eq!(
            labelled(vpn, "Region"),
            Some(("eu-west", FieldKind::CustomConcealed))
        );
        let mail = p.items.get(1).ok_or(AppError::Internal)?;
        assert_eq!(labelled(mail, "Folder"), None);

        let lastpass = "url,username,password,totp,extra,name,grouping,fav\n\
                        https://a.example,u,p,,,A,(none),0\n\
                        https://b.example,u,p,,,B,Shopping,0\n";
        let p = parse(lastpass.as_bytes(), 1)?;
        assert_eq!(p.preview.folders, 1);
        let one = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n\
                   Mail,https://mail.example,alex,pw,,false,false,\"home, email\",\n";
        let p = parse(one.as_bytes(), 1)?;
        let mail = p.items.first().ok_or(AppError::Internal)?;
        assert_eq!(
            labelled(mail, "Tags"),
            Some(("home, email", FieldKind::CustomText))
        );
        Ok(())
    }

    #[test]
    fn bitwarden() -> Result<(), AppError> {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                   ,,login,Northwind Bank,,,0,https://northwind.example,alex,\"pa,ss\"\"word\",\n\
                   ,,note,Wi-Fi,\"Network: Lantern\nKey: 1234\",,0,,,,\n";
        let p = parse(csv.as_bytes(), 7)?;
        assert_eq!(p.preview.source, "Bitwarden");
        assert_eq!((p.preview.logins, p.preview.notes), (1, 1));
        let bank = p.items.first().ok_or(AppError::Internal)?;
        assert_eq!(field(bank, FieldKind::Password), Some("pa,ss\"word"));
        assert_eq!(
            field(bank, FieldKind::Url),
            Some("https://northwind.example")
        );
        let wifi = p.items.get(1).ok_or(AppError::Internal)?;
        assert_eq!(wifi.item_type, ItemType::SecureNote);
        assert_eq!(
            field(wifi, FieldKind::Notes),
            Some("Network: Lantern\nKey: 1234")
        );
        Ok(())
    }

    #[test]
    fn chrome_with_a_byte_order_mark() -> Result<(), AppError> {
        let csv = "\u{feff}name,url,username,password,note\n\
                   ,https://www.mail.example/login,alex,secret,\n";
        let p = parse(csv.as_bytes(), 1)?;
        assert_eq!(p.preview.source, "Chrome, Edge or Brave");
        assert_eq!(p.preview.sample, ["mail.example"]);
        Ok(())
    }

    #[test]
    fn firefox_and_onepassword() -> Result<(), AppError> {
        let firefox = "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\
                       \"https://shop.example\",\"sam\",\"pw1\",,\"\",\"{1}\",\"1\",\"1\",\"1\"\n";
        assert_eq!(parse(firefox.as_bytes(), 1)?.preview.source, "Firefox");
        let one = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n\
                   Mail,https://mail.example,alex,pw,otpauth://totp/x?secret=ABC,false,false,,hi\n";
        let p = parse(one.as_bytes(), 1)?;
        assert_eq!(p.preview.source, "1Password");
        let mail = p.items.first().ok_or(AppError::Internal)?;
        assert_eq!(
            field(mail, FieldKind::TotpSecret),
            Some("otpauth://totp/x?secret=ABC")
        );
        Ok(())
    }

    #[test]
    fn rejects_other_files_and_skips_empty_rows() {
        assert_eq!(
            parse(b"a,b,c\n1,2,3\n", 1).err(),
            Some(AppError::ImportUnreadable)
        );
        assert_eq!(parse(b"", 1).err(), Some(AppError::ImportUnreadable));
        let p = parse(b"name,url,username,password\n,,,\nx,,,pw\n", 1);
        assert!(p.is_ok_and(|p| p.preview.skipped == 1 && p.items.len() == 1));
    }
}
