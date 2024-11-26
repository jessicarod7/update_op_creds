use std::{
    collections::HashMap,
    fmt::{Display, Formatter},
    process::Command,
    vec::IntoIter,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// New creds to update
#[derive(Clone, Debug, Eq, PartialEq, Hash, Deserialize)]
pub struct Creds {
    pub issuers: Vec<CredsIssuer>,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Deserialize)]
pub struct CredsIssuer {
    pub issuer: String,
    pub credentials: Vec<Cred>,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Deserialize)]
pub struct Cred {
    pub name: String,
    pub value: String,
}

/// Iterates through [`Creds`] and retrieves the JSON template associated with each credential.
pub struct CredJsonIter {
    vault_name: String,
    vault_item_list: Vec<OnePasswordListItem>,
    issuer_iter: IntoIter<CredsIssuer>,
    issuer_name: String,
    cred_iter: IntoIter<Cred>,
}

impl Iterator for CredJsonIter {
    type Item = (OnePasswordItem, Cred);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(cred) = self.cred_iter.next() {
            // Search for credentials
            let cred_name = cred.name.to_lowercase();
            if let Some(item) = self.vault_item_list.iter().find(|item| {
                item.title
                    .contains(&format!("{} {}", self.issuer_name, cred_name))
            }) {
                let item_template = Command::new("op")
                    .args(["item", "get", &item.id, "--format", "json"])
                    .output()
                    .expect("failed to retrieve vault item")
                    .stdout;
                Some((
                    serde_json::from_slice::<OnePasswordItem>(item_template.as_slice())
                        .expect("failed to parse vault item"),
                    cred,
                ))
            } else {
                eprintln!(
                    "warn: {{issuer={},cred={}}} not found in vault {}, skipping",
                    self.issuer_name, cred_name, self.vault_name
                );
                self.next()
            }
        } else {
            // Get next issuer
            if let Some(iss) = self.issuer_iter.next() {
                self.issuer_name = iss.issuer.to_lowercase();
                self.cred_iter = iss.credentials.into_iter();
                println!("Issuer: {}", self.issuer_name);
                self.next()
            } else {
                None
            }
        }
    }
}

impl Creds {
    /// Create an iterator to return template for all credentials
    pub fn iter_templates(self, vault_name: &str) -> CredJsonIter {
        // Retrieve vault items, set title to lowercase
        let vault_item_output = Command::new("op")
            .args(["item", "list", "--vault", vault_name, "--format", "json"])
            .output()
            .unwrap_or_else(|err| panic!("failed to retrieve items from vault {vault_name}: {err}"))
            .stdout;
        let vault_item_list: Vec<_> =
            serde_json::from_slice::<Vec<OnePasswordListItem>>(vault_item_output.as_slice())
                .expect("failed to parse vault items")
                .into_iter()
                .map(|item| OnePasswordListItem {
                    title: item.title.to_lowercase(),
                    ..item
                })
                .collect();

        // Setup iterators
        let mut issuer_iter = self.issuers.into_iter();
        let first_issuer = issuer_iter
            .next()
            .expect("no issuers of new credentials found");
        let issuer_name = first_issuer.issuer.to_lowercase();

        println!("Issuer: {issuer_name}");
        CredJsonIter {
            vault_name: vault_name.to_string(),
            vault_item_list,
            issuer_iter,
            issuer_name,
            cred_iter: first_issuer.credentials.into_iter(),
        }
    }
}

/// `op item list`
#[derive(Clone, Debug, Eq, PartialEq, Hash, Deserialize)]
pub struct OnePasswordListItem {
    pub id: String,
    pub title: String,
}

/// Reference: [1Password CLI Documentation - Item JSON template](https://developer.1password.com/docs/cli/item-template-json/)
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OnePasswordItem {
    pub id: String,
    pub title: String,
    pub category: String,
    pub sections: Option<Vec<ItemSection>>,
    pub fields: Option<Vec<ItemField>>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

impl Display for OnePasswordItem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (id: {})", self.title, self.id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ItemSection {
    pub id: String,
    pub label: String,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ItemField {
    /// If this matches a category built-in field, the type does not need to be specified.
    pub id: String,
    pub section: Option<ItemFieldSection>,
    #[serde(rename = "type")]
    pub item_type: ItemType,
    pub label: Option<String>,
    pub value: Option<String>,
    pub reference: String,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ItemFieldSection {
    pub id: String,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

/// Reference: [1Password CLI Documentation - Item Fields](https://developer.1password.com/docs/cli/item-fields/)
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ItemType {
    /// A concealed password.
    Concealed,
    String,
    Email,
    Url,
    /// `YYYY-MM-DD`
    Date,
    /// `YYYYMM` or `YYYY/MM`
    MonthYear,
    Phone,
    /// Accepts `otpauth://` URI
    Otp,
    /// An undocumented field. For example, used by the `type` field in API Credential items
    Menu,
    #[serde(untagged)]
    Unknown,
}

impl ItemType {
    /// The `fieldType` can be used with assignment statements in CLI arguments.
    #[allow(dead_code)]
    pub fn field_type(&self) -> &'static str {
        match self {
            Self::Concealed => "password",
            Self::String => "text",
            Self::Email => "email",
            Self::Url => "url",
            Self::Date => "date",
            Self::MonthYear => "monthYear",
            Self::Phone => "phone",
            Self::Otp => "otp",
            Self::Menu => "menu",
            Self::Unknown => panic!("unrecognized field type"),
        }
    }

    /// The `file` fieldType accepts the path to a file, and can only be used with assignment
    /// statements.
    #[allow(dead_code)]
    pub fn file() -> &'static str {
        "file"
    }
}
