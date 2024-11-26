use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

use clap::Parser;

use crate::templates::{Creds, ItemType};

mod templates;

#[derive(Debug, Parser)]
struct Cli {
    /// Path to the updated credentials
    credentials: PathBuf,
    /// 1Password vault to update credentials in
    vault: String,
    /// Run commands without uploading edits
    #[arg(short = 'n', long)]
    dry_run: bool,
}

fn main() {
    let args = Cli::parse();
    let creds: Creds = toml::from_str(
        &fs::read_to_string(args.credentials).expect("failed to read credentials file"),
    )
    .expect("failed to parse credentials file");

    for (mut item, cred) in creds.iter_templates(&args.vault) {
        if item.fields.is_none() {
            eprintln!("warn: item {item} has no fields, skipping");
            continue;
        };

        let concealed_fields: Vec<_> = item
            .fields
            .as_ref()
            .unwrap()
            .iter()
            .filter(|field| field.item_type == ItemType::Concealed)
            .collect();

        // Assume we are modifying an API credential, otherwise pick the first field not in a
        // section, then the first field.
        let field_id = concealed_fields
            .iter()
            .find(|field| field.section.is_none() && field.id == "credential")
            .or_else(|| {
                concealed_fields
                    .iter()
                    .find(|field| field.section.is_none())
            })
            .or_else(|| concealed_fields.first())
            .map(|inner| inner.id.to_owned());

        if let Some(id) = &field_id {
            item.fields
                .as_mut()
                .unwrap()
                .iter_mut()
                .find(|item| &item.id == id)
                .unwrap()
                .value = Some(cred.value)
        } else {
            eprintln!("unable to find credential field in item {}", item)
        }

        // Save updated credential to 1Password
        let updated_item = serde_json::to_vec(&item).expect("failed to serialize updated item");

        if !args.dry_run {
            let mut edit_cmd = Command::new("op")
                .args(["item", "edit", &item.id])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .spawn()
                .expect("failed to spawn 1Password edit command");

            let mut edit_stdin = edit_cmd
                .stdin
                .take()
                .expect("failed to open pipe to 1Password edit command");
            std::thread::spawn(move || {
                edit_stdin
                    .write_all(updated_item.as_slice())
                    .expect("failed to write updated item to pipe")
            });

            let status = edit_cmd.wait().expect("1Password edit command failed");
            if !status.success() {
                panic!("1Password CLI unexpectedly exited: {status}")
            }
        }

        let field_name = if let Some(label) = item
            .fields
            .as_ref()
            .unwrap()
            .iter()
            .find(|field| &field.id == field_id.as_ref().unwrap())
            .unwrap()
            .label
            .as_ref()
        {
            label
        } else {
            &field_id.unwrap()
        };

        println!(
            r#"placed credential "{}" into field "{}" of vault item {item}"#,
            cred.name, field_name
        );
        continue;
    }
}
