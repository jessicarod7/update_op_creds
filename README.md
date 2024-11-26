# A sketchy script to update credentials in 1Password

I make no guarantees of this tool. It's a dirty way to update API credentials via the 1Password CLI.

## Installation

This tool requires Cargo ([install from here](https://www.rust-lang.org/tools/install)), the [1Password CLI](https://developer.1password.com/docs/cli), and an active 1Password account. Clone this repo, open the directory, and run `cargo install --path .`

## How to use the tool

1. Create a TOML file like this:
   ```toml
   [[issuers]]
   issuer = "GitLab"
   credentials = [
       {name = "cli PAT", value = "XXXXXXXX"},
       {name = "another token", value = "XXXXXXXXX"},
   ]
   [[issuers]]
   issuer = "GitHub"
   credentials = [
       {name = "cli PAT", value = "XXXXXXXX"},
       {name = "Git-over-HTTPS", value = "XXXXXXXXX"},
   ]
   ```
   Reformat however you like, as long as it creates equivalent TOML. The issuer and credential name will be concatenated to search, by title. For example, the first entry will find the first vault item with a title containing `"gitlab cli pat"` (all values are converted to lowercase). Yes, this means the `issuer` field is nothing particularly special — it's just for your own organization.
2. Run the command: `update_op_creds <path to credential file> <1Password vault name>`. The tool will search in the following order for the field to update:
   1. The first concealed-type (i.e. password) field which is not part of any section, and has ID "credential" (this is the built-in field for _API Credential_ items).
   2. The first concealed-type field which is not part of any section.
   3. The first concealed-type field.
3. The 1Password item is updated.

## License

Available under the [Apache License 2.0](./LICENSE).