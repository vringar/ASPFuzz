//! Optional value dictionary for the mailbox mutator, loaded from a JSON/YAML file named by the yaml
//! key `mailbox_dict`. Generated from the (local-only) protocol catalog by `amd_sp/tools/gen_mailbox_dict.py`;
//! the generated file is not committed.
use std::{fs::File, path::Path};

use serde::Deserialize;

/// One argument field inside the mailbox argument buffer.
#[derive(Clone, Debug, Deserialize)]
pub struct DictField {
    /// byte offset inside the argument buffer
    pub offset: usize,
    /// 1, 4 or 8
    pub size: usize,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DictCommand {
    pub id: u32,
    #[serde(default)]
    pub fields: Vec<DictField>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct MailboxDict {
    /// commands to try (handled ids first, then negative controls)
    pub commands: Vec<DictCommand>,
    /// extra u32 values for arguments (sizes, flag masks, window edges)
    #[serde(default)]
    pub values: Vec<u32>,
    /// interesting values for the low 12 bits of the command-buffer address
    #[serde(default)]
    pub buf_lo_low12: Vec<u32>,
}

impl MailboxDict {
    /// # Panics
    /// If the file cannot be read or parsed.
    #[must_use]
    pub fn load(path: &Path) -> Self {
        let file = File::open(path).expect("Unable to open mailbox_dict");
        serde_yaml::from_reader(file).expect("Unable to parse mailbox_dict")
    }
}
