use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeltaPatch {
    pub patch_version: u64,
    pub added_rules: Vec<String>,
    pub removed_rules: Vec<String>,
}

/// Applies an incremental delta patch to a target YARA rules file atomically.
pub fn apply_delta_patch(rules_file: &Path, patch: &DeltaPatch) -> io::Result<usize> {
    let mut current_content = if rules_file.exists() {
        fs::read_to_string(rules_file)?
    } else {
        String::new()
    };

    // 1. Remove rules
    for removed in &patch.removed_rules {
        current_content = current_content.replace(removed, "");
    }

    // 2. Add new rules
    for added in &patch.added_rules {
        if !current_content.contains(added) {
            current_content.push_str("\n\n");
            current_content.push_str(added);
        }
    }

    // 3. Write atomically via temp file swap
    let parent = rules_file.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temp_file = parent.join(format!(".tmp_rules_{}", std::process::id()));
    fs::write(&temp_file, &current_content)?;
    fs::rename(&temp_file, rules_file)?;

    Ok(patch.added_rules.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_delta_patch_atomic() {
        let temp_dir = std::env::temp_dir().join(format!("sentinel_delta_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let rules_file = temp_dir.join("active_rules.yar");
        fs::write(&rules_file, "rule Old_Rule { strings: $a = \"old\" condition: $a }").unwrap();

        let patch = DeltaPatch {
            patch_version: 2,
            added_rules: vec!["rule New_Trojan_Rule { strings: $b = \"trojan\" condition: $b }".into()],
            removed_rules: vec!["rule Old_Rule { strings: $a = \"old\" condition: $a }".into()],
        };

        let added = apply_delta_patch(&rules_file, &patch).unwrap();
        assert_eq!(added, 1);

        let updated = fs::read_to_string(&rules_file).unwrap();
        assert!(!updated.contains("Old_Rule"));
        assert!(updated.contains("New_Trojan_Rule"));

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
