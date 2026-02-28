//! Minimal HCL-style configuration parser.
//!
//! Supports the subset of HCL needed for Plumbum config:
//! - Block declarations: `block_name { ... }`
//! - Key-value pairs: `key = value` (string, number)
//! - Comments: `#` and `//`

use crate::types::*;
use std::path::Path;

/// Parse a config file at the given path.
pub fn parse_config_file(path: &Path) -> Result<PlumbumConfig, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config: {}", e))?;
    parse_config(&content)
}

/// Parse HCL-style config string into PlumbumConfig.
pub fn parse_config(input: &str) -> Result<PlumbumConfig, String> {
    let mut config = PlumbumConfig::default();
    let mut current_block: Option<String> = None;

    for (line_num, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }

        // Block open
        if line.ends_with('{') {
            let block_name = line.trim_end_matches('{').trim();
            current_block = Some(block_name.to_string());
            continue;
        }

        // Block close
        if line == "}" {
            current_block = None;
            continue;
        }

        // Key = value
        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim();
            let val = line[eq_pos + 1..].trim().trim_matches('"');

            match current_block.as_deref() {
                Some("analysis") => {
                    match key {
                        "entropy_weight" => config.analysis.entropy_weight = parse_f64(val, line_num)?,
                        "periodicity_weight" => config.analysis.periodicity_weight = parse_f64(val, line_num)?,
                        "volume_weight" => config.analysis.volume_weight = parse_f64(val, line_num)?,
                        "length_weight" => config.analysis.length_weight = parse_f64(val, line_num)?,
                        "client_rarity_weight" => config.analysis.client_rarity_weight = parse_f64(val, line_num)?,
                        "subdomain_diversity_weight" => config.analysis.subdomain_diversity_weight = parse_f64(val, line_num)?,
                        "weight_preset" => config.analysis.weight_preset = Some(val.to_string()),
                        _ => return Err(format!("Line {}: unknown analysis key '{}'", line_num + 1, key)),
                    }
                }
                Some("thresholds") => {
                    match key {
                        "critical" => config.thresholds.critical = parse_f64(val, line_num)?,
                        "high" => config.thresholds.high = parse_f64(val, line_num)?,
                        "medium" => config.thresholds.medium = parse_f64(val, line_num)?,
                        _ => return Err(format!("Line {}: unknown thresholds key '{}'", line_num + 1, key)),
                    }
                }
                Some(block) => return Err(format!("Line {}: unknown block '{}'", line_num + 1, block)),
                None => return Err(format!("Line {}: key-value outside block", line_num + 1)),
            }
        }
    }

    Ok(config)
}

fn parse_f64(val: &str, line_num: usize) -> Result<f64, String> {
    val.parse::<f64>()
        .map_err(|_| format!("Line {}: invalid number '{}'", line_num + 1, val))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::defaults::DEFAULT_CONFIG_HCL;

    #[test]
    fn test_parse_default_config() {
        let config = parse_config(DEFAULT_CONFIG_HCL).unwrap();
        assert!((config.thresholds.critical - 80.0).abs() < 0.01);
        assert!((config.thresholds.high - 60.0).abs() < 0.01);
        assert!((config.analysis.client_rarity_weight - 1.80).abs() < 0.01);
        assert_eq!(config.analysis.weight_preset.as_deref(), Some("regularized"));
    }

    #[test]
    fn test_parse_with_comments() {
        let input = r#"
# This is a comment
analysis {
  entropy_weight = 1.0
  // Another comment
  periodicity_weight = 2.0
  volume_weight = 0.5
  length_weight = 0.8
  client_rarity_weight = 0.6
  subdomain_diversity_weight = 0.0
}

thresholds {
  critical = 90
  high = 70
  medium = 50
}
"#;
        let config = parse_config(input).unwrap();
        assert!((config.analysis.entropy_weight - 1.0).abs() < 0.01);
        assert!((config.thresholds.critical - 90.0).abs() < 0.01);
    }
}
