use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const DEFAULT_API_URL: &str = "https://api.ectf.mitre.org";

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub token: String,
    pub git_url: String,
    #[serde(default = "default_api_url")]
    pub api_url: String,
}

fn default_api_url() -> String {
    DEFAULT_API_URL.to_string()
}

impl Config {
    pub fn path() -> Result<PathBuf> {
        let home = std::env::var("HOME").context("HOME not set")?;
        Ok(PathBuf::from(home).join(".ectf-config"))
    }

    pub fn exists() -> bool {
        Self::path().map(|p| p.exists()).unwrap_or(false)
    }

    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        let contents = std::fs::read_to_string(&path).with_context(|| {
            format!(
                "Config not found at {}. Run `ectf-tools config` first.",
                path.display()
            )
        })?;
        serde_yaml::from_str(&contents).context("Failed to parse config file")
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        let contents = serde_yaml::to_string(self)?;
        std::fs::write(&path, contents)?;
        Ok(())
    }
}
