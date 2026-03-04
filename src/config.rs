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
        // If all required env vars are set, use them directly (for CI)
        if let (Ok(token), Ok(git_url)) = (
            std::env::var("ECTF_TOKEN"),
            std::env::var("ECTF_GIT_URL"),
        ) {
            let api_url = std::env::var("ECTF_API_URL")
                .unwrap_or_else(|_| DEFAULT_API_URL.to_string());
            return Ok(Self { token, git_url, api_url });
        }

        let path = Self::path()?;
        let contents = std::fs::read_to_string(&path).with_context(|| {
            format!(
                "Config not found at {}. Run `ectf-tools config` first, or set ECTF_TOKEN and ECTF_GIT_URL env vars.",
                path.display()
            )
        })?;
        let mut cfg: Self = serde_yaml::from_str(&contents).context("Failed to parse config file")?;

        // Allow env vars to override individual fields from the config file
        if let Ok(token) = std::env::var("ECTF_TOKEN") {
            cfg.token = token;
        }
        if let Ok(git_url) = std::env::var("ECTF_GIT_URL") {
            cfg.git_url = git_url;
        }
        if let Ok(api_url) = std::env::var("ECTF_API_URL") {
            cfg.api_url = api_url;
        }

        Ok(cfg)
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        let contents = serde_yaml::to_string(self)?;
        std::fs::write(&path, contents)?;
        Ok(())
    }
}
