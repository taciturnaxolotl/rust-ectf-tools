use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};

use anyhow::{Result, bail};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::log;
use crate::serial::open_serial;

const PAGE_SIZE: usize = 8192;
const APP_PAGES: usize = 28;
const TOTAL_SIZE: usize = APP_PAGES * PAGE_SIZE;
const BLOCK_SIZE: usize = 16;
const COMPLETE_CODE: u8 = 20;

fn success_codes() -> HashSet<u8> {
    [1, 2, 3, 4, 5, 7, 8, 10, 11, 13, 16, 18, 19, COMPLETE_CODE]
        .into_iter()
        .collect()
}

fn error_codes() -> HashSet<u8> {
    [6, 9, 12, 14, 15, 17].into_iter().collect()
}

pub struct MAX78000FTHR {
    file: File,
}

impl MAX78000FTHR {
    pub fn open(port: &str) -> Result<Self> {
        let file = open_serial(port, Some(5.0))?;
        Ok(Self { file })
    }

    fn verify_resp(&mut self) -> Result<u8> {
        let success = success_codes();
        let errors = error_codes();

        loop {
            let mut buf = [0u8; 1];
            match self.file.read(&mut buf) {
                Ok(0) => continue, // timeout, retry
                Ok(_) => {}
                Err(e) => return Err(e.into()),
            }
            let resp = buf[0];
            if errors.contains(&resp) {
                bail!("Bootloader error response: {resp}");
            }
            if !success.contains(&resp) {
                bail!("Unexpected bootloader response: {resp}");
            }
            return Ok(resp);
        }
    }

    pub fn flash(&mut self, image: &[u8]) -> Result<()> {
        // Pad to TOTAL_SIZE
        let mut padded = image.to_vec();
        if padded.len() < TOTAL_SIZE {
            padded.resize(TOTAL_SIZE, 0xFF);
        }

        // Send update command
        log::info("Requesting update");
        self.file.write_all(&[0x00])?;
        self.file.flush()?;

        self.verify_resp()?;
        self.verify_resp()?;

        // Send image in BLOCK_SIZE chunks
        log::info("Sending image data...");
        let total_blocks = padded.len() / BLOCK_SIZE;
        for (i, chunk) in padded.chunks(BLOCK_SIZE).enumerate() {
            self.file.write_all(chunk)?;
            self.file.flush()?;
            self.verify_resp()?;

            // Print progress every 10%
            let pct = (i + 1) * 100 / total_blocks;
            let prev_pct = i * 100 / total_blocks;
            if pct / 10 > prev_pct / 10 {
                log::info(&format!("  {pct}%"));
            }
        }

        log::info("Waiting for installation...");
        loop {
            if self.verify_resp()? == COMPLETE_CODE {
                break;
            }
        }

        log::success("Update complete");
        Ok(())
    }

    pub fn unlock(&mut self, secrets: &serde_json::Value) -> Result<()> {
        let challenge_key = secrets
            .get("challenge_key")
            .and_then(|v| v.as_str())
            .context("Missing 'challenge_key' in secrets")?;
        let challenge_key = hex_decode(challenge_key)?;

        // Send challenge request
        self.file.write_all(b"GC\r\n")?;
        self.file.flush()?;

        // Read two lines: echo + challenge hex
        let mut reader = BufReader::new(&mut self.file);
        let mut _echo = String::new();
        reader.read_line(&mut _echo)?;
        let mut challenge_hex = String::new();
        reader.read_line(&mut challenge_hex)?;
        let challenge_bytes = hex_decode(challenge_hex.trim())?;

        log::info(&format!("Challenge: {}", hex_encode(&challenge_bytes)));

        // Compute HMAC-SHA256
        type HmacSha256 = Hmac<Sha256>;
        let mut mac =
            HmacSha256::new_from_slice(&challenge_key).map_err(|e| anyhow::anyhow!("{e}"))?;
        mac.update(&challenge_bytes);
        let result = mac.finalize().into_bytes();
        let response_hex = hex_encode(&result).to_uppercase();

        log::info(&format!("Response: {response_hex}"));

        // Send response + unlock
        let resp_line = format!("SR {response_hex}\r\n");
        // Get the inner file back from BufReader
        let file = reader.into_inner();
        file.write_all(resp_line.as_bytes())?;
        file.write_all(b"UNLOCK\r\n")?;
        file.flush()?;

        log::success("Unlock command sent");
        Ok(())
    }
}

use anyhow::Context;

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        bail!("Hex string must have even length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(Into::into))
        .collect()
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}
