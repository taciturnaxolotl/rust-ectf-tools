mod log;
mod protocol;

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use protocol::{HSMIntf, Opcode};

const PIN_LEN: usize = 6;
const MAX_NAME_LEN: usize = 32;
const MAX_FILE_LEN: usize = 8192;
const UUID_LEN: usize = 16;

#[derive(Parser)]
#[command(name = "ectf-tools", about = "eCTF host tools")]
struct Cli {
    /// Serial port
    port: String,

    /// Verbosity level (-v, -vv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write a file to the HSM
    Write {
        /// 6-digit PIN
        pin: String,
        /// Slot (0-7)
        slot: u8,
        /// Group ID (decimal or 0x hex)
        gid: String,
        /// Path to file to write
        file: PathBuf,
        /// UUID (hex, 32 chars). Random if omitted.
        #[arg(short, long)]
        uuid: Option<String>,
    },
    /// Read a file from the HSM
    Read {
        /// 6-digit PIN
        pin: String,
        /// Slot (0-7)
        slot: u8,
        /// Output directory
        output_dir: PathBuf,
        /// Overwrite existing file
        #[arg(short, long)]
        force: bool,
    },
    /// List files on the HSM
    List {
        /// 6-digit PIN
        pin: String,
    },
    /// Interrogate files on a connected HSM
    Interrogate {
        /// 6-digit PIN
        pin: String,
    },
    /// Alert the HSM to listen for another HSM
    Listen,
    /// Receive a file from another HSM
    Receive {
        /// 6-digit PIN
        pin: String,
        /// Read slot (0-7)
        read_slot: u8,
        /// Write slot (0-7)
        write_slot: u8,
    },
}

fn parse_gid(s: &str) -> Result<u16> {
    let val = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u16::from_str_radix(hex, 16)?
    } else {
        s.parse()?
    };
    Ok(val)
}

fn validate_pin(pin: &str) -> Result<()> {
    if pin.len() != PIN_LEN {
        bail!("PIN must be exactly {PIN_LEN} characters, got {}", pin.len());
    }
    if !pin.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("PIN must contain only hex digits (0-9, a-f, A-F)");
    }
    Ok(())
}

fn validate_slot(slot: u8) -> Result<()> {
    if slot > 7 {
        bail!("Slot must be 0-7, got {slot}");
    }
    Ok(())
}

fn unpack_files(body: &[u8]) -> Result<Vec<(u8, u16, String)>> {
    if body.len() < 4 {
        bail!("File list response too short");
    }
    let n_files = u32::from_le_bytes(body[0..4].try_into().unwrap()) as usize;
    log::debug(&format!("Reported {n_files} files"));
    let entries = &body[4..];
    let entry_size = 1 + 2 + MAX_NAME_LEN; // 35 bytes
    if entries.len() != n_files * entry_size {
        bail!(
            "Expected {} bytes for {n_files} files, got {}",
            n_files * entry_size,
            entries.len()
        );
    }
    let mut files = Vec::with_capacity(n_files);
    for i in 0..n_files {
        let off = i * entry_size;
        let slot = entries[off];
        let group_id = u16::from_le_bytes(entries[off + 1..off + 3].try_into().unwrap());
        let name_bytes = &entries[off + 3..off + 3 + MAX_NAME_LEN];
        let name = String::from_utf8_lossy(
            &name_bytes[..name_bytes.iter().position(|&b| b == 0).unwrap_or(MAX_NAME_LEN)],
        )
        .into_owned();
        files.push((slot, group_id, name));
    }
    Ok(files)
}

fn main() {
    let cli = Cli::parse();
    log::set_verbosity(cli.verbose);

    if let Err(e) = run(cli) {
        let chain: Vec<String> = e.chain().map(|c| c.to_string()).collect();
        log::error(&chain[0]);
        for cause in &chain[1..] {
            log::error_cause(cause);
        }
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    let mut hsm = HSMIntf::open(&cli.port).context("Failed to open serial port")?;

    match cli.command {
        Command::Write {
            pin,
            slot,
            gid,
            file,
            uuid,
        } => {
            validate_pin(&pin)?;
            validate_slot(slot)?;
            let gid = parse_gid(&gid)?;

            let uuid_bytes: [u8; UUID_LEN] = match uuid {
                Some(hex) => {
                    let bytes = hex_decode(&hex).context("Invalid UUID hex")?;
                    bytes
                        .try_into()
                        .map_err(|v: Vec<u8>| anyhow::anyhow!("UUID must be 16 bytes, got {}", v.len()))?
                }
                None => {
                    let id = uuid::Uuid::new_v4();
                    *id.as_bytes()
                }
            };

            let contents = fs::read(&file).context("Failed to read input file")?;
            if contents.len() > MAX_FILE_LEN {
                bail!(
                    "File too large: {} bytes (max {MAX_FILE_LEN})",
                    contents.len()
                );
            }

            let filename = file
                .file_name()
                .context("No filename")?
                .to_str()
                .context("Filename not UTF-8")?;
            let mut name_buf = [0u8; MAX_NAME_LEN];
            let name_bytes = filename.as_bytes();
            if name_bytes.len() > MAX_NAME_LEN {
                bail!("Filename too long (max {MAX_NAME_LEN} bytes)");
            }
            name_buf[..name_bytes.len()].copy_from_slice(name_bytes);

            // Pack frame: pin(6) + slot(1) + gid(2) + name(32) + uuid(16) + contents_len(2) + contents
            let mut frame = Vec::with_capacity(59 + contents.len());
            frame.extend_from_slice(pin.as_bytes());
            frame.push(slot);
            frame.extend_from_slice(&gid.to_le_bytes());
            frame.extend_from_slice(&name_buf);
            frame.extend_from_slice(&uuid_bytes);
            frame.extend_from_slice(&(contents.len() as u16).to_le_bytes());
            frame.extend_from_slice(&contents);

            hsm.send_respond(Opcode::Write, &frame)?;
            log::success("Write successful");
        }

        Command::Read {
            pin,
            slot,
            output_dir,
            force,
        } => {
            validate_pin(&pin)?;
            validate_slot(slot)?;

            // Pack frame: pin(6) + slot(1)
            let mut frame = Vec::with_capacity(7);
            frame.extend_from_slice(pin.as_bytes());
            frame.push(slot);

            let resp = hsm.send_respond(Opcode::Read, &frame)?;
            let body = &resp.body;
            if body.len() < MAX_NAME_LEN {
                bail!("Read response too short");
            }
            let name_bytes = &body[..MAX_NAME_LEN];
            let name = String::from_utf8_lossy(
                &name_bytes[..name_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(MAX_NAME_LEN)],
            );
            let contents = &body[MAX_NAME_LEN..];

            let full_path = output_dir.join(name.as_ref());
            if !force && full_path.exists() {
                bail!("File {} already exists (use --force to overwrite)", full_path.display());
            }
            fs::create_dir_all(&output_dir)?;
            fs::write(&full_path, contents)?;
            log::success(&format!(
                "Read successful. Wrote file to {}",
                full_path.canonicalize().unwrap_or(full_path).display()
            ));
        }

        Command::List { pin } => {
            validate_pin(&pin)?;
            let resp = hsm.send_respond(Opcode::List, pin.as_bytes())?;
            let files = unpack_files(&resp.body)?;
            for (slot, group_id, name) in &files {
                log::info(&format!("Found file: Slot {slot:x}, Group {group_id:x}, {name}"));
            }
            log::success("List successful");
        }

        Command::Interrogate { pin } => {
            validate_pin(&pin)?;
            let resp = hsm.send_respond(Opcode::Interrogate, pin.as_bytes())?;
            let files = unpack_files(&resp.body)?;
            for (slot, group_id, name) in &files {
                log::info(&format!("Found remote file: Slot {slot:x}, Group {group_id:x}, {name}"));
            }
            log::success("Interrogate successful");
        }

        Command::Listen => {
            hsm.send_respond(Opcode::Listen, &[])?;
            log::success("Listen successful");
        }

        Command::Receive {
            pin,
            read_slot,
            write_slot,
        } => {
            validate_pin(&pin)?;
            validate_slot(read_slot)?;
            validate_slot(write_slot)?;

            // Pack frame: pin(6) + read_slot(1) + write_slot(1)
            let mut frame = Vec::with_capacity(8);
            frame.extend_from_slice(pin.as_bytes());
            frame.push(read_slot);
            frame.push(write_slot);

            hsm.send_respond(Opcode::Receive, &frame)?;
            log::success(&format!("Receive successful. Wrote file to local slot {write_slot}"));
        }
    }

    Ok(())
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        bail!("Hex string must have even length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(Into::into))
        .collect()
}
