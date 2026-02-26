mod fthr;
mod log;
mod protocol;
mod serial;
mod ti;

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::{Parser, Subcommand};
use protocol::{HSMIntf, Opcode};

const STYLES: Styles = Styles::styled()
    .header(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .usage(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
    .placeholder(AnsiColor::Cyan.on_default())
    .valid(AnsiColor::Green.on_default())
    .invalid(AnsiColor::Red.on_default())
    .error(AnsiColor::Red.on_default().effects(Effects::BOLD));

const PIN_LEN: usize = 6;
const MAX_NAME_LEN: usize = 32;
const MAX_FILE_LEN: usize = 8192;
const UUID_LEN: usize = 16;

#[derive(Parser)]
#[command(
    name = "ectf-tools",
    about = "eCTF host tools — Rust reimplementation",
    long_about = "Drop-in replacement for MITRE's ectf CLI.\n\
                  Reliable serial I/O using raw termios instead of pyserial.",
    styles = STYLES,
    arg_required_else_help = true,
)]
struct Cli {
    /// Verbosity (-v for debug, -vv for trace w/ hexdump)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: TopLevel,
}

#[derive(Subcommand)]
enum TopLevel {
    /// Interact with the HSM filesystem
    #[command(arg_required_else_help = true)]
    Tools {
        /// Serial port (e.g. /dev/tty.usbmodemXXX)
        port: String,
        #[command(subcommand)]
        command: ToolsCmd,
    },
    /// Manage the hardware bootloader
    #[command(arg_required_else_help = true)]
    Hw {
        /// Serial port (e.g. /dev/tty.usbmodemXXX)
        port: String,
        #[command(subcommand)]
        command: HwCmd,
    },
}

// ─── Tools subcommands ───

#[derive(Subcommand)]
enum ToolsCmd {
    /// Write a file to the HSM
    #[command(long_about = "Write a host file into an HSM slot, protected by PIN and group ID.")]
    Write {
        /// 6-char hex PIN
        pin: String,
        /// Slot number (0-7)
        slot: u8,
        /// Group ID (decimal or 0xHEX)
        gid: String,
        /// File to write
        file: PathBuf,
        /// UUID hex string (random if omitted)
        #[arg(short, long)]
        uuid: Option<String>,
    },
    /// Read a file from the HSM
    Read {
        /// 6-char hex PIN
        pin: String,
        /// Slot number (0-7)
        slot: u8,
        /// Directory to write the file into
        output_dir: PathBuf,
        /// Overwrite if file exists
        #[arg(short, long)]
        force: bool,
    },
    /// List files stored on the HSM
    List {
        /// 6-char hex PIN
        pin: String,
    },
    /// Interrogate files on a connected remote HSM
    Interrogate {
        /// 6-char hex PIN
        pin: String,
    },
    /// Put the HSM into listen mode for file transfer
    Listen,
    /// Receive a file from another HSM
    Receive {
        /// 6-char hex PIN
        pin: String,
        /// Source slot on the remote HSM (0-7)
        read_slot: u8,
        /// Destination slot on this HSM (0-7)
        write_slot: u8,
    },
}

// ─── HW subcommands ───

#[derive(Subcommand)]
enum HwCmd {
    /// Get bootloader status [MSPM0L2228]
    Status,
    /// Erase the current design [MSPM0L2228]
    Erase,
    /// Flash a design image [MSPM0L2228]
    Flash {
        /// Image file (.bin or .hsm)
        infile: PathBuf,
        /// Binary name (required for unprotected images)
        #[arg(short, long)]
        name: Option<String>,
    },
    /// Start the flashed design [MSPM0L2228]
    Start,
    /// Erase + flash + start in one step [MSPM0L2228]
    Reflash {
        /// Image file, or directory containing hsm.bin
        infile: PathBuf,
        /// Binary name (required for unprotected images)
        #[arg(short, long)]
        name: Option<String>,
    },
    /// Get a file digest from the secure bootloader [MSPM0L2228]
    Digest {
        /// File slot number
        slot: u8,
    },
    /// Flash a design image [MAX78000FTHR]
    FlashFthr {
        /// FTHR serial port
        fthr_port: String,
        /// Image file to flash
        infile: PathBuf,
    },
    /// Permanently unlock the secure bootloader [MAX78000FTHR]
    #[command(long_about = "Permanently unlock the MAX78000FTHR secure bootloader.\n\
                            This is irreversible! Requires --force --force to confirm.")]
    UnlockFthr {
        /// FTHR serial port
        fthr_port: String,
        /// Bootloader secrets JSON file
        secrets: PathBuf,
        /// Confirm (must pass twice: --force --force)
        #[arg(short, long, action = clap::ArgAction::Count)]
        force: u8,
    },
}

// ─── Helpers ───

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
        bail!(
            "PIN must be exactly {PIN_LEN} characters, got {}",
            pin.len()
        );
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
            &name_bytes[..name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(MAX_NAME_LEN)],
        )
        .into_owned();
        files.push((slot, group_id, name));
    }
    Ok(files)
}

/// Derive an image name from a file path (file stem, truncated to 8 bytes).
fn infer_image_name(path: &PathBuf) -> Option<String> {
    path.file_stem()
        .and_then(|s| s.to_str())
        .map(|s| s.chars().take(8).collect())
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

// ─── Main ───

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
    match cli.command {
        TopLevel::Tools { port, command } => run_tools(&port, command),
        TopLevel::Hw { port, command } => run_hw(&port, command),
    }
}

// ─── Tools commands ───

fn run_tools(port: &str, cmd: ToolsCmd) -> Result<()> {
    let mut hsm = HSMIntf::open(port).context("Failed to open serial port")?;

    match cmd {
        ToolsCmd::Write {
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
                    bytes.try_into().map_err(|v: Vec<u8>| {
                        anyhow::anyhow!("UUID must be 16 bytes, got {}", v.len())
                    })?
                }
                None => *uuid::Uuid::new_v4().as_bytes(),
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

        ToolsCmd::Read {
            pin,
            slot,
            output_dir,
            force,
        } => {
            validate_pin(&pin)?;
            validate_slot(slot)?;

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
                bail!(
                    "File {} already exists (use --force to overwrite)",
                    full_path.display()
                );
            }
            fs::create_dir_all(&output_dir)?;
            fs::write(&full_path, contents)?;
            log::success(&format!(
                "Read successful. Wrote file to {}",
                full_path.canonicalize().unwrap_or(full_path).display()
            ));
        }

        ToolsCmd::List { pin } => {
            validate_pin(&pin)?;
            let resp = hsm.send_respond(Opcode::List, pin.as_bytes())?;
            let files = unpack_files(&resp.body)?;
            for (slot, group_id, name) in &files {
                log::info(&format!(
                    "Found file: Slot {slot:x}, Group {group_id:x}, {name}"
                ));
            }
            log::success("List successful");
        }

        ToolsCmd::Interrogate { pin } => {
            validate_pin(&pin)?;
            let resp = hsm.send_respond(Opcode::Interrogate, pin.as_bytes())?;
            let files = unpack_files(&resp.body)?;
            for (slot, group_id, name) in &files {
                log::info(&format!(
                    "Found remote file: Slot {slot:x}, Group {group_id:x}, {name}"
                ));
            }
            log::success("Interrogate successful");
        }

        ToolsCmd::Listen => {
            hsm.send_respond(Opcode::Listen, &[])?;
            log::success("Listen successful");
        }

        ToolsCmd::Receive {
            pin,
            read_slot,
            write_slot,
        } => {
            validate_pin(&pin)?;
            validate_slot(read_slot)?;
            validate_slot(write_slot)?;

            let mut frame = Vec::with_capacity(8);
            frame.extend_from_slice(pin.as_bytes());
            frame.push(read_slot);
            frame.push(write_slot);

            hsm.send_respond(Opcode::Receive, &frame)?;
            log::success(&format!(
                "Receive successful. Wrote file to local slot {write_slot}"
            ));
        }
    }

    Ok(())
}

// ─── HW commands ───

fn run_hw(port: &str, cmd: HwCmd) -> Result<()> {
    match cmd {
        HwCmd::Status => {
            let mut board =
                ti::MSPM0L2228::open(port).context("Failed to open serial port")?;
            board.connect()?;
            let status = board.status()?;

            log::success("Successfully got bootloader status:");
            log::success(&format!(
                " - Version: {}.{}.{}",
                status.year, status.major_version, status.minor_version
            ));
            log::success(&format!(
                " - Secure bootloader: {}",
                status.secure != 0
            ));
            match &status.installed {
                Some(name) => log::success(&format!(
                    " - Installed design: {}",
                    String::from_utf8_lossy(name)
                )),
                None => log::success(" - No design installed"),
            }
            if status.app_clear == 0 && status.app_ready == 0 {
                log::warning("Bootloader in unstable state and needs to be erased!");
            }
        }

        HwCmd::Erase => {
            let mut board =
                ti::MSPM0L2228::open(port).context("Failed to open serial port")?;
            board.connect()?;
            board.erase()?;
            log::success("Bootloader erased successfully. The LED should be flashing now");
        }

        HwCmd::Flash { infile, name } => {
            if infile.extension().is_some_and(|e| e == "elf") {
                bail!("Do not flash the .elf file. It's likely you are looking for the .bin file");
            }
            let raw = fs::read(&infile).context("Failed to read image file")?;
            let name = name.or_else(|| infer_image_name(&infile));
            let image = ti::Image::deserialize(&raw, name.as_deref())?;
            log::info(&format!("Flashing design {}", image.name));

            let mut board =
                ti::MSPM0L2228::open(port).context("Failed to open serial port")?;
            board.flash(&image)?;
            log::success(
                "Design was successfully flashed. Send start command or reboot to launch new design",
            );
        }

        HwCmd::Start => {
            log::info("Starting design");
            let mut board =
                ti::MSPM0L2228::open(port).context("Failed to open serial port")?;
            board.connect()?;
            board.start()?;
            log::success("Loaded image should be running now.");
            log::success("Reset while holding S2/PB21 to return to bootloader mode.");
        }

        HwCmd::Reflash { infile, name } => {
            let path = if infile.is_dir() {
                infile.join("hsm.bin")
            } else {
                infile
            };
            let raw = fs::read(&path)
                .with_context(|| format!("Failed to read {}", path.display()))?;
            let name = name.or_else(|| infer_image_name(&path));
            let image = ti::Image::deserialize(&raw, name.as_deref())?;

            log::info("Reflashing design");
            let mut board =
                ti::MSPM0L2228::open(port).context("Failed to open serial port")?;
            board.connect()?;
            log::info("Erasing old design");
            board.erase()?;
            log::info("Flashing new design");
            board.flash(&image)?;
            log::info("Starting new design");
            board.start()?;
            log::success("Loaded image should be running now.");
            log::success("Reset while holding S2/PB21 to return to bootloader mode.");
        }

        HwCmd::Digest { slot } => {
            log::info("Requesting digest");
            let mut board =
                ti::MSPM0L2228::open(port).context("Failed to open serial port")?;
            board.connect()?;
            let digest = board.digest(slot)?;
            log::success(&format!("Successfully retrieved digest for slot {slot}."));
            log::success("Submit the following to the API:");
            let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
            log::success(&format!("    {hex}"));
        }

        HwCmd::FlashFthr { fthr_port, infile } => {
            let raw = fs::read(&infile).context("Failed to read image file")?;
            let mut fthr =
                fthr::MAX78000FTHR::open(&fthr_port).context("Failed to open FTHR serial port")?;
            fthr.flash(&raw)?;
        }

        HwCmd::UnlockFthr {
            fthr_port,
            secrets,
            force,
        } => {
            if force < 2 {
                let msg = if force == 0 {
                    "Unlocking the board is permanent. You will no longer be able to use \
                     the board to load protected binaries.\n\n\
                     Run again with --force to continue"
                } else {
                    "Unlocking the board is permanent. You will no longer be able to use \
                     the board to load protected binaries.\n\n\
                     THIS IS YOUR LAST CHANCE TO TURN BACK!\n\n\
                     Run again with --force --force to continue"
                };
                bail!("{msg}");
            }
            let raw = fs::read_to_string(&secrets).context("Failed to read secrets file")?;
            let secrets: serde_json::Value =
                serde_json::from_str(&raw).context("Invalid JSON in secrets file")?;
            let mut fthr =
                fthr::MAX78000FTHR::open(&fthr_port).context("Failed to open FTHR serial port")?;
            fthr.unlock(&secrets)?;
        }
    }

    Ok(())
}
