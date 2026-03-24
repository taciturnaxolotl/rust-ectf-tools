mod api;
mod config;
mod fthr;
mod log;
mod protocol;
mod serial;
mod ti;

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
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
    version,
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
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        shell: Shell,
    },
    /// Create or update the configuration file
    Config {
        /// Team API token
        #[arg(long)]
        token: Option<String>,
        /// Git repository URL
        #[arg(long)]
        git_url: Option<String>,
        /// API URL
        #[arg(long)]
        api_url: Option<String>,
        /// Overwrite existing config
        #[arg(short, long)]
        force: bool,
    },
    /// Open the API documentation website
    Docs,
    /// Open the eCTF rules website
    Rules,
    /// Interact with the API
    #[command(arg_required_else_help = true)]
    Api {
        #[command(subcommand)]
        command: ApiCmd,
    },
}

// ─── API subcommands ───

#[derive(Subcommand)]
enum ApiCmd {
    /// Submit your design to Handoff
    Submit {
        /// Git commit hash
        commit: String,
        /// Output result as JSON for CI
        #[arg(long)]
        json: bool,
    },
    /// Submit a PNG for the Team Photo flag
    Photo {
        /// PNG file to submit
        file: PathBuf,
    },
    /// Submit a PDF for the Design Doc flag
    Design {
        /// PDF file to submit
        file: PathBuf,
    },
    /// Submit a digest for the Steal Design flag
    Steal {
        /// Target team identifier
        team: String,
        /// Hex digest string
        digest: String,
    },
    /// Get the list of available packages
    List,
    /// Download an Attack Package
    Get {
        /// Package name
        package: String,
        /// Output path
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Overwrite if file exists
        #[arg(short, long)]
        force: bool,
        /// Decrypt and extract with the given key
        #[arg(short, long)]
        decrypt: Option<String>,
    },
    /// Decrypt and extract an attack package
    Decrypt {
        /// Encrypted package file (e.g. mitre.enc)
        file: PathBuf,
        /// Decryption key (hex string)
        key: String,
        /// Output directory (defaults to package name without .enc)
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Test that your design can be cloned by the API
    #[command(arg_required_else_help = true)]
    Clone {
        #[command(subcommand)]
        command: FlowCmd,
    },
    /// Test your design with the API
    #[command(arg_required_else_help = true)]
    Test {
        #[command(subcommand)]
        command: FlowCmd,
    },
    /// Submit to the remote attack scenario
    #[command(arg_required_else_help = true)]
    Remote {
        #[command(subcommand)]
        command: RemoteCmd,
    },
}

#[derive(Subcommand)]
enum FlowCmd {
    /// List recent flows
    Ls {
        /// Number of flows to show (0 for all)
        #[arg(short, long, default_value = "5")]
        number: usize,
        /// Output result as JSON for CI
        #[arg(long)]
        json: bool,
    },
    /// Get flow details
    Info {
        /// Flow ID
        id: String,
        /// Output result as JSON for CI
        #[arg(long)]
        json: bool,
    },
    /// Submit a commit
    Submit {
        /// Git commit hash
        commit: String,
        /// Override git URL
        #[arg(short, long)]
        url: Option<String>,
        /// Output result as JSON for CI
        #[arg(long)]
        json: bool,
    },
    /// Cancel a flow
    Cancel {
        /// Flow ID
        id: String,
    },
    /// Download job output
    Get {
        /// Job ID
        job_id: String,
        /// Output file path
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum RemoteCmd {
    /// Connect to the remote attack scenario
    Connect {
        /// HSM management serial port
        management_port: String,
        /// Transfer interface UART port
        transfer_port: String,
        /// Target team identifier
        team: String,
        /// Timeout in seconds
        #[arg(short, long, default_value = "120")]
        timeout: u64,
    },
    /// List recent remote flows
    Ls {
        /// Number of flows to show (0 for all)
        #[arg(short, long, default_value = "5")]
        number: usize,
        /// Output result as JSON for CI
        #[arg(long)]
        json: bool,
    },
    /// Get remote flow details
    Info {
        /// Flow ID
        id: String,
        /// Output result as JSON for CI
        #[arg(long)]
        json: bool,
    },
    /// Cancel a remote flow
    Cancel {
        /// Flow ID
        id: String,
    },
    /// Download remote job output
    Get {
        /// Job ID
        job_id: String,
        /// Output file path
        out: PathBuf,
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
    /// Run the test suite against real hardware
    Test {
        /// 6-char hex PIN
        pin: String,
        /// Group ID (decimal or 0xHEX)
        gid: String,
        /// Second HSM serial port for transfer tests
        transfer_port: Option<String>,
        /// Skip tests requiring a second HSM
        #[arg(long)]
        no_transfer: bool,
        /// Output results as JSON for CI
        #[arg(long)]
        json: bool,
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

fn open_url(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).spawn()?;
    }
    #[cfg(not(target_os = "macos"))]
    {
        std::process::Command::new("xdg-open").arg(url).spawn()?;
    }
    Ok(())
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        TopLevel::Tools { port, command } => run_tools(&port, command),
        TopLevel::Hw { port, command } => run_hw(&port, command),
        TopLevel::Completions { shell } => {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "ectf-tools",
                &mut std::io::stdout(),
            );
            Ok(())
        }
        TopLevel::Config {
            token,
            git_url,
            api_url,
            force,
        } => run_config(token, git_url, api_url, force),
        TopLevel::Docs => {
            open_url("https://sb.ectf.mitre.org/")?;
            log::success("Opened API documentation");
            Ok(())
        }
        TopLevel::Rules => {
            open_url("https://rules.ectf.mitre.org/")?;
            log::success("Opened eCTF rules");
            Ok(())
        }
        TopLevel::Api { command } => run_api(command),
    }
}

// ─── Config ───

fn prompt(label: &str, default: Option<&str>) -> Result<String> {
    use std::io::Write;
    match default {
        Some(d) => eprint!("{label} [{d}]: "),
        None => eprint!("{label}: "),
    }
    std::io::stderr().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let input = input.trim().to_string();
    if input.is_empty() {
        default
            .map(|d| d.to_string())
            .context(format!("{label} is required"))
    } else {
        Ok(input)
    }
}

fn run_config(
    token: Option<String>,
    git_url: Option<String>,
    api_url: Option<String>,
    force: bool,
) -> Result<()> {
    let has_args = token.is_some() || git_url.is_some() || api_url.is_some() || force;

    // No args: print existing config or prompt for new one
    if !has_args && config::Config::exists() {
        let cfg = config::Config::load()?;
        log::info(&format!("token:   {}", cfg.token));
        log::info(&format!("git_url: {}", cfg.git_url));
        log::info(&format!("api_url: {}", cfg.api_url));
        return Ok(());
    }

    let existing = if config::Config::exists() && !force {
        Some(config::Config::load()?)
    } else {
        None
    };

    let token = match token {
        Some(t) => t,
        None => prompt("Token", existing.as_ref().map(|c| c.token.as_str()))?,
    };
    let git_url = match git_url {
        Some(g) => g,
        None => prompt("Git URL", existing.as_ref().map(|c| c.git_url.as_str()))?,
    };
    let api_url = match api_url {
        Some(a) => a,
        None => prompt(
            "API URL",
            Some(
                existing
                    .as_ref()
                    .map(|c| c.api_url.as_str())
                    .unwrap_or(config::DEFAULT_API_URL),
            ),
        )?,
    };

    config::Config { token, git_url, api_url }.save()?;

    log::success(&format!(
        "Config saved to {}",
        config::Config::path()?.display()
    ));
    Ok(())
}

// ─── API commands ───

fn run_api(cmd: ApiCmd) -> Result<()> {
    match cmd {
        ApiCmd::Submit { commit, json } => api::cmd_submit(&commit, json),
        ApiCmd::Photo { file } => api::cmd_photo(&file),
        ApiCmd::Design { file } => api::cmd_design(&file),
        ApiCmd::Steal { team, digest } => api::cmd_steal(&team, &digest),
        ApiCmd::List => api::cmd_list_packages(),
        ApiCmd::Get {
            package,
            out,
            force,
            decrypt,
        } => {
            api::cmd_get_package(&package, out.as_ref(), force)?;
            if let Some(key) = decrypt {
                let enc_path = out.unwrap_or_else(|| PathBuf::from(&package));
                cmd_decrypt(&enc_path, &key, None)?;
            }
            Ok(())
        }
        ApiCmd::Decrypt { file, key, out } => cmd_decrypt(&file, &key, out.as_ref()),
        ApiCmd::Clone { command } => run_flow("clone", command),
        ApiCmd::Test { command } => run_flow("test", command),
        ApiCmd::Remote { command } => run_remote(command),
    }
}

fn run_flow(flow: &str, cmd: FlowCmd) -> Result<()> {
    match cmd {
        FlowCmd::Ls { number, json } => api::cmd_flow_list(flow, number, json),
        FlowCmd::Info { id, json } => api::cmd_flow_info(flow, &id, json),
        FlowCmd::Submit { commit, url, json } => {
            api::cmd_flow_submit(flow, &commit, url.as_deref(), json)
        }
        FlowCmd::Cancel { id } => api::cmd_flow_cancel(flow, &id),
        FlowCmd::Get { job_id, out } => api::cmd_flow_get(flow, &job_id, &out),
    }
}

fn run_remote(cmd: RemoteCmd) -> Result<()> {
    match cmd {
        RemoteCmd::Connect {
            management_port,
            transfer_port,
            team,
            timeout,
        } => api::cmd_remote_connect(&management_port, &transfer_port, &team, timeout),
        RemoteCmd::Ls { number, json } => api::cmd_flow_list("remote", number, json),
        RemoteCmd::Info { id, json } => api::cmd_flow_info("remote", &id, json),
        RemoteCmd::Cancel { id } => api::cmd_flow_cancel("remote", &id),
        RemoteCmd::Get { job_id, out } => api::cmd_flow_get("remote", &job_id, &out),
    }
}

// ─── Decrypt helper ───

fn cmd_decrypt(file: &PathBuf, key: &str, out: Option<&PathBuf>) -> Result<()> {
    // Determine output directory
    let out_dir = match out {
        Some(p) => p.clone(),
        None => {
            let stem = file
                .file_stem()
                .and_then(|s| s.to_str())
                .context("cannot determine output name from input file")?;
            // Strip .enc -> stem, but if the stem itself has an extension (e.g. foo.enc),
            // just use the stem directly
            PathBuf::from(stem)
        }
    };

    if out_dir.exists() {
        bail!("output directory '{}' already exists", out_dir.display());
    }

    // Decrypt using openssl
    log::info(&format!("decrypting '{}'...", file.display()));
    let output = std::process::Command::new("openssl")
        .args([
            "enc",
            "-d",
            "-aes-256-cbc",
            "-pbkdf2",
            "-salt",
            "-k",
            key,
            "-in",
        ])
        .arg(file)
        .output()
        .context("failed to run openssl — is it installed?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("openssl decryption failed: {stderr}");
    }

    let zip_data = output.stdout;

    // Extract zip into output directory
    log::info(&format!("extracting to '{}'...", out_dir.display()));
    fs::create_dir_all(&out_dir).context("failed to create output directory")?;

    let cursor = std::io::Cursor::new(&zip_data);
    let mut archive = zip::ZipArchive::new(cursor).context("failed to read zip archive")?;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let entry_path = match entry.enclosed_name() {
            Some(p) => p.to_owned(),
            None => continue, // skip entries with unsafe paths
        };
        let dest = out_dir.join(&entry_path);

        if entry.is_dir() {
            fs::create_dir_all(&dest)?;
        } else {
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut out_file = fs::File::create(&dest)?;
            std::io::copy(&mut entry, &mut out_file)?;
        }
    }

    log::success(&format!(
        "extracted {} files to '{}'",
        archive.len(),
        out_dir.display()
    ));
    Ok(())
}

// ─── Tools commands ───

fn report_timing(op: &str, elapsed_ms: u128, limit_ms: u128) {
    if elapsed_ms > limit_ms {
        log::warning(&format!(
            "{op} took {elapsed_ms}ms — exceeds {limit_ms}ms spec limit"
        ));
    } else {
        log::info(&format!("{op} completed in {elapsed_ms}ms (limit: {limit_ms}ms)"));
    }
}

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

            let t = std::time::Instant::now();
            hsm.send_respond(Opcode::Write, &frame)?;
            let ms = t.elapsed().as_millis();
            log::success("Write successful");
            report_timing("Write", ms, 3000);
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

            let t = std::time::Instant::now();
            let resp = hsm.send_respond(Opcode::Read, &frame)?;
            let ms = t.elapsed().as_millis();
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
            report_timing("Read", ms, 3000);
        }

        ToolsCmd::List { pin } => {
            validate_pin(&pin)?;
            let t = std::time::Instant::now();
            let resp = hsm.send_respond(Opcode::List, pin.as_bytes())?;
            let ms = t.elapsed().as_millis();
            let files = unpack_files(&resp.body)?;
            for (slot, group_id, name) in &files {
                log::info(&format!(
                    "Found file: Slot {slot:x}, Group {group_id:x}, {name}"
                ));
            }
            log::success("List successful");
            report_timing("List", ms, 500);
        }

        ToolsCmd::Interrogate { pin } => {
            validate_pin(&pin)?;
            let t = std::time::Instant::now();
            let resp = hsm.send_respond(Opcode::Interrogate, pin.as_bytes())?;
            let ms = t.elapsed().as_millis();
            let files = unpack_files(&resp.body)?;
            for (slot, group_id, name) in &files {
                log::info(&format!(
                    "Found remote file: Slot {slot:x}, Group {group_id:x}, {name}"
                ));
            }
            log::success("Interrogate successful");
            report_timing("Interrogate", ms, 1000);
        }

        ToolsCmd::Listen => {
            let t = std::time::Instant::now();
            hsm.send_respond(Opcode::Listen, &[])?;
            let ms = t.elapsed().as_millis();
            log::success("Listen successful");
            report_timing("Listen (device wake)", ms, 1000);
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

            let t = std::time::Instant::now();
            hsm.send_respond(Opcode::Receive, &frame)?;
            let ms = t.elapsed().as_millis();
            log::success(&format!(
                "Receive successful. Wrote file to local slot {write_slot}"
            ));
            report_timing("Receive", ms, 3000);
        }

        ToolsCmd::Test {
            pin,
            gid,
            transfer_port,
            no_transfer,
            json,
        } => {
            validate_pin(&pin)?;
            let gid = parse_gid(&gid)?;

            if !no_transfer && transfer_port.is_none() {
                bail!("Transfer port required unless --no-transfer is passed");
            }

            let mut hsm2 = match &transfer_port {
                Some(p) if !no_transfer => {
                    Some(HSMIntf::open(p).context("Failed to open transfer serial port")?)
                }
                _ => None,
            };

            return run_test(&mut hsm, hsm2.as_mut(), &pin, gid, no_transfer, json);
        }
    }

    Ok(())
}

// ─── Test runner ───

fn write_frame(pin: &str, slot: u8, gid: u16, filename: &str, content: &[u8]) -> Vec<u8> {
    let mut name_buf = [0u8; MAX_NAME_LEN];
    let name_bytes = filename.as_bytes();
    name_buf[..name_bytes.len().min(MAX_NAME_LEN)]
        .copy_from_slice(&name_bytes[..name_bytes.len().min(MAX_NAME_LEN)]);
    let uuid_bytes = *uuid::Uuid::new_v4().as_bytes();

    let mut frame = Vec::with_capacity(59 + content.len());
    frame.extend_from_slice(pin.as_bytes());
    frame.push(slot);
    frame.extend_from_slice(&gid.to_le_bytes());
    frame.extend_from_slice(&name_buf);
    frame.extend_from_slice(&uuid_bytes);
    frame.extend_from_slice(&(content.len() as u16).to_le_bytes());
    frame.extend_from_slice(content);
    frame
}

fn read_frame(pin: &str, slot: u8) -> Vec<u8> {
    let mut frame = Vec::with_capacity(7);
    frame.extend_from_slice(pin.as_bytes());
    frame.push(slot);
    frame
}

fn recv_frame(pin: &str, read_slot: u8, write_slot: u8) -> Vec<u8> {
    let mut frame = Vec::with_capacity(8);
    frame.extend_from_slice(pin.as_bytes());
    frame.push(read_slot);
    frame.push(write_slot);
    frame
}

fn run_test(
    hsm: &mut HSMIntf,
    mut hsm2: Option<&mut HSMIntf>,
    pin: &str,
    gid: u16,
    no_transfer: bool,
    json: bool,
) -> Result<()> {
    struct TestResult {
        name: &'static str,
        passed: bool,
        duration_secs: f64,
        error: Option<String>,
    }

    let mut results: Vec<TestResult> = Vec::new();

    macro_rules! run_test {
        ($name:expr, $body:expr) => {{
            if !json {
                log::info(&format!("Running: {}", $name));
            }
            let start = std::time::Instant::now();
            match (|| -> Result<()> { $body })() {
                Ok(()) => {
                    let elapsed = start.elapsed();
                    if !json {
                        log::success(&format!("{} passed ({:.1}s)", $name, elapsed.as_secs_f64()));
                    }
                    results.push(TestResult {
                        name: $name,
                        passed: true,
                        duration_secs: elapsed.as_secs_f64(),
                        error: None,
                    });
                }
                Err(e) => {
                    let elapsed = start.elapsed();
                    if !json {
                        log::error(&format!("{} FAILED ({:.1}s): {e}", $name, elapsed.as_secs_f64()));
                    }
                    results.push(TestResult {
                        name: $name,
                        passed: false,
                        duration_secs: elapsed.as_secs_f64(),
                        error: Some(e.to_string()),
                    });
                }
            }
        }};
    }

    // Timing limits from the eCTF spec (milliseconds)
    const TIME_LIST: u128 = 500;
    const TIME_READ: u128 = 3000;
    const TIME_WRITE: u128 = 3000;
    const TIME_RECEIVE: u128 = 3000;
    const TIME_INTERROGATE: u128 = 1000;
    const TIME_BAD_PIN: u128 = 5000;

    macro_rules! timed {
        ($hsm:expr, $op:expr, $frame:expr, $limit_ms:expr) => {{
            let t = std::time::Instant::now();
            let res = $hsm.send_respond($op, $frame);
            let ms = t.elapsed().as_millis();
            if ms > $limit_ms {
                bail!(
                    "{:?} took {}ms, exceeds {}ms limit",
                    $op, ms, $limit_ms
                );
            }
            res
        }};
    }

    // A different group ID for permission tests
    let bad_gid: u16 = if gid == 0xFFFF { gid - 1 } else { gid + 1 };

    // Slot usage plan:
    //   0: write_1, overwrite, write_max_file_name, write_max_file_size
    //   1: write_all_ascii
    //   2: (reserved for write_max)
    //   3: read_without_perms (bad_gid), write_without_perms
    //   4: write_0_byte_file
    //   5,6,7: write_max

    // ── list_empty: verify HSM starts with no files ──

    run_test!("list_empty", {
        let resp = timed!(hsm, Opcode::List, pin.as_bytes(), TIME_LIST)?;
        let files = unpack_files(&resp.body)?;
        if !files.is_empty() {
            bail!("Expected 0 files, found {}", files.len());
        }
        Ok(())
    });

    // ── write_1: write file to slot 0, read back, verify ──

    let write1_content = b"Hi this will be the text inside the file";
    run_test!("write_1", {
        let frame = write_frame(pin, 0, gid, "test.txt", write1_content);
        timed!(hsm, Opcode::Write, &frame, TIME_WRITE)?;

        let resp = timed!(hsm, Opcode::Read, &read_frame(pin, 0), TIME_READ)?;
        if resp.body.len() < MAX_NAME_LEN {
            bail!("Read response too short");
        }
        let contents = &resp.body[MAX_NAME_LEN..];
        if contents != write1_content.as_slice() {
            bail!(
                "Content mismatch: expected {} bytes, got {} bytes",
                write1_content.len(),
                contents.len()
            );
        }
        Ok(())
    });

    // ── interrogate_1 + receive_1: two-HSM file transfer ──

    if !no_transfer {
        let hsm2 = hsm2.as_deref_mut().expect("transfer HSM required");

        run_test!("interrogate_1", {
            hsm2.send_respond(Opcode::Listen, &[])?;
            let resp = timed!(hsm, Opcode::Interrogate, pin.as_bytes(), TIME_INTERROGATE)?;
            let files = unpack_files(&resp.body)?;
            if files.is_empty() {
                bail!("Interrogation returned no files");
            }
            Ok(())
        });

        run_test!("receive_1", {
            hsm2.send_respond(Opcode::Listen, &[])?;
            timed!(hsm, Opcode::Interrogate, pin.as_bytes(), TIME_INTERROGATE)?;
            timed!(hsm2, Opcode::Receive, &recv_frame(pin, 0, 1), TIME_RECEIVE)?;
            Ok(())
        });
    }

    // ── overwrite: overwrite slot 0 with new content ──

    run_test!("overwrite", {
        let content = b"This file will be overwriting an existing file";
        let frame = write_frame(pin, 0, gid, "overwriting_file.txt", content);
        timed!(hsm, Opcode::Write, &frame, TIME_WRITE)?;

        let resp = timed!(hsm, Opcode::Read, &read_frame(pin, 0), TIME_READ)?;
        if resp.body.len() < MAX_NAME_LEN {
            bail!("Read response too short");
        }
        let got = &resp.body[MAX_NAME_LEN..];
        if got != content.as_slice() {
            bail!("Overwrite content mismatch");
        }
        Ok(())
    });

    // ── pass_file_back_and_forth: transfer with different gid ──

    if !no_transfer {
        let hsm2 = hsm2.as_deref_mut().expect("transfer HSM required");

        run_test!("pass_file_back_and_forth", {
            // Write file with a different gid on hsm
            let other_gid: u16 = gid.wrapping_add(0x1000);
            let content = b"This file will be passed back and forth";
            let frame = write_frame(pin, 0, other_gid, "passed_file.txt", content);
            timed!(hsm, Opcode::Write, &frame, TIME_WRITE)?;

            // Transfer hsm → hsm2 (slot 0 → slot 0)
            hsm2.send_respond(Opcode::Listen, &[])?;
            timed!(hsm, Opcode::Interrogate, pin.as_bytes(), TIME_INTERROGATE)?;
            timed!(hsm2, Opcode::Receive, &recv_frame(pin, 0, 0), TIME_RECEIVE)?;

            // Transfer hsm2 → hsm (slot 0 → slot 0)
            hsm.send_respond(Opcode::Listen, &[])?;
            timed!(hsm2, Opcode::Interrogate, pin.as_bytes(), TIME_INTERROGATE)?;
            timed!(hsm, Opcode::Receive, &recv_frame(pin, 0, 0), TIME_RECEIVE)?;
            Ok(())
        });
    }

    // ── write_max_file_name: 32-char filename (max length) ──

    run_test!("write_max_file_name", {
        // 31 visible chars + null terminator fills 32-byte name buffer
        let content = b"Hi this will be the text inside the file";
        let frame = write_frame(pin, 0, gid, "this_filename_is_of_max_size_32", content);
        timed!(hsm, Opcode::Write, &frame, TIME_WRITE)?;
        Ok(())
    });

    // ── write_max_file_size: 8192-byte file (maximum) ──
    // Uses the same Julius Caesar text as the remote test suite.

    let max_content = {
        const BRUTUS: &[u8] = b" SCENE II. A public place. Flourish. Enter CAESAR; \
ANTONY, for the course; CALPURNIA, PORTIA, DECIUS BRUTUS, CICERO, BRUTUS, CASSIUS, \
and CASCA; a great crowd following, among them a Soothsayer CAESAR Calpurnia! CASCA \
Peace, ho! Caesar speaks. CAESAR Calpurnia! CALPURNIA Here, my lord. CAESAR Stand \
you directly in Antonius' way, When he doth run his course. Antonius! ANTONY \
Caesar, my lord? CAESAR Forget not, in your speed, Antonius, To touch Calpurnia; \
for our elders say, The barren, touched in this holy chase, Shake off their sterile \
curse. ANTONY I shall remember: When Caesar says 'do this,' it is perform'd. CAESAR \
Set on; and leave no ceremony out. Flourish Soothsayer Caesar! CAESAR Ha! who \
calls? CASCA Bid every noise be still: peace yet again! CAESAR Who is it in the \
press that calls on me? I hear a tongue, shriller than all the music, Cry 'Caesar!' \
Speak; Caesar is turn'd to hear. Soothsayer Beware the ides of March. CAESAR What \
man is that? BRUTUS A soothsayer bids you beware the ides of March. CAESAR Set him \
before me; let me see his face. CASSIUS Fellow, come from the throng; look upon \
Caesar. CAESAR What say'st thou to me now? speak once again. Soothsayer Beware the \
ides of March. CAESAR He is a dreamer; let us leave him: pass. Sennet. Exeunt all \
except BRUTUS and CASSIUS CASSIUS Will you go see the order of the course? BRUTUS \
Not I. CASSIUS I pray you, do. BRUTUS I am not gamesome: I do lack some part Of \
that quick spirit that is in Antony. Let me not hinder, Cassius, your desires; \
I'll leave you. CASSIUS Brutus, I do observe you now of late: I have not from your \
eyes that gentleness And show of love as I was wont to have: You bear too stubborn \
and too strange a hand Over your friend that loves you. BRUTUS Cassius, Be not \
deceived: if I have veil'd my look, I turn the trouble of my countenance Merely \
upon myself. Vexed I am Of late with passions of some difference, Conceptions only \
proper to myself, Which give some soil perhaps to my behaviors; But let not \
therefore my good friends be grieved- Among which number, Cassius, be you one- Nor \
construe any further my neglect, Than that poor Brutus, with himself at war, \
Forgets the shows of love to other men. CASSIUS Then, Brutus, I have much mistook \
your passion; By means whereof this breast of mine hath buried Thoughts of great \
value, worthy cogitations. Tell me, good Brutus, can you see your face? BRUTUS No, \
Cassius; for the eye sees not itself, But by reflection, by some other things. \
CASSIUS Tis just: And it is very much lamented, Brutus, That you have no such \
mirrors as will turn Your hidden worthiness into your eye, That you might see your \
shadow. I have heard, Where many of the best respect in Rome, Except immortal \
Caesar, speaking of Brutus And groaning underneath this age's yoke, Have wish'd \
that noble Brutus had his eyes. BRUTUS Into what dangers would you lead me, \
Cassius, That you would have me seek into myself For that which is not in me? \
CASSIUS Therefore, good Brutus, be prepared to hear: And since you know you cannot \
see yourself So well as by reflection, I, your glass, Will modestly discover to \
yourself That of yourself which you yet know not of. And be not jealous on me, \
gentle Brutus: Were I a common laugher, or did use To stale with ordinary oaths my \
love To every new protester; if you know That I do fawn on men and hug them hard \
And after scandal them, or if you know That I profess myself in banqueting To all \
the rout, then hold me dangerous. Flourish, and shout BRUTUS What means this \
shouting? I do fear, the people Choose Caesar for their king. CASSIUS Ay, do you \
fear it? Then must I think you would not have it so. BRUTUS I would not, Cassius; \
yet I love him well. But wherefore do you hold me here so long? What is it that \
you would impart to me? If it be aught toward the general good, Set honour in one \
eye and death i' the other, And I will look on both indifferently, For let the gods \
so speed me as I love The name of honour more than I fear death. CASSIUS I know \
that virtue to be in you, Brutus, As well as I do know your outward favour. Well, \
honour is the subject of my story. I cannot tell what you and other men Think of \
this life; but, for my single self, I had as lief not be as live to be In awe of \
such a thing as I myself. I was born free as Caesar; so were you: We both have fed \
as well, and we can both Endure the winter's cold as well as he: For once, upon a \
raw and gusty day, The troubled Tiber chafing with her shores, Caesar said to me \
'Darest thou, Cassius, now Leap in with me into this angry flood, And swim to \
yonder point?' Upon the word, Accoutred as I was, I plunged in And bade him \
follow; so indeed he did. The torrent roar'd, and we did buffet it With lusty \
sinews, throwing it aside And stemming it with hearts of controversy; But ere we \
could arrive the point proposed, Caesar cried 'Help me, Cassius, or I sink!' I, as \
Aeneas, our great ancestor, Did from the flames of Troy upon his shoulder The old \
Anchises bear, so from the waves of Tiber Did I the tired Caesar. And this man Is \
now become a god, and Cassius is A wretched creature and must bend his body, If \
Caesar carelessly but nod on him. He had a fever when he was in Spain, And when the \
fit was on him, I did mark How he did shake: 'tis true, this god did shake; His \
coward lips did from their colour fly, And that same eye whose bend doth awe the \
world Did lose his lustre: I did hear him groan: Ay, and that tongue of his that \
bade the Romans Mark him and write his speeches in their books, Alas, it cried \
'Give me some drink, Titinius,' As a sick girl. Ye gods, it doth amaze me A man of \
such a feeble temper should So get the start of the majestic world And bear the \
palm alone. Shout. Flourish BRUTUS Another general shout! I do believe that these \
applauses are For some new honours that are heap'd on Caesar. CASSIUS Why, man, he \
doth bestride the narrow world Like a Colossus, and we petty men Walk under his \
huge legs and peep about To find ourselves dishonourable graves. Men at some time \
are masters of their fates: The fault, dear Brutus, is not in our stars, But in \
ourselves, that we are underlings. Brutus and Caesar: what should be in that \
'Caesar'? Why should that name be sounded more than yours? Write them together, \
yours is as fair a name; Sound them, it doth become the mouth as well; Weigh them, \
it is as heavy; conjure with 'em, Brutus will start a spirit as soon as Caesar. \
Now, in the names of all the gods at once, Upon what meat doth this our Caesar \
feed, That he is grown so great? Age, thou art shamed! Rome, thou hast lost the \
breed of noble bloods! When went there by an age, since the great flood, But it was \
famed with more than with one man? When could they say till now, that talk'd of \
Rome, That her wide walls encompass'd but one man? Now is it Rome indeed and room \
enough, When there is in it but one only man. O, you and I have heard our fathers \
say, There was a Brutus once that would have brook'd The eternal devil to keep his \
state in Rome As easily as a king. BRUTUS That you do love me, I am nothing \
jealous; What you would work me to, I have some aim: How I have thought of this and \
of these times, I shall recount hereafter; for this present, I would not, so with \
love I might entreat you, Be any further moved. What you have said I will consider; \
what you have to say I will with patience hear, and find a time Both meet to hear \
and answer such high things. Till then, my noble friend, chew upon this: Brutus had \
rather be a villager Than to repute himself a son of Rome Under these hard \
conditions as this time Is like to lay upon us. CASSIUS I am glad that my weak \
words Have struck but thus much show of fire from Brutus. BRUTUS The games are done \
and Caesar is returning. CASSIUS As they pass by, pluck Casca by the sleeve; And \
he will, after his sour fashion, tell you What hath proceeded worthy note to-day. \
Re-enter CAESAR and his Train BRUTUS I will do so. But, look you, Cassius, The \
angry spot doth glow on Caesar's brow, And all the rest look like a chidden train: \
Calpurnia's cheek is pale; and Cicero Looks with such ferret and such fiery eyes \
As we have seen him in the Capitol, Being cross";
        let mut buf = Vec::with_capacity(MAX_FILE_LEN);
        while buf.len() < MAX_FILE_LEN {
            let remaining = MAX_FILE_LEN - buf.len();
            buf.extend_from_slice(&BRUTUS[..remaining.min(BRUTUS.len())]);
        }
        buf
    };
    run_test!("write_max_file_size", {
        let frame = write_frame(pin, 0, gid, "full_file_0.out", &max_content);
        timed!(hsm, Opcode::Write, &frame, TIME_WRITE)?;

        let resp = timed!(hsm, Opcode::Read, &read_frame(pin, 0), TIME_READ)?;
        if resp.body.len() < MAX_NAME_LEN {
            bail!("Read response too short");
        }
        let got = &resp.body[MAX_NAME_LEN..];
        if got.len() != MAX_FILE_LEN {
            bail!("Expected {MAX_FILE_LEN} bytes, got {}", got.len());
        }
        if got != max_content.as_slice() {
            bail!("Max-size file content mismatch");
        }
        Ok(())
    });

    // ── receive_max_file: transfer the 8192-byte file ──

    if !no_transfer {
        let hsm2 = hsm2.as_deref_mut().expect("transfer HSM required");

        run_test!("receive_max_file", {
            hsm2.send_respond(Opcode::Listen, &[])?;
            timed!(hsm, Opcode::Interrogate, pin.as_bytes(), TIME_INTERROGATE)?;
            timed!(hsm2, Opcode::Receive, &recv_frame(pin, 0, 2), TIME_RECEIVE)?;
            Ok(())
        });
    }

    // ── write_all_ascii: write all 256 byte values 0x00-0xFF ──

    run_test!("write_all_ascii", {
        let content: Vec<u8> = (0..=255u8).collect();
        let frame = write_frame(pin, 1, gid, "all_ascii.txt", &content);
        timed!(hsm, Opcode::Write, &frame, TIME_WRITE)?;

        let resp = timed!(hsm, Opcode::Read, &read_frame(pin, 1), TIME_READ)?;
        if resp.body.len() < MAX_NAME_LEN {
            bail!("Read response too short");
        }
        let got = &resp.body[MAX_NAME_LEN..];
        if got != content.as_slice() {
            bail!("All-ASCII content mismatch");
        }
        Ok(())
    });

    // ── bad_pin: wrong pin should error, HSM should still work after ──

    run_test!("bad_pin", {
        // Send a deliberately wrong (too-short) pin — allowed up to 5s
        let bad_result = timed!(hsm, Opcode::List, b"ecd7", TIME_BAD_PIN);
        if bad_result.is_ok() {
            bail!("Expected bad pin to fail, but it succeeded");
        }

        // Verify HSM still works with correct pin
        timed!(hsm, Opcode::List, pin.as_bytes(), TIME_LIST)?;
        Ok(())
    });

    // ── Permission tests: require two HSMs with different gid/permission sets ──

    if !no_transfer {
        let hsm2 = hsm2.as_deref_mut().expect("transfer HSM required");

        // read_without_perms: HSM B writes file with bad_gid, HSM A tries to read
        run_test!("read_without_perms", {
            let content = b"This file should not be readable by the HSM that wrote the data";
            let frame = write_frame(pin, 3, bad_gid, "non_readable.txt", content);
            timed!(hsm2, Opcode::Write, &frame, TIME_WRITE)?;

            hsm2.send_respond(Opcode::Listen, &[])?;
            timed!(hsm, Opcode::Interrogate, pin.as_bytes(), TIME_INTERROGATE)?;

            match timed!(hsm, Opcode::Receive, &recv_frame(pin, 3, 3), TIME_RECEIVE) {
                Err(_) => {} // expected: gid mismatch on receive
                Ok(_) => bail!("Expected receive to fail with wrong group ID, but it succeeded"),
            }
            Ok(())
        });

        // write_without_perms: HSM B writes file with bad_gid, HSM A tries to overwrite
        run_test!("write_without_perms", {
            let content = b"This file should not be receivable on HSM A";
            let frame = write_frame(pin, 3, gid, "replacement.txt", content);
            match timed!(hsm, Opcode::Write, &frame, TIME_WRITE) {
                Err(_) => {} // expected: gid mismatch on overwrite
                Ok(_) => bail!("Expected overwrite to fail with wrong group ID, but it succeeded"),
            }
            Ok(())
        });

        // receive_without_perms: HSM B writes file with bad_gid, HSM A tries to receive
        run_test!("receive_without_perms", {
            let content = b"This file should not be receivable on HSM A";
            let frame = write_frame(pin, 3, bad_gid, "non_receivable.txt", content);
            timed!(hsm2, Opcode::Write, &frame, TIME_WRITE)?;

            hsm.send_respond(Opcode::Listen, &[])?;
            timed!(hsm2, Opcode::Interrogate, pin.as_bytes(), TIME_INTERROGATE)?;

            match timed!(hsm, Opcode::Receive, &recv_frame(pin, 3, 3), TIME_RECEIVE) {
                Err(_) => {} // expected: gid mismatch
                Ok(_) => bail!("Expected receive to fail with wrong group ID, but it succeeded"),
            }
            Ok(())
        });
    }

    // ── write_0_byte_file: write file with 0 bytes content to slot 4 ──
    // Remote sends: pin + slot + gid + "no_contents.txt" + uuid + len(0x0000)
    // Total frame = 59 bytes, no content appended.

    run_test!("write_0_byte_file", {
        let frame = write_frame(pin, 4, gid, "no_contents.txt", &[]);
        timed!(hsm, Opcode::Write, &frame, TIME_WRITE)?;
        Ok(())
    });

    // ── read_0_byte_file: LIST and verify the 0-byte file appears ──
    // Note: the remote test does a LIST here, NOT a READ.

    run_test!("read_0_byte_file", {
        let resp = timed!(hsm, Opcode::List, pin.as_bytes(), TIME_LIST)?;
        let files = unpack_files(&resp.body)?;
        let found = files.iter().any(|(slot, _, name)| *slot == 4 && name == "no_contents.txt");
        if !found {
            bail!("0-byte file not found in file listing");
        }
        Ok(())
    });

    // ── read_back_0_byte: READ slot 4, verify empty content ──
    // (Extra test not in remote suite — verifies actual read returns 0 bytes)

    run_test!("read_back_0_byte", {
        let resp = timed!(hsm, Opcode::Read, &read_frame(pin, 4), TIME_READ)?;
        if resp.body.len() < MAX_NAME_LEN {
            bail!("Read response too short");
        }
        let contents = &resp.body[MAX_NAME_LEN..];
        if !contents.is_empty() {
            bail!("Expected empty contents, got {} bytes", contents.len());
        }
        Ok(())
    });

    // ── receive_0_byte_file: transfer the 0-byte file ──

    if !no_transfer {
        let hsm2 = hsm2.as_deref_mut().expect("transfer HSM required");

        run_test!("receive_0_byte_file", {
            hsm2.send_respond(Opcode::Listen, &[])?;
            timed!(hsm, Opcode::Interrogate, pin.as_bytes(), TIME_INTERROGATE)?;
            timed!(hsm2, Opcode::Receive, &recv_frame(pin, 4, 4), TIME_RECEIVE)?;
            Ok(())
        });
    }

    // ── write_max: fill all remaining empty slots to reach 8 total ──

    run_test!("write_max", {
        // List current files to find which slots are occupied
        let resp = timed!(hsm, Opcode::List, pin.as_bytes(), TIME_LIST)?;
        let files = unpack_files(&resp.body)?;
        let occupied: std::collections::HashSet<u8> = files.iter().map(|(s, _, _)| *s).collect();

        for i in 0u8..8 {
            if occupied.contains(&i) {
                continue;
            }
            let name = format!("file_{i}.txt");
            let content = format!("This is file number {i}");
            let frame = write_frame(pin, i, gid, &name, content.as_bytes());
            timed!(hsm, Opcode::Write, &frame, TIME_WRITE)?;
        }

        let resp = timed!(hsm, Opcode::List, pin.as_bytes(), TIME_LIST)?;
        let files = unpack_files(&resp.body)?;
        if files.len() != 8 {
            bail!("Expected 8 files, found {}", files.len());
        }
        Ok(())
    });

    // ── Summary ──

    let total = results.len();
    let passed = results.iter().filter(|r| r.passed).count();
    let failed = total - passed;

    if json {
        let tests: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                let mut obj = serde_json::Map::new();
                obj.insert("name".into(), serde_json::Value::String(r.name.into()));
                obj.insert("passed".into(), serde_json::Value::Bool(r.passed));
                obj.insert(
                    "duration_secs".into(),
                    serde_json::Value::Number(
                        serde_json::Number::from_f64(r.duration_secs).unwrap(),
                    ),
                );
                if let Some(e) = &r.error {
                    obj.insert("error".into(), serde_json::Value::String(e.clone()));
                }
                serde_json::Value::Object(obj)
            })
            .collect();
        let output = serde_json::json!({
            "total": total,
            "passed": passed,
            "failed": failed,
            "tests": tests,
        });
        println!("{}", serde_json::to_string(&output).unwrap());
    } else {
        println!();
        for r in &results {
            if r.passed {
                log::success(&format!("  PASS  {}", r.name));
            } else {
                log::error(&format!("  FAIL  {}", r.name));
            }
        }
        println!();
        if failed == 0 {
            log::success(&format!("All {total} tests passed"));
        } else {
            log::error(&format!("{failed}/{total} tests failed"));
        }
    }

    if failed > 0 {
        bail!("{failed} test(s) failed");
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
