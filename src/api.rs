use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::config::Config;
use crate::log;
use crate::protocol::{HSMIntf, Opcode};
use crate::serial;

// ─── Types ───

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
pub struct Flow {
    pub id: String,
    pub submit_time: String,
    pub name: String,
    pub completed: bool,
    pub params: serde_json::Value,
    pub jobs: Vec<Job>,
}

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
pub struct Job {
    pub name: String,
    pub id: String,
    pub has_artifacts: bool,
    pub private: bool,
    pub status: String,
}

fn status_color(s: &str) -> &'static str {
    match s {
        "succeeded" | "completed" => "\x1b[38;5;114m",
        "queued" | "running" | "pending" => "\x1b[38;5;221m",
        "canceled" => "\x1b[38;5;242m",
        "failed" => "\x1b[38;5;203m",
        _ => "",
    }
}

fn titlecase(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

fn relative_time(iso: &str) -> String {
    // Parse ISO 8601 timestamp and compute relative time
    let ts = iso
        .split('T')
        .next()
        .and_then(|d| {
            let parts: Vec<&str> = d.split('-').collect();
            if parts.len() == 3 {
                let y: i64 = parts[0].parse().ok()?;
                let m: i64 = parts[1].parse().ok()?;
                let d: i64 = parts[2].parse().ok()?;
                Some(y * 365 + m * 30 + d)
            } else {
                None
            }
        });

    let now = {
        let output = std::process::Command::new("date")
            .arg("+%Y-%m-%d")
            .output()
            .ok();
        output.and_then(|o| {
            let s = String::from_utf8(o.stdout).ok()?;
            let parts: Vec<&str> = s.trim().split('-').collect();
            if parts.len() == 3 {
                let y: i64 = parts[0].parse().ok()?;
                let m: i64 = parts[1].parse().ok()?;
                let d: i64 = parts[2].parse().ok()?;
                Some(y * 365 + m * 30 + d)
            } else {
                None
            }
        })
    };

    match (ts, now) {
        (Some(t), Some(n)) => {
            let days = n - t;
            if days < 0 {
                "in the future".to_string()
            } else if days == 0 {
                "today".to_string()
            } else if days == 1 {
                "yesterday".to_string()
            } else if days < 7 {
                format!("{days} days ago")
            } else if days < 14 {
                "a week ago".to_string()
            } else if days < 30 {
                format!("{} weeks ago", days / 7)
            } else if days < 60 {
                "a month ago".to_string()
            } else if days < 365 {
                format!("{} months ago", days / 30)
            } else {
                format!("{} years ago", days / 365)
            }
        }
        _ => iso.to_string(),
    }
}

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const UNDERLINE: &str = "\x1b[4m";
const CYAN: &str = "\x1b[36m";
const YELLOW: &str = "\x1b[33m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const BLUE: &str = "\x1b[34m";
const DIM: &str = "\x1b[38;5;242m";

/// Auto-highlight a value like Rich's highlighter:
/// UUIDs/hashes → yellow, booleans → green/red, URLs → blue, else → cyan
fn highlight(val: &str) -> String {
    if val.eq_ignore_ascii_case("true") {
        format!("{GREEN}{val}{RESET}")
    } else if val.eq_ignore_ascii_case("false") {
        format!("{RED}{val}{RESET}")
    } else if val.starts_with("http://") || val.starts_with("https://") || val.starts_with("ssh://") || val.starts_with("git@") {
        format!("{BLUE}{val}{RESET}")
    } else if val.contains('-') && val.len() >= 32 && val.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        // UUIDs → yellow
        format!("{YELLOW}{val}{RESET}")
    } else if val.len() >= 32 && val.chars().all(|c| c.is_ascii_hexdigit()) {
        // Commit hashes → blue
        format!("{BLUE}{val}{RESET}")
    } else {
        format!("{CYAN}{val}{RESET}")
    }
}

// ─── Client ───

pub struct ApiClient {
    pub config: Config,
    client: reqwest::blocking::Client,
}

impl ApiClient {
    pub fn new() -> Result<Self> {
        let config = Config::load()?;
        let client = reqwest::blocking::Client::new();
        Ok(Self { config, client })
    }

    fn url(&self, path: &str) -> String {
        // Trailing slash must come before query string
        if let Some((base, query)) = path.split_once('?') {
            format!("{}/api/{base}/?{query}", self.config.api_url)
        } else {
            format!("{}/api/{path}/", self.config.api_url)
        }
    }

    fn get(&self, path: &str) -> Result<reqwest::blocking::Response> {
        let resp = self
            .client
            .get(self.url(path))
            .bearer_auth(&self.config.token)
            .send()?;
        check_status(resp)
    }

    fn post_json(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::blocking::Response> {
        let resp = self
            .client
            .post(self.url(path))
            .bearer_auth(&self.config.token)
            .json(body)
            .send()?;
        check_status(resp)
    }

    fn post_file(
        &self,
        path: &str,
        name: &str,
        data: Vec<u8>,
    ) -> Result<reqwest::blocking::Response> {
        let part = reqwest::blocking::multipart::Part::bytes(data).file_name(name.to_string());
        let form = reqwest::blocking::multipart::Form::new().part("file", part);
        let resp = self
            .client
            .post(self.url(path))
            .bearer_auth(&self.config.token)
            .multipart(form)
            .send()?;
        check_status(resp)
    }

    // ─── Flow operations ───

    pub fn flow_list(&self, flow: &str, count: usize) -> Result<Vec<Flow>> {
        let resp = self.get(&format!("flow/{flow}?num={count}"))?;
        Ok(resp.json()?)
    }

    pub fn flow_info(&self, flow: &str, id: &str) -> Result<Flow> {
        let resp = self.get(&format!("flow/{flow}/{id}"))?;
        Ok(resp.json()?)
    }

    pub fn flow_submit(&self, flow: &str, body: &serde_json::Value) -> Result<String> {
        let resp = self.post_json(&format!("flow/{flow}"), body)?;
        Ok(resp.text()?)
    }

    pub fn flow_cancel(&self, flow: &str, id: &str) -> Result<()> {
        let resp = self
            .client
            .post(self.url(&format!("flow/{flow}/{id}/cancel")))
            .bearer_auth(&self.config.token)
            .send()?;
        check_status(resp)?;
        Ok(())
    }

    pub fn flow_pull(&self, flow: &str, job_id: &str) -> Result<Vec<u8>> {
        let resp = self.get(&format!("flow/{flow}/job/{job_id}"))?;
        Ok(resp.bytes()?.to_vec())
    }

    // ─── Package operations ───

    pub fn list_packages(&self) -> Result<Vec<String>> {
        let resp = self.get("package")?;
        Ok(resp.json()?)
    }

    pub fn get_package(&self, package: &str) -> Result<Vec<u8>> {
        let resp = self.get(&format!("package/{package}"))?;
        Ok(resp.bytes()?.to_vec())
    }

    // ─── Flag operations ───

    pub fn submit_flag(&self, flag: &str, body: &serde_json::Value) -> Result<String> {
        let resp = self.post_json(&format!("flag/{flag}"), body)?;
        Ok(resp.text()?)
    }

    pub fn submit_flag_file(&self, flag: &str, name: &str, data: Vec<u8>) -> Result<String> {
        let resp = self.post_file(&format!("flag/{flag}"), name, data)?;
        Ok(resp.text()?)
    }
}

fn check_status(resp: reqwest::blocking::Response) -> Result<reqwest::blocking::Response> {
    let status = resp.status();
    let url = resp.url().to_string();
    if status.is_success() {
        return Ok(resp);
    }
    let code = status.as_u16();
    let text = resp.text().unwrap_or_default();
    log::debug(&format!("API {code} from {url}: {text}"));
    // Try to extract {"detail": "..."} from JSON responses
    let detail = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| v["detail"].as_str().map(|s| s.to_string()))
        .unwrap_or(text);
    match code {
        401 => bail!("Authentication failed. Check your API token."),
        _ => bail!("{detail}"),
    }
}

// ─── Command implementations ───

fn flow_overall_status(f: &Flow) -> String {
    // Derive status from jobs like the Python tool does
    if f.jobs.iter().any(|j| j.status == "failed") {
        "Failed".to_string()
    } else if f.completed {
        "Succeeded".to_string()
    } else if f.jobs.iter().any(|j| j.status == "running") {
        "Running".to_string()
    } else {
        "Queued".to_string()
    }
}

pub fn cmd_flow_list(flow: &str, count: usize) -> Result<()> {
    let api = ApiClient::new()?;
    let flows = api.flow_list(flow, count)?;
    if flows.is_empty() {
        log::info("No flows found");
        return Ok(());
    }

    let flow_title = titlecase(flow);
    let id_header = format!("{flow_title} ID");

    // Calculate column widths
    let id_w = flows.iter().map(|f| f.id.len()).max().unwrap_or(36).max(id_header.len());
    let time_w = 14; // "When Submitted"
    let status_w = 9;

    let total = id_w + time_w + status_w + 10; // 10 for borders + padding
    let title = format!("Submitted {flow_title} Flows");
    let pad = total.saturating_sub(title.len()) / 2;

    // Title
    println!("{BOLD}{:>pad$}{title}{RESET}", "");
    // Top border
    println!("┏{:━<id_w$}━━┳{:━<time_w$}━━┳{:━<status_w$}━━┓", "", "", "");
    // Header
    println!(
        "┃ {BOLD}{:<id_w$}{RESET} ┃ {BOLD}{:<time_w$}{RESET} ┃ {BOLD}{:<status_w$}{RESET} ┃",
        id_header, "When Submitted", "Status"
    );
    // Header separator
    println!("┡{:━<id_w$}━━╇{:━<time_w$}━━╇{:━<status_w$}━━┩", "", "", "");

    for f in &flows {
        let status = flow_overall_status(f);
        let sc = status_color(&status.to_lowercase());
        let when = relative_time(&f.submit_time);
        println!(
            "│ {:<id_w$} │ {:<time_w$} │ {sc}{:<status_w$}{RESET} │",
            f.id, when, status
        );
    }

    // Bottom border
    println!("└{:─<id_w$}──┴{:─<time_w$}──┴{:─<status_w$}──┘", "", "", "");

    Ok(())
}

pub fn cmd_flow_info(flow: &str, id: &str) -> Result<()> {
    let api = ApiClient::new()?;
    let f = api.flow_info(flow, id)?;
    let status = flow_overall_status(&f);
    let sc = status_color(&status.to_lowercase());
    let when = relative_time(&f.submit_time);

    println!("{BOLD}{UNDERLINE}Flow {flow}{RESET}");
    println!("├── ID: {}", highlight(&f.id));
    // Format like Python: "2026-02-11 22:05:47+00:00"
    let display_time = f.submit_time
        .replace('T', " ")
        .split('.')
        .next()
        .unwrap_or(&f.submit_time)
        .to_string()
        + "+00:00";
    println!("├── Submitted: {} ({when})", highlight(&display_time));
    println!("├── Status: {sc}{status}{RESET}");

    // Parameters
    if let Some(obj) = f.params.as_object() {
        if !obj.is_empty() {
            println!("├── Parameters");
            let params: Vec<_> = obj.iter().collect();
            for (i, (k, v)) in params.iter().enumerate() {
                let connector = if i == params.len() - 1 { "└" } else { "├" };
                let fallback = v.to_string();
                let val = v.as_str().unwrap_or(&fallback);
                println!("│   {connector}── {k}: {}", highlight(val));
            }
        }
    }

    // Jobs
    if !f.jobs.is_empty() {
        println!("└── Jobs");
        for (i, job) in f.jobs.iter().enumerate() {
            let is_last = i == f.jobs.len() - 1;
            let branch = if is_last { "└" } else { "├" };
            let prefix = if is_last { " " } else { "│" };
            let jsc = status_color(&job.status);
            println!("    {branch}── {BOLD}{}{RESET}", job.name);
            println!("    {prefix}   ├── ID: {}", highlight(&job.id));
            println!("    {prefix}   ├── Has Output: {}", highlight(&titlecase(&job.has_artifacts.to_string())));
            println!("    {prefix}   ├── Private: {}", highlight(&titlecase(&job.private.to_string())));
            println!("    {prefix}   └── Status: {jsc}{}{RESET}", titlecase(&job.status));
        }
    }

    Ok(())
}

pub fn cmd_flow_submit(flow: &str, commit: &str, url: Option<&str>) -> Result<()> {
    let api = ApiClient::new()?;
    let git_url = url
        .map(|s| s.to_string())
        .unwrap_or_else(|| api.config.git_url.clone());
    let body = serde_json::json!({
        "git_url": git_url,
        "commit_hash": commit,
    });
    let id = api.flow_submit(flow, &body)?;
    log::success(&format!("Submitted {flow} flow: {id}"));
    Ok(())
}

pub fn cmd_flow_cancel(flow: &str, id: &str) -> Result<()> {
    let api = ApiClient::new()?;
    api.flow_cancel(flow, id)?;
    log::success(&format!("Cancelled flow {id}"));
    Ok(())
}

pub fn cmd_flow_get(flow: &str, job_id: &str, out: &PathBuf) -> Result<()> {
    let api = ApiClient::new()?;
    let data = api.flow_pull(flow, job_id)?;
    std::fs::write(out, &data)?;
    log::success(&format!("Downloaded to {}", out.display()));
    Ok(())
}

pub fn cmd_submit(commit: &str) -> Result<()> {
    cmd_flow_submit("submit", commit, None)
}

pub fn cmd_photo(file: &PathBuf) -> Result<()> {
    let api = ApiClient::new()?;
    let data = std::fs::read(file).context("Failed to read file")?;
    let name = file
        .file_name()
        .context("No filename")?
        .to_str()
        .context("Invalid filename")?;
    let resp = api.submit_flag_file("photo", name, data)?;
    log::success(&format!("Photo submitted: {resp}"));
    Ok(())
}

pub fn cmd_design(file: &PathBuf) -> Result<()> {
    let api = ApiClient::new()?;
    let data = std::fs::read(file).context("Failed to read file")?;
    let name = file
        .file_name()
        .context("No filename")?
        .to_str()
        .context("Invalid filename")?;
    let resp = api.submit_flag_file("design", name, data)?;
    log::success(&format!("Design doc submitted: {resp}"));
    Ok(())
}

pub fn cmd_steal(team: &str, digest: &str) -> Result<()> {
    let api = ApiClient::new()?;
    let body = serde_json::json!({
        "team": team,
        "digest": digest,
    });
    let resp = api.submit_flag("steal", &body)?;
    log::success(&format!("Steal submitted: {resp}"));
    Ok(())
}

pub fn cmd_list_packages() -> Result<()> {
    let api = ApiClient::new()?;
    let packages = api.list_packages()?;
    if packages.is_empty() {
        log::info("No packages available");
    } else {
        for p in &packages {
            log::info(p);
        }
    }
    Ok(())
}

pub fn cmd_get_package(package: &str, out: Option<&PathBuf>, force: bool) -> Result<()> {
    let api = ApiClient::new()?;
    let data = api.get_package(package)?;
    let path = out.cloned().unwrap_or_else(|| PathBuf::from(package));
    if !force && path.exists() {
        bail!(
            "File {} already exists (use --force to overwrite)",
            path.display()
        );
    }
    std::fs::write(&path, &data)?;
    log::success(&format!("Downloaded {} to {}", package, path.display()));
    Ok(())
}

// ─── Remote scenario ───

const REMOTE_HOST: &str = "54.163.176.58";

pub fn cmd_remote_connect(
    mgmt_port: &str,
    transfer_port: &str,
    team: &str,
    timeout: u64,
) -> Result<()> {
    let api = ApiClient::new()?;

    // Submit remote flow
    let body = serde_json::json!({"team": team});
    let flow_id = api.flow_submit("remote", &body)?;
    log::info(&format!("Submitted remote flow: {flow_id}"));

    // Poll for get_ports job
    log::info("Waiting for port assignment...");
    let port: u16 = loop {
        std::thread::sleep(Duration::from_secs(3));
        let flow = api.flow_info("remote", &flow_id)?;
        if let Some(job) = flow.jobs.iter().find(|j| j.name == "get_ports") {
            match job.status.as_str() {
                "succeeded" => {
                    let data = api.flow_pull("remote", &job.id)?;
                    let port_str = String::from_utf8(data)?.trim().to_string();
                    break port_str.parse().context("Invalid port number")?;
                }
                "canceled" | "failed" => bail!("Port assignment failed"),
                _ => continue,
            }
        }
    };

    log::info(&format!("Assigned port {port}, connecting..."));

    // Connect to remote server
    let tcp = TcpStream::connect((REMOTE_HOST, port)).context("Failed to connect to remote")?;
    tcp.set_nodelay(true)?;
    log::success("Connected to remote server");

    // Open serial ports
    let transfer_file = serial::open_serial(transfer_port, None)?;
    let mgmt_port_str = mgmt_port.to_string();

    let done = Arc::new(AtomicBool::new(false));

    // Bridge: TCP → transfer serial
    let tcp_r = tcp.try_clone()?;
    let mut transfer_w = transfer_file.try_clone()?;
    let done1 = done.clone();
    let h1 = std::thread::spawn(move || {
        let mut reader = tcp_r;
        let mut buf = [0u8; 4096];
        while !done1.load(Ordering::Relaxed) {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if transfer_w.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Bridge: transfer serial → TCP
    let mut tcp_w = tcp.try_clone()?;
    let done2 = done.clone();
    let h2 = std::thread::spawn(move || {
        let mut reader = transfer_file;
        let mut buf = [0u8; 4096];
        while !done2.load(Ordering::Relaxed) {
            match reader.read(&mut buf) {
                Ok(0) => continue,
                Ok(n) => {
                    if tcp_w.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // HSM listen on management port
    let done3 = done.clone();
    let h3 = std::thread::spawn(move || {
        if done3.load(Ordering::Relaxed) {
            return;
        }
        match HSMIntf::open(&mgmt_port_str) {
            Ok(mut hsm) => {
                let _ = hsm.send_respond(Opcode::Listen, &[]);
            }
            Err(e) => log::warning(&format!("Management port error: {e}")),
        }
    });

    // Poll flow status with timeout
    let start = Instant::now();
    let timeout_dur = Duration::from_secs(timeout);
    loop {
        std::thread::sleep(Duration::from_secs(3));
        if start.elapsed() > timeout_dur {
            log::warning("Remote scenario timed out");
            break;
        }
        match api.flow_info("remote", &flow_id) {
            Ok(flow) => {
                if let Some(job) = flow
                    .jobs
                    .iter()
                    .find(|j| j.name == "run_remote_scenario")
                {
                    match job.status.as_str() {
                        "succeeded" => {
                            log::success("Remote scenario completed successfully");
                            break;
                        }
                        "canceled" | "failed" => {
                            log::error("Remote scenario failed");
                            break;
                        }
                        _ => {
                            log::debug(&format!("Scenario status: {}", job.status));
                        }
                    }
                }
            }
            Err(e) => log::warning(&format!("Failed to check status: {e}")),
        }
    }

    done.store(true, Ordering::Relaxed);

    // Shutdown TCP to unblock threads
    let _ = tcp.shutdown(std::net::Shutdown::Both);

    let _ = h1.join();
    let _ = h2.join();
    let _ = h3.join();

    Ok(())
}
