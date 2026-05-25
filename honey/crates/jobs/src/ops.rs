//! Host-level ops commands. These shell out to iptables, ipset, curl, docker.
//! Each command is a port of a former `scripts/setup-*.sh` script — kept as
//! thin wrappers since reimplementing iptables in Rust is not the win we want.

use anyhow::{anyhow, Context, Result};
use std::process::Command;
use tracing::info;

/// `iptables -t nat`: redirect 22 → 2222 (SSH) and 23 → 2223 (Telnet).
/// Run on the host as root.
pub fn port_redirect() -> Result<()> {
    add_nat_redirect(22, 2222)?;
    add_nat_redirect(23, 2223)?;
    println!("port redirect active: 22→2222, 23→2223");
    Ok(())
}

fn add_nat_redirect(from: u16, to: u16) -> Result<()> {
    // Use --check to skip if the rule already exists; tolerate non-zero exit.
    let check = Command::new("iptables")
        .args([
            "-t", "nat", "-C", "PREROUTING", "-p", "tcp",
            "--dport", &from.to_string(),
            "-j", "REDIRECT", "--to-port", &to.to_string(),
        ])
        .status();
    if matches!(check, Ok(s) if s.success()) {
        info!(from, to, "rule already present");
        return Ok(());
    }
    let status = Command::new("iptables")
        .args([
            "-t", "nat", "-A", "PREROUTING", "-p", "tcp",
            "--dport", &from.to_string(),
            "-j", "REDIRECT", "--to-port", &to.to_string(),
        ])
        .status()
        .context("running iptables")?;
    if !status.success() {
        return Err(anyhow!("iptables -A PREROUTING failed ({status})"));
    }
    Ok(())
}

/// Restrict a TCP port to Brazilian IPv4 ranges via ipset + iptables.
/// Replaces setup-brazil-ipset.sh + update-brazil-ipset.sh (idempotent).
pub fn brazil_ipset(port: u16, set_name: &str) -> Result<()> {
    use std::io::Write;

    info!(%port, %set_name, "fetching LACNIC delegated ranges");
    let body = curl_text("https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest")?;
    let mut cidrs: Vec<String> = body
        .lines()
        .filter(|l| l.starts_with("lacnic|BR|ipv4"))
        .filter_map(|l| {
            let parts: Vec<&str> = l.split('|').collect();
            if parts.len() < 5 { return None; }
            let ip = parts[3];
            let count: u32 = parts[4].parse().ok()?;
            // count = 2^(32-prefix) → prefix = 32 - log2(count)
            let bits = count.next_power_of_two().trailing_zeros();
            let prefix = 32u32.saturating_sub(bits);
            Some(format!("{ip}/{prefix}"))
        })
        .collect();
    cidrs.sort();
    cidrs.dedup();
    info!(cidrs = cidrs.len(), "loaded ranges");

    // Tear down any previous set with this name (silent if absent).
    let _ = Command::new("ipset").args(["destroy", set_name]).status();

    let status = Command::new("ipset")
        .args(["create", set_name, "hash:net", "family", "inet", "maxelem", "65536"])
        .status()
        .context("ipset create")?;
    if !status.success() {
        return Err(anyhow!("ipset create failed ({status})"));
    }

    // Use `ipset restore` for a single fast batch load.
    let mut child = Command::new("ipset")
        .arg("restore")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("spawning ipset restore")?;
    {
        let stdin = child.stdin.as_mut().ok_or_else(|| anyhow!("no stdin"))?;
        for c in &cidrs {
            writeln!(stdin, "add {set_name} {c}")?;
        }
    }
    let status = child.wait().context("ipset restore wait")?;
    if !status.success() {
        return Err(anyhow!("ipset restore failed ({status})"));
    }

    // Idempotent iptables rules.
    let dport = port.to_string();
    // Remove pre-existing duplicates (silent if absent).
    let _ = Command::new("iptables")
        .args(["-D", "INPUT", "-p", "tcp", "--dport", &dport,
               "-m", "set", "--match-set", set_name, "src", "-j", "ACCEPT"])
        .status();
    let _ = Command::new("iptables")
        .args(["-D", "INPUT", "-p", "tcp", "--dport", &dport, "-j", "DROP"])
        .status();
    run(&["iptables", "-I", "INPUT", "-p", "tcp", "--dport", &dport, "-j", "DROP"])?;
    run(&["iptables", "-I", "INPUT", "-p", "tcp", "--dport", &dport,
          "-m", "set", "--match-set", set_name, "src", "-j", "ACCEPT"])?;

    println!("port {port} restricted to Brazilian IPv4 ({} CIDRs in ipset {set_name})", cidrs.len());
    Ok(())
}

fn curl_text(url: &str) -> Result<String> {
    let out = Command::new("curl")
        .args(["-s", "--fail", url])
        .output()
        .context("running curl")?;
    if !out.status.success() {
        return Err(anyhow!("curl exited {status}", status = out.status));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn run(argv: &[&str]) -> Result<()> {
    let (cmd, rest) = argv.split_first().ok_or_else(|| anyhow!("empty argv"))?;
    let status = Command::new(cmd).args(rest).status()
        .with_context(|| format!("running {cmd}"))?;
    if !status.success() {
        return Err(anyhow!("{cmd} exited {status}"));
    }
    Ok(())
}

/// One-shot Let's Encrypt initial cert. Drives `docker compose` + `certbot/certbot`.
/// Must be run from the project root.
pub fn letsencrypt(target_host: &str, email: &str) -> Result<()> {
    info!(target_host, "starting nginx for ACME challenge");
    run(&["docker", "compose", "up", "-d", "nginx"])?;

    info!(target_host, "running certbot certonly");
    let cwd = std::env::current_dir().context("cwd")?;
    let le_mount = format!("{}/letsencrypt:/etc/letsencrypt", cwd.display());
    let www_mount = format!("{}/certbot/www:/var/www/certbot", cwd.display());
    let status = Command::new("docker")
        .args([
            "run", "--rm", "--network", "host",
            "-v", &le_mount,
            "-v", &www_mount,
            "certbot/certbot", "certonly",
            "--webroot", "--webroot-path", "/var/www/certbot",
            "--email", email,
            "--agree-tos", "--no-eff-email",
            "-d", target_host,
        ])
        .status()
        .context("docker run certbot")?;
    if !status.success() {
        return Err(anyhow!("certbot exited {status}"));
    }

    info!("reloading nginx");
    run(&["docker", "compose", "exec", "nginx", "nginx", "-s", "reload"])?;
    println!("Let's Encrypt cert for {target_host} obtained.");
    println!("Schedule renewal with: docker compose run --rm certbot renew");
    Ok(())
}
