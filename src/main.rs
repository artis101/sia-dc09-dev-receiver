#[cfg(test)]
use aes::cipher::BlockEncryptMut;
use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use clap::Parser;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use std::time::Duration;

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes192CbcDec = cbc::Decryptor<aes::Aes192>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
#[cfg(test)]
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

const LF: u8 = 0x0A;
const CR: u8 = 0x0D;
const PID_FILE: &str = "/var/run/sia-dc09-dev-receiver.pid";
const LOG_FILE: &str = "/var/log/sia-dc09-dev-receiver.log";

#[derive(Parser, Clone)]
#[command(
    name = "sia-dc09-dev-receiver",
    about = "Developer receiver for SIA DC-09 integrations"
)]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value_t = 1111)]
    port: u16,

    /// Reply mode: ACK, NAK, or DUH
    #[arg(short, long, default_value = "ACK")]
    reply: String,

    /// Idle socket timeout in seconds (0 = no timeout)
    #[arg(short, long, default_value_t = 60)]
    idle: u64,

    /// AES encryption key (hex; 16/24/32 bytes for AES-128/192/256)
    #[arg(short, long, default_value = "DEADBEEFCAFEBABEDEADBEEFCAFEBABE")]
    key: String,

    /// Run as daemon in background
    #[arg(short, long)]
    daemon: bool,

    /// PID file path
    #[arg(long, default_value = PID_FILE)]
    pid_file: PathBuf,

    /// Log file path (used in daemon mode; foreground logs to stdout)
    #[arg(short, long, default_value = LOG_FILE)]
    log_file: PathBuf,
}

fn crc16_ibm(data: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000;
    for &byte in data {
        crc ^= byte as u16;
        for _ in 0..8 {
            let lsb = crc & 1;
            crc >>= 1;
            if lsb != 0 {
                crc ^= 0xA001;
            }
        }
    }
    crc
}

fn parse_key(hex_str: &str) -> Vec<u8> {
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(clean).expect("Invalid hex in --key");
    match bytes.len() {
        16 | 24 | 32 => bytes,
        _ => {
            eprintln!("AES key must be 16, 24, or 32 bytes (got {})", bytes.len());
            std::process::exit(1);
        }
    }
}

fn try_decrypt(ct: &[u8], key: &[u8]) -> Option<String> {
    let iv = [0u8; 16];
    let pt = match key.len() {
        16 => Aes128CbcDec::new(key.into(), &iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(ct)
            .ok()?,
        24 => Aes192CbcDec::new(key.into(), &iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(ct)
            .ok()?,
        32 => Aes256CbcDec::new(key.into(), &iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(ct)
            .ok()?,
        _ => return None,
    };
    String::from_utf8(pt).ok()
}

fn decrypt_payload(hex_ct: &str, key: &[u8]) -> Option<String> {
    let ct = hex::decode(hex_ct).ok()?;
    if ct.len() % 16 != 0 || ct.is_empty() {
        return None;
    }
    try_decrypt(&ct, key)
}

/// Parsed SIA DC-09 header fields
struct SiaHeader<'a> {
    seq: &'a str,
    receiver: Option<&'a str>,
    prefix_acct: Option<&'a str>,
    encrypted: bool,
}

fn build_reply(
    kind: &str,
    seq: &str,
    receiver: Option<&str>,
    prefix_acct: Option<&str>,
) -> Vec<u8> {
    let mut reply_middle = format!("\"{kind}\"{seq}");
    if let Some(r) = receiver {
        reply_middle.push_str(r);
    }
    if let Some(a) = prefix_acct {
        reply_middle.push_str(a);
    } else {
        reply_middle.push_str("L0");
    }
    let len_field = format!("0{:03X}", reply_middle.len());
    let crc = crc16_ibm(reply_middle.as_bytes());
    let crc_field = format!("{crc:04X}");

    let mut frame = Vec::new();
    frame.push(LF);
    frame.extend_from_slice(crc_field.as_bytes());
    frame.extend_from_slice(len_field.as_bytes());
    frame.extend_from_slice(reply_middle.as_bytes());
    frame.push(CR);
    frame
}

/// Parse the header after the ID token: SEQ R? A? Lx #acct? [body] _ts?
/// Returns (SiaHeader, remainder starting at '[')
fn parse_header<'a>(id: &'a str, after_id: &'a str) -> Option<(SiaHeader<'a>, &'a str)> {
    let encrypted = id.starts_with('*');

    // Sequence number: 4 digits
    if after_id.len() < 4 {
        return None;
    }
    let seq = &after_id[..4];
    let rest = &after_id[4..];

    // Optional Rxx..x (receiver number)
    let (receiver, rest) = if let Some(stripped) = rest.strip_prefix('R') {
        // R followed by digits up to next letter
        let end = stripped
            .find(|c: char| c.is_ascii_alphabetic() || c == '#' || c == '[')
            .map(|p| p + 1)
            .unwrap_or(rest.len());
        (Some(&rest[..end]), &rest[end..])
    } else {
        (None, rest)
    };

    // Optional Axx..x (area/line) — skip it
    let rest = if let Some(stripped) = rest.strip_prefix('A') {
        let end = stripped
            .find(|c: char| c.is_ascii_alphabetic() || c == '#' || c == '[')
            .map(|p| p + 1)
            .unwrap_or(rest.len());
        &rest[end..]
    } else {
        rest
    };

    // Lx — account prefix length (digits after 'L' give the length)
    let (prefix_acct, rest) = if let Some(stripped) = rest.strip_prefix('L') {
        let digit_end = stripped
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(stripped.len());
        let prefix_len: usize = stripped[..digit_end].parse().unwrap_or(0);
        let l_field_end = 1 + digit_end + prefix_len;
        if l_field_end > rest.len() {
            return None;
        }
        (Some(&rest[..l_field_end]), &rest[l_field_end..])
    } else {
        return None;
    };

    Some((
        SiaHeader {
            seq,
            receiver,
            prefix_acct,
            encrypted,
        },
        rest,
    ))
}

fn parse_and_log_payload(remainder: &str) {
    // remainder = #acct[body]_timestamp  OR  [body]_timestamp  OR  [body]  OR  #acct[]
    // Find the bracket-enclosed body
    let bracket_start = match remainder.find('[') {
        Some(p) => p,
        None => {
            eprintln!("  ! missing '[' in payload");
            return;
        }
    };
    let bracket_end = match remainder.find(']') {
        Some(p) => p,
        None => {
            eprintln!("  ! missing ']' in payload");
            return;
        }
    };

    let prefix = &remainder[..bracket_start]; // e.g. "#acct" or ""
    let body = &remainder[bracket_start + 1..bracket_end];
    let after_bracket = &remainder[bracket_end + 1..];

    // Optional timestamp: _HH:MM:SS,MM-DD-YYYY
    let timestamp = if let Some(ts) = after_bracket.strip_prefix('_') {
        let clean: String = ts
            .chars()
            .filter(|c| c.is_ascii_graphic() || *c == ' ')
            .collect::<String>()
            .trim()
            .to_string();
        if clean.is_empty() { None } else { Some(clean) }
    } else {
        None
    };

    // Account from prefix (#acct) or from body (#acct|event)
    let prefix_acct = prefix.strip_prefix('#');

    if body.is_empty() {
        // NULL / supervision poll
        if let Some(acct) = prefix_acct {
            println!("  Type     : NULL (supervision)");
            println!("  Account  : {acct}");
        } else {
            println!("  Type     : NULL (supervision)");
        }
    } else {
        // Parse body: #account|Nri0/CODE^text^text...
        let parts: Vec<&str> = body.split('^').collect();
        let head = parts[0];

        if let Some(rest) = head.strip_prefix('#') {
            if let Some(pipe) = rest.find('|') {
                let account = &rest[..pipe];
                let event = &rest[pipe + 1..];
                println!("  Account  : {account}");
                println!("  Event    : {event}");
            } else {
                println!("  Account  : {rest}");
            }
        } else if let Some(acct) = prefix_acct {
            println!("  Account  : {acct}");
            println!("  Data     : {head}");
        } else {
            println!("  Data     : {head}");
        }

        let texts: Vec<&str> = parts[1..]
            .iter()
            .copied()
            .filter(|s| !s.is_empty())
            .collect();
        if !texts.is_empty() {
            println!("  Texts    : {texts:?}");
        }
    }

    if let Some(ts) = timestamp {
        println!("  Timestamp: {ts}");
    }
}

fn handle_client(stream: TcpStream, config: Arc<Args>, key: Vec<u8>) {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".into());
    println!("+ Connection from {peer}");

    let mut stream = stream;
    if config.idle > 0 {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(config.idle)));
    }
    let _ = stream.set_nodelay(true);

    let mut rx = Vec::new();
    let mut buf = [0u8; 4096];

    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                rx.extend_from_slice(&buf[..n]);
                process_frames(&mut rx, &mut stream, &config, &key);
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                println!("- Idle timeout for {peer}");
                break;
            }
            Err(e) => {
                eprintln!("- Socket error for {peer}: {e}");
                break;
            }
        }
    }
    println!("- Disconnected {peer}");
}

fn process_frames(rx: &mut Vec<u8>, stream: &mut TcpStream, config: &Args, key: &[u8]) {
    loop {
        let lf_pos = match rx.iter().position(|&b| b == LF) {
            Some(p) => p,
            None => return,
        };
        let cr_pos = match rx[lf_pos + 1..].iter().position(|&b| b == CR) {
            Some(p) => lf_pos + 1 + p,
            None => return,
        };

        let frame = rx[lf_pos + 1..cr_pos].to_vec();
        rx.drain(..=cr_pos);

        let ascii = match std::str::from_utf8(&frame) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("! Non-ASCII frame, sending DUH");
                let _ = stream.write_all(&build_reply("DUH", "0000", None, None));
                continue;
            }
        };

        if ascii.len() < 8 {
            eprintln!("! Frame too short ({} bytes), sending DUH", ascii.len());
            let _ = stream.write_all(&build_reply("DUH", "0000", None, None));
            continue;
        }

        let crc_str = &ascii[..4];
        let len_str = &ascii[4..8];
        let middle = &ascii[8..];

        // Verify length
        let declared_len = match u16::from_str_radix(&len_str[1..], 16) {
            Ok(n) => n as usize,
            Err(_) => {
                eprintln!("! Bad length field: {len_str}");
                let _ = stream.write_all(&build_reply("DUH", "0000", None, None));
                continue;
            }
        };
        if declared_len != middle.len() {
            eprintln!(
                "! Length mismatch: declared {declared_len} vs actual {}",
                middle.len()
            );
            let _ = stream.write_all(&build_reply("DUH", "0000", None, None));
            continue;
        }

        // Verify CRC
        let calc_crc = format!("{:04X}", crc16_ibm(middle.as_bytes()));
        if calc_crc != crc_str {
            eprintln!("! CRC mismatch: got {crc_str}, expected {calc_crc}");
            let _ = stream.write_all(&build_reply("DUH", "0000", None, None));
            continue;
        }

        // Extract ID token: "SIA-DCS" or "*SIA-DCS" or "NULL" etc.
        let id_end = match middle[1..].find('"') {
            Some(p) => p + 2,
            None => {
                eprintln!("! Missing ID token closing quote");
                let duh = build_reply("DUH", "0000", None, None);
                let _ = stream.write_all(&duh);
                continue;
            }
        };

        let id_token = &middle[1..id_end - 1];
        let after_id = &middle[id_end..];

        let (header, remainder) = match parse_header(id_token, after_id) {
            Some(h) => h,
            None => {
                eprintln!("! Failed to parse header: {after_id}");
                let duh = build_reply("DUH", "0000", None, None);
                let _ = stream.write_all(&duh);
                continue;
            }
        };

        let is_null = id_token == "NULL" || id_token == "*NULL";

        if is_null {
            println!(">> NULL (supervision poll) seq={}", header.seq);
            parse_and_log_payload(remainder);
        } else if header.encrypted {
            println!(">> SIA event received (encrypted) seq={}", header.seq);
            // Find bracket-enclosed ciphertext
            let bracket_start = remainder.find('[');
            let bracket_end = remainder.find(']');
            if let (Some(bs), Some(be)) = (bracket_start, bracket_end) {
                let hex_ct = &remainder[bs + 1..be];
                let after_bracket = &remainder[be + 1..];
                let prefix = &remainder[..bs];

                match decrypt_payload(hex_ct, key) {
                    Some(plaintext) => {
                        println!("  Decrypted: {plaintext}");
                        // If decrypted text already contains brackets, use it directly
                        if plaintext.contains('[') && plaintext.contains(']') {
                            let synth = format!("{prefix}{plaintext}{after_bracket}");
                            parse_and_log_payload(&synth);
                        } else {
                            let synth = format!("{prefix}[{plaintext}]{after_bracket}");
                            parse_and_log_payload(&synth);
                        }
                    }
                    None => {
                        eprintln!("  ! Decryption failed (wrong key?)");
                        println!("  Ciphertext: {hex_ct}");
                    }
                }
            } else {
                // No brackets — ciphertext is placed directly after header
                // (brackets are inside the encrypted payload)
                // remainder may be: #acct<hex>_ts, #acct<hex>, <hex>_ts, or just <hex>
                let (prefix, hex_part) = if let Some(stripped) = remainder.strip_prefix('#') {
                    // Has #acct prefix — find where hex starts (first non-alphanumeric after #)
                    let acct_end = stripped
                        .find(|c: char| !c.is_ascii_alphanumeric())
                        .map(|p| p + 1)
                        .unwrap_or(remainder.len());
                    (&remainder[..acct_end], &remainder[acct_end..])
                } else {
                    ("", remainder)
                };
                // Split off _timestamp suffix if present
                let hex_ct = if let Some(ts_pos) = hex_part.find('_') {
                    &hex_part[..ts_pos]
                } else {
                    hex_part.trim_end()
                };
                let hex_ct = hex_ct.trim();
                if hex_ct.is_empty() {
                    eprintln!("  ! empty encrypted payload (remainder: {remainder:?})");
                } else {
                    match decrypt_payload(hex_ct, key) {
                        Some(plaintext) => {
                            println!("  Decrypted: {plaintext}");
                            let synth = if plaintext.contains('[') {
                                format!("{prefix}{plaintext}")
                            } else {
                                format!("{prefix}[{plaintext}]")
                            };
                            parse_and_log_payload(&synth);
                        }
                        None => {
                            eprintln!("  ! Decryption failed (wrong key?)");
                            eprintln!("  Remainder: {remainder:?}");
                            println!("  Ciphertext: {hex_ct}");
                        }
                    }
                }
            }
        } else {
            println!(">> SIA event received seq={}", header.seq);
            parse_and_log_payload(remainder);
        }

        let reply = build_reply(
            &config.reply,
            header.seq,
            header.receiver,
            header.prefix_acct,
        );
        println!("<< Sending {} seq={}", config.reply, header.seq);
        let _ = stream.write_all(&reply);
    }
}

fn read_pid(pid_file: &PathBuf) -> Option<u32> {
    std::fs::read_to_string(pid_file)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

fn daemonize(args: &Args) {
    // Check if already running
    if let Some(pid) = read_pid(&args.pid_file) {
        // Check if process is alive via kill -0
        let alive = unsafe { libc::kill(pid as i32, 0) == 0 };
        if alive {
            println!("Server already running (PID {pid}), restarting...");
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            eprintln!("fork() failed");
            process::exit(1);
        }
        if pid > 0 {
            // Parent
            println!("Daemonized with PID {pid}");
            if let Err(e) = std::fs::write(&args.pid_file, format!("{pid}\n")) {
                eprintln!("Warning: could not write PID file: {e}");
            }
            process::exit(0);
        }
        // Child — new session
        libc::setsid();

        // Redirect stdout/stderr to log file
        if let Ok(file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&args.log_file)
        {
            let fd = file.as_raw_fd();
            libc::dup2(fd, 1); // stdout
            libc::dup2(fd, 2); // stderr
            // fd stays open via dup2; the File drop is fine
            std::mem::forget(file); // keep the fd alive
        } else {
            eprintln!("Warning: could not open log file {:?}", args.log_file);
        }
    }
}

fn main() {
    let args = Args::parse();

    if !matches!(args.reply.as_str(), "ACK" | "NAK" | "DUH") {
        eprintln!("Invalid reply mode: {}. Use ACK, NAK, or DUH.", args.reply);
        process::exit(1);
    }

    if args.daemon {
        daemonize(&args);
    }

    let key = parse_key(&args.key);
    let config = Arc::new(args.clone());

    let bind_addr = format!("0.0.0.0:{}", config.port);
    let listener = match TcpListener::bind(&bind_addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind {bind_addr}: {e}");
            process::exit(1);
        }
    };

    println!(
        "SIA DC-09 Dev Receiver listening on {bind_addr} (reply={}, idle={}s)",
        config.reply, config.idle
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let cfg = Arc::clone(&config);
                let k = key.clone();
                std::thread::spawn(move || handle_client(stream, cfg, k));
            }
            Err(e) => eprintln!("Accept error: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_middle(frame: &[u8]) -> &str {
        assert_eq!(frame.first(), Some(&LF));
        assert_eq!(frame.last(), Some(&CR));
        let ascii = std::str::from_utf8(&frame[1..frame.len() - 1]).unwrap();
        &ascii[8..]
    }

    #[test]
    fn crc16_ibm_matches_standard_check_value() {
        assert_eq!(crc16_ibm(b"123456789"), 0xBB3D);
    }

    #[test]
    fn build_reply_includes_valid_crc_length_and_default_prefix() {
        let frame = build_reply("ACK", "0042", None, None);
        let ascii = std::str::from_utf8(&frame[1..frame.len() - 1]).unwrap();
        let crc = &ascii[..4];
        let len = &ascii[4..8];
        let middle = &ascii[8..];

        assert_eq!(middle, "\"ACK\"0042L0");
        assert_eq!(usize::from_str_radix(&len[1..], 16).unwrap(), middle.len());
        assert_eq!(crc, format!("{:04X}", crc16_ibm(middle.as_bytes())));
    }

    #[test]
    fn build_reply_preserves_receiver_and_account_prefix() {
        let frame = build_reply("NAK", "0007", Some("R12"), Some("L4ACCT"));

        assert_eq!(frame_middle(&frame), "\"NAK\"0007R12L4ACCT");
    }

    #[test]
    fn parse_header_handles_receiver_area_prefix_and_remainder() {
        let (header, remainder) =
            parse_header("SIA-DCS", "0001R22A01L4ACCT[#ACCT|Nri0/BA]").unwrap();

        assert_eq!(header.seq, "0001");
        assert_eq!(header.receiver, Some("R22"));
        assert_eq!(header.prefix_acct, Some("L4ACCT"));
        assert!(!header.encrypted);
        assert_eq!(remainder, "[#ACCT|Nri0/BA]");
    }

    #[test]
    fn parse_header_marks_encrypted_messages() {
        let (header, remainder) = parse_header("*SIA-DCS", "1234L0[00112233]").unwrap();

        assert_eq!(header.seq, "1234");
        assert_eq!(header.prefix_acct, Some("L0"));
        assert!(header.encrypted);
        assert_eq!(remainder, "[00112233]");
    }

    #[test]
    fn decrypt_payload_accepts_aes_128_cbc_hex_ciphertext() {
        let key = hex::decode("DEADBEEFCAFEBABEDEADBEEFCAFEBABE").unwrap();
        let iv = [0u8; 16];
        let ciphertext = Aes128CbcEnc::new(key.as_slice().into(), &iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(b"#1234|Nri0/BA");
        let hex_ciphertext = hex::encode(ciphertext);

        assert_eq!(
            decrypt_payload(&hex_ciphertext, &key),
            Some("#1234|Nri0/BA".to_string())
        );
    }

    #[test]
    fn decrypt_payload_rejects_non_block_sized_ciphertext() {
        let key = hex::decode("DEADBEEFCAFEBABEDEADBEEFCAFEBABE").unwrap();

        assert_eq!(decrypt_payload("001122", &key), None);
    }
}
