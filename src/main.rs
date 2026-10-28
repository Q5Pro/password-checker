//! password-checker: Şifre güvenlik analizi ve güçlü şifre üreticisi.
//! Entropy hesabı, kural kontrolü, zayıf şifre tespiti.
//!
//! Kullanım:
//!     password-checker check "MyP@ssw0rd"
//!     password-checker generate --length 16 --symbols
//!     password-checker generate --count 5
use std::env;
use std::fs::File;
use std::io::Read;
use std::process;

const COMMON: &[&str] = &[
    "password","123456","qwerty","letmein","welcome","monkey","dragon",
    "master","abc123","111111","password1","iloveyou","sunshine","princess",
];

fn entropy(pw: &str) -> f64 {
    let mut pool = 0u32;
    let has_lower = pw.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = pw.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = pw.chars().any(|c| c.is_ascii_digit());
    let has_sym   = pw.chars().any(|c| !c.is_alphanumeric());
    if has_lower { pool += 26; }
    if has_upper { pool += 26; }
    if has_digit { pool += 10; }
    if has_sym   { pool += 32; }
    if pool == 0 { return 0.0; }
    (pw.len() as f64) * (pool as f64).log2()
}

fn strength_label(e: f64) -> (&'static str, &'static str) {
    if e < 28.0 { ("Çok Zayıf", "🔴") }
    else if e < 36.0 { ("Zayıf", "🟠") }
    else if e < 60.0 { ("Orta", "🟡") }
    else if e < 80.0 { ("Güçlü", "🟢") }
    else { ("Çok Güçlü", "✅") }
}

fn check(pw: &str) {
    let lower = pw.to_lowercase();
    println!("Şifre Analizi: \"{}\"", pw);
    println!("{}", "─".repeat(40));

    // Kural kontrolleri
    let rules: Vec<(&str, bool)> = vec![
        ("≥ 8 karakter", pw.len() >= 8),
        ("≥ 12 karakter", pw.len() >= 12),
        ("Büyük harf", pw.chars().any(|c| c.is_ascii_uppercase())),
        ("Küçük harf", pw.chars().any(|c| c.is_ascii_lowercase())),
        ("Rakam", pw.chars().any(|c| c.is_ascii_digit())),
        ("Özel karakter", pw.chars().any(|c| !c.is_alphanumeric())),
    ];

    for (label, ok) in &rules {
        println!("  {} {}", if *ok { "✓" } else { "✗" }, label);
    }

    let e = entropy(pw);
    let (label, icon) = strength_label(e);
    println!("\n  Entropy: {:.1} bit", e);
    println!("  Güç: {} {}", icon, label);

    if COMMON.iter().any(|c| *c == lower) {
        println!("  ⚠️  UYARI: Bu şifre yaygın şifreler listesinde!");
    }
    if pw.chars().all(|c| c.is_ascii_digit()) {
        println!("  ⚠️  Sadece rakamlardan oluşuyor.");
    }

    // Tekrar eden karakter
    let chars: Vec<char> = pw.chars().collect();
    let reps = chars.windows(3).filter(|w| w[0]==w[1] && w[1]==w[2]).count();
    if reps > 0 {
        println!("  ⚠️  {} adet üç veya daha fazla tekrar eden karakter.", reps);
    }
}

fn rand_byte() -> u8 {
    let mut f = File::open("/dev/urandom").unwrap();
    let mut buf = [0u8;1];
    f.read_exact(&mut buf).unwrap();
    buf[0]
}

fn rand_choice(pool: &[u8]) -> u8 {
    loop {
        let b = rand_byte() as usize;
        if b < 256 - (256 % pool.len()) {
            return pool[b % pool.len()];
        }
    }
}

fn generate(length: usize, use_symbols: bool) -> String {
    let lower: Vec<u8> = b"abcdefghijklmnopqrstuvwxyz".to_vec();
    let upper: Vec<u8> = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_vec();
    let digits: Vec<u8> = b"0123456789".to_vec();
    let syms: Vec<u8>   = b"!@#$%^&*()-_=+[]{}|;:,.<>?".to_vec();
    let mut pool: Vec<u8> = [&lower[..], &upper[..], &digits[..]].concat();
    if use_symbols { pool.extend_from_slice(&syms); }

    // En az bir tane her kategoriden
    let mut pw: Vec<u8> = vec![
        rand_choice(&lower), rand_choice(&upper), rand_choice(&digits),
    ];
    if use_symbols { pw.push(rand_choice(&syms)); }
    while pw.len() < length { pw.push(rand_choice(&pool)); }

    // Karıştır
    for i in (1..pw.len()).rev() {
        let j = rand_byte() as usize % (i + 1);
        pw.swap(i, j);
    }
    String::from_utf8(pw).unwrap()
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        println!("Kullanım:");
        println!("  password-checker check \"<şifre>\"");
        println!("  password-checker generate [--length N] [--symbols] [--count N]");
        return;
    }
    match args[0].as_str() {
        "check" => {
            if let Some(pw) = args.get(1) { check(pw); }
            else { eprintln!("Şifre belirtin."); process::exit(1); }
        }
        "generate" => {
            let mut length = 16usize;
            let mut symbols = false;
            let mut count = 1usize;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--length" => { if let Some(v) = args.get(i+1) { length = v.parse().unwrap_or(16); i+=1; } }
                    "--count"  => { if let Some(v) = args.get(i+1) { count  = v.parse().unwrap_or(1);  i+=1; } }
                    "--symbols" => symbols = true,
                    _ => {}
                }
                i += 1;
            }
            for _ in 0..count {
                let pw = generate(length, symbols);
                let e = entropy(&pw);
                let (lbl, icon) = strength_label(e);
                println!("{}  ({} {}, {:.0} bit)", pw, icon, lbl, e);
            }
        }
        _ => { eprintln!("check veya generate belirtin."); process::exit(1); }
    }
}
