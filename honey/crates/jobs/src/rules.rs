//! Mutation rule synthesis for hashcat + john.
//!
//! Logic ported from `scripts/generate-wordlists.py` — keep parity with the
//! Python output (header comments aside) so existing rules consumers don't
//! see a behavioural change.

const YEARS: &[&str] = &[
    "2018", "2019", "2020", "2021", "2022", "2023",
    "2024", "2025", "2026", "2027", "2028", "2029",
];

// Pre-sorted by length descending, matching Python's `sorted(..., key=len, reverse=True)`.
// Stable sort keeps the original input order within each length bucket.
const SPECIALS: &[&str] = &[
    "!@#", "123",
    "12", "01", "1!", "2!", "3!",
    "!", "@", "#", "$", "1", "2",
];

const CASE_SAMPLE: usize = 500;
const CASE_THRESHOLD: f64 = 0.05;
const SUFFIX_TOP_N: usize = 50;

/// Detect the longest known suffix the password ends with. Returns None if
/// nothing matches (or if the entire password equals the suffix).
fn detect_suffix(pw: &str) -> Option<&'static str> {
    for year in YEARS {
        for sfx in SPECIALS {
            let combo_len = year.len() + sfx.len();
            if pw.len() > combo_len
                && pw.ends_with(sfx)
                && pw[..pw.len() - sfx.len()].ends_with(year)
            {
                // Allocate a static-equivalent string by re-deriving from inputs.
                // We can't return a borrow that outlives this call from a temp,
                // so the caller stores the suffix as String in a Counter below.
                // To keep this function cheap and typed, we return Some((year, sfx))
                // via the helper below instead.
                return Some(combo_static(year, sfx));
            }
        }
        if pw.len() > year.len() && pw.ends_with(year) {
            return Some(year);
        }
    }
    for sfx in SPECIALS {
        if pw.len() > sfx.len() && pw.ends_with(sfx) {
            return Some(sfx);
        }
    }
    None
}

/// Return a `&'static str` for the concatenation of two known YEAR + SPECIAL
/// constants. Backed by a static lookup table built once at first call.
fn combo_static(year: &'static str, sfx: &'static str) -> &'static str {
    static TABLE: std::sync::OnceLock<std::collections::HashMap<(&'static str, &'static str), String>> =
        std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut m = std::collections::HashMap::new();
        for y in YEARS {
            for s in SPECIALS {
                m.insert((*y, *s), format!("{y}{s}"));
            }
        }
        m
    });
    // String is owned by the static map → safe to borrow as 'static.
    table.get(&(year, sfx)).map(|s| s.as_str()).unwrap()
}

fn hashcat_append(suffix: &str) -> String {
    let mut out = String::with_capacity(suffix.len() * 3);
    let mut first = true;
    for c in suffix.chars() {
        if !first {
            out.push(' ');
        }
        out.push('$');
        out.push(c);
        first = false;
    }
    out
}

fn john_append(suffix: &str) -> String {
    format!(r#"Az"{suffix}""#)
}

/// Detect prevalent case-mutation rules (l / c / u) above `threshold` of the
/// sampled passwords. Ordered by frequency desc, ties resolve l → c → u.
fn detect_case_rules(passwords: &[String]) -> Vec<&'static str> {
    let sample: Vec<&str> = passwords
        .iter()
        .take(CASE_SAMPLE)
        .map(String::as_str)
        .filter(|pw| pw.chars().any(|c| c.is_alphabetic()))
        .collect();
    if sample.is_empty() {
        return Vec::new();
    }
    let mut counts = [("l", 0usize), ("c", 0usize), ("u", 0usize)];
    for pw in &sample {
        let alpha: Vec<char> = pw.chars().filter(|c| c.is_alphabetic()).collect();
        if alpha.iter().all(|c| c.is_lowercase()) {
            counts[0].1 += 1;
        } else if alpha.iter().all(|c| c.is_uppercase()) {
            counts[2].1 += 1;
        } else {
            // Capitalized: first char uppercase, rest of the *alphabetic* chars lowercase.
            let mut chars = pw.chars();
            let first_upper = chars.next().map(|c| c.is_uppercase()).unwrap_or(false);
            let rest_lower = chars.filter(|c| c.is_alphabetic()).all(|c| c.is_lowercase());
            if first_upper && rest_lower {
                counts[1].1 += 1;
            }
        }
    }
    let total = sample.len() as f64;
    let mut indexed: Vec<(usize, (&'static str, usize))> =
        counts.iter().copied().enumerate().collect();
    // Stable sort by count desc — ties preserve l/c/u original order.
    indexed.sort_by(|a, b| b.1 .1.cmp(&a.1 .1));
    indexed
        .into_iter()
        .filter(|(_, (_, cnt))| (*cnt as f64) / total >= CASE_THRESHOLD)
        .map(|(_, (rule, _))| rule)
        .collect()
}

/// Suffix → frequency, ordered by frequency desc (stable, ties keep first-seen order).
fn rank_suffixes(passwords: &[String]) -> Vec<(&'static str, usize)> {
    use std::collections::HashMap;
    let mut counts: HashMap<&'static str, usize> = HashMap::new();
    let mut first_seen: HashMap<&'static str, usize> = HashMap::new();
    for (i, pw) in passwords.iter().enumerate() {
        if let Some(sfx) = detect_suffix(pw) {
            *counts.entry(sfx).or_default() += 1;
            first_seen.entry(sfx).or_insert(i);
        }
    }
    let mut v: Vec<(&'static str, usize)> = counts.into_iter().collect();
    v.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| first_seen[a.0].cmp(&first_seen[b.0]))
    });
    v
}

pub struct Ruleset {
    pub hashcat: String,
    pub john: String,
}

pub fn generate(passwords: &[String]) -> Ruleset {
    let suffix_counts = rank_suffixes(passwords);
    let case_rules = detect_case_rules(passwords);

    let mut hc = vec![
        "# honey — derived mutation rules (hashcat)".to_string(),
        "# usage: hashcat -a 0 -r hashcat.rule hashes.txt wordlist.txt".to_string(),
    ];
    let mut jt = vec![
        "[List.Rules:honey]".to_string(),
        "# honey — derived mutation rules".to_string(),
        "# append section to john.conf, then:".to_string(),
        "# john --wordlist=words.txt --rules=honey hashes".to_string(),
    ];

    if !case_rules.is_empty() {
        hc.push(String::new());
        jt.push(String::new());
        for r in &case_rules {
            hc.push((*r).to_string());
            jt.push((*r).to_string());
        }
    }

    if !suffix_counts.is_empty() {
        hc.push(String::new());
        jt.push(String::new());
    }

    for (suffix, _) in suffix_counts.iter().take(SUFFIX_TOP_N) {
        let h = hashcat_append(suffix);
        let j = john_append(suffix);
        hc.push(h.clone());
        hc.push(format!("c {h}"));
        jt.push(j.clone());
        jt.push(format!("c{j}"));
    }

    Ruleset {
        hashcat: hc.join("\n") + "\n",
        john: jt.join("\n") + "\n",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn detect_year_plus_special_takes_precedence() {
        // 2024!@# is year+special, longest match for "password2024!@#"
        assert_eq!(detect_suffix("password2024!@#"), Some("2024!@#"));
    }

    #[test]
    fn detect_year_alone() {
        assert_eq!(detect_suffix("admin2024"), Some("2024"));
    }

    #[test]
    fn detect_special_alone() {
        assert_eq!(detect_suffix("admin!"), Some("!"));
    }

    #[test]
    fn detect_none_when_pw_equals_suffix() {
        // "Need len(pw) > len(suffix)" — pure suffix doesn't match.
        assert_eq!(detect_suffix("2024"), None);
        assert_eq!(detect_suffix("!"), None);
    }

    #[test]
    fn detect_none_for_plain_password() {
        assert_eq!(detect_suffix("password"), None);
    }

    #[test]
    fn hashcat_append_spaces_chars() {
        assert_eq!(hashcat_append("2024!"), "$2 $0 $2 $4 $!");
    }

    #[test]
    fn john_append_wraps_in_quotes() {
        assert_eq!(john_append("2024!"), r#"Az"2024!""#);
    }

    #[test]
    fn case_rules_above_threshold_only() {
        // 100 lowercase, 50 capitalised, 1 uppercase → l ≥ 5%, c ≥ 5%, u < 5%
        let mut pws = Vec::new();
        for _ in 0..100 {
            pws.push("aaaaa".to_string());
        }
        for _ in 0..50 {
            pws.push("Aaaaa".to_string());
        }
        pws.push("AAAAA".to_string());
        let rules = detect_case_rules(&pws);
        assert_eq!(rules, vec!["l", "c"]);
    }

    #[test]
    fn case_rules_empty_when_no_alpha() {
        let pws = s(&["12345", "0000", "!!!!"]);
        assert!(detect_case_rules(&pws).is_empty());
    }

    #[test]
    fn ranking_groups_by_suffix_and_orders_by_frequency() {
        // 3× ends in 2024, 1× ends in !
        let pws = s(&["admin2024", "root2024", "test2024", "user!"]);
        let ranked = rank_suffixes(&pws);
        assert_eq!(ranked[0], ("2024", 3));
        assert_eq!(ranked[1], ("!", 1));
    }

    #[test]
    fn generate_includes_headers_and_suffixes() {
        let pws = s(&["admin2024", "root2024", "test2024"]);
        let rs = generate(&pws);
        assert!(rs.hashcat.contains("hashcat"));
        assert!(rs.hashcat.contains("$2 $0 $2 $4"));
        assert!(rs.hashcat.contains("c $2 $0 $2 $4"));
        assert!(rs.john.contains("[List.Rules:honey]"));
        assert!(rs.john.contains(r#"Az"2024""#));
        assert!(rs.john.contains(r#"cAz"2024""#));
        // trailing newline preserved
        assert!(rs.hashcat.ends_with('\n'));
        assert!(rs.john.ends_with('\n'));
    }
}
