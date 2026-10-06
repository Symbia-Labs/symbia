//! Exec command rules: `exec_deny` from config.json plus, unless turned off, the `Bash(...)`
//! entries of Claude Code's `permissions.deny`. A command is split into simple commands and
//! refused if any of them matches a rule.
//!
//! This is a policy convenience, not a boundary: `eval`, `$(...)`, `sh -c` and scripts get
//! around it. The sandbox is the boundary.

use std::path::Path;

use serde_json::Value;

use crate::policy::Policy;

/// Where `exec_deny` rules come from, as named in a refusal.
pub const CONFIG_SOURCE: &str = "config.json exec_deny";

/// One rule and where it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub text: String,
    pub source: String,
}

/// The rules for one call, and notes on settings files that were skipped.
#[derive(Debug, Default)]
pub struct Loaded {
    pub rules: Vec<Rule>,
    pub notes: Vec<String>,
}

/// Collect the rules for a call in `cwd`: config first, then `~/.claude/settings.json`,
/// `<cwd>/.claude/settings.json` and `<cwd>/.claude/settings.local.json` when present.
pub fn load(policy: &Policy, cwd: &Path) -> Loaded {
    let mut out = Loaded::default();
    out.rules.extend(policy.exec_deny().iter().map(|r| Rule { text: r.clone(), source: CONFIG_SOURCE.into() }));
    if policy.import_claude_rules() {
        let files = [
            policy.user_home().join(".claude/settings.json"),
            cwd.join(".claude/settings.json"),
            cwd.join(".claude/settings.local.json"),
        ];
        for (i, f) in files.iter().enumerate() {
            // A cwd at the home would read the user file twice.
            if files[..i].contains(f) {
                continue;
            }
            from_settings(f, &mut out);
        }
    }
    out
}

/// Add the `Bash(<rule>)` entries of one settings file's `permissions.deny`. A missing file
/// adds nothing; an unreadable or malformed one adds a note.
fn from_settings(path: &Path, out: &mut Loaded) {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            out.notes.push(format!("skipped {}: {e}", path.display()));
            return;
        }
    };
    let v: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            out.notes.push(format!("skipped {}: {e}", path.display()));
            return;
        }
    };
    let deny = match v.get("permissions").and_then(|p| p.get("deny")) {
        None | Some(Value::Null) => return,
        Some(Value::Array(a)) => a,
        Some(_) => {
            out.notes.push(format!("skipped {}: permissions.deny is not a list", path.display()));
            return;
        }
    };
    for entry in deny.iter().filter_map(Value::as_str) {
        if let Some(rule) = entry.strip_prefix("Bash(").and_then(|r| r.strip_suffix(')'))
            && !rule.trim().is_empty()
        {
            out.rules.push(Rule { text: rule.to_string(), source: path.display().to_string() });
        }
    }
}

/// Refuse `command` if any of its simple commands matches a rule; the error names the rule and its source.
pub fn check(rules: &[Rule], command: &str) -> Result<(), String> {
    for words in split(command) {
        if let Some(r) = rules.iter().find(|r| matches(&r.text, &words)) {
            return Err(format!("refused: {:?} matches exec rule {:?} from {}", words.join(" "), r.text, r.source));
        }
    }
    Ok(())
}

/// Split a command into simple commands on `&&`, `||`, `;`, `|` and newlines, outside single
/// and double quotes. Each simple command is its words with quotes removed and leading
/// `VAR=value` assignments dropped. Empty commands are left out.
pub fn split(command: &str) -> Vec<Vec<String>> {
    let mut cmds: Vec<Vec<String>> = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = command.chars().peekable();
    let end_word = |words: &mut Vec<String>, word: &mut String, in_word: &mut bool| {
        if *in_word {
            words.push(std::mem::take(word));
            *in_word = false;
        }
    };
    let end_cmd = |cmds: &mut Vec<Vec<String>>, words: &mut Vec<String>| {
        let w: Vec<String> = std::mem::take(words).into_iter().skip_while(|w| is_assignment(w)).collect();
        if !w.is_empty() {
            cmds.push(w);
        }
    };
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                for q in chars.by_ref() {
                    if q == '\'' {
                        break;
                    }
                    word.push(q);
                }
            }
            '"' => {
                in_word = true;
                while let Some(q) = chars.next() {
                    match q {
                        '"' => break,
                        '\\' if matches!(chars.peek(), Some('"' | '\\' | '$' | '`')) => word.extend(chars.next()),
                        '\\' if chars.peek() == Some(&'\n') => {
                            chars.next();
                        }
                        _ => word.push(q),
                    }
                }
            }
            '\\' => match chars.next() {
                Some('\n') | None => {}
                Some(n) => {
                    in_word = true;
                    word.push(n);
                }
            },
            '&' if chars.peek() == Some(&'&') => {
                chars.next();
                end_word(&mut words, &mut word, &mut in_word);
                end_cmd(&mut cmds, &mut words);
            }
            '|' => {
                if chars.peek() == Some(&'|') {
                    chars.next();
                }
                end_word(&mut words, &mut word, &mut in_word);
                end_cmd(&mut cmds, &mut words);
            }
            ';' | '\n' => {
                end_word(&mut words, &mut word, &mut in_word);
                end_cmd(&mut cmds, &mut words);
            }
            c if c.is_whitespace() => end_word(&mut words, &mut word, &mut in_word),
            c => {
                in_word = true;
                word.push(c);
            }
        }
    }
    end_word(&mut words, &mut word, &mut in_word);
    end_cmd(&mut cmds, &mut words);
    cmds
}

/// `NAME=value` with a shell variable name.
fn is_assignment(w: &str) -> bool {
    let Some((name, _)) = w.split_once('=') else { return false };
    let mut c = name.chars();
    c.next().is_some_and(|f| f.is_ascii_alphabetic() || f == '_') && c.all(|x| x.is_ascii_alphanumeric() || x == '_')
}

/// Claude Code's rule forms: `cmd:*` (the words of `cmd`, then anything), a pattern with `*`
/// wildcards (as in `rm -rf *`), or an exact command. Whitespace runs count as one space.
pub fn matches(rule: &str, words: &[String]) -> bool {
    let cmd = words.join(" ");
    if let Some(prefix) = rule.strip_suffix(":*") {
        let p: Vec<&str> = prefix.split_whitespace().collect();
        return !p.is_empty() && words.len() >= p.len() && words.iter().zip(&p).all(|(w, p)| w == p);
    }
    let rule = rule.split_whitespace().collect::<Vec<_>>().join(" ");
    if rule.contains('*') { wildcard(&rule, &cmd) } else { rule == cmd }
}

/// `*` matches any run of characters, including none; everything else matches itself.
fn wildcard(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !text.starts_with(first) {
        return false;
    }
    let mut rest = &text[first.len()..];
    for mid in &parts[1..parts.len() - 1] {
        match rest.find(mid) {
            Some(i) => rest = &rest[i + mid.len()..],
            None => return false,
        }
    }
    rest.len() >= last.len() && rest.ends_with(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(text: &str) -> Rule {
        Rule { text: text.into(), source: CONFIG_SOURCE.into() }
    }

    fn w(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn split_on_operators_outside_quotes() {
        assert_eq!(split("mkdir x && chmod 600 x"), [w(&["mkdir", "x"]), w(&["chmod", "600", "x"])]);
        assert_eq!(split("a || b; c | d\ne"), [w(&["a"]), w(&["b"]), w(&["c"]), w(&["d"]), w(&["e"])]);
        assert_eq!(split(r#"echo "a && chmod""#), [w(&["echo", "a && chmod"])]);
        assert_eq!(split("echo 'x; chmod 1 y' | cat"), [w(&["echo", "x; chmod 1 y"]), w(&["cat"])]);
        assert_eq!(split(r#"echo "say \"hi\"" a\ b"#), [w(&["echo", "say \"hi\"", "a b"])]);
        assert_eq!(split("FOO=1 BAR='a b' chmod 600 x"), [w(&["chmod", "600", "x"])]);
        assert_eq!(split("ls 2>&1 & echo"), [w(&["ls", "2>&1", "&", "echo"])]);
        assert_eq!(split(" ; && "), Vec::<Vec<String>>::new());
        assert_eq!(split("FOO=1"), Vec::<Vec<String>>::new());
    }

    #[test]
    fn rule_forms() {
        assert!(matches("chmod:*", &w(&["chmod", "600", "x"])));
        assert!(matches("chmod:*", &w(&["chmod"])));
        assert!(!matches("chmod:*", &w(&["chmodx", "1"])));
        assert!(!matches("chmod:*", &w(&["echo", "chmod"])));
        assert!(matches("git push:*", &w(&["git", "push", "origin"])));
        assert!(!matches("git push:*", &w(&["git", "pull"])));
        assert!(matches("git push --force", &w(&["git", "push", "--force"])));
        assert!(matches("git  push   --force", &w(&["git", "push", "--force"])));
        assert!(!matches("git push --force", &w(&["git", "push", "--force", "origin"])));
        assert!(matches("rm -rf *", &w(&["rm", "-rf", "/tmp/x"])));
        assert!(!matches("rm -rf *", &w(&["rm", "-r", "x"])));
        assert!(matches("*sudo*", &w(&["env", "sudo", "ls"])));
    }

    #[test]
    fn check_refuses_any_matching_simple_command() {
        let rules = [rule("chmod:*")];
        let e = check(&rules, "mkdir x && chmod 600 x").unwrap_err();
        assert_eq!(e, r#"refused: "chmod 600 x" matches exec rule "chmod:*" from config.json exec_deny"#);
        assert!(check(&rules, r#"echo "a && chmod""#).is_ok());
        assert!(check(&rules, "FOO=1 chmod 600 x").is_err());
        assert!(check(&rules, "ls | chmod 1 x").is_err());
        assert!(check(&rules, "ls -l").is_ok());
        assert!(check(&[], "chmod 600 x").is_ok());
    }

    fn policy(t: &Path, config: serde_json::Value) -> Policy {
        let user = t.join("user");
        let sym = t.join("sym");
        std::fs::create_dir_all(&user).unwrap();
        crate::home::ensure(&sym).unwrap();
        std::fs::write(sym.join("config.json"), config.to_string()).unwrap();
        Policy::load(&sym, &user).unwrap()
    }

    #[test]
    fn rules_are_imported_from_claude_settings() {
        let t = tempfile::tempdir().unwrap();
        let p = policy(t.path(), serde_json::json!({"exec_deny": ["git push --force"]}));
        let user = t.path().join("user");
        let cwd = t.path().join("proj");
        std::fs::create_dir_all(user.join(".claude")).unwrap();
        std::fs::create_dir_all(cwd.join(".claude")).unwrap();
        std::fs::write(user.join(".claude/settings.json"), r#"{"permissions": {"deny": ["Bash(chmod:*)", "Read(~/.ssh)", "Bash()"]}}"#).unwrap();
        std::fs::write(cwd.join(".claude/settings.json"), r#"{"permissions": {"allow": ["Bash(ls)"], "deny": ["Bash(curl:*)"]}}"#).unwrap();
        std::fs::write(cwd.join(".claude/settings.local.json"), r#"{"permissions": {"deny": ["Bash(rm -rf *)"]}}"#).unwrap();
        let l = load(&p, &cwd);
        assert!(l.notes.is_empty(), "{:?}", l.notes);
        let texts: Vec<(&str, &str)> = l.rules.iter().map(|r| (r.text.as_str(), r.source.as_str())).collect();
        let us = user.join(".claude/settings.json").display().to_string();
        let ps = cwd.join(".claude/settings.json").display().to_string();
        let ls = cwd.join(".claude/settings.local.json").display().to_string();
        assert_eq!(texts, [("git push --force", CONFIG_SOURCE), ("chmod:*", us.as_str()), ("curl:*", ps.as_str()), ("rm -rf *", ls.as_str())]);
        let e = check(&l.rules, "chmod 600 x").unwrap_err();
        assert!(e.contains(&us), "{e}");
        // Turned off: only config rules.
        let p = policy(t.path(), serde_json::json!({"exec_deny": ["git push --force"], "exec_import_claude_rules": false}));
        assert_eq!(load(&p, &cwd).rules.len(), 1);
    }

    #[test]
    fn malformed_settings_are_skipped_with_a_note() {
        let t = tempfile::tempdir().unwrap();
        let p = policy(t.path(), serde_json::json!({}));
        let user = t.path().join("user");
        let cwd = t.path().join("proj");
        std::fs::create_dir_all(user.join(".claude")).unwrap();
        std::fs::create_dir_all(cwd.join(".claude")).unwrap();
        std::fs::write(user.join(".claude/settings.json"), "{ not json").unwrap();
        std::fs::write(cwd.join(".claude/settings.json"), r#"{"permissions": {"deny": "Bash(x)"}}"#).unwrap();
        std::fs::write(cwd.join(".claude/settings.local.json"), r#"{"permissions": {"deny": ["Bash(chmod:*)"]}}"#).unwrap();
        let l = load(&p, &cwd);
        assert_eq!(l.notes.len(), 2, "{:?}", l.notes);
        assert!(l.notes[0].starts_with(&format!("skipped {}", user.join(".claude/settings.json").display())));
        assert!(l.notes[1].ends_with("permissions.deny is not a list"));
        assert_eq!(l.rules.len(), 1);
        // No settings files at all: nothing, and no notes.
        let l = load(&p, &t.path().join("nowhere"));
        assert_eq!(l.notes.len(), 1, "the user file is still malformed");
        std::fs::remove_file(user.join(".claude/settings.json")).unwrap();
        let l = load(&p, &t.path().join("nowhere"));
        assert!(l.rules.is_empty() && l.notes.is_empty());
    }
}
