//! `exec_unsandboxed`: named programs `symbia_exec` may run outside the sandbox when a call
//! asks for it with `unsandboxed: true`. No shell runs: the command is split into words here,
//! and the rule's program is started by its absolute path, never found through `PATH`.
//!
//! This is a short, logged list, not containment. A rule for a program that can run arbitrary
//! code (`cargo test`, `git -c`, `gh extension`) grants exactly that.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;

/// The refusal for shell syntax in an unsandboxed command.
pub const NO_SHELL: &str = "refused: unsandboxed commands run without a shell (no pipes, redirects, variables or substitution)";

/// `PATH` folders after the rules' own program folders.
pub const BASE_PATH: [&str; 6] = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"];

/// A rule as written in config.json.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    /// Absolute path of the program; a leading `~` is expanded.
    pub program: String,
    /// Exact argument tokens; a final `"*"` matches any remaining arguments.
    pub args: Vec<String>,
    /// The call's cwd must be this folder or inside it.
    #[serde(default)]
    pub cwd: Option<String>,
}

/// A checked rule.
#[derive(Debug, Clone)]
pub struct Rule {
    /// As configured (expanded): what runs, so a launcher that reads its own name still works.
    pub program: PathBuf,
    /// Its realpath at load, for matching a command word that is a path.
    real: PathBuf,
    pub args: Vec<String>,
    /// Realpath of the folder the call must run in, if the rule sets one.
    pub cwd: Option<PathBuf>,
}

fn executable(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        p.is_file()
    }
}

impl Rule {
    /// Check one configured rule. `expand` turns `~` and requires an absolute path.
    pub fn load(c: &RuleConfig, expand: impl Fn(&str) -> anyhow::Result<PathBuf>) -> anyhow::Result<Self> {
        let program = crate::policy::lexical(&expand(&c.program).with_context(|| format!("exec_unsandboxed program {:?}", c.program))?);
        let real = std::fs::canonicalize(&program).with_context(|| format!("exec_unsandboxed program {}", program.display()))?;
        if !executable(&real) {
            bail!("exec_unsandboxed program {} is not an executable file", program.display());
        }
        if let Some(i) = c.args.iter().position(|a| a == "*")
            && i + 1 != c.args.len()
        {
            bail!("exec_unsandboxed args for {}: \"*\" may only come last", program.display());
        }
        let cwd = match &c.cwd {
            Some(d) => {
                let d = expand(d).with_context(|| format!("exec_unsandboxed cwd {d:?}"))?;
                Some(std::fs::canonicalize(&d).with_context(|| format!("exec_unsandboxed cwd {}", d.display()))?)
            }
            None => None,
        };
        Ok(Self { program, real, args: c.args.clone(), cwd })
    }

    /// `<program> <args>[ (in <cwd>)]`, as listed in status and refusals.
    pub fn describe(&self) -> String {
        let mut s = self.program.display().to_string();
        for a in &self.args {
            s.push(' ');
            s.push_str(a);
        }
        if let Some(d) = &self.cwd {
            s.push_str(&format!(" (in {})", d.display()));
        }
        s
    }

    fn takes(&self, first: &str, first_real: Option<&Path>, args: &[String], cwd: &Path) -> bool {
        let program = match first_real {
            Some(r) => r == self.real,
            None => !first.contains('/') && self.program.file_name().is_some_and(|n| n == first),
        };
        let args_match = match self.args.split_last() {
            Some((last, head)) if last == "*" => args.len() >= head.len() && head.iter().zip(args).all(|(a, b)| a == b),
            _ => self.args == args,
        };
        program && args_match && self.cwd.as_ref().is_none_or(|d| cwd.starts_with(d))
    }
}

/// Split `command` into words without a shell. Single quotes are literal; double quotes
/// allow `\"` and `\\`; a backslash outside quotes escapes the next character. Shell
/// operators, `$` and backticks are refused rather than passed on as text.
pub fn split(command: &str) -> Result<Vec<String>, String> {
    const UNCLOSED: &str = "refused: unclosed quote in an unsandboxed command";
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = command.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(x) => cur.push(x),
                        None => return Err(UNCLOSED.into()),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(x @ ('"' | '\\')) => cur.push(x),
                            Some(x) => {
                                cur.push('\\');
                                cur.push(x);
                            }
                            None => return Err(UNCLOSED.into()),
                        },
                        Some('$' | '`') => return Err(NO_SHELL.into()),
                        Some(x) => cur.push(x),
                        None => return Err(UNCLOSED.into()),
                    }
                }
            }
            '\\' => {
                in_word = true;
                match chars.next() {
                    Some(x) => cur.push(x),
                    None => return Err("refused: trailing backslash in an unsandboxed command".into()),
                }
            }
            '|' | '&' | ';' | '<' | '>' | '(' | ')' | '$' | '`' => return Err(NO_SHELL.into()),
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            c => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    if words.is_empty() {
        return Err("refused: empty command".into());
    }
    Ok(words)
}

/// The first rule that takes `words` (from [`split`]) run in `cwd` (a realpath).
pub fn find<'a>(rules: &'a [Rule], command: &str, words: &[String], cwd: &Path) -> Result<(usize, &'a Rule), String> {
    let first = words[0].as_str();
    let first_real = first.contains('/').then(|| std::fs::canonicalize(cwd.join(first)).ok());
    let hit = match first_real {
        // A path that does not resolve matches nothing.
        Some(None) => None,
        Some(Some(r)) => rules.iter().enumerate().find(|(_, rule)| rule.takes(first, Some(&r), &words[1..], cwd)),
        None => rules.iter().enumerate().find(|(_, rule)| rule.takes(first, None, &words[1..], cwd)),
    };
    hit.ok_or_else(|| {
        let mut e = format!("refused: no exec_unsandboxed rule matches {command:?}; rules:");
        if rules.is_empty() {
            e.push_str(" none");
        }
        for r in rules {
            e.push_str("\n  ");
            e.push_str(&r.describe());
        }
        e
    })
}

/// `PATH` for unsandboxed commands: each rule's program folder in rule order, then
/// [`BASE_PATH`], without duplicates.
pub fn path_env(rules: &[Rule]) -> OsString {
    let mut dirs: Vec<PathBuf> = Vec::new();
    for d in rules.iter().filter_map(|r| r.program.parent()).map(Path::to_path_buf).chain(BASE_PATH.iter().map(PathBuf::from)) {
        if !dirs.contains(&d) {
            dirs.push(d);
        }
    }
    std::env::join_paths(dirs).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn abs(p: &str) -> anyhow::Result<PathBuf> {
        let p = PathBuf::from(p);
        if !p.is_absolute() {
            bail!("path must be absolute");
        }
        Ok(p)
    }

    fn exe(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, "#!/bin/sh\necho hi\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        p
    }

    fn rule(program: &Path, args: &[&str], cwd: Option<&Path>) -> anyhow::Result<Rule> {
        let c = RuleConfig { program: program.display().to_string(), args: w(args), cwd: cwd.map(|d| d.display().to_string()) };
        Rule::load(&c, abs)
    }

    #[test]
    fn split_handles_quotes_and_escapes() {
        assert_eq!(split("gh pr list").unwrap(), w(&["gh", "pr", "list"]));
        assert_eq!(split("  a   'b c'  \"d e\" ").unwrap(), w(&["a", "b c", "d e"]));
        assert_eq!(split(r#"a "x\"y\\z\n" 'q\"'"#).unwrap(), w(&["a", r#"x"y\z\n"#, r#"q\""#]));
        assert_eq!(split(r"a b\ c ''").unwrap(), w(&["a", "b c", ""]));
        assert_eq!(split("git commit -m 'a; b | c > d $HOME `x`'").unwrap(), w(&["git", "commit", "-m", "a; b | c > d $HOME `x`"]));
    }

    #[test]
    fn split_refuses_shell_syntax_and_bad_quoting() {
        for c in ['|', '&', ';', '<', '>', '(', ')', '$', '`'] {
            assert_eq!(split(&format!("gh pr{c}x")).unwrap_err(), NO_SHELL, "{c}");
            assert_eq!(split(&format!("gh {c} x")).unwrap_err(), NO_SHELL, "{c}");
        }
        assert_eq!(split(r#"echo "$HOME""#).unwrap_err(), NO_SHELL);
        assert_eq!(split(r#"echo "`id`""#).unwrap_err(), NO_SHELL);
        assert!(split("echo 'open").unwrap_err().contains("unclosed"));
        assert!(split("echo \"open").unwrap_err().contains("unclosed"));
        assert!(split("echo x\\").unwrap_err().contains("trailing backslash"));
        assert!(split("   ").unwrap_err().contains("empty"));
    }

    #[test]
    fn load_checks_program_args_and_cwd() {
        let t = tempfile::tempdir().unwrap();
        let p = exe(t.path(), "tool");
        assert!(rule(&p, &["*"], None).is_ok());
        assert!(rule(&p, &[], Some(t.path())).is_ok());
        let c = RuleConfig { program: "tool".into(), args: vec![], cwd: None };
        assert!(Rule::load(&c, abs).is_err(), "relative program");
        assert!(rule(&t.path().join("missing"), &["*"], None).is_err());
        let plain = t.path().join("plain");
        std::fs::write(&plain, "x").unwrap();
        assert!(rule(&plain, &["*"], None).unwrap_err().to_string().contains("not an executable"));
        assert!(rule(t.path(), &["*"], None).unwrap_err().to_string().contains("not an executable"), "a folder");
        assert!(rule(&p, &["*", "x"], None).unwrap_err().to_string().contains("only come last"));
        assert!(rule(&p, &["*"], Some(&t.path().join("nope"))).is_err());
        assert!(serde_json::from_str::<RuleConfig>(r#"{"program": "/bin/sh", "args": [1]}"#).is_err());
        assert!(serde_json::from_str::<RuleConfig>(r#"{"program": "/bin/sh", "args": [], "shell": true}"#).is_err());
    }

    #[test]
    fn matching_by_name_path_args_and_cwd() {
        let t = tempfile::tempdir().unwrap();
        let bin = t.path().join("bin");
        let work = t.path().join("work");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(work.join("sub")).unwrap();
        let work = std::fs::canonicalize(&work).unwrap();
        let tool = exe(&bin, "tool");
        let other = exe(&bin, "other");
        let rules = vec![
            rule(&tool, &["push", "*"], None).unwrap(),
            rule(&tool, &["status"], None).unwrap(),
            rule(&other, &[], Some(&work)).unwrap(),
        ];
        let f = |cmd: &str, cwd: &Path| split(cmd).and_then(|ws| find(&rules, cmd, &ws, cwd).map(|(i, _)| i));
        assert_eq!(f("tool push", t.path()), Ok(0));
        assert_eq!(f("tool push origin main", t.path()), Ok(0));
        assert_eq!(f("tool status", t.path()), Ok(1));
        assert!(f("tool status -v", t.path()).is_err(), "exact args, count mismatch");
        assert!(f("tool pull", t.path()).is_err());
        // A path word must resolve to the rule's program.
        assert_eq!(f(&format!("{} status", tool.display()), t.path()), Ok(1));
        assert_eq!(f("../bin/tool status", &work), Ok(1));
        let copy = exe(t.path(), "tool");
        assert!(f(&format!("{} status", copy.display()), t.path()).is_err(), "same name, other file");
        assert!(f("./missing status", t.path()).is_err());
        // cwd: the folder itself or inside it.
        assert_eq!(f("other", &work), Ok(2));
        assert_eq!(f("other", &work.join("sub")), Ok(2));
        assert!(f("other", t.path()).is_err());
        let e = f("nope", t.path()).unwrap_err();
        assert!(e.starts_with("refused: no exec_unsandboxed rule matches \"nope\"; rules:"), "{e}");
        assert!(e.contains(&format!("\n  {} push *", tool.display())), "{e}");
        assert!(e.contains(&format!("(in {})", work.display())), "{e}");
        assert!(find(&[], "x", &w(&["x"]), t.path()).unwrap_err().ends_with("rules: none"));
    }

    #[test]
    fn path_env_puts_rule_folders_first_once() {
        let t = tempfile::tempdir().unwrap();
        let a = exe(t.path(), "a");
        let b = exe(t.path(), "b");
        let rules = vec![rule(&a, &[], None).unwrap(), rule(&b, &[], None).unwrap(), rule(Path::new("/bin/sh"), &[], None).unwrap()];
        let got: Vec<PathBuf> = std::env::split_paths(&path_env(&rules)).collect();
        // /bin comes from the /bin/sh rule, ahead of the base list, and only once.
        let mut want = vec![t.path().to_path_buf(), PathBuf::from("/bin")];
        for d in BASE_PATH {
            let d = PathBuf::from(d);
            if !want.contains(&d) {
                want.push(d);
            }
        }
        assert_eq!(got, want);
    }
}
