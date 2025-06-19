// SPDX-FileCopyrightText: 2023-2025 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    collections::BTreeMap,
    fmt::{self, Write as _},
    fs::{self, File},
    io::{BufRead, BufReader},
    path::Path,
};

use anyhow::{Result, anyhow, bail};
use regex::Regex;

use crate::WORKSPACE_DIR;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct LinkRef {
    link_type: String,
    number: u32,
}

impl fmt::Display for LinkRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{} #{}]", self.link_type, self.number)
    }
}

fn check_brackets(line: &str) -> Result<()> {
    let mut expect_opening = true;

    for c in line.chars() {
        if c == '[' || c == ']' {
            if (c == '[') != expect_opening {
                bail!("Mismatched brackets: {line:?}");
            }

            expect_opening = !expect_opening;
        }
    }

    if !expect_opening {
        bail!("Missing closing bracket: {line:?}");
    }

    Ok(())
}

fn update_changelog_links(path: &Path, base_url: &str) -> Result<()> {
    let re_standalone_link = Regex::new(r"\[([^\]]+)\]($|[^\(\[])")?;
    let re_auto_link = Regex::new(r"^(Discussion|Issue|PR) #([0-9]+)?$")?;
    let mut links = BTreeMap::<LinkRef, String>::new();

    let raw_reader = File::open(path)?;
    let mut reader = BufReader::new(raw_reader);
    let mut result = String::new();
    let mut line = String::new();
    let mut skip_remaining = false;

    loop {
        line.clear();

        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }

        let line = line.trim_end();

        if !skip_remaining {
            check_brackets(line)?;
            for link_captures in re_standalone_link.captures_iter(line) {
                let link_text = link_captures.get(1).unwrap();
                let captures = re_auto_link
                    .captures(link_text.as_str())
                    .ok_or_else(|| anyhow!("Invalid link format: {link_text:?}"))?;

                let link_ref = captures.get(0).unwrap().as_str();
                let link_type = captures.get(1).unwrap().as_str();
                let number: u32 = captures.get(2).unwrap().as_str().parse()?;

                let link = match link_type {
                    "Discussion" => format!("{base_url}/discussions/{number}"),
                    "Issue" => format!("{base_url}/issues/{number}"),
                    "PR" => format!("{base_url}/pull/{number}"),
                    t => bail!("Unknown link type in {link_ref:?}: {t:?}"),
                };

                // #0 is used for examples only.
                if number != 0 {
                    links.insert(
                        LinkRef {
                            link_type: link_type.to_owned(),
                            number,
                        },
                        link,
                    );
                }
            }

            if line.contains("Do not manually edit the lines below") {
                skip_remaining = true;
            }

            result.push_str(line);
            result.push('\n');
        }
    }

    for (link_ref, link) in links {
        let _ = writeln!(result, "{link_ref}: {link}");
    }

    fs::write(path, result)?;

    Ok(())
}

pub fn update_changelog_subcommand() -> Result<()> {
    let path = Path::new(WORKSPACE_DIR).join("CHANGELOG.md");

    update_changelog_links(&path, env!("CARGO_PKG_REPOSITORY"))?;

    Ok(())
}
