/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, File},
    io::{BufRead, BufReader},
    path::Path,
};

use anyhow::{anyhow, bail, Result};
use regex::Regex;

use crate::WORKSPACE_DIR;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct LinkRef {
    link_type: String,
    number: u32,
    user: Option<String>,
}

impl fmt::Display for LinkRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{} #{}", self.link_type, self.number)?;
        if let Some(u) = &self.user {
            write!(f, " @{}", u)?;
        }
        write!(f, "]")
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
    let re_auto_link = Regex::new(r"^(Issue|PR) #([0-9]+)(?: @([a-zA-Z0-9\-]+))?$")?;
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
                let user = captures.get(3).map(|c| c.as_str());

                let link = match link_type {
                    "Issue" => {
                        if user.is_some() {
                            bail!("{link_ref} should not have a username");
                        }
                        format!("{base_url}/issues/{number}")
                    }
                    "PR" => {
                        if user.is_none() {
                            bail!("{link_ref} should have a username");
                        }
                        format!("{base_url}/pull/{number}")
                    }
                    t => bail!("Unknown link type: {t:?}"),
                };

                // #0 is used for examples only.
                if number != 0 {
                    links.insert(
                        LinkRef {
                            link_type: link_type.to_owned(),
                            number,
                            user: user.map(|u| u.to_owned()),
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
        result.push_str(&format!("{link_ref}: {link}\n"));
    }

    fs::write(path, result)?;

    Ok(())
}

pub fn update_changelog_subcommand() -> Result<()> {
    let path = Path::new(WORKSPACE_DIR).join("CHANGELOG.md");

    update_changelog_links(&path, env!("CARGO_PKG_REPOSITORY"))?;

    Ok(())
}
