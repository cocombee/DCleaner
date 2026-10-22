//! Native-derived Mozilla session observation/transform, without effect authority.
//! Kept tabs retain their original byte spans; no private values enter public rows.
use super::moz_lz4;
use serde::de::IgnoredAny;
use std::{
    collections::HashSet,
    ops::Range,
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Copy, Debug)]
pub(super) enum Encoding {
    Json,
    MozLz4,
}
#[derive(Debug)]
pub(super) enum Plan {
    DeleteFile,
    RewritePinned {
        bytes: Vec<u8>,
        // Tab accounting is asserted by the owned fixtures; production review
        // reports only the rewrite and skipped windows.
        #[cfg_attr(not(test), allow(dead_code))]
        pinned_tabs: usize,
        #[cfg_attr(not(test), allow(dead_code))]
        retained_tabs: usize,
        #[cfg_attr(not(test), allow(dead_code))]
        removed_tabs: usize,
        skipped_windows: usize,
    },
}
struct Member {
    name: String,
    value: Node,
}
enum Kind {
    Object(Vec<Member>),
    Array(Vec<Node>),
    Atom,
}
struct Node {
    span: Range<usize>,
    kind: Kind,
}
struct Parser<'a> {
    source: &'a [u8],
    pos: usize,
    values: usize,
    cancel: &'a AtomicBool,
}
fn invalid() -> String {
    "Mozilla session JSON has an unsupported or malformed structure.".into()
}
fn check(cancel: &AtomicBool) -> Result<(), String> {
    if cancel.load(Ordering::Relaxed) {
        Err("Mozilla session observation was cancelled.".into())
    } else {
        Ok(())
    }
}
impl Parser<'_> {
    fn space(&mut self) {
        while self
            .source
            .get(self.pos)
            .is_some_and(|b| matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.pos += 1;
        }
    }
    fn consume(&mut self, byte: u8) -> Result<(), String> {
        self.space();
        if self.source.get(self.pos) != Some(&byte) {
            return Err(invalid());
        }
        self.pos += 1;
        Ok(())
    }
    fn key(&mut self) -> Result<String, String> {
        self.space();
        let mut stream =
            serde_json::Deserializer::from_slice(&self.source[self.pos..]).into_iter::<String>();
        let value = stream.next().ok_or_else(invalid)?.map_err(|_| invalid())?;
        self.pos += stream.byte_offset();
        Ok(value)
    }
    fn node(&mut self, depth: usize) -> Result<Node, String> {
        check(self.cancel)?;
        self.values += 1;
        if depth > 64 || self.values > 100_000 {
            return Err("Mozilla session JSON observation limit reached.".into());
        }
        self.space();
        let start = self.pos;
        let kind = match self.source.get(self.pos) {
            Some(b'{') => {
                self.pos += 1;
                let mut members = Vec::new();
                let mut keys = HashSet::new();
                self.space();
                if self.source.get(self.pos) != Some(&b'}') {
                    loop {
                        let name = self.key()?;
                        if !keys.insert(name.clone()) {
                            return Err(
                                "Mozilla session JSON has ambiguous duplicate members.".into()
                            );
                        }
                        self.consume(b':')?;
                        members.push(Member {
                            name,
                            value: self.node(depth + 1)?,
                        });
                        self.space();
                        if self.source.get(self.pos) == Some(&b'}') {
                            break;
                        }
                        self.consume(b',')?;
                    }
                }
                self.consume(b'}')?;
                Kind::Object(members)
            }
            Some(b'[') => {
                self.pos += 1;
                let mut children = Vec::new();
                self.space();
                if self.source.get(self.pos) != Some(&b']') {
                    loop {
                        children.push(self.node(depth + 1)?);
                        self.space();
                        if self.source.get(self.pos) == Some(&b']') {
                            break;
                        }
                        self.consume(b',')?;
                    }
                }
                self.consume(b']')?;
                Kind::Array(children)
            }
            Some(_) => {
                let mut stream = serde_json::Deserializer::from_slice(&self.source[self.pos..])
                    .into_iter::<IgnoredAny>();
                stream.next().ok_or_else(invalid)?.map_err(|_| invalid())?;
                self.pos += stream.byte_offset();
                if matches!(self.source[start], b'-' | b'0'..=b'9') {
                    let number: f64 = std::str::from_utf8(&self.source[start..self.pos])
                        .map_err(|_| invalid())?
                        .parse()
                        .map_err(|_| invalid())?;
                    if !number.is_finite() {
                        return Err(invalid());
                    }
                }
                Kind::Atom
            }
            None => return Err(invalid()),
        };
        Ok(Node {
            span: start..self.pos,
            kind,
        })
    }
}
fn member<'a>(node: &'a Node, key: &str) -> Option<&'a Node> {
    match &node.kind {
        Kind::Object(fields) => fields
            .iter()
            .find(|field| field.name == key)
            .map(|field| &field.value),
        _ => None,
    }
}
fn pinned(source: &[u8], node: &Node) -> Result<bool, String> {
    let raw = &source[node.span.clone()];
    if raw == b"true" {
        return Ok(true);
    }
    if !matches!(raw.first(), Some(b'-' | b'0'..=b'9')) {
        return Ok(false);
    }
    let number: serde_json::Number = serde_json::from_slice(raw).map_err(|_| invalid())?;
    if let Some(value) = number.as_i64() {
        return Ok(value as u32 != 0);
    }
    if let Some(value) = number.as_u64() {
        return Ok(value as u32 != 0);
    }
    // The native cvttsd2si result is zero only for finite values in (-1,1).
    // Integer overflow and out-of-range doubles are distinct native cases.
    let value = number.as_f64().ok_or_else(invalid)?;
    Ok(value.trunc() != 0.)
}
pub(super) fn plan(
    carrier: &[u8],
    encoding: Encoding,
    cancel: &AtomicBool,
) -> Result<Plan, String> {
    check(cancel)?;
    let owned;
    let source = match encoding {
        Encoding::Json => carrier,
        Encoding::MozLz4 => {
            owned = moz_lz4::decode(carrier, cancel)?;
            &owned
        }
    };
    if source.len() > moz_lz4::MAX_BYTES {
        return Err("Mozilla session exceeds the JSON observation size limit.".into());
    }
    std::str::from_utf8(source).map_err(|_| invalid())?;
    let mut parser = Parser {
        source,
        pos: if source.starts_with(b"\xef\xbb\xbf") {
            3
        } else {
            0
        },
        values: 0,
        cancel,
    };
    let root = parser.node(0)?;
    parser.space();
    if parser.pos != source.len() {
        return Err(invalid());
    }
    let windows = member(&root, "windows").ok_or_else(invalid)?;
    let Kind::Array(windows) = &windows.kind else {
        return Err(invalid());
    };
    let (mut pinned_tabs, mut retained_tabs, mut removed_tabs, mut skipped_windows) = (0, 0, 0, 0);
    let mut bytes = b"{\"windows\":[".to_vec();
    for (window_index, window) in windows.iter().enumerate() {
        check(cancel)?;
        if window_index > 0 {
            bytes.push(b',');
        }
        let tabs = member(window, "tabs").ok_or_else(invalid)?;
        let Kind::Array(tabs) = &tabs.kind else {
            // The recovered routine skips a malformed tabs container, retaining
            // this window, while still processing other valid windows.
            skipped_windows += 1;
            bytes.extend_from_slice(&source[window.span.clone()]);
            continue;
        };
        bytes.extend_from_slice(b"{\"tabs\":[");
        let mut written = false;
        for tab in tabs {
            check(cancel)?;
            let pin = member(tab, "pinned");
            let keep = match pin {
                None => true, // Native missing-key branch advances without erasing.
                Some(pin) if pinned(source, pin)? => {
                    pinned_tabs += 1;
                    true
                }
                Some(_) => {
                    removed_tabs += 1;
                    false
                }
            };
            if keep {
                retained_tabs += 1;
                if written {
                    bytes.push(b',');
                }
                bytes.extend_from_slice(&source[tab.span.clone()]);
                written = true;
            }
        }
        bytes.extend_from_slice(b"]}");
    }
    bytes.extend_from_slice(b"]}");
    check(cancel)?;
    if pinned_tabs == 0 {
        return Ok(Plan::DeleteFile);
    }
    if bytes.len() > moz_lz4::MAX_BYTES {
        return Err("Mozilla session rewrite exceeds its size limit.".into());
    }
    let bytes = match encoding {
        Encoding::Json => bytes,
        Encoding::MozLz4 => moz_lz4::encode(&bytes, cancel)?,
    };
    Ok(Plan::RewritePinned {
        bytes,
        pinned_tabs,
        retained_tabs,
        removed_tabs,
        skipped_windows,
    })
}

#[cfg(test)]
#[path = "session_mozilla_tests.rs"]
mod tests;
