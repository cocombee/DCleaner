//! Bounded JSON member indexing and selective edits without value reserialization.
//! This module does not open or write files. Filesystem authority belongs to the
//! reviewed Preferences owner and its durable effect/recovery protocol.
use serde::de::IgnoredAny;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    ops::Range,
    sync::atomic::{AtomicBool, Ordering},
};

pub(super) const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_VALUES: usize = 100_000;
const MAX_DEPTH: usize = 64;

#[derive(Clone, Copy)]
struct Limits {
    bytes: usize,
    values: usize,
    depth: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            bytes: MAX_BYTES,
            values: MAX_VALUES,
            depth: MAX_DEPTH,
        }
    }
}

struct Member {
    name: String,
    key_start: usize,
    value: Node,
}
enum Kind {
    Object(Vec<Member>),
    Null,
    String { empty: bool },
    Other,
}
struct Node {
    span: Range<usize>,
    kind: Kind,
}
pub(super) struct Document<'a> {
    source: &'a [u8],
    root: Node,
}
struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    values: usize,
    limits: Limits,
    cancel: &'a AtomicBool,
}

fn invalid() -> String {
    "Browser preferences contain unsupported or malformed JSON.".into()
}
impl Parser<'_> {
    fn check(&self) -> Result<(), String> {
        if self.cancel.load(Ordering::Relaxed) {
            Err("Browser preferences observation was cancelled.".into())
        } else {
            Ok(())
        }
    }
    fn space(&mut self) {
        while self
            .bytes
            .get(self.pos)
            .is_some_and(|b| matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.pos += 1;
        }
    }
    fn consume(&mut self, byte: u8) -> Result<(), String> {
        self.space();
        if self.bytes.get(self.pos) != Some(&byte) {
            return Err(invalid());
        }
        self.pos += 1;
        Ok(())
    }
    fn string(&mut self) -> Result<String, String> {
        if self.bytes.get(self.pos) != Some(&b'"') {
            return Err(invalid());
        }
        let mut stream =
            serde_json::Deserializer::from_slice(&self.bytes[self.pos..]).into_iter::<String>();
        let value = stream.next().ok_or_else(invalid)?.map_err(|_| invalid())?;
        self.pos += stream.byte_offset();
        Ok(value)
    }
    fn value(&mut self, depth: usize) -> Result<Node, String> {
        self.check()?;
        self.space();
        self.values += 1;
        if self.values > self.limits.values || depth > self.limits.depth {
            return Err("Browser preferences JSON observation limit reached.".into());
        }
        let start = self.pos;
        let kind = match self.bytes.get(self.pos).copied().ok_or_else(invalid)? {
            b'{' => {
                self.pos += 1;
                self.space();
                let mut members = Vec::new();
                let mut names = HashSet::new();
                if self.bytes.get(self.pos) != Some(&b'}') {
                    loop {
                        self.check()?;
                        self.space();
                        let key_start = self.pos;
                        let name = self.string()?;
                        if !names.insert(name.clone()) {
                            return Err(
                                "Browser preferences have ambiguous duplicate members.".into()
                            );
                        }
                        self.consume(b':')?;
                        let value = self.value(depth + 1)?;
                        members.push(Member {
                            name,
                            key_start,
                            value,
                        });
                        self.space();
                        if self.bytes.get(self.pos) == Some(&b'}') {
                            break;
                        }
                        self.consume(b',')?;
                    }
                }
                self.consume(b'}')?;
                Kind::Object(members)
            }
            b'[' => {
                self.pos += 1;
                self.space();
                if self.bytes.get(self.pos) != Some(&b']') {
                    loop {
                        self.value(depth + 1)?;
                        self.space();
                        if self.bytes.get(self.pos) == Some(&b']') {
                            break;
                        }
                        self.consume(b',')?;
                    }
                }
                self.consume(b']')?;
                Kind::Other
            }
            b'"' => {
                let text = self.string()?; // Validate escapes without retaining private values.
                Kind::String {
                    empty: text.is_empty(),
                }
            }
            _ => {
                let mut stream = serde_json::Deserializer::from_slice(&self.bytes[self.pos..])
                    .into_iter::<IgnoredAny>();
                stream.next().ok_or_else(invalid)?.map_err(|_| invalid())?;
                self.pos += stream.byte_offset();
                let raw = &self.bytes[start..self.pos];
                if raw == b"null" {
                    Kind::Null
                } else {
                    if matches!(raw.first(), Some(b'-' | b'0'..=b'9')) {
                        let number = std::str::from_utf8(raw)
                            .map_err(|_| invalid())?
                            .parse::<f64>()
                            .map_err(|_| invalid())?;
                        if !number.is_finite() {
                            return Err(
                                "Browser preferences number is outside the supported range.".into(),
                            );
                        }
                    }
                    Kind::Other
                }
            }
        };
        Ok(Node {
            span: start..self.pos,
            kind,
        })
    }
}

impl<'a> Document<'a> {
    pub(super) fn parse(source: &'a [u8], cancel: &AtomicBool) -> Result<Self, String> {
        Self::parse_with_limits(source, cancel, Limits::default())
    }
    fn parse_with_limits(
        source: &'a [u8],
        cancel: &AtomicBool,
        limits: Limits,
    ) -> Result<Self, String> {
        if source.len() > limits.bytes {
            return Err("Browser preferences exceed the safe JSON size limit.".into());
        }
        std::str::from_utf8(source).map_err(|_| invalid())?;
        let mut parser = Parser {
            bytes: source,
            pos: 0,
            values: 0,
            limits,
            cancel,
        };
        let root = parser.value(0)?;
        parser.space();
        if parser.pos != source.len() {
            return Err(invalid());
        }
        parser.check()?;
        Ok(Self { source, root })
    }
    fn lookup(&self, path: &[&str]) -> Result<Option<&Node>, String> {
        let mut node = &self.root;
        for name in path {
            match &node.kind {
                Kind::Null => return Ok(None),
                Kind::Object(members) => {
                    let Some(member) = members.iter().find(|member| member.name == *name) else {
                        return Ok(None);
                    };
                    node = &member.value;
                }
                Kind::Other | Kind::String { .. } => {
                    return Err("Browser preferences have an unsupported ancestor type.".into());
                }
            }
        }
        Ok(Some(node))
    }
    /// Return one field identity per non-null native leaf, never nested item units.
    pub(super) fn history_fields(&self) -> Result<Vec<Field>, String> {
        let mut fields = Vec::new();
        for (parent, choices) in [
            (
                &["dns_prefetching"][..],
                &[Field::DnsReferrals, Field::DnsStartup][..],
            ),
            (
                &["profile", "content_settings", "exceptions"][..],
                &[Field::MediaEngagement, Field::SiteEngagement][..],
            ),
        ] {
            if let Some(Node {
                kind: Kind::Object(members),
                ..
            }) = self.lookup(parent)?
            {
                for field in choices {
                    if members.iter().any(|member| {
                        member.name == field.key() && !matches!(member.value.kind, Kind::Null)
                    }) {
                        fields.push(*field);
                    }
                }
            }
        }
        Ok(fields)
    }
    pub(super) fn fields(&self, category: super::PrivacyCategory) -> Result<Vec<Field>, String> {
        use super::PrivacyCategory;
        let field = match category {
            PrivacyCategory::History => return self.history_fields(),
            PrivacyCategory::LastDownloadLocation => Field::LastDownloadLocation,
            PrivacyCategory::SnapLocation => Field::SnapLocation,
            _ => return Ok(vec![]),
        };
        let mut path = field.parent().to_vec();
        path.push(field.key());
        Ok(
            if matches!(
                self.lookup(&path)?,
                Some(Node {
                    kind: Kind::String { .. },
                    ..
                })
            ) {
                vec![field]
            } else {
                vec![]
            },
        )
    }
    fn configured_download(&self) -> Option<&Node> {
        let Some(Node {
            kind: Kind::Object(members),
            ..
        }) = self.lookup(&["download"]).ok().flatten()
        else {
            return None;
        };
        members
            .iter()
            .find(|member| member.name == "default_directory")
            .map(|member| &member.value)
            .filter(|node| matches!(node.kind, Kind::String { empty: false }))
    }
    #[cfg(test)]
    pub(super) fn remove_history(&self, selected: &[Field]) -> Result<Vec<u8>, String> {
        if selected
            .iter()
            .any(|f| f.category() != super::PrivacyCategory::History)
        {
            return Err("A non-history field requires its typed browser action.".into());
        }
        self.apply_fields(selected)
    }
    /// Pure transform. Callers must supply revalidated reviewed field IDs and own
    /// the durable write/recovery protocol before these bytes can affect a file.
    pub(super) fn apply_fields(&self, selected: &[Field]) -> Result<Vec<u8>, String> {
        let selected: BTreeSet<_> = selected.iter().copied().collect();
        if selected.is_empty() {
            return Err("Select reviewed browser preference fields first.".into());
        }
        for field in &selected {
            if !self.fields(field.category())?.contains(field) {
                return Err("A selected browser preference field is no longer eligible.".into());
            }
        }
        let mut groups = BTreeMap::<Vec<&str>, BTreeSet<&str>>::new();
        let mut edits = Vec::<(Range<usize>, Vec<u8>)>::new();
        for field in selected {
            if field == Field::LastDownloadLocation {
                if let Some(configured) = self.configured_download() {
                    let mut path = field.parent().to_vec();
                    path.push(field.key());
                    let target = self
                        .lookup(&path)?
                        .ok_or("A reviewed download location changed.")?;
                    edits.push((
                        target.span.clone(),
                        self.source[configured.span.clone()].to_vec(),
                    ));
                    continue;
                }
                groups
                    .entry(field.parent().to_vec())
                    .or_default()
                    .insert("type");
            } else if field == Field::SnapLocation {
                groups
                    .entry(field.parent().to_vec())
                    .or_default()
                    .insert("used");
            }
            groups
                .entry(field.parent().to_vec())
                .or_default()
                .insert(field.key());
        }
        for (parent, names) in groups {
            let Some(Node {
                kind: Kind::Object(members),
                ..
            }) = self.lookup(&parent)?
            else {
                return Err("A reviewed preference parent changed.".into());
            };
            let mut index = 0;
            while index < members.len() {
                if !names.contains(members[index].name.as_str()) {
                    index += 1;
                    continue;
                }
                let first = index;
                while index < members.len() && names.contains(members[index].name.as_str()) {
                    index += 1;
                }
                let end = index;
                let range = if end < members.len() {
                    members[first].key_start..members[end].key_start
                } else if first > 0 {
                    members[first - 1].value.span.end..members[end - 1].value.span.end
                } else {
                    members[0].key_start..members[end - 1].value.span.end
                };
                edits.push((range, vec![]));
            }
        }
        edits.sort_by_key(|(range, _)| range.start);
        let mut output = Vec::with_capacity(self.source.len());
        let mut cursor = 0;
        for (range, replacement) in edits {
            if range.start < cursor || range.start >= range.end || range.end > self.source.len() {
                return Err("Reviewed browser preference fields overlap.".into());
            }
            output.extend_from_slice(&self.source[cursor..range.start]);
            output.extend_from_slice(&replacement);
            cursor = range.end;
        }
        output.extend_from_slice(&self.source[cursor..]);
        Ok(output)
    }
}

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub(super) enum Field {
    DnsReferrals,
    DnsStartup,
    MediaEngagement,
    SiteEngagement,
    LastDownloadLocation,
    SnapLocation,
}
impl Field {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::DnsReferrals => "DNS referral history",
            Self::DnsStartup => "DNS startup history",
            Self::MediaEngagement => "Media engagement history",
            Self::SiteEngagement => "Site engagement history",
            Self::LastDownloadLocation => "Last download location",
            Self::SnapLocation => "Saved Snap location",
        }
    }
    pub(super) fn category(self) -> super::PrivacyCategory {
        match self {
            Self::LastDownloadLocation => super::PrivacyCategory::LastDownloadLocation,
            Self::SnapLocation => super::PrivacyCategory::SnapLocation,
            _ => super::PrivacyCategory::History,
        }
    }
    pub(super) fn supported_for(self, browser: super::Browser) -> bool {
        if self == Self::SnapLocation {
            matches!(browser, super::Browser::Opera | super::Browser::OperaGx)
        } else {
            browser.is_chromium()
        }
    }
    pub(super) fn cleanup_note(self) -> &'static str {
        match self {
            Self::LastDownloadLocation => {
                "Resets the remembered location to the configured download folder, or removes it and its associated marker when no folder is configured. The configured download folder is kept."
            }
            Self::SnapLocation => {
                "Removes the saved Snap location and its associated usage marker. Other Snap settings are kept."
            }
            _ => "Removes only the reviewed history field. Unrelated browser settings are kept.",
        }
    }
    fn parent(self) -> &'static [&'static str] {
        match self {
            Self::DnsReferrals | Self::DnsStartup => &["dns_prefetching"],
            Self::MediaEngagement | Self::SiteEngagement => {
                &["profile", "content_settings", "exceptions"]
            }
            Self::LastDownloadLocation => &["savefile"],
            Self::SnapLocation => &["snap"],
        }
    }
    fn key(self) -> &'static str {
        match self {
            Self::DnsReferrals => "host_referral_list",
            Self::DnsStartup => "startup_list",
            Self::MediaEngagement => "media_engagement",
            Self::SiteEngagement => "site_engagement",
            Self::LastDownloadLocation => "default_directory",
            Self::SnapLocation => "save_location",
        }
    }
}

#[cfg(test)]
#[path = "json_members_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "json_members_location_tests.rs"]
mod location_tests;
