//! Explicit browser-cache path rules reconstructed from the installed reference.
//! No runtime dependency on reference files; matching never opens file contents.
use std::path::{Component, Path};

#[derive(Clone, Copy, Debug)]
pub struct CacheRule {
    pub directory: &'static str,
    pub files: &'static str,
    pub recursive: bool,
}

#[path = "browser_cache_catalogue.rs"]
mod catalogue;
pub use catalogue::{LABELS, REFERENCE_ROOTS, ReferenceRoot};

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum RootScope {
    Reference(u16),
}

pub fn includes_scoped(id: &str, root: &Path, path: &Path, scope: RootScope) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return false;
    };
    let RootScope::Reference(index) = scope;
    REFERENCE_ROOTS
        .get(usize::from(index))
        .is_some_and(|entry| {
            entry.category == id && entry.rules.iter().any(|rule| rule.matches(relative))
        })
}

pub fn is_category(id: &str) -> bool {
    LABELS.iter().any(|(category, _)| *category == id)
}

/// Browser cache eligibility is independent of the Windows temporary-file age.
pub fn minimum_age_days(id: &str, temporary_file_age: u32) -> u32 {
    if is_category(id) {
        0
    } else {
        temporary_file_age
    }
}

/// Match a Windows filename component. `*.*` also matches extensionless files.
pub(crate) fn wildcard(pattern: &str, value: &str) -> bool {
    let pattern = if pattern == "*.*" { "*" } else { pattern };
    let pattern: Vec<_> = pattern.to_lowercase().chars().collect();
    let value: Vec<_> = value.to_lowercase().chars().collect();
    let (mut p, mut v, mut star, mut retry) = (0, 0, None, 0);
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            p += 1;
            retry = v;
        } else if let Some(s) = star {
            retry += 1;
            v = retry;
            p = s + 1;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

impl CacheRule {
    pub fn matches(&self, relative: &Path) -> bool {
        let mut parts = Vec::new();
        for part in relative.components() {
            match part {
                Component::Normal(value) => {
                    let Some(value) = value.to_str() else {
                        return false;
                    };
                    parts.push(value);
                }
                _ => return false,
            }
        }
        let Some(file) = parts.pop() else {
            return false;
        };
        let directory: Vec<_> = self
            .directory
            .split('/')
            .filter(|p| !p.is_empty())
            .collect();
        if parts.len() < directory.len() || (!self.recursive && parts.len() != directory.len()) {
            return false;
        }
        directory
            .iter()
            .zip(&parts)
            .all(|(pattern, value)| wildcard(pattern, value))
            && self.files.split(';').any(|pattern| wildcard(pattern, file))
    }
}

pub const FIREFOX_RULES: &[CacheRule] = &[
    CacheRule {
        directory: "*/cache",
        files: "*",
        recursive: true,
    },
    CacheRule {
        directory: "*/cache2",
        files: "*",
        recursive: true,
    },
    CacheRule {
        directory: "*/cache.trash*",
        files: "*",
        recursive: true,
    },
    CacheRule {
        directory: "*/jumpListCache",
        files: "*",
        recursive: true,
    },
    CacheRule {
        directory: "*/startupCache",
        files: "*",
        recursive: true,
    },
    CacheRule {
        directory: "*/OfflineCache",
        files: "*",
        recursive: true,
    },
    CacheRule {
        directory: "*/safebrowsing",
        files: "*",
        recursive: true,
    },
];

/// Recheck a selected immutable file against its family's compiled rules.
/// The scanner's stricter per-root scope determines initial admission.
pub fn includes(id: &str, root: &Path, path: &Path) -> bool {
    if !is_category(id) {
        return true;
    }
    path.strip_prefix(root).is_ok_and(|relative| {
        REFERENCE_ROOTS
            .iter()
            .filter(|entry| entry.category == id)
            .any(|entry| entry.rules.iter().any(|rule| rule.matches(relative)))
    })
}

pub const CHROME_RULES: &[CacheRule] = &[
    CacheRule {
        directory: "*/Cache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/Media Cache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/GPUCache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/ShaderCache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/Storage/ext/*/def/Cache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/Storage/ext/*/def/Media Cache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/Storage/ext/*/def/GPUCache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/Storage/ext/*/def/ShaderCache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/Application Cache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/File System",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "",
        files: "*-journal;*.tmp",
        recursive: true,
    },
    CacheRule {
        directory: "*/Code Cache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/Storage/ext/*/def/Code Cache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*",
        files: "TopSites.json",
        recursive: false,
    },
    CacheRule {
        directory: "*/GrShaderCache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/IndexedDB/https_www.instagram.com_0.indexeddb.blob",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/EdgePushStorageWithWinRt",
        files: "*.log",
        recursive: true,
    },
    CacheRule {
        directory: "*/Platform Notifications",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/Storage/ext/*/def/Platform Notifications",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/component_crx_cache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/GraphiteDawnCache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "component_crx_cache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "GraphiteDawnCache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "GrShaderCache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "ShaderCache",
        files: "*.*",
        recursive: true,
    },
];

pub const EDGE_RULES: &[CacheRule] = &[
    CacheRule {
        directory: "*/Cache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/Media Cache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/GPUCache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/ShaderCache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/Storage/ext/*/def/Cache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/Storage/ext/*/def/Media Cache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/Storage/ext/*/def/GPUCache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/Storage/ext/*/def/ShaderCache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/Application Cache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/File System",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "",
        files: "*-journal;*.tmp",
        recursive: true,
    },
    CacheRule {
        directory: "*/Code Cache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/Storage/ext/*/def/Code Cache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/EdgeCoupons/coupons_data.db",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*",
        files: "TopSites.json",
        recursive: false,
    },
    CacheRule {
        directory: "*/GrShaderCache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/IndexedDB/https_www.instagram.com_0.indexeddb.blob",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/EdgePushStorageWithWinRt",
        files: "*.log",
        recursive: true,
    },
    CacheRule {
        directory: "*/Platform Notifications",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/Storage/ext/*/def/Platform Notifications",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/component_crx_cache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "*/GraphiteDawnCache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "component_crx_cache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "GraphiteDawnCache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "GrShaderCache",
        files: "*.*",
        recursive: true,
    },
    CacheRule {
        directory: "ShaderCache",
        files: "*.*",
        recursive: true,
    },
];

// Root variables are explicit relative paths, resolved by the platform owner.
pub const ROOTS: &[(&str, &str, &str)] = &[
    ("chrome", "localappdata", "Google/Chrome/User Data"),
    ("chrome", "localappdata", "Google/Chrome Beta/User Data"),
    ("chrome", "localappdata", "Flock/User Data"),
    ("chrome", "localappdata", "Google/Chrome SxS/User Data"),
    ("chrome", "localappdata", "Chromium/User Data"),
    ("chrome", "localappdata", "RockMelt/User Data"),
    ("chrome", "localappdata", "Comodo/Dragon/User Data"),
    ("chrome", "localappdata", "MapleStudio/ChromePlus/User Data"),
    ("chrome", "localappdata", "Spark/User Data"),
    ("chrome", "localappdata", "Torch/User Data"),
    ("chrome", "localappdata", "Yandex/YandexBrowser/User Data"),
    ("chrome", "localappdata", "ChromePlus/ChromePlusUserData"),
    ("edge", "localappdata", "Microsoft/Edge/User Data"),
    ("edge", "appdata", "Microsoft/Edge/User Data"),
    ("edge", "localappdata", "Microsoft/Edge Beta/User Data"),
    ("edge", "appdata", "Microsoft/Edge Beta/User Data"),
    ("edge", "localappdata", "Microsoft/Edge Dev/User Data"),
    ("edge", "appdata", "Microsoft/Edge Dev/User Data"),
    ("edge", "localappdata", "Microsoft/Edge SxS/User Data"),
    ("edge", "appdata", "Microsoft/Edge SxS/User Data"),
    ("firefox", "appdata", "Phoenix/Profiles"),
    ("firefox", "appdata", "Mozilla/Firefox/Profiles"),
    ("firefox", "appdata", "Mozilla/Profiles"),
    ("firefox", "appdata", "Netscape/NSB/Profiles"),
    ("firefox", "appdata", "Netscape/Navigator/Profiles"),
    ("firefox", "appdata", "Flock/Browser/Profiles"),
    ("firefox", "appdata", "Mozilla/SeaMonkey/Profiles"),
    (
        "firefox",
        "appdata",
        "Moonchild Productions/Pale Moon/Profiles",
    ),
    ("firefox", "appdata", "K-Meleon"),
    ("firefox", "programfiles", "K-Meleon/Profiles"),
    ("firefox", "appdata", "SongBird2/Profiles"),
    ("firefox", "appdata", "Comodo/IceDragon/Profiles"),
    ("firefox", "appdata", "8pecxstudios/Cyberfox/Profiles"),
    (
        "firefox",
        "localappdata",
        "Packages/Mozilla.Firefox_n80bbvh6b1yt2/LocalCache/Roaming/Mozilla/Firefox/Profiles",
    ),
    (
        "firefox",
        "localappdata",
        "Packages/Mozilla.Firefox_n80bbvh6b1yt2/LocalCache/Local/Mozilla/Firefox/Profiles",
    ),
    ("firefox", "localappdata", "Phoenix/Profiles"),
    ("firefox", "localappdata", "Mozilla/Firefox/Profiles"),
    ("firefox", "localappdata", "Mozilla/Profiles"),
    ("firefox", "localappdata", "Netscape/NSB/Profiles"),
    ("firefox", "localappdata", "Netscape/Navigator/Profiles"),
    ("firefox", "localappdata", "Flock/Browser/Profiles"),
    ("firefox", "localappdata", "Mozilla/SeaMonkey/Profiles"),
    (
        "firefox",
        "localappdata",
        "Moonchild Productions/Pale Moon/Profiles",
    ),
    ("firefox", "localappdata", "K-Meleon/Profiles"),
    ("firefox", "localappdata", "SongBird2/Profiles"),
    ("firefox", "localappdata", "Comodo/IceDragon/Profiles"),
    ("firefox", "localappdata", "8pecxstudios/Cyberfox/Profiles"),
];
