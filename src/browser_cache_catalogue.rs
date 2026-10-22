//! Browser cache path catalogue reconstructed from the installed reference rules.
//! Generated data contains no machine-specific paths or runtime reference dependency.
use super::CacheRule;
pub struct ReferenceRoot {
    pub category: &'static str,
    pub environment: &'static str,
    pub relative: &'static str,
    pub rules: &'static [CacheRule],
}
pub const LABELS: &[(&str, &str)] = &[
    ("edge", "Edge Chromium cache"),
    ("avgsecurebrowser", "AVG Secure Browser cache"),
    ("ccleanerbrowser", "CCleaner Browser cache"),
    ("avastsecurebrowser", "Avast Secure Browser cache"),
    ("firefox", "Mozilla cache"),
    ("thunderbird", "Thunderbird cache"),
    ("opera", "Opera cache"),
    ("chrome", "Google Chrome cache"),
    ("vivaldi", "Vivaldi cache"),
    ("brave", "Brave cache"),
    ("operagx", "OperaGX cache"),
    ("nortonprivatebrowser", "Norton Private Browser cache"),
    ("avirasecurebrowser", "Avira Secure Browser cache"),
    ("arc", "Arc cache"),
    ("neobrowser", "Neo Browser cache"),
];
pub const REFERENCE_ROOTS: &[ReferenceRoot] = &[
    ReferenceRoot {
        category: "arc",
        environment: "localappdata",
        relative: "Packages/TheBrowserCompany.Arc_ttt1ap7aakyb4/LocalCache/Local/Arc/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
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
                directory: "*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Platform Notifications",
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
                directory: "*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Profile*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "arc",
        environment: "localappdata",
        relative: "Packages/TheBrowserCompany.Arc_ttt1ap7aakyb4/LocalCache/Local/Arc/User Data/Default",
        rules: &[
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "avastsecurebrowser",
        environment: "appdata",
        relative: "AVAST Software/Browser",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "avastsecurebrowser",
        environment: "localappdata",
        relative: "AVAST Software/Browser",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "avastsecurebrowser",
        environment: "localappdata",
        relative: "AVAST Software/Browser/User Data/Default",
        rules: &[
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "avgsecurebrowser",
        environment: "appdata",
        relative: "AVG/Browser",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "avgsecurebrowser",
        environment: "localappdata",
        relative: "AVG/Browser",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "avgsecurebrowser",
        environment: "localappdata",
        relative: "AVG/Browser/User Data/Default",
        rules: &[
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "avirasecurebrowser",
        environment: "appdata",
        relative: "Avira/Browser/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "avirasecurebrowser",
        environment: "localappdata",
        relative: "Avira/Browser/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgeCoupons/coupons_data.db",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
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
                directory: "*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Platform Notifications",
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
                directory: "*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Profile*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/EdgeCoupons/coupons_data.db",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "avirasecurebrowser",
        environment: "localappdata",
        relative: "Avira/Browser/User Data/Default",
        rules: &[
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgeCoupons/coupons_data.db",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "brave",
        environment: "appdata",
        relative: "BraveSoftware/Brave-Browser-Beta/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "brave",
        environment: "appdata",
        relative: "BraveSoftware/Brave-Browser-Nightly/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "brave",
        environment: "appdata",
        relative: "BraveSoftware/Brave-Browser/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "brave",
        environment: "localappdata",
        relative: "BraveSoftware/Brave-Browser-Beta/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Default/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
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
                directory: "*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Platform Notifications",
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
                directory: "*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "brave",
        environment: "localappdata",
        relative: "BraveSoftware/Brave-Browser-Nightly/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Default/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
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
                directory: "*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Platform Notifications",
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
                directory: "*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "brave",
        environment: "localappdata",
        relative: "BraveSoftware/Brave-Browser/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
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
                directory: "*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Platform Notifications",
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
                directory: "*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Profile*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "brave",
        environment: "localappdata",
        relative: "BraveSoftware/Brave-Browser/User Data/Default",
        rules: &[
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "ccleanerbrowser",
        environment: "appdata",
        relative: "CCleaner Browser/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "ccleanerbrowser",
        environment: "localappdata",
        relative: "CCleaner Browser/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
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
                directory: "*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Platform Notifications",
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
                directory: "*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "ccleanerbrowser",
        environment: "localappdata",
        relative: "CCleaner Browser/User Data/Default",
        rules: &[
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "chrome",
        environment: "localappdata",
        relative: "ChromePlus/ChromePlusUserData",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
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
                directory: "*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Platform Notifications",
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
                directory: "*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "chrome",
        environment: "localappdata",
        relative: "Chromium/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
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
                directory: "*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Platform Notifications",
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
                directory: "*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "chrome",
        environment: "localappdata",
        relative: "Comodo/Dragon/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
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
                directory: "*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Platform Notifications",
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
                directory: "*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "chrome",
        environment: "localappdata",
        relative: "Flock/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
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
                directory: "*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Platform Notifications",
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
                directory: "*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "chrome",
        environment: "localappdata",
        relative: "Google/Chrome Beta/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
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
                directory: "*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Platform Notifications",
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
                directory: "*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "chrome",
        environment: "localappdata",
        relative: "Google/Chrome SxS/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
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
                directory: "*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Platform Notifications",
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
                directory: "*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "chrome",
        environment: "localappdata",
        relative: "Google/Chrome/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
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
                directory: "*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Platform Notifications",
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
                directory: "*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Profile*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "chrome",
        environment: "localappdata",
        relative: "Google/Chrome/User Data/Default",
        rules: &[
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "chrome",
        environment: "localappdata",
        relative: "MapleStudio/ChromePlus/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
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
                directory: "*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Platform Notifications",
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
                directory: "*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "chrome",
        environment: "localappdata",
        relative: "RockMelt/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
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
                directory: "*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Platform Notifications",
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
                directory: "*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "chrome",
        environment: "localappdata",
        relative: "Spark/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
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
                directory: "*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Platform Notifications",
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
                directory: "*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "chrome",
        environment: "localappdata",
        relative: "Torch/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
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
                directory: "*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Platform Notifications",
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
                directory: "*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "chrome",
        environment: "localappdata",
        relative: "Yandex/YandexBrowser/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
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
                directory: "*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Platform Notifications",
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
                directory: "*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "edge",
        environment: "appdata",
        relative: "Microsoft/Edge Beta/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "edge",
        environment: "appdata",
        relative: "Microsoft/Edge Dev/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "edge",
        environment: "appdata",
        relative: "Microsoft/Edge SxS/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "edge",
        environment: "appdata",
        relative: "Microsoft/Edge/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "edge",
        environment: "localappdata",
        relative: "Microsoft/Edge Beta/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Default/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/EdgeCoupons/coupons_data.db",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgeCoupons/coupons_data.db",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
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
                directory: "*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Platform Notifications",
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
                directory: "*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "edge",
        environment: "localappdata",
        relative: "Microsoft/Edge Dev/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Default/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/EdgeCoupons/coupons_data.db",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgeCoupons/coupons_data.db",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
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
                directory: "*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Platform Notifications",
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
                directory: "*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "edge",
        environment: "localappdata",
        relative: "Microsoft/Edge SxS/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Default/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/EdgeCoupons/coupons_data.db",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Default/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgeCoupons/coupons_data.db",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
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
                directory: "*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Platform Notifications",
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
                directory: "*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "edge",
        environment: "localappdata",
        relative: "Microsoft/Edge/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgeCoupons/coupons_data.db",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
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
                directory: "*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Platform Notifications",
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
                directory: "*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Profile*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/EdgeCoupons/coupons_data.db",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "edge",
        environment: "localappdata",
        relative: "Microsoft/Edge/User Data/Default",
        rules: &[
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgeCoupons/coupons_data.db",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "appdata",
        relative: "8pecxstudios/Cyberfox/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "appdata",
        relative: "Comodo/IceDragon/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "appdata",
        relative: "Flock/Browser/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "appdata",
        relative: "K-Meleon",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "appdata",
        relative: "Moonchild Productions/Pale Moon/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "appdata",
        relative: "Mozilla/Firefox/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "appdata",
        relative: "Mozilla/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "appdata",
        relative: "Mozilla/SeaMonkey/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "appdata",
        relative: "Netscape/NSB/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "appdata",
        relative: "Netscape/Navigator/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "appdata",
        relative: "Phoenix/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "appdata",
        relative: "SongBird2/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "commonappdata",
        relative: "Mozilla-*",
        rules: &[CacheRule {
            directory: "",
            files: "profile_count_*.json;uninstall_ping_*.json;*.bg_rm-cachePurge-*",
            recursive: false,
        }],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "localappdata",
        relative: "8pecxstudios/Cyberfox/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "localappdata",
        relative: "Comodo/IceDragon/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "localappdata",
        relative: "Flock/Browser/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "localappdata",
        relative: "K-Meleon/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "localappdata",
        relative: "Moonchild Productions/Pale Moon/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "localappdata",
        relative: "Mozilla/Firefox/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "localappdata",
        relative: "Mozilla/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "localappdata",
        relative: "Mozilla/SeaMonkey/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "localappdata",
        relative: "Netscape/NSB/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "localappdata",
        relative: "Netscape/Navigator/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "localappdata",
        relative: "Packages/Mozilla.Firefox_n80bbvh6b1yt2/LocalCache/Local/Mozilla/Firefox/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "localappdata",
        relative: "Packages/Mozilla.Firefox_n80bbvh6b1yt2/LocalCache/Roaming/Mozilla/Firefox/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "localappdata",
        relative: "Phoenix/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "localappdata",
        relative: "SongBird2/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "firefox",
        environment: "programfiles",
        relative: "K-Meleon/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "neobrowser",
        environment: "localappdata",
        relative: "NEO",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "neobrowser",
        environment: "localappdata",
        relative: "NEO/User Data/Default",
        rules: &[
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "nortonprivatebrowser",
        environment: "appdata",
        relative: "Norton/Browser/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "extensions_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "nortonprivatebrowser",
        environment: "localappdata",
        relative: "Norton/Browser/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgeCoupons/coupons_data.db",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
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
                directory: "*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Platform Notifications",
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
                directory: "*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Profile*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/EdgeCoupons/coupons_data.db",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "extensions_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "nortonprivatebrowser",
        environment: "localappdata",
        relative: "Norton/Browser/User Data/Default",
        rules: &[
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgeCoupons/coupons_data.db",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "opera",
        environment: "appdata",
        relative: "Opera",
        rules: &[
            CacheRule {
                directory: "Opera*/profile",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Opera*/profile/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/cache4",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/icons/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/opcache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/temporary_downloads",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/widgets/*/cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "opera",
        environment: "appdata",
        relative: "Opera Software/Opera Developer",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache4",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "icons/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "opcache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "temporary_downloads",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "widgets/*/cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "opera",
        environment: "appdata",
        relative: "Opera Software/Opera Developer/Default",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache4",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "icons/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "opcache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "temporary_downloads",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "widgets/*/cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "opera",
        environment: "appdata",
        relative: "Opera Software/Opera Next",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache4",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "icons/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "opcache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "temporary_downloads",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "widgets/*/cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "opera",
        environment: "appdata",
        relative: "Opera Software/Opera Next/Default",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache4",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "icons/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "opcache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "temporary_downloads",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "widgets/*/cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "opera",
        environment: "appdata",
        relative: "Opera Software/Opera Stable",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache4",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "icons/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "opcache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "temporary_downloads",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "widgets/*/cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "opera",
        environment: "appdata",
        relative: "Opera Software/Opera Stable/Default",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache4",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "icons/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "opcache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "temporary_downloads",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "widgets/*/cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "opera",
        environment: "appdata",
        relative: "Opera/Opera",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache4",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "icons/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "opcache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "temporary_downloads",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "widgets/*/cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "opera",
        environment: "appdata",
        relative: "Opera/Opera 10",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache4",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "icons/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "opcache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "temporary_downloads",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "widgets/*/cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "opera",
        environment: "appdata",
        relative: "Opera/Opera 10 Beta",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache4",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "icons/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "opcache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "temporary_downloads",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "widgets/*/cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "opera",
        environment: "appdata",
        relative: "Opera/Opera/profile",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache4",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "icons/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "opcache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "temporary_downloads",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "widgets/*/cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "opera",
        environment: "localappdata",
        relative: "Opera",
        rules: &[
            CacheRule {
                directory: "*",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
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
                directory: "*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache4",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/icons/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/opcache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/temporary_downloads",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/widgets/*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Opera*/profile/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/cache4",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/icons/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/opcache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/temporary_downloads",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Opera*/profile/widgets/*/cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "opera",
        environment: "localappdata",
        relative: "Opera Software/Opera Developer",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache4",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "icons/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "opcache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "temporary_downloads",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "widgets/*/cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "opera",
        environment: "localappdata",
        relative: "Opera Software/Opera Developer/Default",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache4",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "icons/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "opcache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "temporary_downloads",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "widgets/*/cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "opera",
        environment: "localappdata",
        relative: "Opera Software/Opera Next",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache4",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "icons/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "opcache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "temporary_downloads",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "widgets/*/cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "opera",
        environment: "localappdata",
        relative: "Opera Software/Opera Next/Default",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache4",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "icons/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "opcache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "temporary_downloads",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "widgets/*/cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "opera",
        environment: "localappdata",
        relative: "Opera Software/Opera Stable",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache4",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "icons/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "opcache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "temporary_downloads",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "widgets/*/cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "opera",
        environment: "localappdata",
        relative: "Opera Software/Opera Stable/Default",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache4",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "icons/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "opcache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "temporary_downloads",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "widgets/*/cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "opera",
        environment: "localappdata",
        relative: "Opera/Opera/profile",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "cache4",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "icons/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "opcache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "temporary_downloads",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "widgets/*/cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "operagx",
        environment: "appdata",
        relative: "Opera Software/Opera GX Stable",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "operagx",
        environment: "appdata",
        relative: "Opera Software/Opera GX Stable/Default",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "operagx",
        environment: "localappdata",
        relative: "Opera Software/Opera GX Stable",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "operagx",
        environment: "localappdata",
        relative: "Opera Software/Opera GX Stable/Default",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "thunderbird",
        environment: "appdata",
        relative: "Thunderbird/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "thunderbird",
        environment: "localappdata",
        relative: "Thunderbird/Profiles",
        rules: &[
            CacheRule {
                directory: "*/OfflineCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache.trash*",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/cache2",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/jumpListCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/safebrowsing",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/startupCache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "vivaldi",
        environment: "appdata",
        relative: "Vivaldi/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "vivaldi",
        environment: "localappdata",
        relative: "Vivaldi/User Data",
        rules: &[
            CacheRule {
                directory: "",
                files: "*-journal;*.tmp",
                recursive: true,
            },
            CacheRule {
                directory: "*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
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
                directory: "*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Platform Notifications",
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
                directory: "*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Profile*/Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Profile*/component_crx_cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
    ReferenceRoot {
        category: "vivaldi",
        environment: "localappdata",
        relative: "Vivaldi/User Data/Default",
        rules: &[
            CacheRule {
                directory: "",
                files: "TopSites.json",
                recursive: false,
            },
            CacheRule {
                directory: "Application Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "EdgePushStorageWithWinRt",
                files: "*.log",
                recursive: true,
            },
            CacheRule {
                directory: "File System",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GrShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "GraphiteDawnCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_ntp.msn.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.blob",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "IndexedDB/https_www.instagram.com_0.indexeddb.leveldb",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Code Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/GPUCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Media Cache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/Platform Notifications",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "Storage/ext/*/def/ShaderCache",
                files: "*.*",
                recursive: true,
            },
            CacheRule {
                directory: "component_crx_cache",
                files: "*.*",
                recursive: true,
            },
        ],
    },
];
