// Generated from the hash-pinned reference rule inventory; no runtime INI dependency.
// Profile-relative scopes consume the Mozilla container child component.
use super::{Browser, Handler, PrivacyCategory, Rule, Scope};
pub(super) static RULES: &[Rule] = &[
    Rule {
        browser: Browser::Edge,
        category: PrivacyCategory::History,
        id: "edge-chromium.history",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Archived History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Visited Links",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Current Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Last Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Top Sites",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Provider Cache",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Network Action Predictor",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Shortcuts",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Preferences",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Index*.*",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History Index*.*",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Archived History",
                delete: true,
            },
            Handler {
                key: "OnFile3",
                pattern: "Visited Links",
                delete: true,
            },
            Handler {
                key: "OnFile4",
                pattern: "Current Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile5",
                pattern: "Last Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile6",
                pattern: "Top Sites",
                delete: true,
            },
            Handler {
                key: "OnFile7",
                pattern: "History Provider Cache",
                delete: true,
            },
            Handler {
                key: "OnFile8",
                pattern: "Network Action Predictor",
                delete: true,
            },
            Handler {
                key: "OnFile9",
                pattern: "*.tmp",
                delete: true,
            },
            Handler {
                key: "OnFile10",
                pattern: "Web Data",
                delete: false,
            },
            Handler {
                key: "OnFile11",
                pattern: "Preferences",
                delete: false,
            },
            Handler {
                key: "OnFile12",
                pattern: "Shortcuts",
                delete: false,
            },
            Handler {
                key: "OnFile13",
                pattern: "History",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::Edge,
        category: PrivacyCategory::Downloads,
        id: "edge-chromium.downloadhistory",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "DownloadMetadata",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History",
                delete: false,
            },
            Handler {
                key: "OnFile2",
                pattern: "DownloadMetadata",
                delete: true,
            },
        ],
    },
    Rule {
        browser: Browser::Edge,
        category: PrivacyCategory::SavedPasswords,
        id: "edge-chromium.savedpasswords",
        scopes: &[
            Scope {
                directory: "",
                mask: "Login Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "Login Data",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Web Data",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::Avg,
        category: PrivacyCategory::History,
        id: "avgsecurebrowser.history",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Archived History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Visited Links",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Current Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Last Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Top Sites",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Provider Cache",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Network Action Predictor",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Shortcuts",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Preferences",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Index*.*",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History Index*.*",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Archived History",
                delete: true,
            },
            Handler {
                key: "OnFile3",
                pattern: "Visited Links",
                delete: true,
            },
            Handler {
                key: "OnFile4",
                pattern: "Current Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile5",
                pattern: "Last Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile6",
                pattern: "Top Sites",
                delete: true,
            },
            Handler {
                key: "OnFile7",
                pattern: "History Provider Cache",
                delete: true,
            },
            Handler {
                key: "OnFile8",
                pattern: "Network Action Predictor",
                delete: true,
            },
            Handler {
                key: "OnFile9",
                pattern: "*.tmp",
                delete: true,
            },
            Handler {
                key: "OnFile10",
                pattern: "Web Data",
                delete: false,
            },
            Handler {
                key: "OnFile11",
                pattern: "Preferences",
                delete: false,
            },
            Handler {
                key: "OnFile12",
                pattern: "Shortcuts",
                delete: false,
            },
            Handler {
                key: "OnFile13",
                pattern: "History",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::Avg,
        category: PrivacyCategory::Downloads,
        id: "avgsecurebrowser.downloadhistory",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "DownloadMetadata",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History",
                delete: false,
            },
            Handler {
                key: "OnFile2",
                pattern: "DownloadMetadata",
                delete: true,
            },
        ],
    },
    Rule {
        browser: Browser::Avg,
        category: PrivacyCategory::SavedPasswords,
        id: "avgsecurebrowser.savedpasswords",
        scopes: &[
            Scope {
                directory: "",
                mask: "Login Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "Login Data",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Web Data",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::Ccleaner,
        category: PrivacyCategory::History,
        id: "ccleanerbrowser.history",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Archived History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Visited Links",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Current Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Last Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Top Sites",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Provider Cache",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Network Action Predictor",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Shortcuts",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Preferences",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Index*.*",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History Index*.*",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Archived History",
                delete: true,
            },
            Handler {
                key: "OnFile3",
                pattern: "Visited Links",
                delete: true,
            },
            Handler {
                key: "OnFile4",
                pattern: "Current Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile5",
                pattern: "Last Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile6",
                pattern: "Top Sites",
                delete: true,
            },
            Handler {
                key: "OnFile7",
                pattern: "History Provider Cache",
                delete: true,
            },
            Handler {
                key: "OnFile8",
                pattern: "Network Action Predictor",
                delete: true,
            },
            Handler {
                key: "OnFile9",
                pattern: "*.tmp",
                delete: true,
            },
            Handler {
                key: "OnFile10",
                pattern: "Web Data",
                delete: false,
            },
            Handler {
                key: "OnFile11",
                pattern: "Preferences",
                delete: false,
            },
            Handler {
                key: "OnFile12",
                pattern: "Shortcuts",
                delete: false,
            },
            Handler {
                key: "OnFile13",
                pattern: "History",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::Ccleaner,
        category: PrivacyCategory::Downloads,
        id: "ccleanerbrowser.downloadhistory",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "DownloadMetadata",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History",
                delete: false,
            },
            Handler {
                key: "OnFile2",
                pattern: "DownloadMetadata",
                delete: true,
            },
        ],
    },
    Rule {
        browser: Browser::Ccleaner,
        category: PrivacyCategory::SavedPasswords,
        id: "ccleanerbrowser.savedpasswords",
        scopes: &[
            Scope {
                directory: "",
                mask: "Login Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "Login Data",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Web Data",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::Avast,
        category: PrivacyCategory::History,
        id: "avastsecurebrowser.history",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Archived History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Visited Links",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Current Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Last Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Top Sites",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Provider Cache",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Network Action Predictor",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Shortcuts",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Preferences",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Index*.*",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History Index*.*",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Archived History",
                delete: true,
            },
            Handler {
                key: "OnFile3",
                pattern: "Visited Links",
                delete: true,
            },
            Handler {
                key: "OnFile4",
                pattern: "Current Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile5",
                pattern: "Last Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile6",
                pattern: "Top Sites",
                delete: true,
            },
            Handler {
                key: "OnFile7",
                pattern: "History Provider Cache",
                delete: true,
            },
            Handler {
                key: "OnFile8",
                pattern: "Network Action Predictor",
                delete: true,
            },
            Handler {
                key: "OnFile9",
                pattern: "*.tmp",
                delete: true,
            },
            Handler {
                key: "OnFile10",
                pattern: "Web Data",
                delete: false,
            },
            Handler {
                key: "OnFile11",
                pattern: "Preferences",
                delete: false,
            },
            Handler {
                key: "OnFile12",
                pattern: "Shortcuts",
                delete: false,
            },
            Handler {
                key: "OnFile13",
                pattern: "History",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::Avast,
        category: PrivacyCategory::Downloads,
        id: "avastsecurebrowser.downloadhistory",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "DownloadMetadata",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History",
                delete: false,
            },
            Handler {
                key: "OnFile2",
                pattern: "DownloadMetadata",
                delete: true,
            },
        ],
    },
    Rule {
        browser: Browser::Avast,
        category: PrivacyCategory::SavedPasswords,
        id: "avastsecurebrowser.savedpasswords",
        scopes: &[
            Scope {
                directory: "",
                mask: "Login Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "Login Data",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Web Data",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::Firefox,
        category: PrivacyCategory::History,
        id: "mozilla.history",
        scopes: &[
            Scope {
                directory: "",
                mask: "history.dat",
                recursive: true,
            },
            Scope {
                directory: "",
                mask: "urlbarhistory.sqlite",
                recursive: true,
            },
            Scope {
                directory: "",
                mask: "places.sqlite",
                recursive: true,
            },
            Scope {
                directory: "",
                mask: "favicons.sqlite",
                recursive: true,
            },
            Scope {
                directory: "thumbnails",
                mask: "*.png",
                recursive: true,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "history.dat",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "urlbarhistory.sqlite",
                delete: true,
            },
            Handler {
                key: "OnFile3",
                pattern: "places.sqlite",
                delete: false,
            },
            Handler {
                key: "OnFile4",
                pattern: "favicons.sqlite",
                delete: false,
            },
            Handler {
                key: "OnFile5",
                pattern: "*.png",
                delete: true,
            },
            Handler {
                key: "OnFile6",
                pattern: "prefs.js",
                delete: false,
            },
            Handler {
                key: "OnFile7",
                pattern: "*.customDestinations-ms",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::Firefox,
        category: PrivacyCategory::Downloads,
        id: "mozilla.downloadhistory",
        scopes: &[
            Scope {
                directory: "",
                mask: "downloads.rdf",
                recursive: true,
            },
            Scope {
                directory: "",
                mask: "downloads.sqlite",
                recursive: true,
            },
            Scope {
                directory: "",
                mask: "places.sqlite",
                recursive: true,
            },
            Scope {
                directory: "",
                mask: "downloads.json",
                recursive: true,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "downloads.rdf",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "downloads.sqlite",
                delete: true,
            },
            Handler {
                key: "OnFile3",
                pattern: "places.sqlite",
                delete: false,
            },
            Handler {
                key: "OnFile4",
                pattern: "downloads.json",
                delete: true,
            },
        ],
    },
    Rule {
        browser: Browser::Firefox,
        category: PrivacyCategory::SavedPasswords,
        id: "mozilla.savedpasswords",
        scopes: &[
            Scope {
                directory: "",
                mask: "signons.txt;signons2.txt;signons3.txt",
                recursive: true,
            },
            Scope {
                directory: "",
                mask: "signons.sqlite",
                recursive: true,
            },
            Scope {
                directory: "",
                mask: "logins.json;logins-backup.json",
                recursive: true,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "signons.sqlite",
                delete: false,
            },
            Handler {
                key: "OnFile2",
                pattern: "*",
                delete: true,
            },
        ],
    },
    Rule {
        browser: Browser::Firefox,
        category: PrivacyCategory::SitePreferences,
        id: "mozilla.sitepreferences",
        scopes: &[
            Scope {
                directory: "",
                mask: "content-prefs.sqlite",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "permissions.sqlite",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "signons.sqlite",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "SiteSecurityServiceState.txt",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "content-prefs.sqlite",
                delete: false,
            },
            Handler {
                key: "OnFile2",
                pattern: "permissions.sqlite",
                delete: false,
            },
            Handler {
                key: "OnFile3",
                pattern: "signons.sqlite",
                delete: false,
            },
            Handler {
                key: "OnFile4",
                pattern: "SiteSecurityServiceState.txt",
                delete: true,
            },
        ],
    },
    Rule {
        browser: Browser::Thunderbird,
        category: PrivacyCategory::History,
        id: "thunderbird.history",
        scopes: &[
            Scope {
                directory: "",
                mask: "history.dat",
                recursive: true,
            },
            Scope {
                directory: "",
                mask: "urlbarhistory.sqlite",
                recursive: true,
            },
            Scope {
                directory: "",
                mask: "places.sqlite",
                recursive: true,
            },
            Scope {
                directory: "",
                mask: "favicons.sqlite",
                recursive: true,
            },
            Scope {
                directory: "thumbnails",
                mask: "*.png",
                recursive: true,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "history.dat",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "urlbarhistory.sqlite",
                delete: true,
            },
            Handler {
                key: "OnFile3",
                pattern: "places.sqlite",
                delete: false,
            },
            Handler {
                key: "OnFile4",
                pattern: "favicons.sqlite",
                delete: false,
            },
            Handler {
                key: "OnFile5",
                pattern: "*.png",
                delete: true,
            },
            Handler {
                key: "OnFile6",
                pattern: "*.customDestinations-ms",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::Thunderbird,
        category: PrivacyCategory::Downloads,
        id: "thunderbird.downloadhistory",
        scopes: &[
            Scope {
                directory: "",
                mask: "downloads.rdf",
                recursive: true,
            },
            Scope {
                directory: "",
                mask: "downloads.sqlite",
                recursive: true,
            },
            Scope {
                directory: "",
                mask: "places.sqlite",
                recursive: true,
            },
            Scope {
                directory: "",
                mask: "downloads.json",
                recursive: true,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "downloads.rdf",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "downloads.sqlite",
                delete: true,
            },
            Handler {
                key: "OnFile3",
                pattern: "places.sqlite",
                delete: false,
            },
            Handler {
                key: "OnFile4",
                pattern: "downloads.json",
                delete: true,
            },
        ],
    },
    Rule {
        browser: Browser::Thunderbird,
        category: PrivacyCategory::SavedPasswords,
        id: "thunderbird.savedpasswords",
        scopes: &[
            Scope {
                directory: "",
                mask: "signons.txt;signons2.txt;signons3.txt",
                recursive: true,
            },
            Scope {
                directory: "",
                mask: "signons.sqlite",
                recursive: true,
            },
            Scope {
                directory: "",
                mask: "logins.json;logins-backup.json",
                recursive: true,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "signons.sqlite",
                delete: false,
            },
            Handler {
                key: "OnFile2",
                pattern: "*",
                delete: true,
            },
        ],
    },
    Rule {
        browser: Browser::Thunderbird,
        category: PrivacyCategory::SitePreferences,
        id: "thunderbird.sitepreferences",
        scopes: &[
            Scope {
                directory: "",
                mask: "content-prefs.sqlite",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "permissions.sqlite",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "signons.sqlite",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "SiteSecurityServiceState.txt",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "content-prefs.sqlite",
                delete: false,
            },
            Handler {
                key: "OnFile2",
                pattern: "permissions.sqlite",
                delete: false,
            },
            Handler {
                key: "OnFile3",
                pattern: "signons.sqlite",
                delete: false,
            },
            Handler {
                key: "OnFile4",
                pattern: "SiteSecurityServiceState.txt",
                delete: true,
            },
        ],
    },
    Rule {
        browser: Browser::Opera,
        category: PrivacyCategory::History,
        id: "opera.history",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Archived History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Visited Links",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Current Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Last Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Top Sites",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Provider Cache",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Network Action Predictor",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Shortcuts",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Preferences",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Index*.*",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "global.dat",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "global_history.dat",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "search_field_history.dat",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "opera.dir",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "download.dat",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "vlink4.dat",
                recursive: false,
            },
            Scope {
                directory: "vps",
                mask: "*",
                recursive: true,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History Index*.*",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Archived History",
                delete: true,
            },
            Handler {
                key: "OnFile3",
                pattern: "Visited Links",
                delete: true,
            },
            Handler {
                key: "OnFile4",
                pattern: "Current Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile5",
                pattern: "Last Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile6",
                pattern: "Top Sites",
                delete: true,
            },
            Handler {
                key: "OnFile7",
                pattern: "History Provider Cache",
                delete: true,
            },
            Handler {
                key: "OnFile8",
                pattern: "Network Action Predictor",
                delete: true,
            },
            Handler {
                key: "OnFile9",
                pattern: "*.tmp",
                delete: true,
            },
            Handler {
                key: "OnFile10",
                pattern: "Web Data",
                delete: false,
            },
            Handler {
                key: "OnFile11",
                pattern: "Preferences",
                delete: false,
            },
            Handler {
                key: "OnFile12",
                pattern: "Shortcuts",
                delete: false,
            },
            Handler {
                key: "OnFile13",
                pattern: "History",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::Opera,
        category: PrivacyCategory::Downloads,
        id: "opera.downloadhistory",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "DownloadMetadata",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History",
                delete: false,
            },
            Handler {
                key: "OnFile2",
                pattern: "DownloadMetadata",
                delete: true,
            },
        ],
    },
    Rule {
        browser: Browser::Opera,
        category: PrivacyCategory::SavedPasswords,
        id: "opera.savedpasswords",
        scopes: &[
            Scope {
                directory: "",
                mask: "Login Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "wand.dat",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "Login Data",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Web Data",
                delete: false,
            },
            Handler {
                key: "OnFile3",
                pattern: "wand.dat",
                delete: true,
            },
        ],
    },
    Rule {
        browser: Browser::Chrome,
        category: PrivacyCategory::History,
        id: "google-chrome.history",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Archived History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Visited Links",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Current Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Last Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Top Sites",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Provider Cache",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Network Action Predictor",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Shortcuts",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Preferences",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Index*.*",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History Index*.*",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Archived History",
                delete: true,
            },
            Handler {
                key: "OnFile3",
                pattern: "Visited Links",
                delete: true,
            },
            Handler {
                key: "OnFile4",
                pattern: "Current Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile5",
                pattern: "Last Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile6",
                pattern: "Top Sites",
                delete: true,
            },
            Handler {
                key: "OnFile7",
                pattern: "History Provider Cache",
                delete: true,
            },
            Handler {
                key: "OnFile8",
                pattern: "Network Action Predictor",
                delete: true,
            },
            Handler {
                key: "OnFile9",
                pattern: "*.tmp",
                delete: true,
            },
            Handler {
                key: "OnFile10",
                pattern: "Web Data",
                delete: false,
            },
            Handler {
                key: "OnFile11",
                pattern: "Preferences",
                delete: false,
            },
            Handler {
                key: "OnFile12",
                pattern: "Shortcuts",
                delete: false,
            },
            Handler {
                key: "OnFile13",
                pattern: "History",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::Chrome,
        category: PrivacyCategory::Downloads,
        id: "google-chrome.downloadhistory",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "DownloadMetadata",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History",
                delete: false,
            },
            Handler {
                key: "OnFile2",
                pattern: "DownloadMetadata",
                delete: true,
            },
        ],
    },
    Rule {
        browser: Browser::Chrome,
        category: PrivacyCategory::SavedPasswords,
        id: "google-chrome.savedpasswords",
        scopes: &[
            Scope {
                directory: "",
                mask: "Login Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "Login Data",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Web Data",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::Vivaldi,
        category: PrivacyCategory::History,
        id: "vivaldi.history",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Archived History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Visited Links",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Current Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Last Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Top Sites",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Provider Cache",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Network Action Predictor",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Shortcuts",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Preferences",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Index*.*",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History Index*.*",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Archived History",
                delete: true,
            },
            Handler {
                key: "OnFile3",
                pattern: "Visited Links",
                delete: true,
            },
            Handler {
                key: "OnFile4",
                pattern: "Current Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile5",
                pattern: "Last Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile6",
                pattern: "Top Sites",
                delete: true,
            },
            Handler {
                key: "OnFile7",
                pattern: "History Provider Cache",
                delete: true,
            },
            Handler {
                key: "OnFile8",
                pattern: "Network Action Predictor",
                delete: true,
            },
            Handler {
                key: "OnFile9",
                pattern: "*.tmp",
                delete: true,
            },
            Handler {
                key: "OnFile10",
                pattern: "Web Data",
                delete: false,
            },
            Handler {
                key: "OnFile11",
                pattern: "Preferences",
                delete: false,
            },
            Handler {
                key: "OnFile12",
                pattern: "Shortcuts",
                delete: false,
            },
            Handler {
                key: "OnFile13",
                pattern: "History",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::Vivaldi,
        category: PrivacyCategory::Downloads,
        id: "vivaldi.downloadhistory",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "DownloadMetadata",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History",
                delete: false,
            },
            Handler {
                key: "OnFile2",
                pattern: "DownloadMetadata",
                delete: true,
            },
        ],
    },
    Rule {
        browser: Browser::Vivaldi,
        category: PrivacyCategory::SavedPasswords,
        id: "vivaldi.savedpasswords",
        scopes: &[
            Scope {
                directory: "",
                mask: "Login Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "Login Data",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Web Data",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::Brave,
        category: PrivacyCategory::History,
        id: "brave.history",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Archived History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Visited Links",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Current Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Last Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Top Sites",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Provider Cache",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Network Action Predictor",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Shortcuts",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Preferences",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Index*.*",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History Index*.*",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Archived History",
                delete: true,
            },
            Handler {
                key: "OnFile3",
                pattern: "Visited Links",
                delete: true,
            },
            Handler {
                key: "OnFile4",
                pattern: "Current Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile5",
                pattern: "Last Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile6",
                pattern: "Top Sites",
                delete: true,
            },
            Handler {
                key: "OnFile7",
                pattern: "History Provider Cache",
                delete: true,
            },
            Handler {
                key: "OnFile8",
                pattern: "Network Action Predictor",
                delete: true,
            },
            Handler {
                key: "OnFile9",
                pattern: "*.tmp",
                delete: true,
            },
            Handler {
                key: "OnFile10",
                pattern: "Web Data",
                delete: false,
            },
            Handler {
                key: "OnFile11",
                pattern: "Preferences",
                delete: false,
            },
            Handler {
                key: "OnFile12",
                pattern: "Shortcuts",
                delete: false,
            },
            Handler {
                key: "OnFile13",
                pattern: "History",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::Brave,
        category: PrivacyCategory::Downloads,
        id: "brave.downloadhistory",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "DownloadMetadata",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History",
                delete: false,
            },
            Handler {
                key: "OnFile2",
                pattern: "DownloadMetadata",
                delete: true,
            },
        ],
    },
    Rule {
        browser: Browser::Brave,
        category: PrivacyCategory::SavedPasswords,
        id: "brave.savedpasswords",
        scopes: &[
            Scope {
                directory: "",
                mask: "Login Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "Login Data",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Web Data",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::OperaGx,
        category: PrivacyCategory::History,
        id: "operagx.history",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Archived History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Visited Links",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Current Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Last Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Top Sites",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Provider Cache",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Network Action Predictor",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Shortcuts",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Preferences",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Index*.*",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History Index*.*",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Archived History",
                delete: true,
            },
            Handler {
                key: "OnFile3",
                pattern: "Visited Links",
                delete: true,
            },
            Handler {
                key: "OnFile4",
                pattern: "Current Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile5",
                pattern: "Last Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile6",
                pattern: "Top Sites",
                delete: true,
            },
            Handler {
                key: "OnFile7",
                pattern: "History Provider Cache",
                delete: true,
            },
            Handler {
                key: "OnFile8",
                pattern: "Network Action Predictor",
                delete: true,
            },
            Handler {
                key: "OnFile9",
                pattern: "*.tmp",
                delete: true,
            },
            Handler {
                key: "OnFile10",
                pattern: "Web Data",
                delete: false,
            },
            Handler {
                key: "OnFile11",
                pattern: "Preferences",
                delete: false,
            },
            Handler {
                key: "OnFile12",
                pattern: "Shortcuts",
                delete: false,
            },
            Handler {
                key: "OnFile13",
                pattern: "History",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::OperaGx,
        category: PrivacyCategory::Downloads,
        id: "operagx.downloadhistory",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "DownloadMetadata",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History",
                delete: false,
            },
            Handler {
                key: "OnFile2",
                pattern: "DownloadMetadata",
                delete: true,
            },
        ],
    },
    Rule {
        browser: Browser::OperaGx,
        category: PrivacyCategory::SavedPasswords,
        id: "operagx.savedpasswords",
        scopes: &[
            Scope {
                directory: "",
                mask: "Login Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "Login Data",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Web Data",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::Norton,
        category: PrivacyCategory::History,
        id: "nortonprivatebrowser.internethistory",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Archived History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Visited Links",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Current Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Last Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Top Sites",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Provider Cache",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Network Action Predictor",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Shortcuts",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Preferences",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Index*.*",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History Index*.*",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Archived History",
                delete: true,
            },
            Handler {
                key: "OnFile3",
                pattern: "Visited Links",
                delete: true,
            },
            Handler {
                key: "OnFile4",
                pattern: "Current Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile5",
                pattern: "Last Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile6",
                pattern: "Top Sites",
                delete: true,
            },
            Handler {
                key: "OnFile7",
                pattern: "History Provider Cache",
                delete: true,
            },
            Handler {
                key: "OnFile8",
                pattern: "Network Action Predictor",
                delete: true,
            },
            Handler {
                key: "OnFile9",
                pattern: "*.tmp",
                delete: true,
            },
            Handler {
                key: "OnFile10",
                pattern: "Web Data",
                delete: false,
            },
            Handler {
                key: "OnFile11",
                pattern: "Preferences",
                delete: false,
            },
            Handler {
                key: "OnFile12",
                pattern: "Shortcuts",
                delete: false,
            },
            Handler {
                key: "OnFile13",
                pattern: "History",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::Norton,
        category: PrivacyCategory::Downloads,
        id: "nortonprivatebrowser.downloadhistory",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "DownloadMetadata",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History",
                delete: false,
            },
            Handler {
                key: "OnFile2",
                pattern: "DownloadMetadata",
                delete: true,
            },
        ],
    },
    Rule {
        browser: Browser::Norton,
        category: PrivacyCategory::SavedPasswords,
        id: "nortonprivatebrowser.savedpasswords",
        scopes: &[
            Scope {
                directory: "",
                mask: "Login Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "Login Data",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Web Data",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::Avira,
        category: PrivacyCategory::History,
        id: "avirasecurebrowser.internethistory",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Archived History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Visited Links",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Current Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Last Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Top Sites",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Provider Cache",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Network Action Predictor",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Shortcuts",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Preferences",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Index*.*",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History Index*.*",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Archived History",
                delete: true,
            },
            Handler {
                key: "OnFile3",
                pattern: "Visited Links",
                delete: true,
            },
            Handler {
                key: "OnFile4",
                pattern: "Current Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile5",
                pattern: "Last Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile6",
                pattern: "Top Sites",
                delete: true,
            },
            Handler {
                key: "OnFile7",
                pattern: "History Provider Cache",
                delete: true,
            },
            Handler {
                key: "OnFile8",
                pattern: "Network Action Predictor",
                delete: true,
            },
            Handler {
                key: "OnFile9",
                pattern: "*.tmp",
                delete: true,
            },
            Handler {
                key: "OnFile10",
                pattern: "Web Data",
                delete: false,
            },
            Handler {
                key: "OnFile11",
                pattern: "Preferences",
                delete: false,
            },
            Handler {
                key: "OnFile12",
                pattern: "Shortcuts",
                delete: false,
            },
            Handler {
                key: "OnFile13",
                pattern: "History",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::Avira,
        category: PrivacyCategory::Downloads,
        id: "avirasecurebrowser.downloadhistory",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "DownloadMetadata",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History",
                delete: false,
            },
            Handler {
                key: "OnFile2",
                pattern: "DownloadMetadata",
                delete: true,
            },
        ],
    },
    Rule {
        browser: Browser::Avira,
        category: PrivacyCategory::SavedPasswords,
        id: "avirasecurebrowser.savedpasswords",
        scopes: &[
            Scope {
                directory: "",
                mask: "Login Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "Login Data",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Web Data",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::Arc,
        category: PrivacyCategory::History,
        id: "arc.history",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Archived History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Visited Links",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Current Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Last Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Top Sites",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Provider Cache",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Network Action Predictor",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Shortcuts",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Preferences",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Index*.*",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History Index*.*",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Archived History",
                delete: true,
            },
            Handler {
                key: "OnFile3",
                pattern: "Visited Links",
                delete: true,
            },
            Handler {
                key: "OnFile4",
                pattern: "Current Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile5",
                pattern: "Last Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile6",
                pattern: "Top Sites",
                delete: true,
            },
            Handler {
                key: "OnFile7",
                pattern: "History Provider Cache",
                delete: true,
            },
            Handler {
                key: "OnFile8",
                pattern: "Network Action Predictor",
                delete: true,
            },
            Handler {
                key: "OnFile9",
                pattern: "*.tmp",
                delete: true,
            },
            Handler {
                key: "OnFile10",
                pattern: "Web Data",
                delete: false,
            },
            Handler {
                key: "OnFile11",
                pattern: "Preferences",
                delete: false,
            },
            Handler {
                key: "OnFile12",
                pattern: "Shortcuts",
                delete: false,
            },
            Handler {
                key: "OnFile13",
                pattern: "History",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::Arc,
        category: PrivacyCategory::Downloads,
        id: "arc.downloadhistory",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "DownloadMetadata",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History",
                delete: false,
            },
            Handler {
                key: "OnFile2",
                pattern: "DownloadMetadata",
                delete: true,
            },
        ],
    },
    Rule {
        browser: Browser::Arc,
        category: PrivacyCategory::SavedPasswords,
        id: "arc.savedpasswords",
        scopes: &[
            Scope {
                directory: "",
                mask: "Login Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "Login Data",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Web Data",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::Neo,
        category: PrivacyCategory::History,
        id: "neobrowser.history",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Archived History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Visited Links",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Current Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Last Tabs",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Top Sites",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Provider Cache",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Network Action Predictor",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Shortcuts",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Preferences",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "History Index*.*",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History Index*.*",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Archived History",
                delete: true,
            },
            Handler {
                key: "OnFile3",
                pattern: "Visited Links",
                delete: true,
            },
            Handler {
                key: "OnFile4",
                pattern: "Current Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile5",
                pattern: "Last Tabs",
                delete: true,
            },
            Handler {
                key: "OnFile6",
                pattern: "Top Sites",
                delete: true,
            },
            Handler {
                key: "OnFile7",
                pattern: "History Provider Cache",
                delete: true,
            },
            Handler {
                key: "OnFile8",
                pattern: "Network Action Predictor",
                delete: true,
            },
            Handler {
                key: "OnFile9",
                pattern: "*.tmp",
                delete: true,
            },
            Handler {
                key: "OnFile10",
                pattern: "Web Data",
                delete: false,
            },
            Handler {
                key: "OnFile11",
                pattern: "Preferences",
                delete: false,
            },
            Handler {
                key: "OnFile12",
                pattern: "Shortcuts",
                delete: false,
            },
            Handler {
                key: "OnFile13",
                pattern: "History",
                delete: false,
            },
        ],
    },
    Rule {
        browser: Browser::Neo,
        category: PrivacyCategory::Downloads,
        id: "neobrowser.downloadhistory",
        scopes: &[
            Scope {
                directory: "",
                mask: "History",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "DownloadMetadata",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "History",
                delete: false,
            },
            Handler {
                key: "OnFile2",
                pattern: "DownloadMetadata",
                delete: true,
            },
        ],
    },
    Rule {
        browser: Browser::Neo,
        category: PrivacyCategory::SavedPasswords,
        id: "neobrowser.savedpasswords",
        scopes: &[
            Scope {
                directory: "",
                mask: "Login Data",
                recursive: false,
            },
            Scope {
                directory: "",
                mask: "Web Data",
                recursive: false,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "Login Data",
                delete: true,
            },
            Handler {
                key: "OnFile2",
                pattern: "Web Data",
                delete: false,
            },
        ],
    },
];
