// Declared installed browser session FileKeys and ordered descriptors.
// Global root/default/age/access/exclusion policy remains separately audited.
use super::{Browser, Handler, Kind, Rule, Scope};
pub(super) const RULES: &[Rule] = &[
    Rule {
        browser: Browser::Firefox,
        id: "mozilla.session",
        scopes: &[
            Scope {
                directory: "",
                masks: "sessionstore.js;sessionstore.jsonlz4;sessionstore.bak*",
                recursive: false,
            },
            Scope {
                directory: "",
                masks: "sessionCheckpoints.json",
                recursive: false,
            },
            Scope {
                directory: "",
                masks: "session.json",
                recursive: false,
            },
            Scope {
                directory: "sessionstore-backups",
                masks: "*",
                recursive: true,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "prefs.js",
                kind: Kind::Text,
            },
            Handler {
                key: "OnFile2",
                pattern: "sessionstore.js",
                kind: Kind::MozillaJson,
            },
            Handler {
                key: "OnFile3",
                pattern: "sessionstore.jsonlz4",
                kind: Kind::MozillaLz4,
            },
            Handler {
                key: "OnFile4",
                pattern: "*",
                kind: Kind::File,
            },
        ],
    },
    Rule {
        browser: Browser::Thunderbird,
        id: "thunderbird.session",
        scopes: &[
            Scope {
                directory: "",
                masks: "sessionstore.js;sessionstore.jsonlz4;sessionstore.bak*",
                recursive: false,
            },
            Scope {
                directory: "",
                masks: "sessionCheckpoints.json",
                recursive: false,
            },
            Scope {
                directory: "",
                masks: "session.json",
                recursive: false,
            },
            Scope {
                directory: "sessionstore-backups",
                masks: "*",
                recursive: true,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "sessionstore.js",
                kind: Kind::MozillaJson,
            },
            Handler {
                key: "OnFile2",
                pattern: "sessionstore.jsonlz4",
                kind: Kind::MozillaLz4,
            },
            Handler {
                key: "OnFile3",
                pattern: "*",
                kind: Kind::File,
            },
        ],
    },
    Rule {
        browser: Browser::Edge,
        id: "edge-chromium.session",
        scopes: &[
            Scope {
                directory: "",
                masks: "Current Session;Last Session",
                recursive: false,
            },
            Scope {
                directory: "Session Storage",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Extension State",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Sessions",
                masks: "*.*",
                recursive: true,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "Current Session",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile2",
                pattern: "Tabs_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile3",
                pattern: "Session_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile4",
                pattern: "*\\Session Storage\\*",
                kind: Kind::Path,
            },
            Handler {
                key: "OnFile5",
                pattern: "*\\Extension State\\*",
                kind: Kind::Path,
            },
        ],
    },
    Rule {
        browser: Browser::Avg,
        id: "avgsecurebrowser.session",
        scopes: &[
            Scope {
                directory: "",
                masks: "Current Session;Last Session",
                recursive: false,
            },
            Scope {
                directory: "Session Storage",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Extension State",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Sessions",
                masks: "*.*",
                recursive: true,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "Current Session",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile2",
                pattern: "Tabs_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile3",
                pattern: "Session_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile4",
                pattern: "*\\Session Storage\\*",
                kind: Kind::Path,
            },
            Handler {
                key: "OnFile5",
                pattern: "*\\Extension State\\*",
                kind: Kind::Path,
            },
        ],
    },
    Rule {
        browser: Browser::Ccleaner,
        id: "ccleanerbrowser.session",
        scopes: &[
            Scope {
                directory: "",
                masks: "Current Session;Last Session",
                recursive: false,
            },
            Scope {
                directory: "Session Storage",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Extension State",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Sessions",
                masks: "*.*",
                recursive: true,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "Current Session",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile2",
                pattern: "Tabs_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile3",
                pattern: "Session_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile4",
                pattern: "*\\Session Storage\\*",
                kind: Kind::Path,
            },
            Handler {
                key: "OnFile5",
                pattern: "*\\Extension State\\*",
                kind: Kind::Path,
            },
        ],
    },
    Rule {
        browser: Browser::Avast,
        id: "avastsecurebrowser.session",
        scopes: &[
            Scope {
                directory: "",
                masks: "Current Session;Last Session",
                recursive: false,
            },
            Scope {
                directory: "Session Storage",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Extension State",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Sessions",
                masks: "*.*",
                recursive: true,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "Current Session",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile2",
                pattern: "Tabs_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile3",
                pattern: "Session_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile4",
                pattern: "*\\Session Storage\\*",
                kind: Kind::Path,
            },
            Handler {
                key: "OnFile5",
                pattern: "*\\Extension State\\*",
                kind: Kind::Path,
            },
        ],
    },
    Rule {
        browser: Browser::Opera,
        id: "opera.session",
        scopes: &[
            Scope {
                directory: "",
                masks: "session.db;session.dbak",
                recursive: false,
            },
            Scope {
                directory: "",
                masks: "Current Session;Last Session",
                recursive: false,
            },
            Scope {
                directory: "Session Storage",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Extension State",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Sessions",
                masks: "*.*",
                recursive: true,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "autosave.*",
                kind: Kind::File,
            },
            Handler {
                key: "OnFile2",
                pattern: "session.*",
                kind: Kind::File,
            },
            Handler {
                key: "OnFile3",
                pattern: "Current Session",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile4",
                pattern: "Tabs_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile5",
                pattern: "Session_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile6",
                pattern: "*\\Session Storage\\*",
                kind: Kind::Path,
            },
            Handler {
                key: "OnFile7",
                pattern: "*\\Extension State\\*",
                kind: Kind::Path,
            },
        ],
    },
    Rule {
        browser: Browser::Chrome,
        id: "google-chrome.session",
        scopes: &[
            Scope {
                directory: "",
                masks: "Current Session;Last Session",
                recursive: false,
            },
            Scope {
                directory: "Session Storage",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Extension State",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Sessions",
                masks: "*.*",
                recursive: true,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "Current Session",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile2",
                pattern: "Tabs_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile3",
                pattern: "Session_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile4",
                pattern: "*\\Session Storage\\*",
                kind: Kind::Path,
            },
            Handler {
                key: "OnFile5",
                pattern: "*\\Extension State\\*",
                kind: Kind::Path,
            },
        ],
    },
    Rule {
        browser: Browser::Vivaldi,
        id: "vivaldi.session",
        scopes: &[
            Scope {
                directory: "",
                masks: "Current Session;Last Session",
                recursive: false,
            },
            Scope {
                directory: "Session Storage",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Extension State",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Sessions",
                masks: "*.*",
                recursive: true,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "Current Session",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile2",
                pattern: "Tabs_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile3",
                pattern: "Session_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile4",
                pattern: "*\\Session Storage\\*",
                kind: Kind::Path,
            },
            Handler {
                key: "OnFile5",
                pattern: "*\\Extension State\\*",
                kind: Kind::Path,
            },
        ],
    },
    Rule {
        browser: Browser::Brave,
        id: "brave.session",
        scopes: &[
            Scope {
                directory: "",
                masks: "Current Session;Last Session",
                recursive: false,
            },
            Scope {
                directory: "Session Storage",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Extension State",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Sessions",
                masks: "*.*",
                recursive: true,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "Current Session",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile2",
                pattern: "Tabs_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile3",
                pattern: "Session_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile4",
                pattern: "*\\Session Storage\\*",
                kind: Kind::Path,
            },
            Handler {
                key: "OnFile5",
                pattern: "*\\Extension State\\*",
                kind: Kind::Path,
            },
        ],
    },
    Rule {
        browser: Browser::OperaGx,
        id: "operagx.session",
        scopes: &[
            Scope {
                directory: "",
                masks: "Current Session;Last Session",
                recursive: false,
            },
            Scope {
                directory: "Session Storage",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Extension State",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Sessions",
                masks: "*.*",
                recursive: true,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "Current Session",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile2",
                pattern: "Tabs_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile3",
                pattern: "Session_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile4",
                pattern: "*\\Session Storage\\*",
                kind: Kind::Path,
            },
            Handler {
                key: "OnFile5",
                pattern: "*\\Extension State\\*",
                kind: Kind::Path,
            },
        ],
    },
    Rule {
        browser: Browser::Norton,
        id: "nortonprivatebrowser.session",
        scopes: &[
            Scope {
                directory: "",
                masks: "Current Session;Last Session",
                recursive: false,
            },
            Scope {
                directory: "Session Storage",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Extension State",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Sessions",
                masks: "*.*",
                recursive: true,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "Current Session",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile2",
                pattern: "Tabs_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile3",
                pattern: "Session_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile4",
                pattern: "*\\Session Storage\\*",
                kind: Kind::Path,
            },
            Handler {
                key: "OnFile5",
                pattern: "*\\Extension State\\*",
                kind: Kind::Path,
            },
        ],
    },
    Rule {
        browser: Browser::Avira,
        id: "avirasecurebrowser.session",
        scopes: &[
            Scope {
                directory: "",
                masks: "Current Session;Last Session",
                recursive: false,
            },
            Scope {
                directory: "Session Storage",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Extension State",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Sessions",
                masks: "*.*",
                recursive: true,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "Current Session",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile2",
                pattern: "Tabs_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile3",
                pattern: "Session_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile4",
                pattern: "*\\Session Storage\\*",
                kind: Kind::Path,
            },
            Handler {
                key: "OnFile5",
                pattern: "*\\Extension State\\*",
                kind: Kind::Path,
            },
        ],
    },
    Rule {
        browser: Browser::Arc,
        id: "arc.session",
        scopes: &[
            Scope {
                directory: "",
                masks: "Current Session;Last Session",
                recursive: false,
            },
            Scope {
                directory: "Session Storage",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Extension State",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Sessions",
                masks: "*.*",
                recursive: true,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "Current Session",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile2",
                pattern: "Tabs_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile3",
                pattern: "Session_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile4",
                pattern: "*\\Session Storage\\*",
                kind: Kind::Path,
            },
            Handler {
                key: "OnFile5",
                pattern: "*\\Extension State\\*",
                kind: Kind::Path,
            },
        ],
    },
    Rule {
        browser: Browser::Neo,
        id: "neobrowser.session",
        scopes: &[
            Scope {
                directory: "",
                masks: "Current Session;Last Session",
                recursive: false,
            },
            Scope {
                directory: "Session Storage",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Extension State",
                masks: "*.*",
                recursive: true,
            },
            Scope {
                directory: "Sessions",
                masks: "*.*",
                recursive: true,
            },
        ],
        handlers: &[
            Handler {
                key: "OnFile1",
                pattern: "Current Session",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile2",
                pattern: "Tabs_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile3",
                pattern: "Session_*",
                kind: Kind::Session,
            },
            Handler {
                key: "OnFile4",
                pattern: "*\\Session Storage\\*",
                kind: Kind::Path,
            },
            Handler {
                key: "OnFile5",
                pattern: "*\\Extension State\\*",
                kind: Kind::Path,
            },
        ],
    },
];
