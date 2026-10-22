use super::*;
use rusqlite::OpenFlags;
use std::{collections::BTreeSet, fs};

fn cancel() -> AtomicBool {
    AtomicBool::new(false)
}
fn forms() -> Key {
    keys(Browser::Chrome, Scope::SavedForms)[0]
}
fn limit(conn: &Connection, kind: i32) -> i32 {
    unsafe { ffi::sqlite3_limit(conn.handle(), kind, -1) }
}

#[test]
fn declared_catalogue_preserves_every_native_table_order_and_missing_default() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/generic-sqlite-tables.json"
    ))
    .unwrap();
    let expected = fixture["rules"].as_array().unwrap();
    assert_eq!(expected.len(), 30);
    assert_eq!(catalogue::RULES.len(), expected.len());
    let mut tables = BTreeSet::new();
    let (mut bindings, mut missing) = (0, 0);
    for (index, (rule, row)) in catalogue::RULES.iter().zip(expected).enumerate() {
        assert_eq!(format!("{:?}", rule.browser), row["browser"]);
        assert_eq!(format!("{:?}", rule.scope), row["scope"]);
        assert_eq!(rule.id, row["rule"]);
        assert_eq!(rule.handler, row["handler"]);
        assert_eq!(rule.database, row["database"]);
        assert_eq!(serde_json::json!(rule.tables), row["tables"]);
        assert_eq!(
            rule.native_default,
            if row["native_default"].is_null() {
                None
            } else {
                Some(false)
            }
        );
        missing += usize::from(rule.native_default.is_none());
        for (table, name) in rule.tables.iter().enumerate() {
            tables.insert(*name);
            bindings += 1;
            let key = lookup(rule.browser, rule.id, name).unwrap();
            assert_eq!(
                key,
                Key {
                    rule: index as u8,
                    table: table as u8
                }
            );
            assert_eq!(key.native_rule().unwrap(), rule.id);
            assert!(keys(rule.browser, rule.scope).contains(&key));
        }
    }
    assert_eq!((tables.len(), bindings, missing), (25, 292, 4));
}

#[test]
fn every_declared_group_counts_rows_without_reading_saved_values() {
    let cancelled = cancel();
    for (index, rule) in catalogue::RULES.iter().enumerate() {
        let mut conn = Connection::open_in_memory().unwrap();
        for table in rule.tables {
            conn.execute_batch(&format!("CREATE TABLE \"{table}\"(secret BLOB); INSERT INTO \"{table}\" VALUES(zeroblob(8)),(NULL),(zeroblob(8));")).unwrap();
        }
        conn.execute_batch(
            "CREATE TABLE unrelated(keep TEXT); INSERT INTO unrelated VALUES('keep');",
        )
        .unwrap();
        {
            let mut reader = Reader::new(&mut conn, &cancelled).unwrap();
            for (table, name) in rule.tables.iter().enumerate() {
                let observation = reader
                    .read(Key {
                        rule: index as u8,
                        table: table as u8,
                    })
                    .unwrap()
                    .unwrap();
                assert_eq!(observation.rows, 3);
                assert_eq!(
                    observation.group_label().unwrap(),
                    format!("{}: {name}", rule.database)
                );
            }
        }
        assert!(conn.is_autocommit());
        assert_eq!(
            conn.query_row("SELECT keep FROM unrelated", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "keep"
        );
        assert_eq!(conn.total_changes(), (rule.tables.len() * 3 + 1) as u64);
    }
}

#[test]
fn exact_case_missing_empty_and_view_gates_match_native_table_existence() {
    let cancelled = cancel();
    for schema in [
        "",
        "CREATE TABLE autofill(x);",
        "CREATE TABLE AUTOFILL(x); INSERT INTO AUTOFILL VALUES(1);",
        "CREATE VIEW autofill AS SELECT * FROM missing;",
    ] {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(schema).unwrap();
        assert!(
            Reader::new(&mut conn, &cancelled)
                .unwrap()
                .read(forms())
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn table_named_like_trigger_is_still_counted_and_virtual_tables_are_explicit() {
    let cancelled = cancel();
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE host(x); CREATE TRIGGER autofill AFTER INSERT ON host BEGIN SELECT 1; END; CREATE TABLE autofill(x); INSERT INTO autofill VALUES(1);").unwrap();
    assert_eq!(
        Reader::new(&mut conn, &cancelled)
            .unwrap()
            .read(forms())
            .unwrap()
            .unwrap()
            .rows,
        1
    );
    let mut virtual_db = Connection::open_in_memory().unwrap();
    virtual_db.execute_batch("CREATE VIRTUAL TABLE autofill USING fts5(value); INSERT INTO autofill VALUES('owned');").unwrap();
    assert!(
        Reader::new(&mut virtual_db, &cancelled)
            .unwrap()
            .read(forms())
            .unwrap_err()
            .contains("Virtual or shadow")
    );
}

#[test]
fn without_rowid_strict_duplicate_and_shadowed_rowid_tables_need_no_row_locator() {
    let cancelled = cancel();
    for schema in [
        "CREATE TABLE autofill(a TEXT,b INTEGER,PRIMARY KEY(a,b)) WITHOUT ROWID; INSERT INTO autofill VALUES('same',1),('same',2);",
        "CREATE TABLE autofill(rowid TEXT,_rowid_ TEXT,oid TEXT); INSERT INTO autofill VALUES('same','same','same'),('same','same','same');",
        "CREATE TABLE autofill(a TEXT) STRICT; INSERT INTO autofill VALUES('same'),('same');",
    ] {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(schema).unwrap();
        assert_eq!(
            Reader::new(&mut conn, &cancelled)
                .unwrap()
                .read(forms())
                .unwrap()
                .unwrap()
                .rows,
            2
        );
    }
}

#[test]
fn payload_larger_than_reader_value_limit_is_never_fetched() {
    let cancelled = cancel();
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE autofill(secret BLOB); INSERT INTO autofill VALUES(zeroblob(3145728));",
    )
    .unwrap();
    let previous = limit(&conn, ffi::SQLITE_LIMIT_LENGTH);
    assert_eq!(
        Reader::new(&mut conn, &cancelled)
            .unwrap()
            .read(forms())
            .unwrap()
            .unwrap()
            .rows,
        1
    );
    assert_eq!(limit(&conn, ffi::SQLITE_LIMIT_LENGTH), previous);
}

#[test]
fn wal_reader_holds_one_committed_snapshot_without_checkpointing() {
    let cancelled = cancel();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("Web Data");
    let wal = temp.path().join("Web Data-wal");
    let writer = Connection::open(&path).unwrap();
    writer.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE autofill(secret); INSERT INTO autofill VALUES('first');").unwrap();
    let mut conn = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    conn.execute_batch("PRAGMA query_only=ON").unwrap();
    let first = (fs::read(&path).unwrap(), fs::read(&wal).unwrap());
    {
        let mut reader = Reader::new(&mut conn, &cancelled).unwrap();
        assert_eq!(reader.read(forms()).unwrap().unwrap().rows, 1);
        assert_eq!((fs::read(&path).unwrap(), fs::read(&wal).unwrap()), first);
        writer
            .execute("INSERT INTO autofill VALUES('second')", [])
            .unwrap();
        let committed = (fs::read(&path).unwrap(), fs::read(&wal).unwrap());
        assert_eq!(reader.read(forms()).unwrap().unwrap().rows, 1);
        assert_eq!(
            (fs::read(&path).unwrap(), fs::read(&wal).unwrap()),
            committed
        );
    }
    let committed = (fs::read(&path).unwrap(), fs::read(&wal).unwrap());
    assert_eq!(
        Reader::new(&mut conn, &cancelled)
            .unwrap()
            .read(forms())
            .unwrap()
            .unwrap()
            .rows,
        2
    );
    assert_eq!(
        (fs::read(&path).unwrap(), fs::read(&wal).unwrap()),
        committed
    );
    assert!(conn.is_autocommit());
}

#[test]
fn undeclared_keys_and_sql_text_cannot_select_a_table() {
    assert!(
        lookup(
            Browser::Chrome,
            "google-chrome.savedforminformation",
            "autofill\"; DELETE FROM unrelated;--"
        )
        .is_none()
    );
    assert!(
        lookup(
            Browser::Firefox,
            "google-chrome.savedforminformation",
            "autofill"
        )
        .is_none()
    );
    let cancelled = cancel();
    let mut conn = Connection::open_in_memory().unwrap();
    let mut reader = Reader::new(&mut conn, &cancelled).unwrap();
    for key in [
        Key {
            rule: 255,
            table: 0,
        },
        Key {
            rule: 0,
            table: 255,
        },
    ] {
        assert!(reader.read(key).is_err());
    }
}

#[test]
fn cancellation_and_table_row_budgets_return_explicit_errors() {
    let cancelled = AtomicBool::new(true);
    let mut conn = Connection::open_in_memory().unwrap();
    assert!(Reader::new(&mut conn, &cancelled).is_err());
    assert!(conn.is_autocommit());
    cancelled.store(false, Ordering::Relaxed);
    conn.execute_batch("CREATE TABLE autofill(x); INSERT INTO autofill VALUES(1),(2);")
        .unwrap();
    {
        let mut reader = Reader::new(&mut conn, &cancelled).unwrap();
        cancelled.store(true, Ordering::Relaxed);
        assert!(reader.read(forms()).unwrap_err().contains("cancelled"));
    }
    cancelled.store(false, Ordering::Relaxed);
    for (bounds, reason) in [
        (
            Bounds {
                tables: 0,
                ..Bounds::default()
            },
            "table observation limit",
        ),
        (
            Bounds {
                rows: 1,
                ..Bounds::default()
            },
            "row-count observation limit",
        ),
    ] {
        assert!(
            Reader::with_bounds(&mut conn, &cancelled, bounds)
                .unwrap()
                .read(forms())
                .unwrap_err()
                .contains(reason)
        );
        assert!(conn.is_autocommit());
    }
}

#[test]
fn schema_budgets_restore_transaction_and_connection_limits_on_error() {
    let cancelled = cancel();
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE autofill(x); CREATE TABLE other(y);")
        .unwrap();
    let original = (
        limit(&conn, ffi::SQLITE_LIMIT_LENGTH),
        limit(&conn, ffi::SQLITE_LIMIT_SQL_LENGTH),
    );
    for bounds in [
        Bounds {
            schema_objects: 1,
            ..Bounds::default()
        },
        Bounds {
            schema_bytes: 1,
            ..Bounds::default()
        },
    ] {
        assert!(Reader::with_bounds(&mut conn, &cancelled, bounds).is_err());
        assert!(conn.is_autocommit());
        assert_eq!(
            (
                limit(&conn, ffi::SQLITE_LIMIT_LENGTH),
                limit(&conn, ffi::SQLITE_LIMIT_SQL_LENGTH)
            ),
            original
        );
    }
    unsafe {
        ffi::sqlite3_limit(conn.handle(), ffi::SQLITE_LIMIT_SQL_LENGTH, 20);
    }
    assert!(Reader::new(&mut conn, &cancelled).is_err());
    assert_eq!(limit(&conn, ffi::SQLITE_LIMIT_SQL_LENGTH), 20);
    assert!(conn.is_autocommit());
}

#[test]
fn schema_identity_does_not_claim_content_identity_or_cleanup_authority() {
    let cancelled = cancel();
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE autofill(secret); INSERT INTO autofill VALUES('before');")
        .unwrap();
    let before = Reader::new(&mut conn, &cancelled)
        .unwrap()
        .read(forms())
        .unwrap()
        .unwrap();
    conn.execute("UPDATE autofill SET secret='after'", [])
        .unwrap();
    let after = Reader::new(&mut conn, &cancelled)
        .unwrap()
        .read(forms())
        .unwrap()
        .unwrap();
    assert_eq!(
        before, after,
        "Schema/count cannot authorize a table-wide effect"
    );
    conn.execute_batch("ALTER TABLE autofill ADD COLUMN another;")
        .unwrap();
    let altered = Reader::new(&mut conn, &cancelled)
        .unwrap()
        .read(forms())
        .unwrap()
        .unwrap();
    assert_ne!(before.schema_signature, altered.schema_signature);
}
