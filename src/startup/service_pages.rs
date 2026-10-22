//! Retain records returned with ERROR_MORE_DATA before following its resume
//! cursor. bytes_needed describes remaining entries, not a replacement page.
use std::collections::HashSet;

pub(super) const MAX_BUFFER_BYTES: usize = 256 * 1024;

pub(super) struct Page {
    pub entries: Vec<(String, String)>,
    pub resume: u32,
    pub more_data: bool,
    pub bytes_needed: usize,
}

pub(super) fn collect(
    initial_bytes: usize,
    limit: usize,
    mut read: impl FnMut(usize, u32) -> Result<Page, String>,
) -> Result<(Vec<(String, String)>, bool), String> {
    let mut capacity = initial_bytes.clamp(1024, MAX_BUFFER_BYTES);
    let mut cursor = 0;
    let mut seen = HashSet::from([0]);
    let mut entries = Vec::new();
    loop {
        let page = read(capacity, cursor)?;
        let returned = page.entries.len();
        let available = limit.saturating_sub(entries.len());
        // A partial native page is still valid positive inventory evidence.
        entries.extend(page.entries.into_iter().take(available));
        if returned > available {
            return Ok((entries, true));
        }
        if !page.more_data {
            if page.resume != 0 {
                return Err("Service enumeration returned an invalid completion cursor.".into());
            }
            return Ok((entries, false));
        }
        if entries.len() == limit {
            return Ok((entries, true));
        }
        if returned > 0 && page.resume != 0 && seen.insert(page.resume) {
            cursor = page.resume;
            continue;
        }
        // No record fits yet. Grow only at the same cursor, within the native
        // API's 256 KiB limit; never restart at zero and drop an earlier page.
        if returned == 0
            && page.resume == cursor
            && capacity < MAX_BUFFER_BYTES
            && page.bytes_needed > capacity
        {
            capacity = page.bytes_needed.max(capacity * 2).min(MAX_BUFFER_BYTES);
            continue;
        }
        return Ok((entries, true));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn page(names: &[&str], resume: u32, more_data: bool, bytes_needed: usize) -> Page {
        Page {
            entries: names
                .iter()
                .map(|name| (name.to_string(), name.to_string()))
                .collect(),
            resume,
            more_data,
            bytes_needed,
        }
    }
    fn names(rows: &[(String, String)]) -> Vec<&str> {
        rows.iter().map(|row| row.0.as_str()).collect()
    }

    #[test]
    fn partial_records_survive_both_larger_and_smaller_remaining_byte_counts() {
        for needed in [1024, 128 * 1024] {
            let mut calls = 0;
            let (rows, truncated) = collect(64 * 1024, 10, |capacity, cursor| {
                assert_eq!(capacity, 64 * 1024);
                calls += 1;
                Ok(match cursor {
                    0 => page(&["Alpha", "Beta"], 17, true, needed),
                    17 => page(&["Gamma"], 0, false, 0),
                    _ => panic!("unexpected resume"),
                })
            })
            .unwrap();
            assert_eq!(names(&rows), ["Alpha", "Beta", "Gamma"]);
            assert!(!truncated);
            assert_eq!(calls, 2);
        }
    }

    #[test]
    fn an_empty_page_grows_at_its_existing_cursor_within_the_native_cap() {
        let mut calls = 0;
        let (rows, truncated) = collect(1024, 10, |capacity, cursor| {
            calls += 1;
            Ok(match calls {
                1 => page(&["Alpha"], 9, true, 0),
                2 => {
                    assert_eq!((capacity, cursor), (1024, 9));
                    page(&[], 9, true, usize::MAX)
                }
                3 => {
                    assert_eq!((capacity, cursor), (MAX_BUFFER_BYTES, 9));
                    page(&["Beta"], 0, false, 0)
                }
                _ => panic!("unbounded retries"),
            })
        })
        .unwrap();
        assert_eq!(names(&rows), ["Alpha", "Beta"]);
        assert!(!truncated);
    }

    #[test]
    fn item_limit_distinguishes_exact_completion_from_more_or_excess_data() {
        for (count, more, expected_truncated) in
            [(2, false, false), (2, true, true), (3, false, true)]
        {
            let all = ["Alpha", "Beta", "Gamma"];
            let (rows, truncated) = collect(1024, 2, |_, _| {
                Ok(page(&all[..count], if more { 1 } else { 0 }, more, 0))
            })
            .unwrap();
            assert_eq!(names(&rows), ["Alpha", "Beta"]);
            assert_eq!(truncated, expected_truncated);
        }
    }

    #[test]
    fn stalled_or_repeated_cursors_and_oversized_empty_pages_are_partial() {
        for mode in 0..3 {
            let mut calls = 0;
            let (rows, truncated) = collect(MAX_BUFFER_BYTES, 10, |_, cursor| {
                calls += 1;
                assert!(calls <= 3, "pagination must stop without progress");
                Ok(match (mode, calls) {
                    (0, _) => page(&[], cursor, true, usize::MAX),
                    (1, _) => page(&["Alpha"], cursor, true, 0),
                    (2, 1) => page(&["Alpha"], 1, true, 0),
                    (2, 2) => page(&["Beta"], 2, true, 0),
                    (2, _) => page(&["Gamma"], 1, true, 0),
                    _ => unreachable!(),
                })
            })
            .unwrap();
            assert!(truncated);
            assert!(rows.len() <= 3);
        }
    }

    #[test]
    fn incremental_size_hints_cannot_cause_unbounded_growth_retries() {
        let mut calls = 0;
        let (rows, truncated) = collect(1024, 10, |capacity, cursor| {
            calls += 1;
            assert!(calls <= 9, "growth must be exponential and bounded");
            Ok(page(&[], cursor, true, capacity + 1))
        })
        .unwrap();
        assert!(rows.is_empty() && truncated);
        assert_eq!(calls, 9);
    }

    #[test]
    fn native_failures_and_invalid_completion_never_become_complete_inventory() {
        let mut calls = 0;
        let error = collect(1024, 10, |_, _| {
            calls += 1;
            if calls == 1 {
                Ok(page(&["Alpha"], 1, true, 0))
            } else {
                Err("read denied".into())
            }
        })
        .unwrap_err();
        assert_eq!(error, "read denied");
        assert!(collect(1024, 10, |_, _| Ok(page(&["Alpha"], 9, false, 0))).is_err());
    }
}
