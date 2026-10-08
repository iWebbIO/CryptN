//! IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`) generation for `Date:` headers.

use std::time::{SystemTime, UNIX_EPOCH};

/// Day of week and month names, per the fixed-length tables. `Month` is stored
/// as [day, hour, minute, second, weekday, monthday, month, year] after
/// reduction from the Unix epoch.
const WDAY: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Current time formatted as `Date: <IMF-fixdate>`.
pub fn httpdate_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_httpdate(secs)
}

/// Format a Unix timestamp (seconds) as an IMF-fixdate string.
pub fn format_httpdate(unix_secs: u64) -> String {
    // Civil-from-days algorithm (Howard Hinnant): days since 1970-01-01.
    let days = (unix_secs / 86_400) as i64;
    let rem = unix_secs % 86_400;
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };

    // Weekday: 1970-01-01 was a Thursday (index 0 above).
    let wday = (days.rem_euclid(7)) as usize;

    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        WDAY[wday],
        d,
        MONTHS[(m - 1) as usize],
        year,
        hour,
        minute,
        second
    )
}

/// Parse an IMF-fixdate (or the looser formats browsers send in
/// If-Modified-Since) back to Unix seconds. Returns `None` when unparseable.
pub fn parse_httpdate(s: &str) -> Option<u64> {
    let s = s.trim();
    // Expect: "Sun, 06 Nov 1994 08:49:37 GMT" — split on spaces after the comma part.
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() != 6 {
        return None;
    }
    let day: u32 = parts[1].parse().ok()?;
    let month = MONTHS.iter().position(|m| *m == parts[2])? as u32 + 1;
    let year: i64 = parts[3].parse().ok()?;
    let time: Vec<&str> = parts[4].split(':').collect();
    if time.len() != 3 {
        return None;
    }
    let hour: u64 = time[0].parse().ok()?;
    let minute: u64 = time[1].parse().ok()?;
    let second: u64 = time[2].parse().ok()?;

    // Days-from-civil (inverse of the above).
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + (hour * 3600 + minute * 60 + second) as i64;
    if secs < 0 {
        return None;
    }
    Some(secs as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_reference_date() {
        assert_eq!(
            format_httpdate(784_111_777),
            "Sun, 06 Nov 1994 08:49:37 GMT"
        );
    }

    #[test]
    fn roundtrips() {
        for secs in [0u64, 784_111_777, 1_700_000_000, 1_800_000_000] {
            let s = format_httpdate(secs);
            assert_eq!(parse_httpdate(&s), Some(secs));
        }
    }

    #[test]
    fn epoch_is_thursday() {
        assert_eq!(format_httpdate(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    }
}
