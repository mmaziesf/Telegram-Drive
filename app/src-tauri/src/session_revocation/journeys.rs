//! Pending-revocation journeys for the native end-to-end suite.
//!
//! They run inside the native e2e driver and are started by
//! `tests/native_e2e.rs`. Each one works in its own directory and reports the
//! first broken expectation instead of panicking. Telegram itself is not
//! contacted: the journeys cover the marker, which sessions are offered and
//! which confirmations are accepted.

use std::path::Path;

use super::*;

/// A journey checks one behavior and reports the first broken expectation.
type Journey = fn(&Path) -> Result<(), String>;

/// Every journey, by the name the native e2e suite uses to start it.
pub(crate) const JOURNEYS: &[(&str, Journey)] = &[
    (
        "unrevoked_sign_out_leaves_a_marker",
        unrevoked_sign_out_leaves_a_marker,
    ),
    (
        "another_account_is_not_offered_the_marker",
        another_account_is_not_offered_the_marker,
    ),
    (
        "only_older_sessions_of_the_same_app_are_offered",
        only_older_sessions_of_the_same_app_are_offered,
    ),
    (
        "only_offered_sessions_can_be_confirmed",
        only_offered_sessions_can_be_confirmed,
    ),
];

/// Runs the journey called `name` in `directory`.
pub(crate) fn run(name: &str, directory: &Path) -> Result<(), String> {
    let journey = JOURNEYS
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, journey)| *journey)
        .ok_or_else(|| format!("unknown session revocation journey: {name}"))?;
    journey(directory)
}

fn expect<T: PartialEq + std::fmt::Debug>(
    what: &str,
    actual: T,
    expected: T,
) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{what}: expected {expected:?}, got {actual:?}"))
    }
}

fn unrevoked_sign_out_leaves_a_marker(directory: &Path) -> Result<(), String> {
    let at = |since, owner| Some(Pending { since, owner });
    expect("no marker at first", pending(directory), None)?;
    after_sign_out(directory, true, true, 100, Some(7));
    expect(
        "a revoked session leaves no marker",
        pending(directory),
        None,
    )?;
    after_sign_out(directory, false, false, 100, Some(7));
    expect(
        "no saved session leaves no marker",
        pending(directory),
        None,
    )?;
    after_sign_out(directory, true, false, 100, None);
    expect(
        "an unrevoked locked session is recorded without an account",
        pending(directory),
        at(100, None),
    )?;
    let stored =
        std::fs::read_to_string(directory.join(MARKER)).map_err(|error| error.to_string())?;
    expect(
        "an unknown account is left out",
        stored.as_str(),
        "{\"since\":100}",
    )?;
    after_sign_out(directory, true, false, 250, Some(7));
    expect(
        "a later sign-out replaces the marker",
        pending(directory),
        at(250, Some(7)),
    )?;
    let stored =
        std::fs::read_to_string(directory.join(MARKER)).map_err(|error| error.to_string())?;
    expect(
        "the marker holds only the time and the account",
        stored.as_str(),
        "{\"since\":250,\"owner\":7}",
    )?;
    clear(directory);
    expect("clearing removes the marker", pending(directory), None)?;
    clear(directory);
    std::fs::write(directory.join(MARKER), b"not json").map_err(|error| error.to_string())?;
    expect("a malformed marker is ignored", pending(directory), None)
}

fn another_account_is_not_offered_the_marker(_: &Path) -> Result<(), String> {
    let known = Pending {
        since: 1,
        owner: Some(7),
    };
    expect("the same account is asked", known.applies_to(7), true)?;
    expect("another account is not", known.applies_to(8), false)?;
    let unknown = Pending {
        since: 1,
        owner: None,
    };
    expect(
        "after a locked session the next account is asked",
        unknown.applies_to(8),
        true,
    )
}

fn authorization(hash: i64, current: bool, api_id: i32, created: i64) -> Authorization {
    Authorization {
        hash,
        current,
        api_id,
        device_model: "Desktop".to_string(),
        platform: " Linux ".to_string(),
        system_version: String::new(),
        app_name: "Telegram Drive".to_string(),
        app_version: "4.1.2".to_string(),
        date_created: created,
        date_active: created + 10,
    }
}

fn sample() -> Vec<Authorization> {
    vec![
        authorization(0, true, 7, 10),
        authorization(11, true, 7, 10),
        authorization(12, false, 7, 10),
        authorization(13, false, 8, 10),
        authorization(14, false, 7, 500),
        authorization(-9_007_199_254_740_993, false, 7, 99),
    ]
}

fn only_older_sessions_of_the_same_app_are_offered(_: &Path) -> Result<(), String> {
    let offered = stale_sessions(&sample(), 7, 100);
    let ids: Vec<&str> = offered.iter().map(|session| session.id.as_str()).collect();
    expect(
        "current, other-app and newer sessions are excluded",
        ids,
        vec!["12", "-9007199254740993"],
    )?;
    expect(
        "labels name the device, app and last activity",
        offered[0].clone(),
        StaleSession {
            id: "12".to_string(),
            device: "Desktop Linux".to_string(),
            app: "Telegram Drive 4.1.2".to_string(),
            last_active: 20,
        },
    )?;
    expect(
        "nothing is offered without a match",
        stale_sessions(&sample(), 9, 100),
        Vec::new(),
    )
}

fn only_offered_sessions_can_be_confirmed(_: &Path) -> Result<(), String> {
    let offered = stale_sessions(&sample(), 7, 100);
    let ids = |values: &[&str]| {
        values
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
    };
    expect(
        "confirmed sessions are ended once each",
        confirmed_hashes(&offered, &ids(&["12", "-9007199254740993", "12"])),
        Ok(vec![12, -9_007_199_254_740_993]),
    )?;
    expect(
        "an empty confirmation is rejected",
        confirmed_hashes(&offered, &[]).is_err(),
        true,
    )?;
    for refused in ["0", "11", "13", "14", "999", "twelve"] {
        expect(
            &format!("{refused} cannot be confirmed"),
            confirmed_hashes(&offered, &ids(&["12", refused])).is_err(),
            true,
        )?;
    }
    Ok(())
}
