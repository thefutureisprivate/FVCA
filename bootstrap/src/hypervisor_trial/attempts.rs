//! Durable reservations for the EFI one-shot boot.

use std::io;
use std::path::{Path, PathBuf};

use super::{publish, read_record};
use crate::invalid;

pub(super) const LIMIT: u8 = 3;

#[derive(Clone, Copy)]
pub(super) struct Attempt(pub(super) u8);

impl Attempt {
    pub(super) fn path(self, directory: &Path, tx: &str, suffix: &str) -> PathBuf {
        directory.join(format!("{tx}.attempt-{}{suffix}", self.0))
    }

    pub(super) fn mark(self, directory: &Path, tx: &str, suffix: &str) -> io::Result<()> {
        publish(&self.path(directory, tx, suffix), b"")
    }

    pub(super) fn marked(self, directory: &Path, tx: &str, suffix: &str) -> io::Result<bool> {
        match read_record(&self.path(directory, tx, suffix)) {
            Ok(raw) if raw.is_empty() => Ok(true),
            Ok(_) => Err(invalid("invalid durable trial attempt marker")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(super) fn require_armed(self, directory: &Path, tx: &str) -> io::Result<()> {
        if self.0 == 0 || !self.marked(directory, tx, ".armed")? {
            return Err(invalid(
                "candidate trial has no verified firmware arming record",
            ));
        }
        Ok(())
    }
}

pub(super) fn last(directory: &Path, tx: &str) -> io::Result<Attempt> {
    let mut last = Attempt(0);
    for number in 1..=LIMIT {
        let attempt = Attempt(number);
        if attempt.marked(directory, tx, "")? {
            if last.0 + 1 != number {
                return Err(invalid("nonconsecutive durable trial attempt reservations"));
            }
            last = attempt;
        }
    }
    Ok(last)
}
