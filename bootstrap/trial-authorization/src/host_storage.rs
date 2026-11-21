//! Public binding to the signed storage enrollment and its physical backing.

use std::io;

use crate::{digest, invalid, signed_argument, uuid};

pub const ARGUMENT: &str = "fvca.host_storage";

#[derive(Debug, PartialEq, Eq)]
pub struct Binding {
    pub digest: String,
    pub partitions: [String; 2],
}

pub fn binding(cmdline: &str) -> io::Result<Option<Binding>> {
    let Some(value) = signed_argument(cmdline, ARGUMENT)? else {
        return Ok(None);
    };
    let mut fields = value.split(',');
    let (Some(policy), Some(first), Some(second), None) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err(invalid("invalid signed Host storage binding"));
    };
    if first == second || [first, second].contains(&"00000000-0000-0000-0000-000000000000") {
        return Err(invalid("Host storage requires two distinct data partition UUIDs"));
    }
    Ok(Some(Binding {
        digest: digest(policy, "")?.into(),
        partitions: [uuid(first)?.into(), uuid(second)?.into()],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_one_canonical_binding_to_distinct_partitions() -> io::Result<()> {
        let digest = "a".repeat(64);
        let a = "641cc360-a531-45f8-ac75-31ccd7eafae1";
        let b = "4acfd676-937a-4f34-93d3-cceba42fb9dc";
        let marker = format!("{ARGUMENT}={digest},{a},{b}");
        assert!(binding("ro enforcing=1")?.is_none());
        let approved = binding(&format!("ro {marker}"))?.unwrap();
        assert_eq!(approved.digest, digest);
        assert_eq!(approved.partitions, [a, b]);
        for unapproved in [
            format!("{marker} {marker}"),
            format!("{ARGUMENT}={digest},{a},{a}"),
            format!("{ARGUMENT}={digest},{a}"),
            format!("{ARGUMENT}={digest},{a},{}", b.to_uppercase()),
            format!("{marker},extra"),
        ] {
            assert!(binding(&unapproved).is_err());
        }
        Ok(())
    }
}
