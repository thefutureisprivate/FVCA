use std::collections::BTreeSet;

use crate::records::{Healthcheck, Launch};
use crate::{Result, invalid};

fn text(value: &str) -> bool {
    value.len() <= 4096 && !value.bytes().any(|byte| byte == 0)
}

fn arguments(values: &[String]) -> bool {
    values.len() <= 256 && values.iter().all(|value| text(value))
}

fn absolute_path(value: &str) -> bool {
    text(value)
        && (value == "/"
            || value.strip_prefix('/').is_some_and(|path| {
                path.split('/')
                    .all(|component| !matches!(component, "" | "." | ".."))
            }))
}

fn beneath(path: &str, directory: &str) -> bool {
    path == directory
        || path
            .strip_prefix(directory)
            .is_some_and(|remainder| remainder.starts_with('/'))
}

fn environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn signal(value: &str) -> bool {
    value.strip_prefix("SIG").is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    }) || (value
        .as_bytes()
        .first()
        .is_some_and(|byte| (b'1'..=b'9').contains(byte))
        && value.len() <= 2
        && value.bytes().all(|byte| byte.is_ascii_digit()))
}

impl Healthcheck {
    fn valid(&self) -> bool {
        let valid_test = match self.test.split_first() {
            Some((name, args)) if name == "NONE" => args.is_empty(),
            Some((name, args)) if name == "CMD" => !args.is_empty() && !args[0].is_empty(),
            Some((name, args)) if name == "CMD-SHELL" => args.len() == 1 && !args[0].is_empty(),
            _ => false,
        };
        valid_test
            && arguments(&self.test)
            && [
                self.interval,
                self.timeout,
                self.start_period,
                self.start_interval,
            ]
            .into_iter()
            .flatten()
            .all(|value| value <= 86_400_000_000_000)
    }
}

impl Launch {
    pub(crate) fn validate(&self) -> Result<()> {
        let executable = self
            .entrypoint
            .first()
            .or_else(|| self.command.first())
            .filter(|path| *path != "/" && absolute_path(path))
            .ok_or_else(|| invalid("workload launch requires an absolute container executable"))?;
        if !arguments(&self.entrypoint)
            || !arguments(&self.command)
            || !arguments(&self.environment)
            || !text(&self.image_user)
            || !absolute_path(&self.working_directory)
            || !signal(&self.stop_signal)
            || self
                .healthcheck
                .as_ref()
                .is_some_and(|health| !health.valid())
        {
            return Err(invalid(
                "workload launch arguments, signal, or healthcheck are invalid",
            ));
        }
        let mut environment = BTreeSet::new();
        if !self.environment.iter().all(|setting| {
            setting
                .split_once('=')
                .is_some_and(|(name, _)| environment_name(name) && environment.insert(name))
        }) {
            return Err(invalid(
                "workload environment contains invalid or repeated names",
            ));
        }
        if !arguments(&self.volumes)
            || !self.volumes.is_sorted()
            || self.volumes.iter().any(|volume| {
                volume == "/"
                    || !absolute_path(volume)
                    || beneath(executable, volume)
                    || ["/dev", "/proc", "/sys", "/run"]
                        .iter()
                        .any(|path| beneath(volume, path))
            })
            || self.volumes.iter().enumerate().any(|(index, volume)| {
                self.volumes[..index]
                    .iter()
                    .any(|parent| beneath(volume, parent))
            })
        {
            return Err(invalid(
                "workload volume obscures protected container paths or overlaps another volume",
            ));
        }
        Ok(())
    }
}
