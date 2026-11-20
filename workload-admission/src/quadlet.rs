//! Translate the authenticated launch record into a constrained Quadlet.

use std::fmt::Write;
use std::net::Ipv4Addr;

use openssl::sha::sha256;

use crate::{Result, VerifiedWorkload, digest, invalid};

pub const ROOT: &str = "/run/fvca/workload-image/root";
pub const PAYLOAD: &str = "/run/fvca/guest-data/payload";
pub const SERVICE: &str = "fvca-workload-payload.service";
pub const CONTAINER: &str = "fvca-workload-payload";
pub const NAMESPACE: &str = "/run/netns/fvca-workload";

pub struct Volume {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
}

pub struct Definition {
    pub source: String,
    pub volumes: Vec<Volume>,
}

// Quadlet parses the source once and PID 1 parses the generated ExecStart. Escape
// systemd expansions separately from quoting Quadlet's whitespace-delimited words.
fn literal(value: &str) -> String {
    value.replace('%', "%%").replace('$', "$$")
}

fn word(value: &str) -> Result<String> {
    if value.chars().any(char::is_control) {
        return Err(invalid(
            "workload launch values must not contain control characters",
        ));
    }
    Ok(format!(
        "\"{}\"",
        literal(value).replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

fn volume_path(path: &str) -> bool {
    path.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"/_-.".contains(&byte))
}

fn entrypoint(entry: &[String], command: &[String]) -> Result<String> {
    // Podman receives the complete OCI argv as one JSON option. Quadlet's Exec
    // word list can drop empty arguments and emit systemd command separators.
    let argv: Vec<_> = entry.iter().chain(command).collect();
    Ok(literal(&serde_json::to_string(&argv)?))
}

pub fn render(workload: &VerifiedWorkload, dns: Option<Ipv4Addr>) -> Result<Definition> {
    let application = workload.launch();
    let map = workload.id_map();
    let limits = workload.limits();
    let expires = workload.expires();
    let profile = workload.network_profile().unwrap_or("none");
    let network = if workload.network_profile().is_some() {
        let dns = dns.map_or_else(
            || "none\n".into(),
            |address| format!("{address}\nDNSSearch=.\n"),
        );
        format!("Network=ns:{NAMESPACE}\nDNS={dns}")
    } else {
        "Network=none\n".into()
    };
    let payload = format!("{PAYLOAD}/{}", workload.service());
    let entrypoint = entrypoint(&application.entrypoint, &application.command)?;
    let mut source = format!(
        "[Quadlet]\nDefaultDependencies=false\n\n\
         [Unit]\nBindsTo=fvca-workload-root.service\nAfter=fvca-workload-root.service\n\
         StartLimitIntervalSec=60s\nStartLimitBurst=3\n\n\
         [Container]\nContainerName={CONTAINER}\nRootfs={ROOT}\n\
         {network}Pull=never\nReadOnly=true\nNoNewPrivileges=true\nDropCapability=all\n\
         RunInit=true\nPodmanArgs=--init-path=/usr/libexec/catatonit/catatonit\n\
         LogDriver=k8s-file\nLogOpt=max-size=1mb\nUser={}\nGroup={}\nUIDMap=0:{}:{}\nGIDMap=0:{}:{}\n\
         PidsLimit={}\nStopSignal={}\nStopTimeout=20\nWorkingDir={}\n",
        application.uid,
        application.gid,
        map.uid_base,
        map.size,
        map.gid_base,
        map.size,
        limits.pids,
        application.stop_signal,
        word(&application.working_directory)?,
    );
    writeln!(source, "Entrypoint={entrypoint}")?;
    for setting in &application.environment {
        writeln!(source, "Environment={}", word(setting)?)?;
    }

    let mut volumes = Vec::new();
    for target in &application.volumes {
        if !volume_path(target) {
            return Err(invalid(
                "workload volume path cannot be represented safely in Quadlet",
            ));
        }
        let name = digest(&sha256(target.as_bytes())).split_off(7);
        writeln!(
            source,
            "Volume={payload}/{name}:{target}:rw,nodev,nosuid,noexec,Z"
        )?;
        volumes.push(Volume {
            name,
            uid: map.uid_base + u32::from(application.uid),
            gid: map.gid_base + u32::from(application.gid),
        });
    }

    if let Some(health) = &application.healthcheck {
        if health.test[0] == "NONE" {
            source.push_str("HealthCmd=none\n");
        } else {
            writeln!(
                source,
                "HealthCmd={}",
                literal(&serde_json::to_string(&health.test)?)
            )?;
            for (key, value) in [
                ("HealthInterval", health.interval),
                ("HealthTimeout", health.timeout),
                ("HealthStartPeriod", health.start_period),
                ("HealthStartInterval", health.start_interval),
            ] {
                if let Some(value) = value.filter(|value| *value != 0) {
                    writeln!(source, "{key}={value}ns")?;
                }
            }
            if let Some(retries) = health.retries.filter(|retries| *retries != 0) {
                writeln!(source, "HealthRetries={retries}")?;
            }
            source.push_str("Notify=healthy\nHealthMaxLogCount=5\nHealthMaxLogSize=512\n");
        }
    }
    writeln!(
        source,
        "\n[Service]\nExecCondition=/usr/lib/fvca/activate-workload check-start {expires} {profile}\n\
         NoNewPrivileges=yes\nMemoryDenyWriteExecute=yes\nSystemCallArchitectures=native\n\
         MemoryMax={}\nMemorySwapMax=0\nCPUQuota={}%\nTasksMax={}\n\
         LogRateLimitIntervalSec=30s\nLogRateLimitBurst=500\n\
         TimeoutStartSec=100s\nTimeoutStopSec=30s\nRestart=on-failure\nRestartSec=5s",
        limits.memory_bytes, limits.cpu_percent, limits.pids,
    )?;
    Ok(Definition { source, volumes })
}

#[cfg(test)]
mod tests {
    use super::{entrypoint, word};

    #[test]
    fn quotes_arguments_and_preserves_literal_expansions() {
        assert_eq!(
            word(r#"a \"quote\" $HOME %n"#).unwrap(),
            r#""a \\\"quote\\\" $$HOME %%n""#,
        );
        assert!(word("value\n[Service]\nExecStart=/usr/bin/false").is_err());
    }

    #[test]
    fn combines_oci_argv_in_one_json_option() {
        assert_eq!(
            entrypoint(
                &["/usr/bin/workload".to_owned()],
                &["".to_owned(), ";".to_owned()]
            )
            .unwrap(),
            r#"["/usr/bin/workload","",";"]"#,
        );
    }
}
