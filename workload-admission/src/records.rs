use serde::Deserialize;
use serde::de::IgnoredAny;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub guest: String,
    pub service: String,
    pub source_policy: String,
    pub minimum_epoch: u64,
    pub revoked: Vec<String>,
    pub unsigned_permit_authority: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    ServiceGuest,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Provenance {
    PublisherVerified,
    UnsignedUpstreamApproved,
}

impl Provenance {
    pub fn label(self) -> &'static str {
        match self {
            Self::PublisherVerified => "PUBLISHER_VERIFIED",
            Self::UnsignedUpstreamApproved => "UNSIGNED_UPSTREAM_APPROVED",
        }
    }
}

#[derive(Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    None,
    Workload(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub memory_bytes: u64,
    pub cpu_percent: u16,
    pub pids: u16,
    pub read_bytes_per_second: u32,
    pub write_bytes_per_second: u32,
}

#[derive(Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IdMap {
    pub uid_base: u32,
    pub gid_base: u32,
    pub size: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    #[serde(rename = "role")]
    _role: Role,
    pub network: Network,
    pub schema: String,
    pub guest: String,
    pub service: String,
    pub source_index: String,
    pub manifest: String,
    pub launch: String,
    pub provenance: Provenance,
    pub valid_from: u64,
    pub expires: u64,
    pub security_epoch: u64,
    pub revocation_id: String,
    pub limits: Limits,
    pub id_map: IdMap,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Blob {
    pub digest: String,
    pub size: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub schema: String,
    pub deployment: String,
    pub deployment_certificate: String,
    pub workload_certificate: String,
    pub derivation: String,
    pub source_evidence: String,
    pub artifact: Blob,
    pub verity_root_hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Healthcheck {
    #[serde(rename = "Test")]
    pub test: Vec<String>,
    #[serde(rename = "Interval")]
    pub interval: Option<u64>,
    #[serde(rename = "Timeout")]
    pub timeout: Option<u64>,
    #[serde(rename = "StartPeriod")]
    pub start_period: Option<u64>,
    #[serde(rename = "StartInterval")]
    pub start_interval: Option<u64>,
    #[serde(rename = "Retries")]
    pub retries: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Launch {
    pub entrypoint: Vec<String>,
    pub command: Vec<String>,
    pub environment: Vec<String>,
    pub working_directory: String,
    pub image_user: String,
    pub uid: u16,
    pub gid: u16,
    pub stop_signal: String,
    pub healthcheck: Option<Healthcheck>,
    pub volumes: Vec<String>,
}

#[derive(Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Platform {
    pub os: String,
    pub architecture: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub index: String,
    pub repository: String,
    pub certificate_identity: Option<String>,
    pub certificate_issuer: Option<String>,
    pub permit_authority: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub digest: String,
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub size: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Derivation {
    pub schema: String,
    pub service: String,
    pub source_policy: String,
    pub provenance: Provenance,
    pub permit: Option<String>,
    pub worker_image: String,
    pub source: Source,
    pub platform: Platform,
    pub manifest: Descriptor,
    pub launch: String,
    pub root: Blob,
    pub verity_tree: Blob,
    pub verity_root_hash: String,
    // These remain signed audit evidence. The Guest does not re-run the conversion.
    #[serde(rename = "config")]
    _config: IgnoredAny,
    #[serde(rename = "layers")]
    _layers: IgnoredAny,
    #[serde(rename = "converter")]
    _converter: IgnoredAny,
    #[serde(rename = "transforms")]
    _transforms: IgnoredAny,
}
