use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use fvca_initrd_bootstrap::btrfs::{self, Pool};
use fvca_initrd_bootstrap::{find_partition, identity, invalid, run, sys_block, verify_superblock};

use super::hash;

#[path = "storage_integrity.rs"]
mod integrity;
#[path = "tpm.rs"]
mod tpm;

const POLICY: &str = "/usr/lib/fvca/host-storage";
const MAPPERS: [&str; 2] = ["fvca-host-a", "fvca-host-b"];
const VOLUMES: [&str; 2] = ["/dev/mapper/fvca-host-a", "/dev/mapper/fvca-host-b"];
const DATA: &str = "/run/fvca/host-data";

struct Member<'a> {
    partition: &'a str,
    luks: &'a str,
}

struct Token<'a> {
    index: &'a str,
    digest: &'a str,
}

struct Selection<'a> {
    members: [Member<'a>; 2],
    tokens: Option<[Token<'a>; 2]>,
    filesystem: &'a str,
    authenticated: bool,
}

fn member<'a>(field: &'a str, prefix: &str) -> io::Result<Member<'a>> {
    let (partition, luks) = field.strip_prefix(prefix).and_then(|value| value.split_once(','))
        .ok_or_else(|| invalid("storage member must specify a partition and LUKS2 UUID"))?;
    let uuid = [8, 4, 4, 4, 12];
    Ok(Member {
        partition: identity(partition, "", &uuid, '-')?,
        luks: identity(luks, "", &uuid, '-')?,
    })
}

fn token<'a>(field: &'a str, prefix: &str) -> io::Result<Token<'a>> {
    let (index, digest) = field.strip_prefix(prefix).and_then(|value| value.split_once(','))
        .ok_or_else(|| invalid("missing TPM token authorization"))?;
    let number = index.parse::<u8>().map_err(|_| invalid("invalid TPM token index"))?;
    if number > 31 || number.to_string() != index {
        return Err(invalid("invalid TPM token index"));
    }
    Ok(Token { index, digest: hash(digest)? })
}

fn selection(text: &str) -> io::Result<Selection<'_>> {
    let fields: Vec<_> = text.split('\n').collect();
    let ["FVCA-HOST-STORAGE-4", unlock, protection, a, b, "filesystem=btrfs", filesystem, rest @ ..] =
        fields.as_slice()
    else {
        return Err(invalid("malformed Hypervisor storage selection"));
    };
    let a = member(a, "member_a=")?;
    let b = member(b, "member_b=")?;
    if a.partition == b.partition || a.luks == b.luks {
        return Err(invalid("storage selection must name distinct partitions and LUKS2 volumes"));
    }
    let authenticated = match *protection {
        "protection=development-luks2" => false,
        "protection=luks2-xts-hmac-sha256" => true,
        _ => return Err(invalid("unsupported Host storage protection")),
    };
    let tokens = match (*unlock, rest) {
        ("unlock=development-passphrase", [""]) => None,
        ("unlock=tpm2-pin", [a, b, ""]) => {
            let a = token(a, "token_a=")?;
            let b = token(b, "token_b=")?;
            if a.digest == b.digest {
                return Err(invalid("storage members require separate TPM tokens"));
            }
            Some([a, b])
        }
        _ => return Err(invalid("unsupported storage unlock policy")),
    };
    Ok(Selection {
        members: [a, b],
        tokens,
        filesystem: identity(filesystem, "filesystem_uuid=", &[8, 4, 4, 4, 12], '-')?,
        authenticated,
    })
}

fn find_members(members: &[Member<'_>; 2]) -> io::Result<[PathBuf; 2]> {
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        if let (Some(a), Some(b)) = (find_partition(members[0].partition)?, find_partition(members[1].partition)?) {
            // Distinct partitions on the same drive cannot provide redundancy.
            if parent_device(&a)? == parent_device(&b)? {
                return Err(invalid("mirror members reside on the same disk"));
            }
            for (path, member) in [(&a, &members[0]), (&b, &members[1])] {
                verify_superblock(path, "crypto_LUKS", member.luks, Some("2"))?;
            }
            return Ok([a, b]);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::NotFound, "both authorized storage members are required"));
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn parent_device(path: &Path) -> io::Result<PathBuf> {
    let partition = sys_block(path)?;
    if !partition.join("partition").try_exists()? {
        return Err(invalid("a mirror member must be a partition"));
    }
    partition.parent().map(Path::to_path_buf).ok_or_else(|| invalid("missing parent block device"))
}

fn sole_backing(mapped: &Path) -> io::Result<PathBuf> {
    let mut slaves = fs::read_dir(mapped.join("slaves"))?;
    let backing = slaves.next().transpose()?;
    match backing {
        Some(backing) if slaves.next().transpose()?.is_none() => fs::canonicalize(backing.path()),
        _ => Err(invalid("Host storage mapping requires exactly one backing device")),
    }
}

fn unlock_development(source: &Path, mapper: &str) -> io::Result<()> {
    let status = Command::new("/usr/bin/systemd-cryptsetup").env_clear()
        .env("SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE", "0")
        .args(["attach", mapper]).arg(source)
        .args(["none", "luks,tries=1,timeout=55,password-cache=no"]).status()?;
    if !status.success() {
        return Err(io::Error::other(format!("development passphrase unlock exited with {status}")));
    }
    Ok(())
}

fn open_data(selection: &Selection<'_>, sources: &[PathBuf; 2]) -> io::Result<()> {
    let volumes = VOLUMES.map(Path::new);
    let mut opened = 0;
    let result = (|| {
        for index in 0..2 {
            let source = &sources[index];
            let mapper = MAPPERS[index];
            if let Some(tokens) = &selection.tokens {
                let token = &tokens[index];
                tpm::unlock(source, mapper, selection.members[index].luks, token.index, token.digest)?;
            } else {
                unlock_development(source, mapper)?;
            }
            opened += 1;
            let volume = sys_block(&fs::canonicalize(volumes[index])?)?;
            let partition = sys_block(source)?;
            if selection.authenticated {
                integrity::verify(&volume, &partition)?;
            } else if sole_backing(&volume)? != partition {
                return Err(invalid("LUKS mapping has an unselected backing device"));
            }
        }
        if selection.authenticated {
            println!("FVCA_HOST_STORAGE_AUTHENTICATED");
        }
        btrfs::mount(Pool::Hypervisor(volumes), selection.filesystem, DATA)
    })();
    if result.is_err() {
        for mapper in MAPPERS[..opened].iter().rev() {
            let _ = run(Command::new("/usr/bin/cryptsetup").args(["close", mapper]));
        }
    }
    result
}

pub(super) fn activate_if_selected() -> io::Result<()> {
    let policy = match fs::read_to_string(POLICY) {
        Ok(policy) => policy,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let selection = selection(&policy)?;
    let sources = find_members(&selection.members)?;
    bind_readiness_probe()?;
    open_data(&selection, &sources)?;
    if selection.tokens.is_some() {
        println!("FVCA_HOST_STORAGE_TPM_UNLOCKED");
    }
    println!("FVCA_HOST_STORAGE_ACTIVE");
    Ok(())
}

fn bind_readiness_probe() -> io::Result<()> {
    let drop_in = "/run/systemd/system/fvca-vm-runtime-probe.service.d";
    fs::create_dir_all(drop_in)?;
    fs::write(format!("{drop_in}/10-storage.conf"), concat!(
        "[Service]\n",
        "ExecStartPre=/usr/bin/findmnt --mountpoint /run/fvca/host-data",
        " --types btrfs --options rw,nodev,nosuid,noexec\n",
    ))
}
