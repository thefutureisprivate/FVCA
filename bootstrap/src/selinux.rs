use std::fs;
use std::io::{self, Read, Write};

pub fn require_enforcing_domain(context: &str) -> io::Result<()> {
    const AVD_FLAGS_PERMISSIVE: u32 = 1;
    let class = fs::read_to_string("/sys/fs/selinux/class/process/index")?;
    let request = format!("{context} system_u:system_r:init_t:s0 {}", class.trim_end());
    // selinuxfs returns the decision and its flags on the same descriptor.
    let mut access = fs::OpenOptions::new().read(true).write(true).open("/sys/fs/selinux/access")?;
    access.write_all(request.as_bytes())?;
    let mut response = String::new();
    access.read_to_string(&mut response)?;
    let flags = response.split_ascii_whitespace().nth(5)
        .and_then(|field| u32::from_str_radix(field, 16).ok())
        .ok_or_else(|| io::Error::other("missing SELinux access decision flags"))?;
    if flags & AVD_FLAGS_PERMISSIVE != 0 {
        return Err(io::Error::other(format!("SELinux domain {context} is permissive")));
    }
    Ok(())
}
