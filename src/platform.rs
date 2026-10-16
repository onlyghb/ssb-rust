//! Platform-specific process lifecycle, privileges, and read-only IPv6 probes.
use anyhow::Result;
use std::{path::Path, process::Command};

#[derive(Debug)]
pub struct ProcessInfo {
    pub image: std::path::PathBuf,
    pub identity: String,
    pub args: Vec<String>,
}

#[cfg(unix)]
pub fn detach(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    // Only async-signal-safe libc calls are used between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}
#[cfg(windows)]
pub fn detach(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS};
    cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
}

#[cfg(target_os = "linux")]
pub fn process_info(pid: u32) -> Option<ProcessInfo> {
    let root = format!("/proc/{pid}");
    let stat = std::fs::read_to_string(format!("{root}/stat")).ok()?;
    let fields: Vec<_> = stat.rsplit_once(") ")?.1.split_whitespace().collect();
    if matches!(*fields.first()?, "Z" | "X") {
        return None;
    }
    let image = std::fs::read_link(format!("{root}/exe")).ok()?;
    let bytes = std::fs::read(format!("{root}/cmdline")).ok()?;
    let args = bytes
        .split(|b| *b == 0)
        .filter(|b| !b.is_empty())
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .collect();
    Some(ProcessInfo {
        image,
        identity: fields.get(19)?.to_string(),
        args,
    })
}

#[cfg(all(unix, not(target_os = "linux")))]
pub fn process_info(pid: u32) -> Option<ProcessInfo> {
    let out = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm=", "-o", "lstart="])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let (image, identity) = text.trim().split_once(' ')?;
    Some(ProcessInfo {
        image: image.into(),
        identity: identity.trim().into(),
        args: vec![],
    })
}

#[cfg(windows)]
pub fn process_info(pid: u32) -> Option<ProcessInfo> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, FILETIME},
        System::Threading::*,
    };
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let result = (|| {
            let mut code = 0;
            if GetExitCodeProcess(handle, &mut code) == 0 || code != 259 {
                return None;
            }
            let mut name = vec![0u16; 32768];
            let mut len = name.len() as u32;
            if QueryFullProcessImageNameW(handle, 0, name.as_mut_ptr(), &mut len) == 0 {
                return None;
            }
            let mut created: FILETIME = std::mem::zeroed();
            let mut exit = created;
            let mut kernel = created;
            let mut user = created;
            if GetProcessTimes(handle, &mut created, &mut exit, &mut kernel, &mut user) == 0 {
                return None;
            }
            Some(ProcessInfo {
                image: String::from_utf16_lossy(&name[..len as usize]).into(),
                identity: format!("{}:{}", created.dwHighDateTime, created.dwLowDateTime),
                args: vec![],
            })
        })();
        CloseHandle(handle);
        result
    }
}

#[cfg(unix)]
pub fn terminate(pid: u32, force: bool) -> Result<()> {
    if pid <= 1 || pid > i32::MAX as u32 {
        anyhow::bail!("拒绝无效 PID");
    }
    if unsafe {
        libc::kill(
            pid as i32,
            if force { libc::SIGKILL } else { libc::SIGTERM },
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
#[cfg(windows)]
pub fn terminate(pid: u32, _force: bool) -> Result<()> {
    use windows_sys::Win32::{Foundation::CloseHandle, System::Threading::*};
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if h.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        let result = TerminateProcess(h, 0);
        let err = std::io::Error::last_os_error();
        CloseHandle(h);
        if result == 0 {
            return Err(err.into());
        }
    }
    Ok(())
}

#[cfg(unix)]
pub fn foreground(cmd: &mut Command) -> Result<()> {
    use std::os::unix::process::CommandExt;
    Err(cmd.exec().into())
}
#[cfg(windows)]
pub fn foreground(cmd: &mut Command) -> Result<()> {
    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("sing-box 退出: {status}");
    }
    Ok(())
}

#[cfg(unix)]
pub fn elevated() -> bool {
    unsafe { libc::geteuid() == 0 }
}
#[cfg(windows)]
pub fn elevated() -> bool {
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        Security::*,
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut size = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        ) != 0;
        CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}
pub fn has_tun_privilege(bin: &Path) -> bool {
    if elevated() {
        return true;
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(out) = Command::new("getcap").arg(bin).output() {
            if out.status.success()
                && String::from_utf8_lossy(&out.stdout).contains("cap_net_admin")
            {
                return true;
            }
        }
    }
    let _ = bin;
    false
}
pub fn privilege_hint(bin: &Path) -> String {
    if cfg!(windows) {
        "TUN 需要管理员权限：右键 ssb.exe 或终端，以管理员身份运行；也可在设置中关闭 TUN".into()
    } else {
        format!(
            "TUN 需要 root/CAP_NET_ADMIN：使用 sudo，或为 {} 设置 cap_net_admin+ep；也可关闭 TUN",
            bin.display()
        )
    }
}

pub fn host_has_ipv6() -> bool {
    #[cfg(target_os = "linux")]
    {
        if !Path::new("/proc/net/if_inet6").exists()
            || std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6")
                .is_ok_and(|s| s.trim() == "1")
        {
            return false;
        }
        ipv6_rule_supported() == 1
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::net::TcpListener::bind("[::1]:0").is_ok()
    }
}

#[cfg(target_os = "linux")]
pub fn ipv6_rule_supported() -> i8 {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    unsafe {
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        );
        if fd < 0 {
            return -1;
        }
        let fd = OwnedFd::from_raw_fd(fd);
        let raw = fd.as_raw_fd();
        let timeout = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        libc::setsockopt(
            raw,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const _ as *const _,
            std::mem::size_of_val(&timeout) as _,
        );
        let mut addr: libc::sockaddr_nl = std::mem::zeroed();
        addr.nl_family = libc::AF_NETLINK as u16;
        let len = std::mem::size_of_val(&addr) as libc::socklen_t;
        if libc::bind(raw, &addr as *const _ as *const _, len) < 0 {
            return -1;
        }
        let mut request = [0u8; 28];
        request[..4].copy_from_slice(&28u32.to_ne_bytes());
        request[4..6].copy_from_slice(&34u16.to_ne_bytes()); // RTM_GETRULE
        request[6..8].copy_from_slice(&0x301u16.to_ne_bytes()); // REQUEST | DUMP
        request[8..12].copy_from_slice(&1u32.to_ne_bytes());
        request[16] = libc::AF_INET6 as u8;
        if libc::sendto(
            raw,
            request.as_ptr() as *const _,
            request.len(),
            0,
            &addr as *const _ as *const _,
            len,
        ) < 0
        {
            return -1;
        }
        let mut buf = [0u8; 65536];
        loop {
            let n = libc::recv(raw, buf.as_mut_ptr() as *mut _, buf.len(), 0);
            if n <= 0 {
                return -1;
            }
            let mut offset = 0;
            while offset + 16 <= n as usize {
                let msg = &buf[offset..n as usize];
                let size = u32::from_ne_bytes(msg[..4].try_into().unwrap()) as usize;
                if size < 16 || size > msg.len() {
                    return -1;
                }
                let typ = u16::from_ne_bytes(msg[4..6].try_into().unwrap());
                if typ == 2 || typ == 3 {
                    return probe_result(typ, &msg[16..size]);
                }
                offset += (size + 3) & !3;
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub fn probe_result(typ: u16, payload: &[u8]) -> i8 {
    if payload.len() < 4 {
        return if typ == 3 { 1 } else { -1 };
    }
    match i32::from_ne_bytes(payload[..4].try_into().unwrap()) {
        0 => 1,
        n if n == -libc::EAFNOSUPPORT => 0,
        _ => -1,
    }
}
