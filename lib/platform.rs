#[cfg(target_os = "macos")]
pub(crate) fn get_platform() -> String {
    "macos".to_string()
}

#[cfg(target_os = "windows")]
pub(crate) fn get_platform() -> String {
    "win32".to_string()
}

#[cfg(target_os = "linux")]
pub(crate) fn get_platform() -> String {
    "linux".to_string()
}
#[cfg(target_os = "ios")]
pub(crate) fn get_platform() -> String {
    "ios".to_string()
}

#[cfg(target_os = "android")]
pub(crate) fn get_platform() -> String {
    "android".to_string()
}
#[cfg(target_os = "freebsd")]
pub(crate) fn get_platform() -> String {
    "freebsd".to_string()
}

#[cfg(target_os = "dragonfly")]
pub(crate) fn get_platform() -> String {
    "dragonfly".to_string()
}

#[cfg(target_os = "bitrig")]
pub(crate) fn get_platform() -> String {
    "bitrig".to_string()
}
#[cfg(target_os = "openbsd")]
pub(crate) fn get_platform() -> String {
    "openbsd".to_string()
}

#[cfg(target_os = "netbsd")]
pub(crate) fn get_platform() -> String {
    "netbsd".to_string()
}
#[cfg(target_arch = "x86")]
pub(crate) fn get_arch() -> String {
    "x86".to_string()
}
#[cfg(target_arch = "x86")]
pub(crate) fn get_arch() -> String {
    "x86".to_string()
}

#[cfg(target_arch = "x8_64")]
pub(crate) fn get_arch() -> String {
    "x8_64".to_string()
}
#[cfg(target_arch = "x86_64")]
pub(crate) fn get_arch() -> String {
    "x86_64".to_string()
}
#[cfg(target_arch = "mips")]
pub(crate) fn get_arch() -> String {
    "mips".to_string()
}
#[cfg(target_arch = "powerpc")]
pub(crate) fn get_arch() -> String {
    "powerpc".to_string()
}
#[cfg(target_arch = "powerpc64")]
pub(crate) fn get_arch() -> String {
    "powerpc64".to_string()
}

#[cfg(target_arch = "arm")]
pub(crate) fn get_arch() -> String {
    "arm".to_string()
}
#[cfg(target_arch = "arm64")]
pub(crate) fn get_arch() -> String {
    "arm64".to_string()
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn get_arch() -> String {
    "aarch64".to_string()
}
#[cfg(target_arch = "ia64")]
pub(crate) fn get_arch() -> String {
    "ia64".to_string()
}
#[cfg(target_arch = "sparc")]
pub(crate) fn get_arch() -> String {
    "sparc".to_string()
}
