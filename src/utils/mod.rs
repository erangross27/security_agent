pub mod logger;

/// Checks if the current process is running with administrator privileges.
/// 
/// # Returns
/// 
/// * `true` - If the process has administrator privileges
/// * `false` - If the process does not have administrator privileges or if the check fails
#[cfg(target_os = "windows")]
pub fn is_admin() -> bool {
    use std::process::Command;
    
    // On Windows, the "net session" command requires administrator privileges
    // If it succeeds, the user has admin rights
    match Command::new("net")
        .args(["session"])  // Use slice literals instead of &[]
        .output() {
            Ok(output) => {
                // Check if the command executed successfully (exit code 0)
                output.status.success()
            },
            Err(e) => {
                // Log the error and return false
                log::warn!("Failed to check admin privileges: {}", e);
                false
            },
        }
}

/// Checks if the current process is running with root privileges.
/// 
/// # Returns
/// 
/// * `false` - This is a placeholder for non-Windows platforms
#[cfg(not(target_os = "windows"))]
pub fn is_admin() -> bool {
    // For non-Windows platforms - replace with actual implementation if needed
    false
}