use log::{info, warn, error, debug};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use std::thread;
use sysinfo::{ProcessExt, System, SystemExt};
use crate::monitors::MonitorError;
use crate::detection::{behavior, ml};
use crate::ui::alerts;

static RUNNING: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone)]
struct ProcessInfo {
    pid: u32,
    name: String,
    exec_path: String,
    start_time: Instant,
    memory_usage: u64,
    cpu_usage: f32,
    user: String,
    cmd_line: Vec<String>,
    parent_pid: Option<u32>,
    last_updated: Instant,
}

struct ProcessMonitor {
    system: System,
    processes: HashMap<u32, ProcessInfo>,
    whitelist: HashSet<String>,
    blacklist: HashSet<String>,
    scan_interval: Duration,
}

impl ProcessMonitor {
    fn new() -> Self {
        let mut sys = System::new();
        sys.refresh_all();
        
        ProcessMonitor {
            system: sys,
            processes: HashMap::new(),
            whitelist: HashSet::new(),
            blacklist: HashSet::new(),
            scan_interval: Duration::from_secs(5),
        }
    }
    
    fn update_whitelist(&mut self, processes: Vec<String>) {
        for process in processes {
            self.whitelist.insert(process);
        }
    }
    
    fn update_blacklist(&mut self, processes: Vec<String>) {
        for process in processes {
            self.blacklist.insert(process);
        }
    }
    
    fn scan_processes(&mut self) -> Vec<ProcessInfo> {
        self.system.refresh_all();
        
        let mut new_processes = Vec::new();
        let mut current_pids = HashSet::new();
        
        for (pid, proc) in self.system.processes() {
            let pid = pid.as_u32();
            current_pids.insert(pid);
            
            let proc_info = ProcessInfo {
                pid,
                name: proc.name().to_string(),
                exec_path: proc.exe().to_string_lossy().to_string(),
                start_time: Instant::now(), // Note: sysinfo doesn't provide start time directly
                memory_usage: proc.memory(),
                cpu_usage: proc.cpu_usage(),
                user: "unknown".to_string(), // Note: would need elevated privileges for this
                cmd_line: proc.cmd().to_vec(),
                parent_pid: None, // sysinfo doesn't provide parent PID directly
                last_updated: Instant::now(),
            };
            
            if !self.processes.contains_key(&pid) {
                // New process detected
                debug!("New process detected: {} (PID: {})", proc_info.name, pid);
                new_processes.push(proc_info.clone());
                
                // Check blacklist
                if self.blacklist.contains(&proc_info.name) {
                    warn!("Blacklisted process detected: {} (PID: {})", proc_info.name, pid);
                    
                    // Generate an alert
                    alerts::add_alert(
                        alerts::AlertType::Threat,
                        "Blacklisted Process Started",
                        &format!("Process '{}' (PID: {}) is on the blacklist", proc_info.name, pid)
                    );
                    
                    // Generate a behavior event
                    let mut details = HashMap::new();
                    details.insert("pid".to_string(), pid.to_string());
                    details.insert("executable".to_string(), proc_info.exec_path.clone());
                    
                    let _ = behavior::process_event(behavior::Event::new(
                        behavior::EventType::ProcessStart,
                        &proc_info.name,
                        None,
                        details
                    ));
                    
                    // Run ML analysis if available
                    match ml::extract_process_features(&proc_info.name) {
                        Ok(features) => {
                            if let Ok(prediction) = ml::predict_process(&proc_info.name, features) {
                                if prediction.is_malicious {
                                    warn!(
                                        "ML detection for process '{}': {} ({:.2}% confidence)",
                                        proc_info.name,
                                        prediction.label,
                                        prediction.confidence * 100.0
                                    );
                                }
                            }
                        },
                        Err(e) => error!("Failed to extract process features: {}", e),
                    }
                }
            }
            
            // Update the process in our map
            self.processes.insert(pid, proc_info);
        }
        
        // Check for terminated processes
        let mut terminated = Vec::new();
        for pid in self.processes.keys().cloned().collect::<Vec<_>>() {
            if !current_pids.contains(&pid) {
                if let Some(proc_info) = self.processes.remove(&pid) {
                    debug!("Process terminated: {} (PID: {})", proc_info.name, pid);
                    
                    // Generate a behavior event for process termination
                    let mut details = HashMap::new();
                    details.insert("pid".to_string(), pid.to_string());
                    details.insert("executable".to_string(), proc_info.exec_path.clone());
                    
                    let _ = behavior::process_event(behavior::Event::new(
                        behavior::EventType::ProcessTermination,
                        &proc_info.name,
                        None,
                        details
                    ));
                    
                    terminated.push(proc_info);
                }
            }
        }
        
        new_processes
    }
}

// Global monitor instance
static MONITOR: Mutex<Option<ProcessMonitor>> = Mutex::new(None);

pub fn start() -> Result<(), MonitorError> {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return Err(MonitorError::AlreadyRunning);
    }
    
    info!("Starting process monitoring...");
    
    // Initialize monitor
    let mut monitor = ProcessMonitor::new();
    
    // Default whitelist
    monitor.update_whitelist(vec![
        "explorer.exe".to_string(),
        "svchost.exe".to_string(),
        "lsass.exe".to_string(),
        "winlogon.exe".to_string(),
        "services.exe".to_string(),
        "wininit.exe".to_string(),
        "csrss.exe".to_string(),
        "smss.exe".to_string(),
        "system".to_string(),
        "registry".to_string(),
    ]);
    
    // Default blacklist
    monitor.update_blacklist(vec![
        "mimikatz.exe".to_string(),
        "pwdump.exe".to_string(),
        "netcat.exe".to_string(),
        "nc.exe".to_string(),
        "psexec.exe".to_string(),
    ]);
    
    // Store the monitor
    {
        let mut guard = MONITOR.lock().unwrap();
        *guard = Some(monitor);
    }
    
    // Start monitoring thread
    thread::spawn(|| {
        process_monitor_thread();
    });
    
    Ok(())
}

fn process_monitor_thread() {
    while RUNNING.load(Ordering::SeqCst) {
        // Get the monitor
        let mut guard = match MONITOR.lock() {
            Ok(guard) => guard,
            Err(e) => {
                error!("Failed to acquire process monitor lock: {}", e);
                thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        
        let monitor = match &mut *guard {
            Some(monitor) => monitor,
            None => {
                error!("Process monitor not initialized");
                thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        
        // Scan for new/changed processes
        monitor.scan_processes();
        
        // Release the lock and sleep
        drop(guard);
        thread::sleep(monitor.scan_interval);
    }
    
    info!("Process monitoring thread exited");
}

pub fn stop() -> Result<(), MonitorError> {
    if !RUNNING.swap(false, Ordering::SeqCst) {
        return Err(MonitorError::NotRunning);
    }
    
    info!("Stopping process monitoring...");
    
    // Clear the monitor
    let mut guard = MONITOR.lock().unwrap();
    *guard = None;
    
    Ok(())
}

pub fn update_whitelist(processes: Vec<String>) -> Result<(), MonitorError> {
    let mut guard = MONITOR.lock().unwrap();
    
    if let Some(monitor) = &mut *guard {
        monitor.update_whitelist(processes);
        Ok(())
    } else {
        Err(MonitorError::NotRunning)
    }
}

pub fn update_blacklist(processes: Vec<String>) -> Result<(), MonitorError> {
    let mut guard = MONITOR.lock().unwrap();
    
    if let Some(monitor) = &mut *guard {
        monitor.update_blacklist(processes);
        Ok(())
    } else {
        Err(MonitorError::NotRunning)
    }
}

pub fn get_process_list() -> Result<Vec<(u32, String)>, MonitorError> {
    let guard = MONITOR.lock().unwrap();
    
    if let Some(monitor) = &*guard {
        let mut process_list = Vec::new();
        for (pid, info) in &monitor.processes {
            process_list.push((*pid, info.name.clone()));
        }
        Ok(process_list)
    } else {
        Err(MonitorError::NotRunning)
    }
}