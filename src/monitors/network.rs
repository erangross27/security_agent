use log::{info, warn, error, debug};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use std::thread;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use pcap::{Device, Capture, Active};
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use sysinfo::{System, SystemExt, NetworkExt};
use crate::monitors::MonitorError;
use crate::detection::{behavior, ml};
use crate::ui::alerts;

static RUNNING: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ConnectionKey {
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
    protocol: Protocol,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Protocol {
    TCP,
    UDP,
    ICMP,
    Other(u8),
}

impl From<u8> for Protocol {
    fn from(protocol: u8) -> Self {
        match protocol {
            6 => Protocol::TCP,
            17 => Protocol::UDP,
            1 => Protocol::ICMP,
            other => Protocol::Other(other),
        }
    }
}

#[derive(Debug, Clone)]
struct ConnectionInfo {
    connection_key: ConnectionKey,
    process_id: Option<u32>,
    process_name: Option<String>,
    first_seen: Instant,
    last_seen: Instant,
    bytes_sent: u64,
    bytes_received: u64,
    packet_count: u64,
}

#[derive(Debug, Clone)]
struct DnsQuery {
    domain: String,
    query_type: String,
    timestamp: Instant,
    process_id: Option<u32>,
    process_name: Option<String>,
    resolved_ips: Vec<IpAddr>,
}

struct NetworkMonitor {
    system: System,
    active_connections: HashMap<ConnectionKey, ConnectionInfo>,
    dns_queries: Vec<DnsQuery>,
    suspicious_ips: HashSet<IpAddr>,
    suspicious_domains: HashSet<String>,
    known_safe_ips: HashSet<IpAddr>,
    known_safe_domains: HashSet<String>,
    max_dns_history: usize,
    network_interfaces: Vec<String>,
    dns_resolver: Option<Resolver>,
}

impl NetworkMonitor {
    fn new() -> Self {
        let mut sys = System::new();
        sys.refresh_all();
        
        let dns_resolver = match Resolver::new(ResolverConfig::default(), ResolverOpts::default()) {
            Ok(resolver) => Some(resolver),
            Err(e) => {
                error!("Failed to create DNS resolver: {}", e);
                None
            }
        };
        
        let mut network_interfaces = Vec::new();
        if let Ok(devices) = Device::list() {
            for device in devices {
                if let Some(name) = device.name {
                    network_interfaces.push(name);
                }
            }
        }
        
        NetworkMonitor {
            system: sys,
            active_connections: HashMap::new(),
            dns_queries: Vec::new(),
            suspicious_ips: HashSet::new(),
            suspicious_domains: HashSet::new(),
            known_safe_ips: HashSet::new(),
            known_safe_domains: HashSet::new(),
            max_dns_history: 1000,
            network_interfaces,
            dns_resolver,
        }
    }
    
    fn add_suspicious_ip(&mut self, ip_str: &str) -> Result<(), &'static str> {
        match IpAddr::from_str(ip_str) {
            Ok(ip) => {
                self.suspicious_ips.insert(ip);
                Ok(())
            },
            Err(_) => Err("Invalid IP address format"),
        }
    }
    
    fn add_suspicious_domain(&mut self, domain: &str) {
        self.suspicious_domains.insert(domain.to_lowercase());
    }
    
    fn add_safe_ip(&mut self, ip_str: &str) -> Result<(), &'static str> {
        match IpAddr::from_str(ip_str) {
            Ok(ip) => {
                self.known_safe_ips.insert(ip);
                Ok(())
            },
            Err(_) => Err("Invalid IP address format"),
        }
    }
    
    fn add_safe_domain(&mut self, domain: &str) {
        self.known_safe_domains.insert(domain.to_lowercase());
    }
    
    fn scan_connections(&mut self) {
        self.system.refresh_networks();
        
        // This is a simplified version - in a real implementation, 
        // we'd get actual connection info from the OS networking APIs
        let now = Instant::now();
        
        // Placeholder for detected connections
        // In a real implementation, we'd get this from the OS
        let detected_connections: Vec<ConnectionKey> = Vec::new();
        
        // Update active connections
        for conn_key in detected_connections {
            if let Some(conn_info) = self.active_connections.get_mut(&conn_key) {
                // Update existing connection
                conn_info.last_seen = now;
                conn_info.packet_count += 1;
                // We'd also update bytes sent/received
            } else {
                // New connection
                let conn_info = ConnectionInfo {
                    connection_key: conn_key.clone(),
                    process_id: None, // We'd try to get this from the OS
                    process_name: None, // We'd try to get this from the OS
                    first_seen: now,
                    last_seen: now,
                    bytes_sent: 0,
                    bytes_received: 0,
                    packet_count: 1,
                };
                
                self.active_connections.insert(conn_key.clone(), conn_info.clone());
                
                // Check for suspicious IPs
                if self.suspicious_ips.contains(&conn_key.remote_ip) {
                    self.handle_suspicious_connection(&conn_info);
                }
                
                // Try to get domain for this IP
                self.check_ip_domain(&conn_key.remote_ip);
                
                // Generate behavior event
                self.generate_connection_behavior_event(&conn_info);
            }
        }
        
        // Remove stale connections (older than 5 minutes)
        let stale_time = now - Duration::from_secs(300);
        self.active_connections.retain(|_, conn| conn.last_seen > stale_time);
    }
    
    fn handle_suspicious_connection(&self, conn_info: &ConnectionInfo) {
        let conn_key = &conn_info.connection_key;
        let remote = format!("{}:{}", conn_key.remote_ip, conn_key.remote_port);
        let local = format!("{}:{}", conn_key.local_ip, conn_key.local_port);
        let protocol = match conn_key.protocol {
            Protocol::TCP => "TCP",
            Protocol::UDP => "UDP",
            Protocol::ICMP => "ICMP",
            Protocol::Other(p) => "Unknown",
        };
        
        warn!(
            "Suspicious connection detected: {} {} -> {}",
            protocol, local, remote
        );
        
        let process_info = if let Some(name) = &conn_info.process_name {
            format!(" (Process: {})", name)
        } else {
            String::new()
        };
        
        alerts::add_alert(
            alerts::AlertType::Threat,
            "Suspicious Network Connection",
            &format!(
                "Connection to suspicious IP address detected: {} {} -> {}{}",
                protocol, local, remote, process_info
            )
        );
    }
    
    fn check_ip_domain(&mut self, ip: &IpAddr) {
        // Skip if we don't have a resolver
        if self.dns_resolver.is_none() {
            return;
        }
        
        // Skip if IP is already known safe
        if self.known_safe_ips.contains(ip) {
            return;
        }
        
        // Try reverse DNS lookup
        if let Some(resolver) = &self.dns_resolver {
            match resolver.reverse_lookup(*ip) {
                Ok(response) => {
                    for name in response.iter() {
                        let domain = name.to_string().to_lowercase();
                        
                        // Check if domain is in suspicious list
                        if self.suspicious_domains.contains(&domain) {
                            warn!("Connection to suspicious domain detected: {} (IP: {})", domain, ip);
                            
                            alerts::add_alert(
                                alerts::AlertType::Threat,
                                "Suspicious Network Connection",
                                &format!("Connection to suspicious domain detected: {} (IP: {})", domain, ip)
                            );
                        }
                    }
                },
                Err(e) => {
                    debug!("Failed to perform reverse DNS lookup for {}: {}", ip, e);
                }
            }
        }
    }
    
    fn record_dns_query(&mut self, query: DnsQuery) {
        // Check if domain is suspicious
        if self.suspicious_domains.contains(&query.domain.to_lowercase()) {
            warn!("Query to suspicious domain detected: {}", query.domain);
            
            let process_info = if let Some(name) = &query.process_name {
                format!(" (Process: {})", name)
            } else {
                String::new()
            };
            
            alerts::add_alert(
                alerts::AlertType::Threat,
                "Suspicious DNS Query",
                &format!("Query to suspicious domain detected: {}{}", query.domain, process_info)
            );
        }
        
        // Add to history
        self.dns_queries.push(query);
        
        // Keep history under max size
        while self.dns_queries.len() > self.max_dns_history {
            self.dns_queries.remove(0);
        }
    }
    
    fn generate_connection_behavior_event(&self, conn_info: &ConnectionInfo) {
        let conn_key = &conn_info.connection_key;
        let remote = format!("{}:{}", conn_key.remote_ip, conn_key.remote_port);
        let local = format!("{}:{}", conn_key.local_ip, conn_key.local_port);
        let protocol = match conn_key.protocol {
            Protocol::TCP => "TCP",
            Protocol::UDP => "UDP",
            Protocol::ICMP => "ICMP",
            Protocol::Other(p) => format!("Protocol-{}", p),
        };
        
        let mut details = HashMap::new();
        details.insert("local".to_string(), local);
        details.insert("remote".to_string(), remote);
        details.insert("protocol".to_string(), protocol);
        
        if let Some(pid) = conn_info.process_id {
            details.insert("process_id".to_string(), pid.to_string());
        }
        
        if let Some(name) = &conn_info.process_name {
            details.insert("process_name".to_string(), name.clone());
        }
        
        let source = if let Some(name) = &conn_info.process_name {
            name.clone()
        } else {
            "unknown-process".to_string()
        };
        
        let _ = behavior::process_event(behavior::Event::new(
            behavior::EventType::NetworkConnection,
            &source,
            Some(&remote),
            details
        ));
    }
    
    fn run_ml_analysis(&self, conn_info: &ConnectionInfo) {
        let conn_key = &conn_info.connection_key;
        let remote = format!("{}:{}", conn_key.remote_ip, conn_key.remote_port);
        
        // Extract features and run ML prediction
        match ml::extract_network_features(&remote) {
            Ok(features) => {
                if let Ok(prediction) = ml::predict_network(&remote, features) {
                    if prediction.is_malicious {
                        warn!(
                            "ML detection for network connection to '{}': {} ({:.2}% confidence)",
                            remote,
                            prediction.label,
                            prediction.confidence * 100.0
                        );
                    }
                }
            },
            Err(e) => error!("Failed to extract network features: {}", e),
        }
    }
}

// Global monitor instance
static MONITOR: Mutex<Option<NetworkMonitor>> = Mutex::new(None);

pub fn start() -> Result<(), MonitorError> {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return Err(MonitorError::AlreadyRunning);
    }
    
    info!("Starting network monitoring...");
    
    // Initialize monitor
    let mut monitor = NetworkMonitor::new();
    
    // Add default suspicious IPs
    let default_suspicious_ips = [
        "185.45.193.122", // Example malicious IP (placeholder)
        "193.183.98.66",  // Example malicious IP (placeholder)
    ];
    
    for ip in &default_suspicious_ips {
        if let Err(e) = monitor.add_suspicious_ip(ip) {
            error!("Failed to add suspicious IP {}: {}", ip, e);
        }
    }
    
    // Add default suspicious domains
    let default_suspicious_domains = [
        "malware-domain.example", // Example malicious domain (placeholder)
        "phishing-site.example",  // Example malicious domain (placeholder)
    ];
    
    for domain in &default_suspicious_domains {
        monitor.add_suspicious_domain(domain);
    }
    
    // Store the monitor
    {
        let mut guard = MONITOR.lock().unwrap();
        *guard = Some(monitor);
    }
    
    // Start monitoring thread
    thread::spawn(|| {
        network_monitor_thread();
    });
    
    // Start packet capture thread if pcap is available
    thread::spawn(|| {
        packet_capture_thread();
    });
    
    Ok(())
}

fn network_monitor_thread() {
    while RUNNING.load(Ordering::SeqCst) {
        // Get the monitor
        let mut guard = match MONITOR.lock() {
            Ok(guard) => guard,
            Err(e) => {
                error!("Failed to acquire network monitor lock: {}", e);
                thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        
        let monitor = match &mut *guard {
            Some(monitor) => monitor,
            None => {
                error!("Network monitor not initialized");
                thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        
        // Scan for new connections
        monitor.scan_connections();
        
        // Release the lock and sleep
        drop(guard);
        thread::sleep(Duration::from_secs(5));
    }
    
    info!("Network monitoring thread exited");
}

fn packet_capture_thread() {
    // Get the network interfaces to monitor
    let interfaces = {
        let guard = match MONITOR.lock() {
            Ok(guard) => guard,
            Err(e) => {
                error!("Failed to acquire network monitor lock: {}", e);
                return;
            }
        };
        
        let monitor = match &*guard {
            Some(monitor) => monitor,
            None => {
                error!("Network monitor not initialized");
                return;
            }
        };
        
        monitor.network_interfaces.clone()
    };
    
    // Select the first interface if available
    let interface = match interfaces.first() {
        Some(iface) => iface,
        None => {
            error!("No network interfaces available for packet capture");
            return;
        }
    };
    
    // Create packet capture
    let mut cap = match Capture::from_device(interface.as_str())
        .and_then(|d| d.promisc(true).snaplen(65535).timeout(1000).open()) {
        Ok(cap) => cap,
        Err(e) => {
            error!("Failed to open packet capture on {}: {}", interface, e);
            return;
        }
    };
    
    info!("Packet capture started on interface: {}", interface);
    
    // Set filter to only capture IP traffic
    if let Err(e) = cap.filter("ip or ip6") {
        error!("Failed to set packet filter: {}", e);
    }
    
    // Capture loop
    while RUNNING.load(Ordering::SeqCst) {
        match cap.next_packet() {
            Ok(packet) => {
                // Process packet data
                // This is simplified - in a real implementation we'd parse the packet
                // to extract source/destination IPs, ports, protocol, etc.
                debug!("Captured packet: {} bytes", packet.data.len());
            },
            Err(pcap::Error::TimeoutExpired) => {
                // This is expected when no packets are received
                continue;
            },
            Err(e) => {
                error!("Error capturing packet: {}", e);
                break;
            }
        }
    }
    
    info!("Packet capture thread exited");
}

pub fn stop() -> Result<(), MonitorError> {
    if !RUNNING.swap(false, Ordering::SeqCst) {
        return Err(MonitorError::NotRunning);
    }
    
    info!("Stopping network monitoring...");
    
    // Clear the monitor
    let mut guard = MONITOR.lock().unwrap();
    *guard = None;
    
    Ok(())
}

pub fn add_suspicious_ip(ip: &str) -> Result<(), MonitorError> {
    let mut guard = MONITOR.lock().unwrap();
    
    if let Some(monitor) = &mut *guard {
        monitor.add_suspicious_ip(ip)
            .map_err(|e| MonitorError::NetworkError(e.to_string()))
    } else {
        Err(MonitorError::NotRunning)
    }
}

pub fn add_suspicious_domain(domain: &str) -> Result<(), MonitorError> {
    let mut guard = MONITOR.lock().unwrap();
    
    if let Some(monitor) = &mut *guard {
        monitor.add_suspicious_domain(domain);
        Ok(())
    } else {
        Err(MonitorError::NotRunning)
    }
}

pub fn add_safe_ip(ip: &str) -> Result<(), MonitorError> {
    let mut guard = MONITOR.lock().unwrap();
    
    if let Some(monitor) = &mut *guard {
        monitor.add_safe_ip(ip)
            .map_err(|e| MonitorError::NetworkError(e.to_string()))
    } else {
        Err(MonitorError::NotRunning)
    }
}

pub fn add_safe_domain(domain: &str) -> Result<(), MonitorError> {
    let mut guard = MONITOR.lock().unwrap();
    
    if let Some(monitor) = &mut *guard {
        monitor.add_safe_domain(domain);
        Ok(())
    } else {
        Err(MonitorError::NotRunning)
    }
}

pub fn get_active_connections() -> Result<Vec<(String, String, String)>, MonitorError> {
    let guard = MONITOR.lock().unwrap();
    
    if let Some(monitor) = &*guard {
        let mut connections = Vec::new();
        
        for conn_info in monitor.active_connections.values() {
            let conn_key = &conn_info.connection_key;
            let local = format!("{}:{}", conn_key.local_ip, conn_key.local_port);
            let remote = format!("{}:{}", conn_key.remote_ip, conn_key.remote_port);
            let protocol = match conn_key.protocol {
                Protocol::TCP => "TCP".to_string(),
                Protocol::UDP => "UDP".to_string(),
                Protocol::ICMP => "ICMP".to_string(),
                Protocol::Other(p) => format!("Protocol-{}", p),
            };
            
            connections.push((protocol, local, remote));
        }
        
        Ok(connections)
    } else {
        Err(MonitorError::NotRunning)
    }
}