use log::{info, warn, error, debug};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use crate::protection::ProtectionSettings;
use crate::ui::alerts;

static RUNNING: AtomicBool = AtomicBool::new(false);

pub struct NetworkProtection {
    active_ip_blocklist: HashSet<IpAddr>,
    active_domain_blocklist: HashSet<String>,
}

impl NetworkProtection {
    pub fn new() -> Self {
        NetworkProtection {
            active_ip_blocklist: HashSet::new(),
            active_domain_blocklist: HashSet::new(),
        }
    }
    
    pub fn start(&mut self, settings: &ProtectionSettings) -> io::Result<()> {
        if RUNNING.swap(true, Ordering::SeqCst) {
            info!("Network protection already running");
            return Ok(());
        }
        
        info!("Starting network protection...");
        
        // Initialize blocklists from settings
        self.active_ip_blocklist.clear();
        for ip_str in &settings.network_blocklist {
            if let Ok(ip) = IpAddr::from_str(ip_str) {
                self.active_ip_blocklist.insert(ip);
            } else {
                warn!("Invalid IP address in network blocklist: {}", ip_str);
            }
        }
        
        self.active_domain_blocklist = settings.domain_blocklist.clone();
        
        Ok(())
    }
    
    pub fn stop(&mut self) -> io::Result<()> {
        if !RUNNING.swap(false, Ordering::SeqCst) {
            return Ok(());
        }
        
        info!("Stopping network protection...");
        
        Ok(())
    }
    
    pub fn update_settings(&mut self, settings: &ProtectionSettings) -> io::Result<()> {
        // Update IP blocklist
        self.active_ip_blocklist.clear();
        for ip_str in &settings.network_blocklist {
            if let Ok(ip) = IpAddr::from_str(ip_str) {
                self.active_ip_blocklist.insert(ip);
            } else {
                warn!("Invalid IP address in network blocklist: {}", ip_str);
            }
        }
        
        // Update domain blocklist
        self.active_domain_blocklist = settings.domain_blocklist.clone();
        
        info!("Network protection settings updated");
        Ok(())
    }
    
    pub fn block_ip(&self, ip: &IpAddr) -> bool {
        // Check if the IP is in the blocklist
        if self.active_ip_blocklist.contains(ip) {
            warn!("Blocked connection to suspicious IP: {}", ip);
            
            // Generate alert
            alerts::add_alert(
                alerts::AlertType::Threat,
                "Suspicious Connection Blocked",
                &format!("Blocked connection to suspicious IP address: {}", ip)
            );
            
            return true;
        }
        
        false
    }
    
    pub fn block_domain(&self, domain: &str) -> bool {
        // Check if the domain is in the blocklist
        let domain_lower = domain.to_lowercase();
        if self.active_domain_blocklist.contains(&domain_lower) {
            warn!("Blocked connection to suspicious domain: {}", domain);
            
            // Generate alert
            alerts::add_alert(
                alerts::AlertType::Threat,
                "Suspicious Connection Blocked",
                &format!("Blocked connection to suspicious domain: {}", domain)
            );
            
            return true;
        }
        
        false
    }
    
    pub fn add_to_ip_blocklist(&mut self, ip_str: &str) -> Result<(), String> {
        match IpAddr::from_str(ip_str) {
            Ok(ip) => {
                self.active_ip_blocklist.insert(ip);
                info!("Added IP to blocklist: {}", ip);
                Ok(())
            },
            Err(e) => {
                let error_msg = format!("Invalid IP address: {}", e);
                error!("{}", error_msg);
                Err(error_msg)
            }
        }
    }
    
    pub fn add_to_domain_blocklist(&mut self, domain: &str) {
        let domain_lower = domain.to_lowercase();
        self.active_domain_blocklist.insert(domain_lower);
        info!("Added domain to blocklist: {}", domain);
    }
    
    pub fn remove_from_ip_blocklist(&mut self, ip_str: &str) -> Result<(), String> {
        match IpAddr::from_str(ip_str) {
            Ok(ip) => {
                if self.active_ip_blocklist.remove(&ip) {
                    info!("Removed IP from blocklist: {}", ip);
                }
                Ok(())
            },
            Err(e) => {
                let error_msg = format!("Invalid IP address: {}", e);
                error!("{}", error_msg);
                Err(error_msg)
            }
        }
    }
    
    pub fn remove_from_domain_blocklist(&mut self, domain: &str) {
        let domain_lower = domain.to_lowercase();
        if self.active_domain_blocklist.remove(&domain_lower) {
            info!("Removed domain from blocklist: {}", domain);
        }
    }
    
    pub fn get_ip_blocklist(&self) -> Vec<String> {
        self.active_ip_blocklist.iter().map(|ip| ip.to_string()).collect()
    }
    
    pub fn get_domain_blocklist(&self) -> HashSet<String> {
        self.active_domain_blocklist.clone()
    }
}