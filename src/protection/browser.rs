use log::{info, warn, error, debug};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::collections::HashSet;
use crate::protection::ProtectionSettings;
use crate::ui::alerts;

static RUNNING: AtomicBool = AtomicBool::new(false);

pub struct BrowserProtection {
    active_phishing_domains: HashSet<String>,
    active_malware_domains: HashSet<String>,
    download_blocklist: HashSet<String>, // File extensions
}

impl BrowserProtection {
    pub fn new() -> Self {
        let mut download_blocklist = HashSet::new();
        
        // Add default download blocklist
        for ext in &["exe", "dll", "bat", "ps1", "vbs", "js"] {
            download_blocklist.insert(ext.to_string());
        }
        
        BrowserProtection {
            active_phishing_domains: HashSet::new(),
            active_malware_domains: HashSet::new(),
            download_blocklist,
        }
    }
    
    pub fn start(&mut self, settings: &ProtectionSettings) -> io::Result<()> {
        if RUNNING.swap(true, Ordering::SeqCst) {
            info!("Browser protection already running");
            return Ok(());
        }
        
        info!("Starting browser protection...");
        
        // Initialize domain blocklists from settings
        self.active_phishing_domains = HashSet::new();
        self.active_malware_domains = HashSet::new();
        
        for domain in &settings.domain_blocklist {
            // For simplicity, we treat all blocked domains as both phishing and malware domains
            self.active_phishing_domains.insert(domain.to_lowercase());
            self.active_malware_domains.insert(domain.to_lowercase());
        }
        
        Ok(())
    }
    
    pub fn stop(&mut self) -> io::Result<()> {
        if !RUNNING.swap(false, Ordering::SeqCst) {
            return Ok(());
        }
        
        info!("Stopping browser protection...");
        
        Ok(())
    }
    
    pub fn update_settings(&mut self, settings: &ProtectionSettings) -> io::Result<()> {
        // Update domain blocklists
        self.active_phishing_domains = HashSet::new();
        self.active_malware_domains = HashSet::new();
        
        for domain in &settings.domain_blocklist {
            // For simplicity, we treat all blocked domains as both phishing and malware domains
            self.active_phishing_domains.insert(domain.to_lowercase());
            self.active_malware_domains.insert(domain.to_lowercase());
        }
        
        info!("Browser protection settings updated");
        Ok(())
    }
    
    pub fn block_url_access(&self, url: &str) -> bool {
        // Try to extract domain from URL
        let domain = match extract_domain_from_url(url) {
            Some(domain) => domain.to_lowercase(),
            None => return false,
        };
        
        // Check if the domain is in the phishing or malware blocklists
        if self.active_phishing_domains.contains(&domain) {
            warn!("Blocked access to phishing site: {}", domain);
            
            // Generate alert
            alerts::add_alert(
                alerts::AlertType::Threat,
                "Phishing Site Blocked",
                &format!("Blocked access to known phishing site: {}", domain)
            );
            
            return true;
        }
        
        if self.active_malware_domains.contains(&domain) {
            warn!("Blocked access to malware site: {}", domain);
            
            // Generate alert
            alerts::add_alert(
                alerts::AlertType::Threat,
                "Malware Site Blocked",
                &format!("Blocked access to known malware distribution site: {}", domain)
            );
            
            return true;
        }
        
        false
    }
    
    pub fn block_download(&self, url: &str, file_name: &str) -> bool {
        // Check if the file has a blocked extension
        if let Some(ext) = file_name.rsplit_once('.').map(|(_, ext)| ext.to_lowercase()) {
            if self.download_blocklist.contains(&ext) {
                warn!("Blocked download of potentially unsafe file: {}", file_name);
                
                // Generate alert
                alerts::add_alert(
                    alerts::AlertType::Warning,
                    "Unsafe Download Blocked",
                    &format!("Blocked download of potentially unsafe file: {}", file_name)
                );
                
                return true;
            }
        }
        
        // Check if the domain is in the malware blocklist
        if let Some(domain) = extract_domain_from_url(url) {
            let domain = domain.to_lowercase();
            
            if self.active_malware_domains.contains(&domain) {
                warn!("Blocked download from malware site: {}", domain);
                
                // Generate alert
                alerts::add_alert(
                    alerts::AlertType::Threat,
                    "Malware Download Blocked",
                    &format!("Blocked download from known malware distribution site: {}", domain)
                );
                
                return true;
            }
        }
        
        false
    }
    
    pub fn add_to_phishing_blocklist(&mut self, domain: &str) {
        let domain_lower = domain.to_lowercase();
        self.active_phishing_domains.insert(domain_lower);
        info!("Added domain to phishing blocklist: {}", domain);
    }
    
    pub fn add_to_malware_blocklist(&mut self, domain: &str) {
        let domain_lower = domain.to_lowercase();
        self.active_malware_domains.insert(domain_lower);
        info!("Added domain to malware blocklist: {}", domain);
    }
    
    pub fn add_to_download_blocklist(&mut self, ext: &str) {
        let ext_lower = ext.to_lowercase();
        self.download_blocklist.insert(ext_lower);
        info!("Added extension to download blocklist: {}", ext);
    }
    
    pub fn remove_from_phishing_blocklist(&mut self, domain: &str) {
        let domain_lower = domain.to_lowercase();
        if self.active_phishing_domains.remove(&domain_lower) {
            info!("Removed domain from phishing blocklist: {}", domain);
        }
    }
    
    pub fn remove_from_malware_blocklist(&mut self, domain: &str) {
        let domain_lower = domain.to_lowercase();
        if self.active_malware_domains.remove(&domain_lower) {
            info!("Removed domain from malware blocklist: {}", domain);
        }
    }
    
    pub fn remove_from_download_blocklist(&mut self, ext: &str) {
        let ext_lower = ext.to_lowercase();
        if self.download_blocklist.remove(&ext_lower) {
            info!("Removed extension from download blocklist: {}", ext);
        }
    }
    
    pub fn get_phishing_blocklist(&self) -> HashSet<String> {
        self.active_phishing_domains.clone()
    }
    
    pub fn get_malware_blocklist(&self) -> HashSet<String> {
        self.active_malware_domains.clone()
    }
    
    pub fn get_download_blocklist(&self) -> HashSet<String> {
        self.download_blocklist.clone()
    }
}

// Helper function to extract domain from URL
fn extract_domain_from_url(url: &str) -> Option<String> {
    // Very simple URL parsing
    let url = url.trim().to_lowercase();
    
    // Remove protocol
    let domain_part = if url.starts_with("http://") {
        &url[7..]
    } else if url.starts_with("https://") {
        &url[8..]
    } else {
        &url
    };
    
    // Find end of domain
    let end = domain_part.find('/').unwrap_or(domain_part.len());
    let domain = &domain_part[..end];
    
    // Remove port if present
    let domain = if let Some(pos) = domain.find(':') {
        &domain[..pos]
    } else {
        domain
    };
    
    if domain.is_empty() {
        None
    } else {
        Some(domain.to_string())
    }
}