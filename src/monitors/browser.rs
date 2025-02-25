use log::{info, warn, error, debug};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use std::thread;
use std::fs;
use rusqlite::{Connection, Result as SqlResult};
use crate::monitors::MonitorError;
use crate::detection::behavior;
use crate::ui::alerts;

static RUNNING: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone)]
struct BrowserHistory {
    browser: BrowserType,
    url: String,
    title: Option<String>,
    visit_time: i64, // Unix timestamp
    visit_count: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum BrowserType {
    Chrome,
    Firefox,
    Edge,
    Safari,
    Opera,
    Unknown,
}

impl ToString for BrowserType {
    fn to_string(&self) -> String {
        match self {
            BrowserType::Chrome => "Chrome",
            BrowserType::Firefox => "Firefox",
            BrowserType::Edge => "Edge",
            BrowserType::Safari => "Safari",
            BrowserType::Opera => "Opera",
            BrowserType::Unknown => "Unknown",
        }.to_string()
    }
}

#[derive(Debug, Clone)]
struct BrowserDownload {
    browser: BrowserType,
    url: String,
    target_path: String,
    download_time: i64, // Unix timestamp
    file_size: Option<i64>,
    mime_type: Option<String>,
}

struct BrowserMonitor {
    history_entries: Vec<BrowserHistory>,
    downloads: Vec<BrowserDownload>,
    phishing_domains: HashSet<String>,
    malware_domains: HashSet<String>,
    browser_paths: HashMap<BrowserType, PathBuf>,
    max_history_size: usize,
    scan_interval: Duration,
    last_scan_time: HashMap<BrowserType, Instant>,
}

impl BrowserMonitor {
    fn new() -> Self {
        BrowserMonitor {
            history_entries: Vec::new(),
            downloads: Vec::new(),
            phishing_domains: HashSet::new(),
            malware_domains: HashSet::new(),
            browser_paths: HashMap::new(),
            max_history_size: 10000,
            scan_interval: Duration::from_secs(300), // 5 minutes
            last_scan_time: HashMap::new(),
        }
    }
    
    fn add_phishing_domain(&mut self, domain: &str) {
        self.phishing_domains.insert(domain.to_lowercase());
    }
    
    fn add_malware_domain(&mut self, domain: &str) {
        self.malware_domains.insert(domain.to_lowercase());
    }
    
    fn detect_browsers(&mut self) {
        // Detect installed browsers and their data paths
        if cfg!(target_os = "windows") {
            self.detect_windows_browsers();
        } else if cfg!(target_os = "macos") {
            self.detect_macos_browsers();
        } else if cfg!(target_os = "linux") {
            self.detect_linux_browsers();
        }
    }
    
    fn detect_windows_browsers(&mut self) {
        let appdata = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let appdata_path = Path::new(&appdata);
        
        // Chrome
        let chrome_path = appdata_path.join("Google\\Chrome\\User Data\\Default");
        if chrome_path.exists() {
            self.browser_paths.insert(BrowserType::Chrome, chrome_path);
        }
        
        // Edge
        let edge_path = appdata_path.join("Microsoft\\Edge\\User Data\\Default");
        if edge_path.exists() {
            self.browser_paths.insert(BrowserType::Edge, edge_path);
        }
        
        // Firefox
        let firefox_path = appdata_path.join("Mozilla\\Firefox\\Profiles");
        if firefox_path.exists() {
            if let Ok(entries) = fs::read_dir(firefox_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() && path.file_name().unwrap_or_default().to_string_lossy().ends_with(".default") {
                        self.browser_paths.insert(BrowserType::Firefox, path);
                        break;
                    }
                }
            }
        }
        
        // Opera
        let opera_path = appdata_path.join("Opera Software\\Opera Stable");
        if opera_path.exists() {
            self.browser_paths.insert(BrowserType::Opera, opera_path);
        }
    }
    
    fn detect_macos_browsers(&mut self) {
        let home = std::env::var("HOME").unwrap_or_default();
        let home_path = Path::new(&home);
        
        // Chrome
        let chrome_path = home_path.join("Library/Application Support/Google/Chrome/Default");
        if chrome_path.exists() {
            self.browser_paths.insert(BrowserType::Chrome, chrome_path);
        }
        
        // Safari
        let safari_path = home_path.join("Library/Safari");
        if safari_path.exists() {
            self.browser_paths.insert(BrowserType::Safari, safari_path);
        }
        
        // Firefox
        let firefox_path = home_path.join("Library/Application Support/Firefox/Profiles");
        if firefox_path.exists() {
            if let Ok(entries) = fs::read_dir(firefox_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() && path.file_name().unwrap_or_default().to_string_lossy().ends_with(".default") {
                        self.browser_paths.insert(BrowserType::Firefox, path);
                        break;
                    }
                }
            }
        }
    }
    
    fn detect_linux_browsers(&mut self) {
        let home = std::env::var("HOME").unwrap_or_default();
        let home_path = Path::new(&home);
        
        // Chrome
        let chrome_path = home_path.join(".config/google-chrome/Default");
        if chrome_path.exists() {
            self.browser_paths.insert(BrowserType::Chrome, chrome_path);
        }
        
        // Firefox
        let firefox_path = home_path.join(".mozilla/firefox");
        if firefox_path.exists() {
            if let Ok(entries) = fs::read_dir(firefox_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() && path.file_name().unwrap_or_default().to_string_lossy().ends_with(".default") {
                        self.browser_paths.insert(BrowserType::Firefox, path);
                        break;
                    }
                }
            }
        }
    }
    
    fn scan_browsers(&mut self) {
        let now = Instant::now();
        
        for (browser_type, path) in &self.browser_paths {
            // Check if it's time to scan this browser again
            if let Some(last_scan) = self.last_scan_time.get(browser_type) {
                if now.duration_since(*last_scan) < self.scan_interval {
                    continue;
                }
            }
            
            match browser_type {
                BrowserType::Chrome | BrowserType::Edge | BrowserType::Opera => {
                    self.scan_chrome_based_browser(*browser_type, path);
                },
                BrowserType::Firefox => {
                    self.scan_firefox_browser(path);
                },
                BrowserType::Safari => {
                    self.scan_safari_browser(path);
                },
                BrowserType::Unknown => {},
            }
            
            // Update last scan time
            self.last_scan_time.insert(*browser_type, now);
        }
    }
    
    fn scan_chrome_based_browser(&mut self, browser_type: BrowserType, path: &Path) {
        let history_db_path = path.join("History");
        
        if !history_db_path.exists() {
            return;
        }
        
        // Make a copy of the database file since it might be locked by the browser
        let temp_dir = std::env::temp_dir();
        let temp_db_path = temp_dir.join(format!("{}_history.db", browser_type.to_string()));
        
        if let Err(e) = fs::copy(&history_db_path, &temp_db_path) {
            error!("Failed to copy {} history database: {}", browser_type.to_string(), e);
            return;
        }
        
        // Open the database
        match Connection::open(&temp_db_path) {
            Ok(conn) => {
                // Query history
                self.query_chrome_history(&conn, browser_type);
                
                // Query downloads
                self.query_chrome_downloads(&conn, browser_type);
            },
            Err(e) => error!("Failed to open {} history database: {}", browser_type.to_string(), e),
        }
        
        // Remove temporary file
        let _ = fs::remove_file(temp_db_path);
    }
    
    fn query_chrome_history(&mut self, conn: &Connection, browser_type: BrowserType) {
        let query = "SELECT url, title, last_visit_time, visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 1000";
        
        let mut stmt = match conn.prepare(query) {
            Ok(stmt) => stmt,
            Err(e) => {
                error!("Failed to prepare SQL statement for {} history: {}", browser_type.to_string(), e);
                return;
            }
        };
        
        let history_result = stmt.query_map([], |row| {
            Ok(BrowserHistory {
                browser: browser_type,
                url: row.get(0)?,
                title: row.get(1)?,
                visit_time: row.get(2)?,
                visit_count: row.get(3)?,
            })
        });
        
        match history_result {
            Ok(history_rows) => {
                for history in history_rows.flatten() {
                    // Check if this is a new entry
                    if !self.history_entries.iter().any(|h| h.url == history.url && h.visit_time == history.visit_time) {
                        // Check against malicious domains
                        self.check_url_against_blocklists(&history);
                        
                        // Add to history entries
                        self.history_entries.push(history);
                    }
                }
                
                // Keep history under max size
                if self.history_entries.len() > self.max_history_size {
                    self.history_entries.sort_by(|a, b| b.visit_time.cmp(&a.visit_time));
                    self.history_entries.truncate(self.max_history_size);
                }
            },
            Err(e) => error!("Failed to query {} history: {}", browser_type.to_string(), e),
        }
    }
    
    fn query_chrome_downloads(&mut self, conn: &Connection, browser_type: BrowserType) {
        let query = "SELECT target_path, url, start_time, received_bytes, mime_type FROM downloads ORDER BY start_time DESC LIMIT 100";
        
        let mut stmt = match conn.prepare(query) {
            Ok(stmt) => stmt,
            Err(e) => {
                error!("Failed to prepare SQL statement for {} downloads: {}", browser_type.to_string(), e);
                return;
            }
        };
        
        let downloads_result = stmt.query_map([], |row| {
            Ok(BrowserDownload {
                browser: browser_type,
                target_path: row.get(0)?,
                url: row.get(1)?,
                download_time: row.get(2)?,
                file_size: row.get(3)?,
                mime_type: row.get(4)?,
            })
        });
        
        match downloads_result {
            Ok(download_rows) => {
                for download in download_rows.flatten() {
                    // Check if this is a new download
                    if !self.downloads.iter().any(|d| d.url == download.url && d.download_time == download.download_time) {
                        // Check the download
                        self.check_download(&download);
                        
                        // Add to downloads
                        self.downloads.push(download);
                    }
                }
            },
            Err(e) => error!("Failed to query {} downloads: {}", browser_type.to_string(), e),
        }
    }
    
    fn scan_firefox_browser(&mut self, path: &Path) {
        let places_db_path = path.join("places.sqlite");
        
        if !places_db_path.exists() {
            return;
        }
        
        // Make a copy of the database file since it might be locked by the browser
        let temp_dir = std::env::temp_dir();
        let temp_db_path = temp_dir.join("firefox_places.db");
        
        if let Err(e) = fs::copy(&places_db_path, &temp_db_path) {
            error!("Failed to copy Firefox places database: {}", e);
            return;
        }
        
        // Open the database
        match Connection::open(&temp_db_path) {
            Ok(conn) => {
                // Query history
                self.query_firefox_history(&conn);
            },
            Err(e) => error!("Failed to open Firefox places database: {}", e),
        }
        
        // Remove temporary file
        let _ = fs::remove_file(temp_db_path);
    }
    
    fn query_firefox_history(&mut self, conn: &Connection) {
        let query = "SELECT url, title, visit_date, visit_count FROM moz_places JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id ORDER BY visit_date DESC LIMIT 1000";
        
        let mut stmt = match conn.prepare(query) {
            Ok(stmt) => stmt,
            Err(e) => {
                error!("Failed to prepare SQL statement for Firefox history: {}", e);
                return;
            }
        };
        
        let history_result = stmt.query_map([], |row| {
            Ok(BrowserHistory {
                browser: BrowserType::Firefox,
                url: row.get(0)?,
                title: row.get(1)?,
                visit_time: row.get(2)?,
                visit_count: row.get(3)?,
            })
        });
        
        match history_result {
            Ok(history_rows) => {
                for history in history_rows.flatten() {
                    // Check if this is a new entry
                    if !self.history_entries.iter().any(|h| h.url == history.url && h.visit_time == history.visit_time) {
                        // Check against malicious domains
                        self.check_url_against_blocklists(&history);
                        
                        // Add to history entries
                        self.history_entries.push(history);
                    }
                }
                
                // Keep history under max size
                if self.history_entries.len() > self.max_history_size {
                    self.history_entries.sort_by(|a, b| b.visit_time.cmp(&a.visit_time));
                    self.history_entries.truncate(self.max_history_size);
                }
            },
            Err(e) => error!("Failed to query Firefox history: {}", e),
        }
    }
    
    fn scan_safari_browser(&mut self, _path: &Path) {
        // Safari browser history scanning would be implemented here
        // It uses a different storage mechanism (Property Lists)
    }
    
    fn check_url_against_blocklists(&self, history: &BrowserHistory) {
        // Try to extract domain from URL
        let domain = match extract_domain_from_url(&history.url) {
            Some(domain) => domain.to_lowercase(),
            None => return,
        };
        
        // Check against phishing domains
        if self.phishing_domains.contains(&domain) {
            warn!("Visit to known phishing site detected: {} ({})", domain, history.url);
            
            alerts::add_alert(
                alerts::AlertType::Threat,
                "Phishing Site Visited",
                &format!(
                    "A visit to a known phishing site was detected: {}\nBrowser: {}\nTime: {}",
                    domain,
                    history.browser.to_string(),
                    format_timestamp(history.visit_time)
                )
            );
            
            // Generate behavior event
            let mut details = HashMap::new();
            details.insert("url".to_string(), history.url.clone());
            details.insert("browser".to_string(), history.browser.to_string());
            details.insert("timestamp".to_string(), history.visit_time.to_string());
            
            let _ = behavior::process_event(behavior::Event::new(
                behavior::EventType::NetworkConnection,
                &history.browser.to_string(),
                Some(&domain),
                details
            ));
        }
        
        // Check against malware domains
        if self.malware_domains.contains(&domain) {
            warn!("Visit to known malware site detected: {} ({})", domain, history.url);
            
            alerts::add_alert(
                alerts::AlertType::Threat,
                "Malware Site Visited",
                &format!(
                    "A visit to a known malware distribution site was detected: {}\nBrowser: {}\nTime: {}",
                    domain,
                    history.browser.to_string(),
                    format_timestamp(history.visit_time)
                )
            );
            
            // Generate behavior event
            let mut details = HashMap::new();
            details.insert("url".to_string(), history.url.clone());
            details.insert("browser".to_string(), history.browser.to_string());
            details.insert("timestamp".to_string(), history.visit_time.to_string());
            
            let _ = behavior::process_event(behavior::Event::new(
                behavior::EventType::NetworkConnection,
                &history.browser.to_string(),
                Some(&domain),
                details
            ));
        }
    }
    
    fn check_download(&self, download: &BrowserDownload) {
        // Check file extension
        if let Some(ext) = Path::new(&download.target_path).extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            
            // Check if it's a potentially risky file type
            if is_risky_file_type(&ext_str) {
                warn!("Potentially risky file downloaded: {} ({})", download.target_path, ext_str);
                
                let mime_type_str = download.mime_type.as_deref().unwrap_or("unknown");
                
                alerts::add_alert(
                    alerts::AlertType::Warning,
                    "Potentially Risky Download",
                    &format!(
                        "A potentially risky file was downloaded: {}\nType: {}\nSource: {}\nBrowser: {}\nTime: {}",
                        download.target_path,
                        mime_type_str,
                        download.url,
                        download.browser.to_string(),
                        format_timestamp(download.download_time)
                    )
                );
                
                // Generate behavior event
                let mut details = HashMap::new();
                details.insert("url".to_string(), download.url.clone());
                details.insert("path".to_string(), download.target_path.clone());
                details.insert("browser".to_string(), download.browser.to_string());
                details.insert("mime_type".to_string(), mime_type_str.to_string());
                
                let _ = behavior::process_event(behavior::Event::new(
                    behavior::EventType::FileCreated,
                    &download.browser.to_string(),
                    Some(&download.target_path),
                    details
                ));
            }
        }
        
        // Check URL domain
        if let Some(domain) = extract_domain_from_url(&download.url) {
            let domain = domain.to_lowercase();
            
            // Check against malware domains
            if self.malware_domains.contains(&domain) {
                warn!("File downloaded from known malware site: {} ({})", domain, download.url);
                
                alerts::add_alert(
                    alerts::AlertType::Threat,
                    "Malware Download Detected",
                    &format!(
                        "A file was downloaded from a known malware site: {}\nFile: {}\nBrowser: {}\nTime: {}",
                        domain,
                        download.target_path,
                        download.browser.to_string(),
                        format_timestamp(download.download_time)
                    )
                );
            }
        }
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

// Helper function to check if a file type is risky
fn is_risky_file_type(ext: &str) -> bool {
    let risky_exts = [
        "exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "jar", "msi",
        "pif", "scr", "com", "hta", "cpl", "reg", "vbe", "jse", "ws",
        "wsf", "wsc", "wsh", "msc", "lnk",
    ];
    
    risky_exts.contains(&ext)
}

// Helper function to format a timestamp
fn format_timestamp(timestamp: i64) -> String {
    use chrono::{DateTime, Local, TimeZone};
    
    // Convert timestamp to local time
    // Chrome/Edge store time as microseconds since Jan 1, 1601
    // Firefox stores time as microseconds since Jan 1, 1970
    // We'll assume Chrome-style timestamp for now
    
    // First convert to seconds since 1970 (Unix epoch)
    let unix_time = timestamp / 1_000_000 - 11_644_473_600;
    
    if let Some(dt) = Local.timestamp_opt(unix_time, 0).single() {
        dt.format("%Y-%m-%d %H:%M:%S").to_string()
    } else {
        "Invalid timestamp".to_string()
    }
}

// Global monitor instance
static MONITOR: Mutex<Option<BrowserMonitor>> = Mutex::new(None);

pub fn start() -> Result<(), MonitorError> {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return Err(MonitorError::AlreadyRunning);
    }
    
    info!("Starting browser monitoring...");
    
    // Initialize monitor
    let mut monitor = BrowserMonitor::new();
    
    // Detect browsers
    monitor.detect_browsers();
    
    info!("Detected browsers: {}", monitor.browser_paths.len());
    for (browser, path) in &monitor.browser_paths {
        info!("  {}: {}", browser.to_string(), path.display());
    }
    
    // Add default phishing domains (examples)
    for domain in &["phishing-example.com", "fake-bank.example.org"] {
        monitor.add_phishing_domain(domain);
    }
    
    // Add default malware domains (examples)
    for domain in &["malware-distribution.example", "trojan-download.example.net"] {
        monitor.add_malware_domain(domain);
    }
    
    // Store the monitor
    {
        let mut guard = MONITOR.lock().unwrap();
        *guard = Some(monitor);
    }
    
    // Start monitoring thread
    thread::spawn(|| {
        browser_monitor_thread();
    });
    
    Ok(())
}

fn browser_monitor_thread() {
    while RUNNING.load(Ordering::SeqCst) {
        // Get the monitor
        let mut guard = match MONITOR.lock() {
            Ok(guard) => guard,
            Err(e) => {
                error!("Failed to acquire browser monitor lock: {}", e);
                thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        
        let monitor = match &mut *guard {
            Some(monitor) => monitor,
            None => {
                error!("Browser monitor not initialized");
                thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        
        // Scan browsers
        monitor.scan_browsers();
        
        // Release the lock and sleep
        drop(guard);
        thread::sleep(Duration::from_secs(60)); // Check every minute
    }
    
    info!("Browser monitoring thread exited");
}

pub fn stop() -> Result<(), MonitorError> {
    if !RUNNING.swap(false, Ordering::SeqCst) {
        return Err(MonitorError::NotRunning);
    }
    
    info!("Stopping browser monitoring...");
    
    // Clear the monitor
    let mut guard = MONITOR.lock().unwrap();
    *guard = None;
    
    Ok(())
}

pub fn add_phishing_domain(domain: &str) -> Result<(), MonitorError> {
    let mut guard = MONITOR.lock().unwrap();
    
    if let Some(monitor) = &mut *guard {
        monitor.add_phishing_domain(domain);
        Ok(())
    } else {
        Err(MonitorError::NotRunning)
    }
}

pub fn add_malware_domain(domain: &str) -> Result<(), MonitorError> {
    let mut guard = MONITOR.lock().unwrap();
    
    if let Some(monitor) = &mut *guard {
        monitor.add_malware_domain(domain);
        Ok(())
    } else {
        Err(MonitorError::NotRunning)
    }
}

pub fn get_recent_visits(limit: usize) -> Result<Vec<(String, String, String)>, MonitorError> {
    let guard = MONITOR.lock().unwrap();
    
    if let Some(monitor) = &*guard {
        let mut entries = monitor.history_entries.clone();
        entries.sort_by(|a, b| b.visit_time.cmp(&a.visit_time));
        entries.truncate(limit);
        
        let mut result = Vec::new();
        for entry in entries {
            let browser = entry.browser.to_string();
            let url = entry.url;
            let time = format_timestamp(entry.visit_time);
            
            result.push((browser, url, time));
        }
        
        Ok(result)
    } else {
        Err(MonitorError::NotRunning)
    }
}