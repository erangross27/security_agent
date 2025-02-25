use std::path::PathBuf;
use std::fs;
use std::io;
use log::info;
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub general: GeneralConfig,
    pub monitoring: MonitoringConfig,
    pub protection: ProtectionConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub auto_start: bool,
    pub log_level: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub enable_process_monitoring: bool,
    pub enable_file_monitoring: bool,
    pub enable_network_monitoring: bool,
    pub enable_browser_monitoring: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProtectionConfig {
    pub block_suspicious_processes: bool,
    pub block_suspicious_network: bool,
    pub prevent_phishing: bool,
    pub prevent_social_engineering: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            general: GeneralConfig {
                auto_start: true,
                log_level: "info".to_string(),
            },
            monitoring: MonitoringConfig {
                enable_process_monitoring: true,
                enable_file_monitoring: true,
                enable_network_monitoring: true,
                enable_browser_monitoring: true,
            },
            protection: ProtectionConfig {
                block_suspicious_processes: true,
                block_suspicious_network: true,
                prevent_phishing: true,
                prevent_social_engineering: true,
            },
        }
    }
}

pub fn load() -> Result<Config, io::Error> {
    let config_path = get_config_path()?;
    
    if !config_path.exists() {
        info!("Config file not found, creating default config");
        let default_config = Config::default();
        save(&default_config)?;
        return Ok(default_config);
    }
    
    let config_data = fs::read_to_string(config_path)?;
    let config: Config = serde_json::from_str(&config_data)?;
    
    Ok(config)
}

pub fn save(config: &Config) -> Result<(), io::Error> {
    let config_path = get_config_path()?;
    
    // Ensure directory exists
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)?;
    }
    
    let config_json = serde_json::to_string_pretty(config)?;
    fs::write(config_path, config_json)?;
    
    Ok(())
}

fn get_config_path() -> Result<PathBuf, io::Error> {
    let dirs = directories::ProjectDirs::from("com", "securityagent", "securityagent")
        .ok_or(io::Error::new(io::ErrorKind::NotFound, "Could not determine config directory"))?;
    
    let config_dir = dirs.config_dir();
    Ok(config_dir.join("config.json"))
}