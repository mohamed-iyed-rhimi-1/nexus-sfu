use crate::config::{validation::ConfigError, ConfigLoader, NexusConfig};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

pub struct ConfigWatcher {
    config: Arc<RwLock<NexusConfig>>,
    _watcher: RecommendedWatcher,
    _path: PathBuf,
}

impl ConfigWatcher {
    pub fn new(path: PathBuf, initial_config: NexusConfig) -> Result<Self, ConfigError> {
        let config = Arc::new(RwLock::new(initial_config));
        let config_clone = Arc::clone(&config);
        let path_clone = path.clone();

        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                if event.kind.is_modify() {
                    // Reload config on file modification
                    match ConfigLoader::from_file(&path_clone) {
                        Ok(mut new_config) => {
                            // Apply environment variable overrides to maintain precedence
                            match ConfigLoader::merge_from_env(new_config) {
                                Ok(merged_config) => {
                                    new_config = merged_config;
                                }
                                Err(e) => {
                                    error!("Hot-reload: failed to merge env overrides: {}", e);
                                    return;
                                }
                            }

                            // Validate the new configuration before applying
                            if let Err(e) = new_config.validate() {
                                error!("Hot-reload: invalid configuration, skipping reload: {}", e);
                                return;
                            }

                            // Only reload control plane settings
                            let rt = tokio::runtime::Handle::try_current();
                            if let Ok(handle) = rt {
                                let config_clone = Arc::clone(&config_clone);
                                handle.spawn(async move {
                                    let mut config = config_clone.write().await;
                                    config.reload_control_plane(&new_config);
                                    info!("Configuration reloaded (control plane settings only)");
                                });
                            }
                        }
                        Err(e) => {
                            error!("Hot-reload: failed to load config file: {}", e);
                        }
                    }
                }
            }
        })
        .map_err(|e| ConfigError::load_error(&format!("failed to create watcher: {}", e)))?;

        watcher
            .watch(&path, RecursiveMode::NonRecursive)
            .map_err(|e| ConfigError::load_error(&format!("failed to watch config file: {}", e)))?;

        Ok(Self {
            config,
            _watcher: watcher,
            _path: path,
        })
    }

    pub fn config(&self) -> Arc<RwLock<NexusConfig>> {
        Arc::clone(&self.config)
    }
}
