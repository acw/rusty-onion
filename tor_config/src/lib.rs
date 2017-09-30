extern crate chrono;
extern crate fern;
extern crate log;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate toml;
extern crate xdg;

mod logger;

use logger::{LoggingConfig,DEFAULT_LOGGING_CONFIG,start_logger};
use std::fmt;
use std::fs::File;
use std::io::{Error,Read};
use xdg::{BaseDirectories,BaseDirectoriesError};

#[derive(Clone,Deserialize)]
pub struct Config {
    pub log: LoggingConfig,
    pub security: SecurityConfig,
    pub relay: RelayConfig
}

#[derive(Clone,Deserialize)]
pub struct SecurityConfig {
    pub minimum_consensus_signatures: u32,
    pub import_authorities_from_consensus: bool
}

#[derive(Clone,Deserialize)]
pub struct RelayConfig {
    pub or_port: Option<u16>
}

pub enum ConfigError {
    XdgError(BaseDirectoriesError),
    ConfigParseError(toml::de::Error),
    IOError(Error)
}

impl fmt::Debug for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &ConfigError::XdgError(ref bde) =>
                write!(f, "Failed to get XDG info: {}", bde),
            &ConfigError::ConfigParseError(ref e) =>
                write!(f, "Failed to parse config file: {}", e),
            &ConfigError::IOError(ref e) =>
                write!(f, "Error reading config file: {}", e)
        }
    }
}

impl From<BaseDirectoriesError> for ConfigError {
    fn from(err: BaseDirectoriesError) -> ConfigError {
        ConfigError::XdgError(err)
    }
}

impl From<Error> for ConfigError {
    fn from(err: Error) -> ConfigError {
        ConfigError::IOError(err)
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(err: toml::de::Error) -> ConfigError {
        ConfigError::ConfigParseError(err)
    }
}

pub fn load_config() -> Result<Config,ConfigError> {
    let xdg = try!(BaseDirectories::with_prefix(env!("CARGO_PKG_NAME")));

    let res: Config = match xdg.find_config_file("config.ini") {
        None =>
            Config {
                    log: DEFAULT_LOGGING_CONFIG,
                    security: SecurityConfig {
                        minimum_consensus_signatures: 5,
                        import_authorities_from_consensus: true
                    },
                    relay: RelayConfig {
                        or_port: None
                    }
             },
        Some(path) => {
            let mut file = try!(File::open(path));
            let mut buffer: String = String::new();
            try!(file.read_to_string(&mut buffer));
            let v: Config = try!(toml::from_str(buffer.as_str()));
            v
        }
    };

    start_logger(&res.log);
    Ok(res)
}

