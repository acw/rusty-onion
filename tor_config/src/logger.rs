use chrono;
use fern;
use log::LogLevelFilter;
use std::io;

#[derive(Deserialize)]
pub struct LoggingConfig {
    default: Option<String>,
    consensus: Option<String>,
    directories: Option<String>,
    key_manager: Option<String>,
    target: Option<String>
}

pub const DEFAULT_LOGGING_CONFIG: LoggingConfig = LoggingConfig {
    default: None,
    consensus: None,
    directories: None,
    key_manager: None,
    target: None
};

pub fn start_logger(config: &LoggingConfig) {
    let mut f: fern::Dispatch = fern::Dispatch::new();

    f = f.format(|out, message, record| {
                     out.finish(format_args!("{} {}/{}: {}",
                          chrono::Local::now().format("[%Y-%m-%d %H:%M:%S]"),
                          record.target(),
                          record.level(),
                          message))
                  });

    match config.target {
        None       => f = f.chain(io::stderr()),
        Some(ref file) =>
            match fern::log_file(file) {
                Err(e) =>
                    panic!("Couldn't prep log file {:?}", e),
                Ok(lf) =>
                    f = f.chain(lf)
            }
    }

    match config.default {
        None        => f = f.level(LogLevelFilter::Info),
        Some(ref x) => f = f.level(to_log_level(x))
    }

    match config.consensus {
        None        => (),
        Some(ref x) => f = f.level_for("DIRECTORIES", to_log_level(x))
    }

    match config.directories {
        None        => (),
        Some(ref x) => f = f.level_for("DIRECTORIES", to_log_level(x))
    }

    match config.key_manager {
        None        => (),
        Some(ref x) => f = f.level_for("KEYS", to_log_level(x))
    }

    match f.apply() {
        Ok(_) => (),
        Err(e) =>
            panic!("Failure in final initialization of logger: {:?}", e)
    }
}

fn to_log_level(s: &String) -> LogLevelFilter {
    match s.to_lowercase().as_ref() {
        "off"   => LogLevelFilter::Off,
        "error" => LogLevelFilter::Error,
        "warn"  => LogLevelFilter::Warn,
        "info"  => LogLevelFilter::Info,
        "debug" => LogLevelFilter::Debug,
        "trace" => LogLevelFilter::Trace,
        _       => panic!("Couldn't translate log level {:?}", s)
    }
}
