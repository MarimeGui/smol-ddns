mod config;
mod dns_protocol;
#[cfg(target_os = "linux")]
mod linux_monitoring;
mod params;
mod signing;
mod update;

use std::path::PathBuf;

use clap::Parser;

use crate::{
    config::{ConfigFile, example_yaml_config},
    linux_monitoring::{find_all_addresses, monitor_changes},
    params::Parameters,
    update::make_and_send_updates,
};

// TODO LIST
// - Generate PTR records from IPs and prefix lengths
// - Windows IP monitor
// - For certain HWaddresses, use a specific set of names. Have a default for all other interfaces, with a white/blacklist
// - Retrieve default nameserver
// - There might be multiple GUAs (temporary address), is it possible to check which one we want ?
// - Only delete A or AAAA records if the correct version is associated with the name
// - Generate personalized config file with command line
// - Option to delete all records on shutdown
// - Currently relying on init system to restart if anything goes wrong... Should we try again here ?
// - Maybe have a separate file instead of serializing the example

#[derive(Parser)]
enum Args {
    /// Print out an example config then quits
    ExampleConfig,
    /// Run the daemon, provided a config file
    Run {
        /// Path to the config file
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    // Parse args and config
    let args = Args::parse();

    let config_path = match args {
        Args::ExampleConfig => {
            // Simply print the example and quit
            println!("{}", example_yaml_config());
            return;
        }
        Args::Run { config } => config,
    };

    let config = ConfigFile::from_file(&config_path).expect("failed to interpret config file");

    let params = Parameters::from_config(config).unwrap();

    println!("Using server at {}", params.server_socket_addr.ip());

    let mut ips = find_all_addresses().await.unwrap();
    println!("Initial IPs: {:?}", ips.keys());

    // First DNS update
    make_and_send_updates(&params, &ips).unwrap();

    // If any IP changes, re-send entire list of IPs
    monitor_changes(&params, &mut ips).await.unwrap();
}
