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
    config::{generate_example_config, get_config_path, read_config},
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
// - Instead of writing to a file, output config to stdout
// - Make config file mandatory
// - Option to delete all records on shutdown
// - Listen to response, if problem try again later

#[derive(Parser)]
struct Args {
    /// Generate an example config file and exit
    #[arg(short, long)]
    generate_config: bool,
    /// Specify an alternative path for the config file
    #[arg(short, long)]
    config_path: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    // Parse args and config
    let args = Args::parse();

    let config_path = args.config_path.unwrap_or_else(|| {
        get_config_path()
            .expect("no default config dir for this system, please specify a path directly")
    });

    if args.generate_config {
        generate_example_config(&config_path);
        println!("Config created at {}", config_path.display());
        return;
    }

    let config = read_config(&config_path).expect("failed to interpret config file");

    let params = Parameters::from_config(config).unwrap();

    let mut ips = find_all_addresses().await.unwrap();

    // First DNS update
    make_and_send_updates(&params, &ips).unwrap();

    // If any IP changes, re-send entire list of IPs
    monitor_changes(&params, &mut ips).await.unwrap();
}
