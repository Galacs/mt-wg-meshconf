use clap::{Parser, Subcommand};
use std::{error::Error, io, process};

use wireguard_keys::Privkey;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long, default_value = "mesh.csv")]
    filename: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initializes the csv file to store peer information
    Init,
}

use serde::Serialize;

#[derive(Debug, Serialize)]
struct Record {
    name: String,
    interface: String,
    endpoint: Option<String>,
    port_min: Option<u16>,
    port_max: Option<u16>,
    keepalive: Option<u64>,
    privkey: Option<Privkey>,
}

fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Some(Commands::Init) => {
            println!("on init la db....");
        }
        None => {}
    }

    let mut wtr = csv::Writer::from_writer(io::stdout());
    // Add example
    wtr.serialize(Record {
        name: "node1".to_owned(),
        interface: "node1".to_owned(),
        endpoint: Some("10.200.0.10".to_owned()),
        port_min: Some(1000),
        port_max: Some(1050),
        keepalive: Some(25),
        privkey: Some(Privkey::generate()),
    })
    .unwrap();

    // Continued program logic goes here...
}
