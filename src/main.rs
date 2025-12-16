use clap::{Parser, Subcommand};
use std::path::PathBuf;

use wireguard_keys::Privkey;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long, default_value = "mesh.csv")]
    filename: PathBuf,

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
            let mut wtr = csv::Writer::from_path(cli.filename.clone()).unwrap();
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
            wtr.flush().unwrap();
            println!("{} was created.", cli.filename.to_str().unwrap());
        }
        None => {}
    }
}
