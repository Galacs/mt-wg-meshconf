use clap::{Parser, Subcommand};
use std::{cmp::min, path::PathBuf};

use anyhow::{Context, Result, anyhow};

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

    /// Generate missing private keys
    GenPrivkeys,

    /// Check csv for duplicate and other configuration issues
    Check,
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Record {
    name: String,
    interface: String,
    endpoint: Option<String>,
    port_min: Option<u16>,
    port_max: Option<u16>,
    keepalive: Option<u64>,
    privkey: Option<Privkey>,
}

fn main() -> Result<()> {
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
            println!("{} was created.", cli.filename.to_str().unwrap());
            wtr.flush().unwrap();
        }
        Some(Commands::GenPrivkeys) => {
            let mut rdr = csv::Reader::from_path(cli.filename.clone()).unwrap();
            let mut generated_privkeys: u32 = 0;
            let mut records = vec![];

            for result in rdr.deserialize() {
                let mut record: Record = result.unwrap();
                if record.privkey.is_none() {
                    record.privkey = Some(Privkey::generate());
                    generated_privkeys += 1;
                }
                records.push(record);
            }

            let mut wtr = csv::Writer::from_path(cli.filename.clone()).unwrap();
            records.iter().for_each(|r| wtr.serialize(r).unwrap());
            wtr.flush().unwrap();

            if generated_privkeys > 0 {
                println!("{generated_privkeys} key(s) were generated");
            } else {
                println!("no keys were generated");
            }
        }
        Some(Commands::Check) => {
            // Number of nodes (will be optimized)
            let nodes = csv::Reader::from_path(cli.filename.clone())?
                .deserialize::<Record>()
                .count() as u16;

            // Not enough port Check
            let mut rdr = csv::Reader::from_path(cli.filename.clone()).unwrap();
            let mut smallest_port_range = u16::MAX;
            for (i, result) in (2..).zip(rdr.deserialize()) {
                let record: Record = result.unwrap();
                if let Some(port_min) = record.port_min
                    && let Some(port_max) = record.port_max
                {
                    let range = port_max.checked_sub(port_min).context(format!(
                        "{}:{} {}: invalid port range port_min > port_max",
                        cli.filename.display(),
                        i,
                        record.name
                    ))? + 1;

                    if range < nodes {
                        Err(anyhow!(format!(
                            "{}:{} {}: needs {} listening ports, but only {} were allowed ({}-{})",
                            cli.filename.display(),
                            i,
                            record.name,
                            nodes,
                            range,
                            port_min,
                            port_max
                        )))?;
                    }

                    smallest_port_range = min(smallest_port_range, range);
                }
            }
            println!("{}: {} nodes are valid", cli.filename.display(), nodes);
        }
        None => {}
    }
    Ok(())
}
