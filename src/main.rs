use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
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

    /// Generate mikrotik config
    GenConfig {
        #[arg(short, long)]
        ptp_start_ip: IpAddr,
    },
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Record {
    name: String,
    interface: String,
    endpoint: Option<String>,
    loopback: IpAddr,
    port_min: Option<u16>,
    port_max: Option<u16>,
    keepalive: Option<u64>,
    privkey: Option<Privkey>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Init) => {
            let mut wtr = csv::Writer::from_path(cli.filename.clone())
                .context(format!("Failed to write csv to {}", cli.filename.display()))?;
            wtr.serialize(Record {
                name: "node1".to_owned(),
                interface: "node1".to_owned(),
                endpoint: Some("10.200.0.10".to_owned()),
                loopback: IpAddr::V4(Ipv4Addr::new(10, 69, 0, 10)),
                port_min: Some(1000),
                port_max: Some(1050),
                keepalive: Some(25),
                privkey: Some(Privkey::generate()),
            })?;
            println!(
                "{} was created.",
                cli.filename.to_str().context("filename error")?
            );
            wtr.flush()
                .context(format!("Failed to write to {}", cli.filename.display()))?;
        }
        Some(Commands::GenPrivkeys) => {
            let mut rdr = csv::Reader::from_path(cli.filename.clone()).context(format!(
                "Failed to read csv from {}",
                cli.filename.display()
            ))?;
            let mut generated_privkeys: u32 = 0;
            let mut records = vec![];

            for result in rdr.deserialize() {
                let mut record: Record = result?;
                if record.privkey.is_none() {
                    record.privkey = Some(Privkey::generate());
                    generated_privkeys += 1;
                }
                records.push(record);
            }

            let mut wtr = csv::Writer::from_path(cli.filename.clone())
                .context(format!("Failed to write csv to {}", cli.filename.display()))?;
            records
                .iter()
                .try_for_each(|r| wtr.serialize(r).context("csv reading error"))?;
            wtr.flush()
                .context(format!("Failed to write to {}", cli.filename.display()))?;

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

            let mut rdr = csv::Reader::from_path(cli.filename.clone()).context(format!(
                "Failed to read csv from {}",
                cli.filename.display()
            ))?;

            let mut maps: Vec<HashMap<String, usize>> = vec![];
            for _ in 0..4 {
                maps.push(HashMap::new());
            }

            let mut smallest_port_range = u16::MAX;
            for (i, result) in (2..).zip(rdr.deserialize()) {
                let record: Record = result?;

                // Check for duplicate name, interface, loopback, privkey
                for ((k, field), field_name) in [
                    record.name.clone(),
                    record.interface,
                    record.loopback.to_string(),
                    record
                        .privkey
                        .context(format!(
                            "{}: {} {}: missing privkey",
                            cli.filename.display(),
                            i,
                            record.name,
                        ))?
                        .to_string(),
                ]
                .iter()
                .enumerate()
                .zip(["name", "interface", "loopback", "privkey"])
                {
                    if let Some(prev_record) = maps[k].get(field) {
                        Err(anyhow!(format!(
                            "{}:{} {}: duplicate {} found on line {}",
                            cli.filename.display(),
                            prev_record,
                            record.name,
                            field_name,
                            i
                        )))?;
                    } else {
                        maps[k].insert(field.to_owned(), i);
                    }
                }

                // Not enough port Check
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
        Some(Commands::GenConfig { ptp_start_ip }) => {
            // Generate PTP ip pairs

            let mut rdr = csv::Reader::from_path(cli.filename.clone()).context(format!(
                "Failed to read csv from {}",
                cli.filename.display()
            ))?;

            let records: Vec<Record> = rdr.deserialize().collect::<Result<Vec<_>, _>>()?;

            let mut interfaces = vec![];
            let mut ptp_addresses = vec![];
            for (i, a) in records.iter().enumerate() {
                let mut x = 1;
                for b in records.iter().skip(x + i) {
                    interfaces.append(&mut vec![a, b]);
                    x += 1;

                    // Generate addresses pairs
                }
            }

            for i in &interfaces {
                dbg!(&i.interface);
            }

            for _ in 0..interfaces.len() {
                let ptp_next_ip = match ptp_addresses.last().unwrap_or(ptp_start_ip) {
                    IpAddr::V4(ip4) => {
                        IpAddr::from((u32::from_be_bytes(ip4.octets()) + 1).to_be_bytes())
                    }
                    IpAddr::V6(ip6) => {
                        IpAddr::from((u128::from_be_bytes(ip6.octets()) + 1).to_be_bytes())
                    }
                };
                ptp_addresses.push(ptp_next_ip);
            }
            dbg!(&ptp_addresses);

            for (ip, r) in ptp_addresses
                .windows(2)
                .zip(interfaces.windows(2))
                .step_by(2)
            {
                println!("on {}:", r[0].name);
                println!("add address={}/31 interface={}", ip[0], r[1].interface);
                println!("on {}:", r[1].name);
                println!("add address={}/31 interface={}", ip[1], r[0].interface);
                println!();
            }
        }
        None => {}
    }
    Ok(())
}
