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

            let mut configs = HashMap::new();

            let mut rdr = csv::Reader::from_path(cli.filename.clone()).context(format!(
                "Failed to read csv from {}",
                cli.filename.display()
            ))?;

            let records: Vec<Record> = rdr.deserialize().collect::<Result<Vec<_>, _>>()?;

            // Create config entries
            for r in &records {
                configs.insert(
                    r.name.clone(),
                    format!(
                        "# {} config generated by mt-wg-mesgconf at {}",
                        r.name,
                        chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
                    ),
                );
            }

            // Wireguard
            records.iter().for_each(|r| {
                configs
                    .get_mut(&r.name)
                    .unwrap()
                    .push_str("\n\n/interface wireguard")
            });

            // bad way to store which enpoint port each peer has to use
            // ((local_peer, remote_peer), port)
            let mut port_assignations = HashMap::new();

            // "server side" config
            for server in &records {
                let mut port = server.port_min.context("no min port set")?;
                for peer in &records {
                    if server.name == peer.name {
                        continue;
                    }
                    configs.get_mut(&server.name).unwrap().push_str(&format!(
                        "\nadd listen-port={} mtu=1420 name={} private-key=\"{}\" comment=mt-wg-meshconf",
                        port,
                        peer.interface,
                        server.privkey.context("missing privkey")?
                    ));
                    port_assignations.insert((server.name.clone(), peer.name.clone()), port);
                    port += 1;
                }
            }

            // "peer side" config

            records.iter().for_each(|r| {
                configs
                    .get_mut(&r.name)
                    .unwrap()
                    .push_str("\n/interface wireguard peers")
            });

            for server in &records {
                for peer in &records {
                    if server.name == peer.name {
                        continue;
                    }
                    configs.get_mut(&server.name).unwrap().push_str(&format!(
                        "\nadd allowed-address=0.0.0.0/0 endpoint-address={} endpoint-port={} interface={} name={} persistent-keepalive={}s public-key=\"{}\" comment=mt-wg-meshconf",
                        peer.endpoint.clone().context("no endpoint address")?,
                        port_assignations.get(&(peer.name.clone(), server.name.clone())).unwrap(),
                        peer.interface,
                        peer.name,
                        peer.keepalive.unwrap_or(0),
                        peer.privkey.context("missing privkey")?.pubkey(),
                    ));
                }
            }

            // Add addresses
            // Add loopback addresses
            records.iter().for_each(|r| {
                configs.get_mut(&r.name).unwrap().push_str(&format!(
                    "\n/ip address\nadd address={}/32 interface=lo comment=mt-wg-meshconf",
                    r.loopback
                ))
            });

            // Add PTP addresses
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

            ptp_addresses.push(*ptp_start_ip);
            for _ in 1..interfaces.len() {
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

            for (ip, r) in ptp_addresses
                .windows(2)
                .zip(interfaces.windows(2))
                .step_by(2)
            {
                configs.get_mut(&r[0].name).unwrap().push_str(&format!(
                    "\nadd address={}/31 interface={} comment=mt-wg-meshconf",
                    ip[0], r[1].interface
                ));

                configs.get_mut(&r[1].name).unwrap().push_str(&format!(
                    "\nadd address={}/31 interface={} comment=mt-wg-meshconf",
                    ip[1], r[0].interface
                ));
            }

            for (node, config) in configs {
                println!("{node}:\n{config}");
            }
        }
        None => {}
    }
    Ok(())
}
