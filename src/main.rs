use clap::{Parser, Subcommand};
use serde_with::{StringWithSeparator, serde_as};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::{cmp::min, path::PathBuf};

use rand::prelude::*;

use serde::{Deserialize, Serialize};
use serde_with::formats::SemicolonSeparator;

use anyhow::{Context, Result, anyhow};

use wireguard_keys::Privkey;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// csv file path
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
        /// The first ip to use for ptp links between wg peers
        #[arg(short, long)]
        ptp_start_ip: IpAddr,

        /// Use OSPF igp
        #[arg(short, long, default_value_t = true)]
        ospf: bool,

        /// Use EVPN with vxlan
        #[arg(short, long, default_value_t = true)]
        evpn: bool,

        /// Use EVPN with vxlan
        #[arg(short, long, default_value_t = 65001)]
        as_num: u32,

        /// Anycast gateway vlans
        #[arg(short, long, value_delimiter = ',')]
        vlans: Option<Vec<u16>>,

        /// Anycast gateway addresses
        #[arg(long, value_delimiter = ',')]
        anycast_addresses: Option<Vec<IpAddr>>,
    },
}

#[serde_as]
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
    #[serde_as(as = "Option<StringWithSeparator::<SemicolonSeparator, u16>>")]
    vlan: Option<Vec<u16>>,
    #[serde_as(as = "Option<StringWithSeparator::<SemicolonSeparator, String>>")]
    vlan_ifs: Option<Vec<String>>,
    #[serde_as(as = "Option<StringWithSeparator::<SemicolonSeparator, String>>")]
    ifs_ips: Option<Vec<String>>,
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
                vlan: Some(vec![100, 101]),
                vlan_ifs: Some(vec!["ether2".to_owned(), "ether3".to_owned()]),
                ifs_ips: Some(vec![
                    "192.168.0.5/24".to_owned(),
                    "192.168.1.5/24".to_owned(),
                ]),
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

                if let Some(ips) = record.ifs_ips {
                    for ip in ips {
                        if !ip.contains("/") {
                            return Err(anyhow!(format!(
                                "{}: {} {}: {ip} doesn't have netmask",
                                cli.filename.display(),
                                i,
                                record.name
                            )));
                        }
                    }
                }
            }
            println!("{}: {} nodes are valid", cli.filename.display(), nodes);
        }
        Some(Commands::GenConfig {
            ptp_start_ip,
            ospf,
            evpn,
            as_num,
            vlans,
            anycast_addresses,
        }) => {
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
                        "# {} config generated by mt-wg-meshconf at {}",
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
                    .push_str("\n\n/interface wireguard\nremove [find comment=\"mt-wg-meshconf\"]")
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
                configs.get_mut(&r.name).unwrap().push_str(
                    "\n/interface wireguard peers\nremove [find comment=\"mt-wg-meshconf\"]",
                )
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
                    "\n\n/ip address\nremove [find comment=\"mt-wg-meshconf\"]\nadd address={}/32 interface=lo comment=mt-wg-meshconf",
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

            // OSPF
            if *ospf {
                records.iter().for_each(|r| {
                    configs.get_mut(&r.name).unwrap().push_str(
                        &format!("\n\n/routing ospf instance\nremove [find comment=\"mt-wg-meshconf\"]\nadd disabled=no name=ospf-ipv4 router-id={} comment=mt-wg-meshconf", r.loopback),
                    )
                });
                records.iter().for_each(|r| {
                    configs.get_mut(&r.name).unwrap().push_str(
                        "\n/routing ospf area\nremove [find comment=\"mt-wg-meshconf\"]\nadd disabled=no instance=ospf-ipv4 name=area0-ipv4 comment=mt-wg-meshconf",
                    )
                });
                records.iter().for_each(|r| {
                    configs.get_mut(&r.name).unwrap().push_str(
                        "\n/routing ospf interface-template\nremove [find comment=\"mt-wg-meshconf\"]\nadd area=area0-ipv4 disabled=no interfaces=lo passive comment=mt-wg-meshconf",
                    )
                });
                // add individual ospf adjutancies

                records.iter().for_each(|r| {
                    let mut if_list = String::new();
                    for b in &records {
                        if r.name == b.name {
                            continue;
                        }
                        dbg!(&b.interface);
                        if_list.push_str(&format!("{},", b.interface));
                    }
                    if_list.pop();
                    configs.get_mut(&r.name).unwrap().push_str(
                        &format!("\nadd area=area0-ipv4 disabled=no interfaces={if_list} type=ptp comment=mt-wg-meshconf"),
                    )
                });
            }

            // EVPN
            if *evpn {
                // Bridge

                records.iter().for_each(|r| {
                    configs
                        .get_mut(&r.name)
                        .unwrap()
                        .push_str("\n\n/interface bridge\nremove [find comment=\"mt-wg-meshconf\"]\nadd name=wg-mesh-br vlan-filtering=yes comment=mt-wg-meshconf")
                });
                records.iter().for_each(|r| {
                    configs.get_mut(&r.name).unwrap().push_str(
                        "\n/interface bridge port\nremove [find comment=\"mt-wg-meshconf\"]",
                    )
                });
                records.iter().try_for_each(|r| {
                    let ifs = r.vlan_ifs.clone().context("no vlan if set")?;
                    let vlans = r.vlan.clone().context("no vlan set")?;
                    for (i, vlan) in ifs.iter().zip(vlans) {
                    configs.get_mut(&r.name).unwrap().push_str(&format!("\nadd bridge=wg-mesh-br frame-types=admit-only-untagged-and-priority-tagged interface={i} pvid={vlan} comment=mt-wg-meshconf"));
                    }
                    Ok::<(), anyhow::Error>(())
                }).context("vlan error")?;

                // VXLAN
                records.iter().for_each(|r| {
                    configs
                        .get_mut(&r.name)
                        .unwrap()
                        .push_str("\n\n/interface vxlan\nremove [find comment=\"mt-wg-meshconf\"]")
                });
                records.iter().try_for_each(|r| {
                    for vlan in r.vlan.clone().context("no vlan set")? {
                        configs.get_mut(&r.name).unwrap().push_str(&format!("\nadd bridge=wg-mesh-br bridge-pvid={} dont-fragment=disabled learning=no local-address={} name=vxlan1000{} vni=1000{} comment=mt-wg-meshconf", vlan, r.loopback, vlan, vlan));
                    }
                    Ok::<(), anyhow::Error>(())
                }).context("vxlan error")?;

                // BGP
                records.iter().for_each(|r| {
                    configs.get_mut(&r.name).unwrap().push_str(
                        &format!("\n\n/routing bgp instance\nremove [find comment=\"mt-wg-meshconf\"]\nadd as={as_num} disabled=no name=wg-mesh-bgp router-id={} comment=mt-wg-meshconf", r.loopback),
                    )
                });
                records.iter().for_each(|r| {
                    configs.get_mut(&r.name).unwrap().push_str(
                        "\n/routing bgp connection\nremove [find comment=\"mt-wg-meshconf\"]",
                    )
                });
                records.iter().try_for_each(|r| {
                    for b in &records {
                        if r.name == b.name {
                            continue;
                        }
                    configs.get_mut(&r.name).unwrap().push_str(&format!("\nadd afi=evpn connect=yes disabled=no instance=wg-mesh-bgp listen=yes local.address={} .role=ibgp name={} remote.address={}/32 .as={} comment=mt-wg-meshconf",
                        r.loopback, b.interface, b.loopback, as_num,
                    ));
                    }
                    Ok::<(), anyhow::Error>(())
                }).context("vxlan error")?;

                // EVPN
                records.iter().for_each(|r| {
                    configs
                        .get_mut(&r.name)
                        .unwrap()
                        .push_str("\n\n/routing bgp evpn\nremove [find comment=\"mt-wg-meshconf\"]")
                });
                records.iter().try_for_each(|r| {
                    for vlan in r.vlan.clone().context("no vlan set")? {
                    configs.get_mut(&r.name).unwrap().push_str(&format!("\nadd export.route-targets={as_num}:1000{vlan} import.route-targets={as_num}:1000{vlan} instance=wg-mesh-bgp name=wg-mesh-evpn-1000{vlan} vni=1000{vlan} comment=mt-wg-meshconf"));
                    }
                    Ok::<(), anyhow::Error>(())
                }).context("vxlan error")?;
            }

            // Vlans IP
            records.iter().for_each(|r| {
                configs
                    .get_mut(&r.name)
                    .unwrap()
                    .push_str("\n\n/interface vlan\nremove [find comment=\"mt-wg-meshconf\"]")
            });

            records.iter().try_for_each(|r| {
                for vlan in r.vlan.clone().context("no vlan set")? {
                    configs.get_mut(&r.name).unwrap().push_str(&format!("\nadd interface=wg-mesh-br name=vlan{vlan} vlan-id={vlan} comment=mt-wg-meshconf"));
                }
                Ok::<(), anyhow::Error>(())
            }).context("vlan interface error")?;

            records
                .iter()
                .for_each(|r| configs.get_mut(&r.name).unwrap().push_str("\n/ip address"));

            records
                .iter()
                .try_for_each(|r| {
                    if let Some(ifs_ips) = &r.ifs_ips {
                        for (ip, vlan) in ifs_ips.iter().zip(r.vlan.clone().context("no vlan set")?)
                        {
                            configs.get_mut(&r.name).unwrap().push_str(&format!(
                                "\nadd address={ip} interface=vlan{vlan} comment=mt-wg-meshconf"
                            ));
                        }
                    }
                    Ok::<(), anyhow::Error>(())
                })
                .context("vlan address error")?;

            // Anycast gateways

            if let Some(vlans) = vlans
                && let Some(addrs) = anycast_addresses
            {
                if vlans.len() != addrs.len() {
                    return Err(anyhow!(
                        "Numbers of vlans and anycast addresses don't match"
                    ));
                }
                // One anycast mac address for each vlan
                let mut rng = rand::rng();

                // Create macvlans
                records.iter().for_each(|r| {
                    configs.get_mut(&r.name).unwrap().push_str(
                        "\n\n/interface macvlan\nremove [find comment=\"mt-wg-meshconf\"]",
                    )
                });

                for vlan in vlans {
                    let mut data = [0u8; 6];
                    rng.fill_bytes(&mut data);
                    data[0] |= 0x02; // Locally administerred
                    data[0] &= 0xFE; // Unicast
                    let mac = macaddr::MacAddr6::from(data);
                    records.iter().for_each(|r| {
                        configs.get_mut(&r.name).unwrap().push_str(&format!(
                            "\nadd interface=vlan{vlan} mac-address={mac} name=macvlan-wg-{vlan} comment=mt-wg-meshconf"),
                        )
                    });
                }

                // Add ip addresses
                records
                    .iter()
                    .for_each(|r| configs.get_mut(&r.name).unwrap().push_str("\n/ip address"));

                records.iter().for_each(|r| {
                    for (vlan, addr) in vlans.iter().zip(addrs) {
                        configs.get_mut(&r.name).unwrap().push_str(&format!(
                            "\nadd interface=macvlan-wg-{vlan} address={addr} comment=mt-wg-meshconf"),
                        )
                    }
                });
            }

            for (node, config) in configs {
                println!("{node}:\n{config}");
            }
        }
        None => {}
    }
    Ok(())
}
