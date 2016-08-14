#[macro_use]
extern crate clap;
#[macro_use]
extern crate lazy_static;
extern crate pnet;
extern crate ipnetwork;
extern crate rips;

use std::io::{Read, Write};
use std::process;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::str::FromStr;

use pnet::datalink::{self, NetworkInterface};

use ipnetwork::Ipv4Network;

use rips::udp::UdpSocket;

lazy_static! {
    static ref DEFAULT_ROUTE: Ipv4Network = Ipv4Network::from_cidr("0.0.0.0/0").unwrap();
}

macro_rules! eprintln {
    ($($arg:tt)*) => (
        match writeln!(&mut ::std::io::stderr(), $($arg)* ) {
            Ok(_) => {},
            Err(x) => panic!("Unable to write to stderr: {}", x),
        }
    )
}

fn main() {
    let args = ArgumentParser::new();

    let (iface, rips_iface) = args.get_iface();
    let src_net = args.get_src_net();
    let gw = args.get_gw();
    let channel = args.create_channel();
    let src = SocketAddr::V4(SocketAddrV4::new(src_net.ip(), 9999));
    let dst = args.get_dst();

    eprintln!("iface: {}", &iface.name);
    eprintln!("src net: {}", &src_net);
    eprintln!("Connecting to {}", dst);

    let mut stack = rips::NetworkStack::new();
    stack.add_interface(rips_iface.clone(), channel).unwrap();
    stack.add_ipv4(&rips_iface, src_net).unwrap();
    {
        let routing_table = stack.routing_table();
        routing_table.add_route(*DEFAULT_ROUTE, Some(gw), rips_iface);
    }

    let stack = Arc::new(Mutex::new(stack));
    let socket = UdpSocket::bind(stack, src).unwrap();

    send_stdin(socket, dst);
}

fn send_stdin(mut socket: UdpSocket, dst: SocketAddr) {
    let stdin = std::io::stdin();
    let mut handle = stdin.lock();
    let mut buffer = vec![0; 1024*64];
    while let Ok(len) = handle.read(&mut buffer) {
        if let Err(e) = socket.send_to(&buffer[..len], dst) {
            eprintln!("Error while sending on the network: {}", e);
            process::exit(1);
        }
    }
}

struct ArgumentParser {
    app: clap::App<'static, 'static>,
    matches: clap::ArgMatches<'static>,
}

impl ArgumentParser {
    pub fn new() -> ArgumentParser {
        let app = Self::create_app();
        let matches = app.clone().get_matches();
        ArgumentParser {
            app: app,
            matches: matches,
        }
    }

    pub fn get_iface(&self) -> (NetworkInterface, rips::Interface) {
        let iface_name = self.matches.value_of("iface").unwrap();
        for iface in datalink::interfaces().into_iter() {
            if iface.name == iface_name {
                if let Ok(rips_iface) = rips::convert_interface(&iface) {
                    return (iface, rips_iface);
                } else {
                    self.print_error(&format!("Interface {} can't be used with rips", iface_name));
                }
            }
        }
        self.print_error(&format!("Found no interface named {}", iface_name));
    }

    pub fn get_src_net(&self) -> Ipv4Network {
        if let Some(src_net) = self.matches.value_of("src_net") {
            match Ipv4Network::from_cidr(src_net) {
                Ok(src_net) => src_net,
                Err(_) => self.print_error("Invalid CIDR"),
            }
        } else {
            let (iface, _) = self.get_iface();
            if let Some(ips) = iface.ips.as_ref() {
                for ip in ips {
                    if let &IpAddr::V4(ip) = ip {
                        return Ipv4Network::new(ip, 24).unwrap();
                    }
                }
            }
            self.print_error("No IPv4 to use on given interface");
        }
    }

    pub fn get_gw(&self) -> Ipv4Addr {
        if let Some(gw_str) = self.matches.value_of("gw") {
            if let Ok(gw) = Ipv4Addr::from_str(gw_str) {
                gw
            } else {
                self.print_error("Unable to parse gateway ip");
            }
        } else {
            let src_net = self.get_src_net();
            if let Some(gw) = src_net.nth(1) {
                gw
            } else {
                self.print_error(&format!("Could not guess a default gateway inside {}", src_net));
            }
        }
    }

    pub fn get_dst(&self) -> SocketAddr {
        let matches = &self.matches;
        match value_t!(matches, "target", SocketAddr) {
            Ok(dst) => dst,
            Err(e) => self.print_error(&format!("Invalid target. {}", e)),
        }
    }

    pub fn create_channel(&self) -> rips::EthernetChannel {
        let (iface, _) = self.get_iface();
        let config = datalink::Config::default();
        match datalink::channel(&iface, config) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => rips::EthernetChannel(tx, rx),
            _ => self.print_error(&format!("Unable to open network channel on {}", iface.name)),
        }
    }

    fn create_app() -> clap::App<'static, 'static> {
        let src_net_arg = clap::Arg::with_name("src_net")
            .long("ip")
            .value_name("CIDR")
            .help("Local IP and prefix to send from, in CIDR format. Will default to first IP on given iface and prefix 24.")
            .takes_value(true);
        let gw = clap::Arg::with_name("gw")
            .long("gateway")
            .short("gw")
            .value_name("IP")
            .help("The default gateway to use if the destination is not on the local network. Must be inside the network given to --ip. Defaults to the first address in the network given to --ip")
            .takes_value(true);
        let iface_arg = clap::Arg::with_name("iface")
            .help("Network interface to use")
            .required(true)
            .index(1);
        let dst_arg = clap::Arg::with_name("target")
            .help("Target to connect to. Given as <ip>:<port>")
            .required(true)
            .index(2);

        let app = clap::App::new("Netcat in Rust")
            .version(crate_version!())
            .author(crate_authors!())
            .about("A netcat like program using the rips userspace network stack.")
            .arg(src_net_arg)
            .arg(iface_arg)
            .arg(dst_arg);

        app
    }

    fn print_error(&self, error: &str) -> ! {
        eprintln!("ERROR: {}\n", error);
        self.app.write_help(&mut ::std::io::stderr()).unwrap();
        eprintln!("");
        process::exit(1);
    }
}
