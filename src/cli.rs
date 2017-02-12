use clap;

use ipnetwork::Ipv4Network;

use pnet::datalink::{self, NetworkInterface};

use rips;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process;
use std::str::FromStr;


macro_rules! eprintln {
    ($($arg:tt)*) => {{
        use std::io::Write;
        let _ = writeln!(&mut ::std::io::stderr(), $($arg)* );
    }}
}


pub struct ArgumentParser {
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
                if let Ok(rips_iface) = rips::Interface::try_from(&iface) {
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
            match Ipv4Network::from_str(src_net) {
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

    pub fn get_src_port(&self) -> u16 {
        let matches = &self.matches;
        value_t!(matches, "src_port", u16).unwrap()
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

    pub fn get_mtu(&self) -> usize {
        let matches = &self.matches;
        value_t!(matches, "mtu", usize).unwrap()
    }

    pub fn get_netbuf(&self) -> usize {
        let matches = &self.matches;
        value_t!(matches, "netbuf", usize).unwrap()
    }

    pub fn get_iobuf(&self) -> usize {
        let matches = &self.matches;
        value_t!(matches, "iobuf", usize).unwrap()
    }

    pub fn get_dst(&self) -> SocketAddr {
        let matches = &self.matches;
        match value_t!(matches, "target", SocketAddr) {
            Ok(dst) => dst,
            Err(e) => self.print_error(&format!("Invalid target. {}", e)),
        }
    }

    pub fn is_stats(&self) -> bool {
        self.matches.is_present("stats")
    }

    pub fn create_channel(&self) -> rips::EthernetChannel {
        let bufsize = self.get_netbuf();
        let (iface, _) = self.get_iface();
        let mut config = datalink::Config::default();
        config.write_buffer_size = bufsize;
        config.read_buffer_size = bufsize;
        match datalink::channel(&iface, config) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => {
                rips::EthernetChannel {
                    sender: tx,
                    write_buffer_size: bufsize,
                    receiver: rx,
                    read_buffer_size: bufsize,
                }
            }
            _ => self.print_error(&format!("Unable to open network channel on {}", iface.name)),
        }
    }

    fn create_app() -> clap::App<'static, 'static> {
        let src_net_arg = clap::Arg::with_name("src_net")
            .long("ip")
            .value_name("CIDR")
            .help("Local IP and prefix to send from, in CIDR format. Will default to first IP on \
                   given iface and prefix 24.")
            .takes_value(true);
        let src_port_arg = clap::Arg::with_name("src_port")
            .long("sport")
            .value_name("PORT")
            .help("Local port to bind to and send from.")
            .default_value("9999");
        let gw_arg = clap::Arg::with_name("gw")
            .long("gateway")
            .short("gw")
            .value_name("IP")
            .help("The default gateway to use if the destination is not on the local network. \
                   Must be inside the network given to --ip. Defaults to the first address in \
                   the network given to --ip")
            .takes_value(true);
        let mtu_arg = clap::Arg::with_name("mtu")
            .long("mtu")
            .value_name("MTU")
            .help("Maximum transmission unit (MTU) for the transmission.")
            .default_value("1500");
        let netbuf_arg = clap::Arg::with_name("netbuf")
            .long("netbuf")
            .value_name("SIZE")
            .help("Number of bytes allocated for the network TX/RX buffers.")
            .default_value("65535");
        let iobuf_arg = clap::Arg::with_name("iobuf")
            .long("iobuf")
            .value_name("SIZE")
            .help("Number of bytes allocated for the stdin/stdout buffers.")
            .default_value("63600");
        let iface_arg = clap::Arg::with_name("iface")
            .help("Network interface to use")
            .required(true)
            .index(1);
        let dst_arg = clap::Arg::with_name("target")
            .help("Target to connect to. Given as <ip>:<port>")
            .required(true)
            .index(2);
        let stats_arg = clap::Arg::with_name("stats")
            .help("Print performance statistics to stderr every second")
            .long("stat");

        let app = clap::App::new(crate_name!())
            .version(crate_version!())
            .author(crate_authors!())
            .about(crate_description!())
            .arg(src_net_arg)
            .arg(src_port_arg)
            .arg(gw_arg)
            .arg(mtu_arg)
            .arg(netbuf_arg)
            .arg(iobuf_arg)
            .arg(iface_arg)
            .arg(dst_arg)
            .arg(stats_arg);

        app
    }

    fn print_error(&self, error: &str) -> ! {
        eprintln!("ERROR: {}\n", error);
        self.app.write_help(&mut ::std::io::stderr()).unwrap();
        eprintln!("");
        process::exit(1);
    }
}
