#[macro_use]
extern crate clap;
#[macro_use]
extern crate lazy_static;
extern crate pnet;
extern crate ipnetwork;
extern crate rips;

#[macro_use]
mod cli;

use ipnetwork::Ipv4Network;

use rips::udp::UdpSocket as RipsUdpSocket;

use std::io::{self, Read, Write};
use std::net::{SocketAddr, SocketAddrV4};
use std::process;
use std::str::FromStr;
// use std::net::UdpSocket as StdUdpSocket;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

static ATOMIC_ORDERING: Ordering = Ordering::Relaxed;

lazy_static! {
    static ref DEFAULT_ROUTE: Ipv4Network = Ipv4Network::from_str("0.0.0.0/0").unwrap();
}

fn bytes_to_human(mut bytes: usize) -> (usize, &'static str) {
    static SIZE_SUFFIXES: [&'static str; 6] = ["", "k", "M", "G", "T", "P"];
    for i in 0..SIZE_SUFFIXES.len() {
        if bytes >= 1024 {
            bytes /= 1024;
        } else {
            return (bytes, SIZE_SUFFIXES[i]);
        }
    }
    return (bytes, SIZE_SUFFIXES[SIZE_SUFFIXES.len() - 1]);
}

fn main() {
    let args = cli::ArgumentParser::new();

    let (_, iface) = args.get_iface();
    let src_net = args.get_src_net();
    let gw = args.get_gw();
    let src_port = args.get_src_port();
    let mtu = args.get_mtu();
    let iobuf = args.get_iobuf();
    let channel = args.create_channel();
    let src = SocketAddr::V4(SocketAddrV4::new(src_net.ip(), src_port));
    let dst = args.get_dst();

    let mut stack = rips::NetworkStack::new();
    stack.add_interface(iface.clone(), channel).unwrap();
    stack.interface(&iface).unwrap().set_mtu(mtu);
    stack.add_ipv4(&iface, src_net).unwrap();
    stack.routing_table().add_route(*DEFAULT_ROUTE, Some(gw), iface);

    let stack = Arc::new(Mutex::new(stack));
    let socket = RipsUdpSocket::bind(stack, src).unwrap();
    let socket_clone = socket.try_clone().unwrap();

    let rx_pkgs = Arc::new(AtomicUsize::new(0));
    let rx_bytes = Arc::new(AtomicUsize::new(0));
    let tx_bytes = Arc::new(AtomicUsize::new(0));
    read_to_stdout(socket, iobuf, rx_pkgs.clone(), rx_bytes.clone());
    send_stdin(socket_clone, dst, iobuf, tx_bytes.clone());
    if args.is_stats() {
        print_statistics(rx_pkgs, rx_bytes, tx_bytes);
    } else {
        loop {
            thread::sleep(Duration::new(1, 0));
        }
    }
}

fn read_to_stdout(socket: RipsUdpSocket,
                  bufsize: usize,
                  pkgs: Arc<AtomicUsize>,
                  bytes: Arc<AtomicUsize>) {
    thread::spawn(move || {
        let stdout = io::stdout();
        let mut locked_stdout = stdout.lock();
        let mut buffer = vec![0; bufsize];
        loop {
            let (len, _src) = socket.recv_from(&mut buffer).expect("Unable to read from socket");
            locked_stdout.write_all(&buffer[..len]).expect("Unable to write to stdout");
            locked_stdout.flush().expect("Unable to flush stdout");
            pkgs.fetch_add(1, ATOMIC_ORDERING);
            bytes.fetch_add(len, ATOMIC_ORDERING);
        }
    });
}

fn send_stdin(mut socket: RipsUdpSocket,
              dst: SocketAddr,
              bufsize: usize,
              bytes: Arc<AtomicUsize>) {
    thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut handle = stdin.lock();
        let mut buffer = vec![0; bufsize];
        while let Ok(len) = handle.read(&mut buffer) {
            if len == 0 {
                break;
            }
            match socket.send_to(&buffer[..len], dst) {
                Err(e) => {
                    eprintln!("Error while sending to the network: {}", e);
                    process::exit(1);
                }
                Ok(_size) => {
                    bytes.fetch_add(len, ATOMIC_ORDERING);
                }
            }
        }
    });
}

fn print_statistics(rx_pkgs: Arc<AtomicUsize>,
                    rx_bytes: Arc<AtomicUsize>,
                    tx_bytes: Arc<AtomicUsize>) {
    let stderr = io::stdout();
    let mut stderr_lock = stderr.lock();
    loop {
        thread::sleep(Duration::new(1, 0));
        let rx_pkgs = rx_pkgs.swap(0, ATOMIC_ORDERING);
        let rx_bytes = rx_bytes.swap(0, ATOMIC_ORDERING);
        let (rx_scaled_bytes, rx_bytes_suffix) = bytes_to_human(rx_bytes);

        let tx_bytes = tx_bytes.swap(0, ATOMIC_ORDERING);
        let (tx_scaled_bytes, tx_bytes_suffix) = bytes_to_human(tx_bytes);
        write!(stderr_lock,
               "Rx: {} {}B/s ({} pps). Tx: {} {}B/s\r",
               rx_scaled_bytes,
               rx_bytes_suffix,
               rx_pkgs,
               tx_scaled_bytes,
               tx_bytes_suffix)
            .unwrap();
        stderr_lock.flush().unwrap();
    }
}
