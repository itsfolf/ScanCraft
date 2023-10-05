use std::borrow::BorrowMut;
use std::collections::{HashMap, HashSet};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddrV4;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use parking_lot::Mutex;
use perfect_rand::PerfectRng;
use pnet::packet::tcp::TcpFlags;
use tokio::time::Instant;
use tracing::{debug, trace, warn};

use throttle::Throttler;

use crate::net::tcp::{StatelessTcp, StatelessTcpWriteHalf};
use crate::processing::SharedData;
use crate::scanner::protocols::{ParseResponseError, Protocol, Response};
use crate::scanner::protocols::minecraft::Minecraft;
use crate::scanner::targets::{ScanRanges, StaticScanRanges};

pub mod targets;
pub mod throttle;
pub mod protocols;

pub struct Scanner {
    pub seed: u64,
    pub client: StatelessTcp,
    pub conns: HashMap<SocketAddrV4, ConnState>,
}

impl Scanner {
    pub fn new(source_port: u16) -> Self {
        let seed = rand::random::<u64>();
        let mut client = StatelessTcp::new(source_port);

        client.write.fingerprint.mss = client.write.mtu();
        if client.write.has_ethernet_header() {
            client.write.fingerprint.mss -= 40;
        }

        Self {
            seed,
            client,
            conns: HashMap::<SocketAddrV4, ConnState>::new(),
        }
    }

    pub fn purge_old_conns(&mut self, ping_timeout: Duration) {
        let now = Instant::now();
        let mut to_delete = Vec::new();
        for (addr, conn) in &mut self.conns {
            if now - conn.started > ping_timeout {
                debug!("dropping connection to {addr} because it took too long");
                // if it took longer than 60 seconds to reply, then drop the connection
                to_delete.push(*addr)
            }
        }
        for key in &to_delete {
            self.conns.remove(key);
        }
    }
}

pub struct ScannerReceiver {
    pub shared_process_data: Arc<Mutex<SharedData>>,
    pub scanner: Scanner,
    pub has_ended: Arc<AtomicBool>,
}

impl ScannerReceiver {
    pub fn recv_loop(&mut self, ping_timeout: Duration) {
        let mut received_from_ips = HashSet::<SocketAddrV4>::new();
        let mut syn_acks_received: usize = 0;
        let mut connections_started: usize = 0;

        let mut last_purge = Instant::now();

        let protocol = Minecraft::new("yiffuwu", 25565, 47);

        loop {
            if self.has_ended.load(Ordering::Relaxed) {
                break;
            }


            while let Some((ipv4, tcp)) = self.scanner.client.read.recv() {
                let address = SocketAddrV4::new(ipv4.source, tcp.source);
                trace!("con from {}", address);
                if tcp.flags & TcpFlags::RST != 0 {
                    trace!("RST from {}", address);


                    continue;
                } else if tcp.flags & TcpFlags::FIN != 0 {
                    trace!("FIN from {}", address);
                    if let Some(conn) = self.scanner.conns.get_mut(&address) {
                        self.scanner.client.write.send_ack(
                            address,
                            tcp.destination,
                            conn.local_seq,
                            tcp.sequence + 1,
                        );

                        if !conn.fin_sent {
                            self.scanner.client.write.send_fin(
                                address,
                                tcp.destination,
                                conn.local_seq,
                                tcp.sequence + 1,
                            );
                            conn.fin_sent = true;
                        }

                        if conn.data.is_empty() {
                            debug!("FIN with no data :( {}:{}", ipv4.source, tcp.source);
                            // if there was no data then parse that as a response
                            if let Ok(data) = protocol.parse_response(Response::Data(vec![])) {
                                self.shared_process_data
                                    .lock()
                                    .found_server_queue
                                    .push_back((address, data));
                            }
                        } else {
                            debug!("FIN {}:{}", ipv4.source, tcp.source);
                            self.scanner.conns.borrow_mut().remove(&address);
                        }
                    } else {
                        debug!(
                            "FIN with no connection, probably already forgotten by us {}:{}",
                            ipv4.source, tcp.source
                        );
                        self.scanner.client.write.send_ack(
                            address,
                            tcp.destination,
                            tcp.acknowledgement,
                            tcp.sequence + 1,
                        );
                    }


                    continue;
                } else if tcp.flags & TcpFlags::SYN != 0 && tcp.flags & TcpFlags::ACK != 0 {
                    trace!("SYN+ACK {}:{}", ipv4.source, tcp.source);

                    received_from_ips.insert(address);

                    // SYN+ACK
                    // verify that the ack is the cookie+1
                    let ack_number = tcp.acknowledgement;

                    let original_cookie = cookie(&address, self.scanner.seed);
                    let expected_ack = original_cookie + 1;
                    if ack_number != expected_ack {
                        warn!("cookie mismatch for {address} (expected {expected_ack}, got {ack_number})");
                        continue;
                    }

                    self.scanner.client.write.send_ack(
                        address,
                        tcp.destination,
                        tcp.acknowledgement,
                        tcp.sequence + 1,
                    );

                    let payload = protocol.payload(address);
                    if payload.is_empty() {
                        // this means we're skipping this server, give them an rst
                        self.scanner.client.write.send_rst(
                            address,
                            tcp.destination,
                            tcp.acknowledgement,
                            tcp.sequence + 1,
                        );
                        continue;
                    }
                    self.scanner.client.write.send_data(
                        address,
                        tcp.destination,
                        tcp.acknowledgement,
                        tcp.sequence + 1,
                        &payload,
                    );

                    syn_acks_received += 1;
                    trace!("syn acks: {syn_acks_received}");

                    // println!("ok sent first ACK+data");
                    continue;
                } else if tcp.flags & TcpFlags::ACK != 0 {
                    // ACK
                    trace!(
                        "ACK {address} with data: {}",
                        String::from_utf8_lossy(&tcp.payload)
                    );
                    // println!("ACK {}:{}", ipv4.source, tcp.source);

                    // cookie +packet size + 1
                    let ack_number = tcp.acknowledgement;

                    if tcp.payload.is_empty() {
                        trace!("empty payload, ignoring {address}");
                        // just an ack and not data
                        continue;
                    }

                    // check if it's already in the connections map
                    let (ping_response, is_tracked) = if let Some(conn) =
                        self.scanner.conns.get_mut(&address)
                    {
                        if tcp.sequence != conn.remote_seq {
                            let difference = tcp.sequence as i64 - conn.remote_seq as i64;
                            warn!(
                                "Got wrong seq number {}! expected {} (difference = {difference}). This is probably because of a re-transmission.",
                                tcp.sequence,
                                conn.remote_seq
                            );

                            self.scanner.client.write.send_ack(
                                address,
                                tcp.destination,
                                ack_number,
                                conn.remote_seq,
                            );

                            continue;
                        }
                        // this means it's adding more data to this connection
                        conn.data.extend(tcp.payload.clone());
                        conn.remote_seq = tcp.sequence + tcp.payload.len() as u32;
                        (
                            protocol.parse_response(Response::Data(conn.data.clone())),
                            true,
                        )
                    } else {
                        // this means it's the first data packet we got, verify it
                        let original_cookie = cookie(&address, self.scanner.seed);
                        // we never send anything other than the SYN and initial ping so this is
                        // fine
                        let packet_size = protocol.payload(address).len();
                        let cookie_offset = (packet_size + 1) as u32;

                        let expected_ack = original_cookie.wrapping_add(cookie_offset);
                        if ack_number != expected_ack {
                            warn!("cookie mismatch when reading data for {address} (expected {expected_ack}, got {ack_number}, initial was {original_cookie})");
                            continue;
                        }

                        let ping_response =
                            protocol.parse_response(Response::Data(tcp.payload.clone()));
                        (ping_response, false)
                    };

                    match ping_response {
                        Ok(ping_response) => {
                            let data_string = String::from_utf8_lossy(&ping_response);
                            trace!("\n\n{address} {data_string}");

                            if !is_tracked {
                                self.scanner.conns.borrow_mut().insert(
                                    address,
                                    ConnState {
                                        data: tcp.payload.to_vec(),
                                        remote_seq: tcp
                                            .sequence
                                            .wrapping_add(tcp.payload.len() as u32),
                                        local_seq: tcp.acknowledgement,
                                        started: Instant::now(),
                                        fin_sent: false,
                                    },
                                );
                                connections_started += 1;
                                debug!("connection #{connections_started} started");
                            }

                            let conn = self.scanner.conns.get(&address).unwrap();

                            self.shared_process_data
                                .lock()
                                .found_server_queue
                                .push_back((address, ping_response));

                            self.scanner.client.write.send_ack(
                                address,
                                tcp.destination,
                                ack_number,
                                conn.remote_seq,
                            );
                            self.scanner.client.write.send_fin(
                                address,
                                tcp.destination,
                                ack_number,
                                conn.remote_seq,
                            );

                            if !is_tracked {
                                connections_started += 1;
                                debug!("connection #{connections_started} started and ended immediately");
                            }
                        }
                        Err(e) => {
                            match e {
                                ParseResponseError::Invalid => {
                                    trace!("packet error, ignoring");
                                }
                                ParseResponseError::Incomplete { .. } => {
                                    if !is_tracked {
                                        self.scanner.conns.borrow_mut().insert(
                                            address,
                                            ConnState {
                                                data: tcp.payload.to_vec(),
                                                remote_seq: tcp
                                                    .sequence
                                                    .wrapping_add(tcp.payload.len() as u32),
                                                local_seq: tcp.acknowledgement,
                                                started: Instant::now(),
                                                fin_sent: false,
                                            },
                                        );
                                        connections_started += 1;
                                        debug!("connection #{connections_started} started");
                                    }

                                    let conn = self.scanner.conns.get(&address).unwrap();
                                    // always ack whatever they send
                                    // a better tcp implementation would only ack every 2 packets or
                                    // after .5 seconds but this technically still follows the spec
                                    self.scanner.client.write.send_ack(
                                        address,
                                        tcp.destination,
                                        ack_number,
                                        conn.remote_seq,
                                    );
                                }
                            };
                        }
                    }

                    continue;
                }
            }
            //drop(protocol);

            thread::sleep(Duration::from_millis(50));

            if last_purge.elapsed() > Duration::from_secs(60) {
                self.scanner.purge_old_conns(ping_timeout);
                last_purge = Instant::now();
            }
        }

        self.scanner.purge_old_conns(ping_timeout);
    }
}

pub struct ScanSession {
    pub rng: PerfectRng,
    pub ranges: StaticScanRanges,
}

impl ScanSession {
    pub fn new(ranges: ScanRanges) -> Self {
        Self {
            rng: PerfectRng::new(ranges.count() as u64, rand::random(), 14),
            ranges: ranges.to_static(),
        }
    }

    pub fn run(
        self,
        max_packets_per_second: u64,
        scanner_writer: &mut StatelessTcpWriteHalf,
        seed: u64,
    ) -> u64 {
        let mut throttler = Throttler::new(max_packets_per_second);

        let mut packets_sent: u64 = 0;
        let total_packets = self.ranges.count as u64;

        let start = Instant::now();

        let mut packets_sent_last_log = 0;
        let mut last_log_time = Instant::now();

        loop {
            let is_done = packets_sent >= total_packets;

            let time_since_last_log = Instant::now() - last_log_time;
            if is_done || (packets_sent != 0 && time_since_last_log > Duration::from_secs(5)) {
                let packets_per_second = (packets_sent - packets_sent_last_log) as f64
                    / last_log_time.elapsed().as_secs_f64();
                let pps_total = packets_sent as f64 / start.elapsed().as_secs_f64();

                println!(
                    "sent {} packets in {} seconds ({:.2} packets per second, estimated: {:.2})",
                    packets_sent,
                    time_since_last_log.as_secs_f64(),
                    packets_per_second,
                    throttler.estimated_packets_per_second()
                );

                let minutes_left = (total_packets - packets_sent) as f64 / packets_per_second / 60.;
                let minutes_left_total = (total_packets - packets_sent) as f64 / pps_total / 60.;
                println!(
                    "estimated time left: {:.2} minutes ({:.2} considering total)",
                    minutes_left, minutes_left_total
                );

                packets_sent_last_log = packets_sent;
                last_log_time = Instant::now();
            }

            if is_done {
                break;
            }

            let mut batch_size = throttler.next_batch();
            if packets_sent + batch_size > total_packets {
                batch_size = total_packets - packets_sent;
            }

            for _ in 0..batch_size {
                let index = self.rng.shuffle(packets_sent);
                let addr = self.ranges.index(index as usize);
                trace!("sending SYN to {}", addr);
                scanner_writer.send_syn(addr, cookie(&addr, seed));
                packets_sent += 1;
            }
        }
        debug!("sent {} packets in {} seconds", packets_sent, start.elapsed().as_secs_f64());

        packets_sent
    }
}

fn cookie(address: &SocketAddrV4, seed: u64) -> u32 {
    let mut hasher = DefaultHasher::new();
    (*address.ip(), address.port(), seed).hash(&mut hasher);
    hasher.finish() as u32
}

/// The state stored for active connections. We try to keep this existing for
/// the shortest amount of time possible.
pub struct ConnState {
    /// The data we've received so far.
    data: Vec<u8>,

    /// The (last received sequence number + payload length); aka the
    /// `ack_number` we send; aka the next expected starting sequence number.
    remote_seq: u32,

    /// The sequence number we send.
    local_seq: u32,

    /// The time that the connection was created. Connections are closed 30
    /// seconds after creation (if it wasn't closed earlier).
    started: Instant,

    /// Whether we've sent a fin packet.
    fin_sent: bool,
}