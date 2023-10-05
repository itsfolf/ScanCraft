use std::collections::VecDeque;
use std::net::SocketAddrV4;

pub struct SharedData {
    pub found_server_queue: VecDeque<(SocketAddrV4, Vec<u8>)>,

    pub results: usize,
}