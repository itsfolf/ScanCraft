use std::collections::VecDeque;
use std::net::SocketAddrV4;
use amqprs::connection::Connection;

pub struct SharedData {
    pub connection: Connection,
    pub found_server_queue: VecDeque<(SocketAddrV4, Vec<u8>)>,
    pub results: usize,
}