use std::net::SocketAddrV4;

pub mod minecraft;

#[derive(Debug)]
pub enum ParseResponseError {
    Invalid,
    Incomplete { expected_length: u32 },
}

pub enum Response {
    Data(Vec<u8>),
    Rst,
}

pub trait Protocol: Send + Sync {
    fn payload(&self, address: SocketAddrV4) -> Vec<u8>;
    fn parse_response(&self, response: Response) -> Result<Vec<u8>, ParseResponseError>;
}