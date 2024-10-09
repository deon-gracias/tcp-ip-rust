use std::{io, net::Ipv4Addr};

#[derive(Default)]
pub enum TCPState {
    Closed,
    #[default]
    Listen,
    SynReceived,
    Established,
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct StateQuad {
    pub source: (Ipv4Addr, u16),
    pub destination: (Ipv4Addr, u16),
}

impl TCPState {
    pub fn on_packet(
        &mut self,
        nic: &tun_tap::Iface,
        ip_header: etherparse::Ipv4HeaderSlice,
        tcp_header: etherparse::TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<usize> {
        let mut buff = [0u8; 1500];
        let mut buff_p = 0;

        match *self {
            TCPState::Closed => Ok(0),
            TCPState::Listen => {
                if !tcp_header.syn() {
                    // Only expected SYN packet
                    return Ok(0);
                }

                // Need to establish connection
                let syn_ack = etherparse::TcpHeader {
                    source_port: tcp_header.destination_port(),
                    destination_port: tcp_header.source_port(),
                    syn: true,
                    ack: true,
                    ..Default::default()
                }
                .to_bytes();

                let ip = etherparse::Ipv4Header {
                    source: ip_header.destination(),
                    destination: ip_header.source(),
                    protocol: etherparse::IpNumber::TCP,
                    total_len: (etherparse::Ipv4Header::MIN_LEN + syn_ack.len()) as u16,
                    ..Default::default()
                }
                .to_bytes();

                // Writing the packets to the buffer
                buff[buff_p..ip.as_slice().len()].copy_from_slice(ip.as_slice());
                buff_p += ip.as_slice().len();
                buff[buff_p..(buff_p + syn_ack.as_slice().len())]
                    .copy_from_slice(syn_ack.as_slice());
                buff_p += syn_ack.as_slice().len();

                nic.send(&buff[..(buff_p + 1)])
            }
            TCPState::SynReceived => todo!(),
            TCPState::Established => todo!(),
        }
    }
}
