use std::collections::HashMap;

// https://tools.ietf.org/html/rfc793
// https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
mod ip;
mod tcp;

fn main() {
    let mut connections: HashMap<tcp::StateQuad, tcp::TCPState> = Default::default();

    let nic =
        tun_tap::Iface::new("tun0", tun_tap::Mode::Tun).expect("Failed to create a TUN device");

    println!("{}", nic.name());

    let mut buffer = [0u8; 1504]; // MTU + 4 for the header

    loop {
        let nbytes: usize = match nic.recv(&mut buffer) {
            Ok(v) => v,
            Err(e) => {
                panic!("Error occured while reading receive buffer: {}", e);
            }
        };

        // TUN TCP Frame Format: https://docs.kernel.org/networking/tuntap.html#frame-format
        let _eth_flags = u16::from_be_bytes([buffer[0], buffer[1]]);
        let eth_proto = u16::from_be_bytes([buffer[2], buffer[3]]);

        // Hexadecimal values of protocols: https://en.wikipedia.org/wiki/EtherType
        if eth_proto != 0x0800 {
            // No IPv4
            continue;
        }

        let ip_payload = match etherparse::Ipv4Slice::from_slice(&buffer[4..nbytes]) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Err: {:?}", e);
                continue;
            }
        };

        if ip_payload.header().protocol() != etherparse::IpNumber::TCP {
            // Not a TCP packet
            continue;
        }

        let tcp_payload = match etherparse::TcpSlice::from_slice(ip_payload.payload().payload) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Err: {:?}", e);
                continue;
            }
        };

        // Check connection
        let _ = connections
            .entry(tcp::StateQuad {
                source: (ip_payload.header().source_addr(), tcp_payload.source_port()),
                destination: (
                    ip_payload.header().destination_addr(),
                    tcp_payload.destination_port(),
                ),
            })
            .or_default()
            .on_packet(
                &nic,
                ip_payload.header(),
                etherparse::TcpHeaderSlice::from_slice(tcp_payload.header_slice())
                    .expect("Parse shouldn't Fail"),
                tcp_payload.payload(),
            );
    }
}
