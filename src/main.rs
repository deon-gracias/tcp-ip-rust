use tcp::tcp::{TCPHeader, TCPPayload};

// https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
mod ip;
mod tcp;

fn main() {
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

        let ip_payload = match ip::ipv4::IPv4Payload::from_slice(&buffer[4..]) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{}", e.message);
                continue;
            }
        };

        // let payload_length = match ip_payload.get_header().get_total_length() {
        //     Ok(v) => v,
        //     Err(e) => {
        //         eprintln!("{}", e.message);
        //         continue;
        //     }
        // };

        // let data = match String::from_utf8(packet.get_data().clone()) {
        //     Ok(v) => v,
        //     Err(e) => {
        //         eprintln!("Error parsing: {}", e);
        //         continue;
        //     }
        // };

        // println!(
        //     "{} {} protocol={} len={} bytes",
        //     ip_payload.get_header().get_source_address(),
        //     ip_payload.get_header().get_destination_address(),
        //     ip_payload.get_header().get_protocol(),
        //     payload_length,
        //     // packet.get_data(),
        // );

        if ip_payload.get_header().get_protocol() != 0x06 {
            // Not a TCP packet
            continue;
        }

        let tcp_payload = match TCPPayload::from_slice(&ip_payload.get_data().as_slice()) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{}", e.message);
                continue;
            }
        };

        println!(
            "Source={} | Destination={} | Data={:?}",
            tcp_payload.header.source_port,
            tcp_payload.header.destination_port,
            tcp_payload.get_data()
        );
    }
}
