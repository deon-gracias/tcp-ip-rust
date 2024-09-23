// https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
mod ip;

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

        let packet = match ip::ipv4::IPv4Payload::from_slice(&buffer[4..]) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{}", e.message);
                continue;
            }
        };

        let payload_length = match packet.get_header().get_total_length() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{}", e.message);
                continue;
            }
        };

        let data = match String::from_utf8(packet.get_data().clone()) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error parsing: {}", e);
                continue;
            }
        };

        println!(
            "{} {} protocol={} len={} data={}",
            packet.get_header().get_source_address(),
            packet.get_header().get_destination_address(),
            packet.get_header().get_protocol(),
            payload_length,
            data,
            // packet.get_data(),
        );

        // println!("Read {} Bytes: {:x?}", nbytes, &buffer[4..nbytes]);
        // println!("Flags {} Proto: {:x}", flags, proto);
    }
}
