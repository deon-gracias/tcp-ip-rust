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
        let flags = u16::from_be_bytes([buffer[0], buffer[1]]);
        let proto = u16::from_be_bytes([buffer[2], buffer[3]]);

        // Hexadecimal values of protocols: https://en.wikipedia.org/wiki/EtherType
        if proto != 0x0800 {
            // No IPv4
            continue;
        }

        let header = match ip::ip::IPv4Header::from_slice(&buffer[4..]) {
            Ok(v) => v,
            Err(e) => {
                panic!("{}", e.message);
            }
        };

        dbg!(header);

        // println!("Read {} Bytes: {:x?}", nbytes, &buffer[4..nbytes]);
        // println!("Flags {} Proto: {:x}", flags, proto);
    }
}
