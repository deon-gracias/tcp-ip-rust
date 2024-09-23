pub mod ip {
    use core::fmt;
    use std::net::Ipv4Addr;

    #[derive(Debug)]
    pub struct IPv4ParsingError {
        pub message: String,
    }

    impl fmt::Display for IPv4ParsingError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            return write!(f, "{}", self.message);
        }
    }

    #[derive(Debug)]
    pub struct IPv4Header {
        version: u8,                            // 4 bits
        ihl: u8,                                // 4 bits
        differentiated_services_code_point: u8, // 6 bits
        explicit_congestion_notification: u8,   // 2 bits
        total_length: u16,                      // 16 bits
        identification: u16,                    // 16 bits
        flags: u8,                              // 3 bits
        fragment_offset: u16,                   // 13 bits
        time_to_live: u8,                       // 8 bits
        protocol: u8,                           // 8 bits
        header_checksum: u16,                   // 16 bits
        source_address: Ipv4Addr,               // 32 bits
        destination_address: Ipv4Addr,          // 32 bits
    }

    #[derive(Debug)]
    pub struct IPFlags {
        reserved: bool,
        df: bool,
        mf: bool,
    }

    impl IPv4Header {
        pub fn from_slice(slice: &[u8]) -> Result<IPv4Header, IPv4ParsingError> {
            if slice.len() < 20 {
                // minimum length of IP packet is 20 bytes
                return Err(IPv4ParsingError {
                    message: format!("Min length of IP Packet is 20 received {}", slice.len()),
                });
            }

            // Read version and IHL
            let version = (slice[0] & 0xf0) >> 4;
            let ihl = slice[0] & 0x0f;

            // Read DSCP and ECN
            let differentiated_services_code_point = (slice[1] & 0xfd) >> 2;
            let explicit_congestion_notification = slice[1] & 0x03;

            // Total length
            let total_length: u16 = ((slice[2] as u16) << 8) | slice[3] as u16;

            if total_length as usize >= slice.len() * 8 {
                return Err(IPv4ParsingError {
                    message: format!(
                        "Total length ({}) of IP is greater than packet size ({})",
                        total_length,
                        slice.len()
                    ),
                });
            }

            // Identification
            let identification: u16 = ((slice[4] as u16) << 8) | slice[5] as u16;

            // Flags
            let flags: u8 = (slice[6] & 0xe0) >> 5;

            // Fragment Offset
            let fragment_offset: u16 = ((slice[6] & 0x1f) as u16) << 8 | slice[7] as u16;

            // Time to live
            let time_to_live: u8 = slice[8];

            // Protocol
            let protocol: u8 = slice[9];

            // Header Checksum
            let header_checksum: u16 = ((slice[10] as u16) << 8) | slice[11] as u16;

            // Source Address
            let source_address = Ipv4Addr::new(slice[12], slice[13], slice[14], slice[15]);

            // Destination Address
            let destination_address = Ipv4Addr::new(slice[16], slice[17], slice[18], slice[19]);

            return Ok(IPv4Header {
                version,
                ihl,
                differentiated_services_code_point,
                explicit_congestion_notification,
                total_length,
                identification,
                flags,
                fragment_offset,
                time_to_live,
                protocol,
                header_checksum,
                source_address,
                destination_address,
            });
        }

        pub fn get_flags(&self) -> IPFlags {
            let reserved: bool = (0b100 & self.flags) != 0;
            let df: bool = (0b010 & self.flags) != 0;
            let mf: bool = (0b001 & self.flags) != 0;

            return IPFlags { reserved, df, mf };
        }

        pub fn to_slice(&self) -> [u8; 20] {
            let mut slice = [0u8; 20];

            // Set Version and IHL
            slice[0] = (self.version << 4) | (self.ihl & 0x0f);

            // Set DSCP and ECN
            slice[1] = (self.differentiated_services_code_point << 2)
                | (self.explicit_congestion_notification & 0x03);

            // Set Total Length
            slice[2] = (self.total_length >> 8) as u8;
            slice[3] = (self.total_length & 0xff) as u8;

            // Set Identification
            slice[4] = (self.identification >> 8) as u8;
            slice[5] = (self.identification & 0xff) as u8;

            // Set Flags and Fragment Offset
            // u8 u16
            slice[6] = (self.flags << 5) | (((self.fragment_offset >> 8) as u8) & 5);
            slice[7] = (self.fragment_offset & 0xff) as u8;

            // Set Time to Live
            slice[8] = self.time_to_live;

            // Set Protocol
            slice[9] = self.protocol;

            // Set Header Checksum
            slice[10] = (self.header_checksum >> 8) as u8;
            slice[11] = (self.header_checksum & 0xff) as u8;

            // Set Source Address
            let src = self.source_address.octets();
            slice[12] = src[0];
            slice[13] = src[1];
            slice[14] = src[2];
            slice[15] = src[3];

            // Set Destination Address
            let dst = self.destination_address.octets();
            slice[16] = dst[0];
            slice[17] = dst[1];
            slice[18] = dst[2];
            slice[19] = dst[3];

            return slice;
        }
    }
}

#[cfg(test)]
mod tests {
    use ip::IPv4Header;

    use super::*;

    #[test]
    fn packet_should_parse() {
        let packet: [u8; 32] = [
            0b01000110, 0b11000000, 0b00000000, 0b00110000, 0b00000000, 0b00000000, 0b01000000,
            0b00000000, 0b00000001, 0b00000010, 0b01000011, 0b00111111, 0b11000000, 0b10101000,
            0b00000000, 0b00001010, 0b11100000, 0b00000000, 0b00000000, 0b00010110, 0b10010100,
            0b00000100, 0b00000000, 0b00000000, 0b00100010, 0b00000000, 0b00000101, 0b00000110,
            0b00000000, 0b00000000, 0b00000000, 0b00000010,
        ];

        let header = IPv4Header::from_slice(&packet).expect("Failed to parse valid slice");

        assert_eq!(header.to_slice(), packet[..20]);
    }
}
