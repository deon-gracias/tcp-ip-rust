pub mod ipv4 {
    use core::fmt;
    use std::{net::Ipv4Addr, u16};

    pub const HEADER_MIN_LENGTH: usize = 20; // 20 bytes
    pub const HEADER_MAX_LENGTH: usize = 60; // 60 bytes
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
        options: Vec<u8>,
    }

    #[derive(Debug)]
    pub struct IPFlags {
        reserved: bool,
        df: bool,
        mf: bool,
    }

    pub struct IPv4Payload {
        header: IPv4Header,
        bytes: Vec<u8>,
    }

    impl IPv4Payload {
        pub fn from_slice(slice: &[u8]) -> Result<IPv4Payload, IPv4ParsingError> {
            let header = IPv4Header::from_slice(slice)?;
            let payload_length = header.get_total_length()?;

            let mut bytes = vec![0u8; payload_length - header.get_header_length()];
            bytes.copy_from_slice(&slice[header.get_header_length()..payload_length]);

            return Ok(IPv4Payload { header, bytes });
        }

        pub fn to_bytes(&self) -> [u8; u16::MAX as usize] {
            let mut payload = [0u8; u16::MAX as usize];
            let header_length = self.header.get_header_length();

            payload[..header_length].copy_from_slice(&self.header.to_bytes().as_slice());
            payload[header_length..(self.bytes.len() + header_length)]
                .copy_from_slice(&self.bytes.as_slice());

            return payload;
        }

        pub fn get_data(&self) -> &Vec<u8> {
            return &self.bytes;
        }

        pub fn get_header(&self) -> &IPv4Header {
            return &self.header;
        }
    }

    impl IPv4Header {
        pub fn from_slice(slice: &[u8]) -> Result<IPv4Header, IPv4ParsingError> {
            if slice.len() < HEADER_MIN_LENGTH {
                // minimum length of IP packet is 20 bytes
                return Err(IPv4ParsingError {
                    message: format!(
                        "Min length of IP Packet is {} received {}",
                        HEADER_MIN_LENGTH,
                        slice.len()
                    ),
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

            let options = slice[20..].to_vec();

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
                options,
            });
        }

        pub fn get_version(&self) -> u8 {
            return self.version;
        }

        pub fn get_source_address(&self) -> Ipv4Addr {
            return self.source_address;
        }

        pub fn get_destination_address(&self) -> Ipv4Addr {
            return self.destination_address;
        }

        pub fn get_protocol(&self) -> u8 {
            return self.protocol;
        }

        pub fn get_header_length(&self) -> usize {
            return (self.ihl * 4) as usize;
        }

        pub fn get_flags(&self) -> IPFlags {
            let reserved: bool = (0b100 & self.flags) != 0;
            let df: bool = (0b010 & self.flags) != 0;
            let mf: bool = (0b001 & self.flags) != 0;

            return IPFlags { reserved, df, mf };
        }

        pub fn get_total_length(&self) -> Result<usize, IPv4ParsingError> {
            if HEADER_MIN_LENGTH <= self.total_length as usize {
                return Ok(self.total_length as usize);
            }

            return Err(IPv4ParsingError {
                message: format!(
                    "Header length ({}) more than total length ({})",
                    HEADER_MIN_LENGTH, self.total_length
                ),
            });
        }

        pub fn to_bytes(&self) -> Vec<u8> {
            let mut slice = vec![0u8; self.get_header_length()];

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

            if self.get_header_length() - 20 > 0 {
                slice[20..(self.get_header_length())].copy_from_slice(self.options.as_slice());
            }

            return slice;
        }
    }
}

#[cfg(test)]
mod tests {
    use ipv4;

    use super::*;

    #[test]
    fn packet_should_parse() {
        let mut ip_packet = [0u8; 65535];
        //
        // Fill in some payload data (example)
        let data: &[u8] = b"Hello, World! This is an example payload.";

        // Fill in the IP header (first 20 bytes)
        ip_packet[0] = 0x45; // Version + IHL
        ip_packet[1] = 0x00; // Type of Service
        ip_packet[2..4].copy_from_slice(&((20 + data.len()) as u16).to_be_bytes()); // Total Length
        ip_packet[4..6].copy_from_slice(&[0xd4, 0x31]); // Identification
        ip_packet[6..8].copy_from_slice(&[0x40, 0x00]); // Flags + Fragment Offset
        ip_packet[8] = 0x40; // Time to Live
        ip_packet[9] = 0x06; // Protocol (TCP)
        ip_packet[10..12].copy_from_slice(&[0x1a, 0x2b]); // Header checksum (Placeholder)
        ip_packet[12..16].copy_from_slice(&[0xc0, 0xa8, 0x01, 0x01]); // Source IP: 192.168.1.1
        ip_packet[16..20].copy_from_slice(&[0xc0, 0xa8, 0x01, 0x02]); // Destination IP: 192.168.1.2

        ip_packet[20..20 + data.len()].copy_from_slice(data);

        let payload =
            ipv4::IPv4Payload::from_slice(&ip_packet).expect("Failed to parse valid slice");

        assert_eq!(payload.get_header().get_version(), 4);
        assert_eq!(payload.get_header().get_header_length(), 20);
        assert_eq!(
            payload.get_header().get_source_address().to_string(),
            "192.168.1.1"
        );
        assert_eq!(
            payload.get_header().get_destination_address().to_string(),
            "192.168.1.2"
        );

        assert_eq!(payload.get_data(), data);
        assert_eq!(payload.to_bytes(), ip_packet);
    }
}
