pub mod tcp {
    #[derive(Debug)]
    pub struct TCPParsingError {
        pub message: String,
    }

    pub const TCP_MIN_HEADER_LENGTH: usize = 20;
    pub const TCP_MAX_HEADER_LENGTH: usize = 60;

    pub struct TCPHeader {
        pub source_port: u16,
        pub destination_port: u16,
        pub sequence_number: u32,
        pub acknowledgement_number: u32,
        pub data_offset: u8,
        pub flags: u8,
        pub window: u16,
        pub checksum: u16,
        pub urgent_pointer: u16,
        pub options: Vec<u8>,
    }

    pub struct TCPPayload {
        pub header: TCPHeader,
        pub bytes: Vec<u8>,
    }

    #[derive(Debug)]
    pub struct TCPFlags {
        pub congestion_window_reduced: bool,
        pub explicit_congesiton_notification_echo: bool,
        pub urgent: bool,
        pub acknowledgement: bool,
        pub push: bool,
        pub reset: bool,
        pub synchronize: bool,
        pub finish: bool,
    }

    impl TCPPayload {
        pub fn from_slice(slice: &[u8]) -> Result<TCPPayload, TCPParsingError> {
            let header = TCPHeader::from_slice(slice);
            let payload_length = slice.len();

            println!(
                "Payload Length: {}, Header length: {}",
                payload_length,
                header.get_header_length()
            );
            // println!("Header: {:?}", header.to_slice());
            println!("Data: {:?}", &slice[header.get_header_length()..]);

            let mut bytes = vec![0u8; payload_length - header.get_header_length()];
            bytes.copy_from_slice(&slice[header.get_header_length()..payload_length]);

            return Ok(TCPPayload { header, bytes });
        }

        pub fn to_bytes(&self) -> [u8; u16::MAX as usize] {
            let mut payload = [0u8; u16::MAX as usize];
            let header_length = self.header.get_header_length();

            payload[..header_length].copy_from_slice(&self.header.to_slice().as_slice());
            payload[header_length..(self.bytes.len() + header_length)]
                .copy_from_slice(&self.bytes.as_slice());

            return payload;
        }

        pub fn get_data(&self) -> &Vec<u8> {
            return &self.bytes;
        }

        pub fn get_header(&self) -> &TCPHeader {
            return &self.header;
        }
    }

    impl TCPHeader {
        pub fn from_slice(slice: &[u8]) -> TCPHeader {
            let source_port = ((slice[0] as u16) << 8) | slice[1] as u16;
            let destination_port = ((slice[2] as u16) << 8) | slice[3] as u16;
            let sequence_number: u32 = ((slice[4] as u32) << 24)
                | ((slice[5] as u32) << 16)
                | ((slice[6] as u32) << 8)
                | slice[7] as u32;
            let acknowledgement_number: u32 = ((slice[8] as u32) << 24)
                | ((slice[9] as u32) << 16)
                | ((slice[10] as u32) << 8)
                | slice[11] as u32;
            let data_offset = slice[12] >> 4;
            let flags = slice[13];
            let window = ((slice[14] as u16) << 8) | slice[15] as u16;
            let checksum = ((slice[16] as u16) << 8) | slice[17] as u16;
            let urgent_pointer = ((slice[18] as u16) << 8) | slice[19] as u16;
            let options: Vec<u8> = if data_offset as usize > TCP_MIN_HEADER_LENGTH {
                slice[20..(((data_offset * 4) as usize) - TCP_MIN_HEADER_LENGTH)].to_vec()
            } else {
                Vec::new()
            };

            return TCPHeader {
                source_port,
                destination_port,
                sequence_number,
                acknowledgement_number,
                data_offset,
                flags,
                window,
                checksum,
                urgent_pointer,
                options,
            };
        }

        pub fn to_slice(&self) -> Vec<u8> {
            let mut bytes = vec![0u8; self.window as usize];
            bytes[0..2].copy_from_slice(&[(self.source_port >> 8) as u8, self.source_port as u8]);
            bytes[2..4].copy_from_slice(&[
                (self.destination_port >> 8) as u8,
                self.destination_port as u8,
            ]);
            bytes[4..8].copy_from_slice(&[
                (self.sequence_number >> 24) as u8,
                (self.sequence_number >> 16) as u8,
                (self.sequence_number >> 8) as u8,
                self.sequence_number as u8,
            ]);
            bytes[8..12].copy_from_slice(&[
                (self.data_offset << 4) | 0,
                self.flags,
                (self.window << 8) as u8,
                self.window as u8,
            ]);
            bytes[12..16].copy_from_slice(&[
                (self.checksum << 8) as u8,
                self.checksum as u8,
                (self.urgent_pointer << 8) as u8,
                self.urgent_pointer as u8,
            ]);
            if self.options.len() > 0 {
                bytes[TCP_MIN_HEADER_LENGTH..].copy_from_slice(self.options.as_slice());
            }

            return bytes;
        }

        pub fn get_flags(&self) -> TCPFlags {
            let congestion_window_reduced: bool = (0b10000000 & self.flags) != 0;
            let explicit_congesiton_notification_echo: bool = (0b01000000 & self.flags) != 0;
            let urgent: bool = (0b00100000 & self.flags) != 0;
            let acknowledgement: bool = (0b00010000 & self.flags) != 0;
            let push: bool = (0b00001000 & self.flags) != 0;
            let reset: bool = (0b00000100 & self.flags) != 0;
            let synchronize: bool = (0b00000010 & self.flags) != 0;
            let finish: bool = (0b00000001 & self.flags) != 0;

            return TCPFlags {
                congestion_window_reduced,
                explicit_congesiton_notification_echo,
                urgent,
                acknowledgement,
                push,
                reset,
                synchronize,
                finish,
            };
        }

        pub fn get_header_length(&self) -> usize {
            return (self.data_offset * 4) as usize;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::tcp::*;

    #[test]
    fn test_tcp_header_parsing() {
        let valid_tcp_packet: [u8; 20] = [
            0x1F, 0x90, // Source Port (8080)
            0x00, 0x50, // Destination Port (80)
            0x00, 0x00, 0x00, 0x01, // Sequence Number
            0x00, 0x00, 0x00, 0x01,       // Acknowledgement Number
            0x50,       // Data Offset (5 * 4 = 20 bytes)
            0b00011000, // Flags
            0x00, 0x00, // Window Size
            0x00, 0x00, // Checksum (Placeholder)
            0x00, 0x00, // Urgent Pointer
        ];

        let header = TCPHeader::from_slice(&valid_tcp_packet);

        let flags = header.get_flags();
        assert!(flags.acknowledgement);
        assert!(flags.push);
        assert!(!flags.reset);
        assert!(!flags.synchronize);
        assert!(!flags.finish);
    }

    #[test]
    fn test_tcp_flags() {
        let valid_tcp_packet: [u8; 20] = [
            0x1F, 0x90, // Source Port
            0x00, 0x50, // Destination Port
            0x00, 0x00, 0x00, 0x01, // Sequence Number
            0x00, 0x00, 0x00, 0x01,       // Acknowledgement Number
            0x50,       // Data Offset
            0b00011001, // Flags
            0x00, 0x00, // Window Size
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent Pointer
        ];

        let header = TCPHeader::from_slice(&valid_tcp_packet);

        let flags = header.get_flags();
        assert!(flags.acknowledgement);
        assert!(flags.push);
        assert!(flags.finish);
        assert!(!flags.reset);
        assert!(!flags.synchronize);
    }

    #[test]
    fn test_tcp_payload_from_slice() {
        let data: [u8; 22] = [
            0x1A, 0x2B, // Source Port
            0x3C, 0x4D, // Destination Port
            0x00, 0x00, 0x00, 0x01, // Sequence Number
            0x00, 0x00, 0x00, 0x02, // Acknowledgement Number
            0x50, // Data Offset (5, indicating 20 bytes header)
            0x18, // Flags
            0x00, 0xFF, // Window
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent Pointer
            0x01, 0x01, // Data
        ];

        let payload = TCPPayload::from_slice(&data).expect("Failed to create TCPPayload");

        assert_eq!(payload.header.source_port, 0x1A2B);
        assert_eq!(payload.header.destination_port, 0x3C4D);
        assert_eq!(payload.header.sequence_number, 1);
        assert_eq!(payload.header.acknowledgement_number, 2);
        assert_eq!(payload.header.get_header_length(), 20);
    }
}
