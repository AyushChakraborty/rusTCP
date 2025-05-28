pub struct TCPState {  
    
}

impl TCPState {
    pub fn on_packet<'a>(&mut self, ip: etherparse::Ipv4HeaderSlice<'a>, ud: etherparse::TcpHeaderSlice<'a>, buf: &'a [u8]) {
        eprintln!("({:?}: {}) -> ({:?}: {}) | tcp payload: {}B", ip.source_addr(), ud.source_port(), ip.destination_addr(), ud.destination_port(), buf.len());
    }
}