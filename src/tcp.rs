use std::io;

pub enum TCPState {  
    Closed,
    Listen,
    SynRcvd,
    Estab
}//following the TCP state diagram, refer RFC 793 page 22

impl Default for TCPState {
    fn default() -> Self {
        TCPState::Listen
    }
}


impl TCPState {
    pub fn on_packet<'a>(&mut self, 
        nic: &mut tun_tap::Iface,
        ip: etherparse::Ipv4HeaderSlice<'a>, 
        ud: etherparse::TcpHeaderSlice<'a>, 
        buf: &'a [u8]) -> io::Result<usize>{

        let mut send_buf = [0u8; 1500];      //before things get sent to the virtual NIC, its stored in this buffer
            
        match *self {
            TCPState::Closed => return Ok(0),
            
            TCPState::Listen => {
                if !ud.syn() {
                    return Ok(0);     
                }
                //from the TCP state diagram as given in RFC 793, we must send a ACK for their SYN, as well as send another SYN
                let mut syn_ack_headers = etherparse::TcpHeader::new(ud.destination_port(), ud.source_port(), 0, 0);
                //syn_ack goes from server to client, assuming client first sends the syn packet, which is captured first here
                syn_ack_headers.syn = true;
                syn_ack_headers.ack = true;
                
                //done with the transport layer details for this case, so passing it to the network layer, by encapsulating
                //it in a IP packet
                
                let ip_syn_ack_headers = etherparse::Ipv4Header::new(syn_ack_headers.header_len_u16(), 64, etherparse::IpNumber::TCP, [ip.destination()[0], ip.destination()[1], ip.destination()[2], ip.destination()[3]], [ip.source()[0], ip.source()[1], ip.source()[2], ip.source()[3]]).unwrap();
                
                let unwritten = {
                    let mut send_buf_ref = &mut send_buf[..];  //needed due to the signature of .write()
                    syn_ack_headers.write(&mut send_buf_ref)?;
                    ip_syn_ack_headers.write(&mut send_buf_ref)?;
                    //no payload in case of syn_ack packets, so none written
                    send_buf_ref.len()
                };
                
                nic.send(&send_buf[..unwritten])
            }
       
            TCPState::SynRcvd => return Ok(0),
            
            TCPState::Estab => return Ok(0)
        }
        //eprintln!("({:?}: {}) -> ({:?}: {}) | tcp payload: {}B", ip.source_addr(), ud.source_port(), ip.destination_addr(), ud.destination_port(), buf.len());
    }
}