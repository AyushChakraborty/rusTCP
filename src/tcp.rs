use std::io;


pub enum TCPState {  
    Closed,
    Listen,
    SynRcvd,
    Estab
}//following the TCP state diagram, refer RFC 793 page 22


//several sequence variables to maintain the flow of user datagrams, both in sender and receiver space
struct SenSeqSpace {
    
///                         Send Sequence Space
///                 1         2          3          4      
///             ----------|----------|----------|---------- 
///                    SND.UNA    SND.NXT    SND.UNA        
///                                         +SND.WND        

///       1 - old sequence numbers which have been acknowledged  
///       2 - sequence numbers of unacknowledged data            
///       3 - sequence numbers allowed for new data transmission 
///       4 - future sequence numbers which are not yet allowed  

///                         Send Sequence Space
///                              Figure 4.

///The send window is the portion of the sequence space labeled 3 in figure 4.
    
    ///send unacknowledged
    una: u32,  
    ///send next    
    nxt: u32,  
    ///send window
    wnd: u16, 
    ///send urgent pointer
    up: bool,  
    ///segment sequence number used for last window update
    wl1: u16,
    ///segment acknowledgement number used for last window update
    wl2: u16,      
    ///initial send seq number 
    iss: u32      
}


struct RecvSeqSpace {
    /// Receive Sequence Space
  
    ///                      1          2          3      
    ///                  ----------|----------|---------- 
    ///                         RCV.NXT    RCV.NXT        
    ///                                   +RCV.WND        
  
    ///       1 - old sequence numbers which have been acknowledged  
    ///       2 - sequence numbers allowed for new reception         
    ///       3 - future sequence numbers which are not yet allowed  
  
    ///                        Receive Sequence Space
    ///                              Figure 5.

    ///receive next
    nxt: u32,
    ///receive window
    wnd: u16,
    ///receive urgent pointer
    up: u32,
    ///intial receive sequence number
    irs: u32
}


pub struct Connection {
    state: TCPState,
    snd: SenSeqSpace,
    recv: RecvSeqSpace
}

impl Default for Connection {
    fn default() -> Self {
        Connection {state: TCPState::Listen}
    }
}


impl Connection {
    pub fn on_packet<'a>(&mut self, 
        nic: &mut tun_tap::Iface,
        ip: etherparse::Ipv4HeaderSlice<'a>, 
        ud: etherparse::TcpHeaderSlice<'a>, 
        buf: &'a [u8]) -> io::Result<usize>{

        let mut send_buf = [0u8; 1500];      //before things get sent to the virtual NIC, its stored in this buffer
            
        match self.state {
            TCPState::Closed => return Ok(0),
            
            TCPState::Listen => {
                if !ud.syn() {       //only want a SYN segment in this state
                    return Ok(0);     
                }
                //from the TCP state diagram as given in RFC 793, we must send a ACK for their SYN, as well as send another SYN
                
                //LISTEN --> SYN_RCVD transition:
                //state transition from LISTEN TO SYN_RCVD is encoded here, where the SYN segment is already received, and we send SYN, ACK segment
                //by turning both of these bits on for this segment
                
                //keep track of sender info
                self.recv.nxt = ud.sequence_number() + 1;
                self.recv.wnd = ud.window_size();
                self.recv.irs = ud.sequence_number();
                
                //decide on things this host(receiver) wants to send to the sender
                self.snd.iss = 0;        //HAVE TO MAKE THIS RANDOMISED
                self.snd.una = self.snd.iss;
                self.snd.nxt = self.snd.iss + 1;
                self.snd.wnd = 10;       //decided 
                
                
                let mut syn_ack_headers = etherparse::TcpHeader::new(ud.destination_port(), ud.source_port(), self.snd.iss, self.snd.wnd);
                //syn_ack goes from server to client, assuming client first sends the syn packet, which is captured first here
                syn_ack_headers.syn = true;
                syn_ack_headers.ack = true;
                syn_ack_headers.acknowledgment_number =self.recv.nxt;
                
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