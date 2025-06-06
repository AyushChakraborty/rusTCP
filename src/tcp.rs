use std::io::{self, Write};
use std::cmp::{min, Ordering};


pub enum TCPState {  
    //Closed,
    //Listen,
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    TimeWait
}//following the TCP state diagram, refer RFC 793 page 22

impl TCPState {
    fn is_synchronised(&self) -> bool {
        match *self {
            Self::SynRcvd => false,
            Self::Estab | Self::FinWait1 | Self::TimeWait | Self::FinWait2 => true
        }
    }
}


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
    up: bool,
    ///intial receive sequence number
    irs: u32
}


pub struct Connection {
    state: TCPState,
    snd: SenSeqSpace,
    recv: RecvSeqSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader
}


impl Connection {
    
    //this method will now be called when a new connection is to be set
    pub fn accept<'a>( 
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>, 
        udh: etherparse::TcpHeaderSlice<'a>, 
        _data: &'a [u8]) -> io::Result<Option<Self>> {
    
        if !udh.syn() {       //only want a SYN segment in this state
            return Ok(None);     
        }
        //from the TCP state diagram as given in RFC 793, we must send a ACK for their SYN, as well as send another SYN
        
        /*
        LISTEN --> SYN_RCVD transition:
        state transition from LISTEN TO SYN_RCVD is encoded here, where the SYN segment is already received, and we send SYN, ACK segment
        by turning both of these bits on for this segment
        */
        
        let iss = 0;    //HAVE TO MAKE THIS RANDOMISED
        let wnd = 10;
        
        let mut c = Connection {
            state: TCPState::SynRcvd,
            snd: SenSeqSpace { 
                //decide on things this host(receiver) wants to send to the sender
                iss : iss,           
                una : iss,
                nxt : iss,
                wnd : wnd,        //decided 
                wl1 : 0,
                wl2 : 0,
                up : false
            },
            recv: RecvSeqSpace {
                //keep track of sender info
                nxt : udh.sequence_number() + 1,
                wnd : udh.window_size(),
                irs : udh.sequence_number(),
                up : false
            },
            
            ip: etherparse::Ipv4Header::new(0, 64, etherparse::IpNumber::TCP, iph.destination(), iph.source()).unwrap(),
            
            tcp: etherparse::TcpHeader::new(udh.destination_port(), udh.source_port(), iss, wnd)
        };
    
        //syn_ack goes from server to client, assuming client first sends the syn packet, which is captured first here
        c.tcp.syn = true;
        c.tcp.ack = true;
        //c.tcp.acknowledgment_number = c.recv.nxt;
    
        c.send(nic, &[])?;
        Ok(Some(c))
    } 
    
    
    fn send(&mut self, nic: &mut tun_tap::Iface, payload: &[u8]) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        
        //since we cant write more than the size of the buffer
        let size = min(buf.len(), self.tcp.header_len() + self.ip.header_len() + payload.len());
        //ip headers must be included here, since they too are written to the buffer
        
        self.tcp.sequence_number = self.snd.nxt;
        self.tcp.acknowledgment_number = self.recv.nxt;
        self.ip.set_payload_len(size - self.ip.header_len()).unwrap();    //but upon setting the payload size 
        //the ip headers must not be included since its the payload of the ip packet itself 
        
        self.tcp.checksum = self.tcp.calc_checksum_ipv4(&self.ip, &[]).expect("failed to compute checksum");
        
        let mut send_buf_ref = &mut buf[..];  
        self.ip.write(&mut send_buf_ref)?;  
        self.tcp.write(&mut send_buf_ref)?;
        //payload present now 
        let payload_bytes = send_buf_ref.write(payload).unwrap();       //returns the amt of bytes written to the buffer,
        //might not be the full payload due to buffer size
        let unwritten = send_buf_ref.len();
        
        self.snd.nxt = self.snd.nxt.wrapping_add(payload_bytes as u32);
        
        //since syn, fin bits are a part of the payload too
        if self.tcp.syn {
            self.snd.nxt = self.snd.nxt.wrapping_add(1);
            self.tcp.syn = false;
        } 
        if self.tcp.fin {
            self.snd.nxt = self.snd.nxt.wrapping_add(1);
            self.tcp.fin = false;
        }
        
        nic.send(&buf[..buf.len() - unwritten])?;
        Ok(payload_bytes)
    }
    
    
    //to send a RESET segment
    pub fn send_rst(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        /*
        TODO: fix seq numbers
        If the incoming segment has an ACK field, the reset takes its
        sequence number from the ACK field of the segment, otherwise the
        reset has sequence number zero and the ACK field is set to the sum
        of the sequence number and segment length of the incoming segment.
        The connection remains in the same state
        */
        
        /*
        TODO: also handle synchronised states 
        If the connection is in a synchronized state (ESTABLISHED,
        FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT),
        any unacceptable segment (out of window sequence number or
        unacceptible acknowledgment number) must elicit only an empty
        acknowledgment segment containing the current send-sequence number
        and an acknowledgment indicating the next sequence number expected
        to be received, and the connection remains in the same state
        */
        
        self.tcp.rst = true;
        self.tcp.acknowledgment_number = 0;
        self.tcp.sequence_number = 0;
        self.ip.set_payload_len(self.tcp.header_len()).unwrap(); 
        self.send(nic, &[])?;
        Ok(())
    }
    
    //when a connection already exists, and need to continue on for that connection
    pub fn continue_existing<'a>(&mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>, 
        udh: etherparse::TcpHeaderSlice<'a>, 
        data: &'a [u8]) -> io::Result<()> {
            
            //following checks based on RFC 793 pg 24
            
            //valid SEG check 
            //                               RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND         (first data byte sent)
            // and                       RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND   (last data byte sent)
            let segseq = udh.sequence_number(); 
            let mut seglen = data.len();
            
            //as per RFC 793, SEG.LEN must include the syn, fin bits if the segment is of one of those types
            if udh.syn() {
                seglen += 1;
            }
            if udh.fin() {
                seglen += 1;
            }
            
            let mut ok = false;
            
            if seglen == 0 && !udh.syn() && !udh.fin() {
                //has its own case, where the segment length is 0 (keep in mind that segment length is the payload
                //length that the segment carries) and its only an ACK segment
                if self.recv.wnd == 0 {
                    if segseq != self.recv.nxt {
                        ok = false;
                    }else {
                        ok = true;
                    }
                }else if self.recv.wnd > 0 {
                    if !is_between_wrapped(&self.recv.nxt.wrapping_sub(1), &segseq, &(self.recv.nxt + self.recv.wnd as u32)) {
                        ok = false;
                    }else {
                        ok = true;
                    }
                }else {
                    false;
                }
            }else if seglen > 0 && !udh.syn() && !udh.fin(){
                if self.recv.wnd == 0 {
                    ok = false;
                }else if self.recv.wnd > 0 {
                    if !is_between_wrapped(&self.recv.nxt.wrapping_sub(1), &segseq, &self.snd.nxt.wrapping_add(self.recv.wnd as u32)) &&
                    !is_between_wrapped(&self.recv.nxt.wrapping_sub(1), &(segseq.wrapping_add(seglen as u32 - 1)), &self.snd.nxt.wrapping_add(self.recv.wnd as u32)) { 
                        ok = false;
                    }else {
                        ok = true;
                    }
                }else {
                    ok = false;
                }
            }else {
                ok = false;
            }
            
            if !ok {
                self.send(nic, &[])?;
                return Ok(());
            }
            
            //incrementing UNA, NXT
            self.recv.nxt = segseq.wrapping_add(seglen as u32);        /*
            the next thing the initial receiver has to send 
            is the byte from its current sending byte(SEG num) plus(wrapped) length of the segment payload length
            
            TODO: if not acceptanble, send an ack
            */
            
            if !udh.ack() {
                return Ok(()); 
            }
            
            /*
            accptable ACK check, where U < A <= N and since the function is for exclusive checks, 
            .wrapping_add(1) is done so that N now becomes N + 1 and the check is also valid for N 
                                           SND.UNA < SEG.ACK =< SND.NXT    
            */
            let segack = udh.acknowledgment_number();
            
            if !is_between_wrapped(&self.snd.una, &segack, &self.snd.nxt.wrapping_add(1)) { 
                /*
                if the ACK is not as intended, and its in a non-synchronised state, then send RST segment
                to be done 
                */
                return Ok(());
            }
            
            /*
            so right at this stage, the ACK itself has been rightfully acknowledged, hence we increment UNA
            of the sender 
            */
        
            //now that the checks are done,
            
            if let TCPState::SynRcvd = self.state {
                //////////
                if is_between_wrapped(&self.snd.una.wrapping_sub(1), &segack, &self.snd.nxt.wrapping_add(1)) { 
                    self.state = TCPState::Estab;
                }else {
                    // TODO: return RSN <SEQ=SEG.ACK><CTL=RST>
                }
                self.snd.una = segack; 
            }
            
            if let TCPState::Estab | TCPState::FinWait1 | TCPState::FinWait2 = self.state {
                if !is_between_wrapped(&self.snd.una, &segack, &self.snd.nxt.wrapping_add(1)) { 
                    return Ok(());
                }
                self.snd.una = segack;
                assert!(data.is_empty());
                /*
                for now, lets close the connection immediately
                FIN shld only be sent once the transmission queue is fully empty, so that needs to be handled
                but for now, just plain going to close state this end
                */  
                if let TCPState::Estab = self.state {
                    self.tcp.fin = true;
                    self.send(nic, &[])?;
                    self.state = TCPState::FinWait1;
                }
            } 
            
            if let TCPState::FinWait1 = self.state {                    
                if self.snd.una == self.snd.iss + 2 {
                    //+2 since it has to account for the FIN as well as the ACK sent
                    self.state = TCPState::FinWait2;
                }
            }
            
            if udh.fin() {
                if let TCPState::FinWait2 = self.state {
                    //done, connection closed 
                    self.send(nic, &[])?;
                    self.state = TCPState::TimeWait;
                } 
            }
            Ok(())
        }
}

fn is_between_wrapped(start: &u32, x: &u32, end: &u32) -> bool{
    /*
    this check if exclusive of the endpoints start and end itself, x must be strictly between
    start and end for the function to return true
    */
    match start.cmp(x) {
        Ordering::Equal => {return false;},
        Ordering::Less => {
            if end >= start && end <= x {
                return false;
            }else {return true;}
        },
        Ordering::Greater => {
            if x < end && end < start {return true;}
            else {
                return false;
            }
        }
    }
}
