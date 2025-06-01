use std::io;
use std::cmp::Ordering;


pub enum TCPState {  
    //Closed,
    //Listen,
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
    up: bool,
    ///intial receive sequence number
    irs: u32
}


pub struct Connection {
    state: TCPState,
    snd: SenSeqSpace,
    recv: RecvSeqSpace
}

// impl Default for Connection {
//     fn default() -> Self {
//         Connection {state: TCPState::Listen}
//     }
// }


impl Connection {
    
    //this method will now be called when a new connection is to be set
    pub fn accept<'a>( 
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>, 
        udh: etherparse::TcpHeaderSlice<'a>, 
        data: &'a [u8]) -> io::Result<Option<Self>> {

        let mut buf = [0u8; 1500];      //before things get sent to the virtual NIC, its stored in this buffer
        
    
        if !udh.syn() {       //only want a SYN segment in this state
            return Ok(None);     
        }
        //from the TCP state diagram as given in RFC 793, we must send a ACK for their SYN, as well as send another SYN
        
        //LISTEN --> SYN_RCVD transition:
        //state transition from LISTEN TO SYN_RCVD is encoded here, where the SYN segment is already received, and we send SYN, ACK segment
        //by turning both of these bits on for this segment
        
        let iss = 0;    //HAVE TO MAKE THIS RANDOMISED
        
        let mut c = Connection {
            state: TCPState::SynRcvd,
            snd: SenSeqSpace {
                //decide on things this host(receiver) wants to send to the sender
                iss : iss,           
                una : iss,
                nxt : iss + 1,
                wnd : 10,        //decided 
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
            }
        };
    
        let mut syn_ack_headers = etherparse::TcpHeader::new(udh.destination_port(), udh.source_port(), c.snd.iss, c.snd.wnd);
        //syn_ack goes from server to cli ent, assuming client first sends the syn packet, which is captured first here
        syn_ack_headers.syn = true;
        syn_ack_headers.ack = true;
        syn_ack_headers.acknowledgment_number = c.recv.nxt;
        
        //done with the transport layer details for this case, so passing it to the network layer, by encapsulating
        //it in a IP packet
        
        let ip_syn_ack_headers = etherparse::Ipv4Header::new(syn_ack_headers.header_len_u16(), 64, etherparse::IpNumber::TCP, 
            [iph.destination()[0], iph.destination()[1], iph.destination()[2], iph.destination()[3]], 
            [iph.source()[0], iph.source()[1], iph.source()[2], iph.source()[3]]).unwrap(); 
        
        eprintln!("got ip header:\n{:02x?}", iph);
        eprintln!("got tcp header:\n{:02x?}", udh);
        
        syn_ack_headers.checksum = syn_ack_headers.calc_checksum_ipv4(&ip_syn_ack_headers, &[]).expect("failed to compute checksum");
        
        let unwritten = {
            let mut send_buf_ref = &mut buf[..];  //needed due to the signature of .write()
            ip_syn_ack_headers.write(&mut send_buf_ref)?;   //it comes first since ip headers are wrapped around the
            //the segment from the transport layer 
            syn_ack_headers.write(&mut send_buf_ref)?;
            //no payload in case of syn_ack packets, so none written
            send_buf_ref.len()
        };
        
        eprintln!("responding with: {:02x?}", &buf[..buf.len() - unwritten]);
        nic.send(&buf[..unwritten])?;
        Ok(Some(c))
    } 
    
    //when a connection already exists, and need to continue on for that connection
    pub fn continue_existing<'a>(&mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>, 
        udh: etherparse::TcpHeaderSlice<'a>, 
        data: &'a [u8]) -> io::Result<()> {
            
            //following checks based on RFC 793 pg 24
        
            //accptable ACK check, where U < A <= N and since the function is for exclusive checks, 
            //.wrapping_add(1) is done so that N now becomes N + 1 and the check is also valid for N 
            //                              SND.UNA < SEG.ACK =< SND.NXT    
            let segack = udh.acknowledgment_number();
            
            if !is_between_wrapped(&self.snd.una, &segack, &self.snd.nxt.wrapping_add(1)) { 
                return Ok(());
            }
            
            //valid SEG check
            //                               RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND         (first data byte sent)
            // and                       RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND   (last data byte sent)
            let segseq = udh.sequence_number(); 
            let mut seglen = data.len();
            
            //as per RFC 793, SEG.LEN must include the syn, fin bits if the segment is of one of those types
            if udh.syn() || udh.fin() {
                seglen += 1;
            }
            
            if seglen == 0 && !udh.syn() && !udh.fin() {
                //has its own case, where the segment length is 0 (keep in mind that segment length is the payload
                //length that the segment carries) and its only an ACK segment
                if self.recv.wnd == 0 {
                    if segseq != self.recv.nxt {
                        return Ok(());
                    }
                }else if self.recv.wnd > 0 {
                    if !is_between_wrapped(&self.recv.nxt.wrapping_sub(1), &segseq, &(self.recv.nxt + self.recv.wnd as u32)) {
                        return Ok(());
                    }
                }else {
                    return Ok(());
                }
            }else if seglen > 0 && !udh.syn() && !udh.fin(){
                if self.recv.wnd == 0 {
                    return Ok(());
                }else if self.recv.wnd > 0 {
                    if !is_between_wrapped(&self.recv.nxt.wrapping_sub(1), &segseq, &self.snd.nxt.wrapping_add(self.recv.wnd as u32)) &&
                    !is_between_wrapped(&self.recv.nxt.wrapping_sub(1), &(segseq + seglen as u32 - 1), &self.snd.nxt.wrapping_add(self.recv.wnd as u32)) { 
                        return Ok(());
                    }
                }else {
                    return Ok(()); 
                }
            }else {
                return Ok(());
            }
            //now that the checks are done,
            
            
            match self.state {
                TCPState::SynRcvd => {
                    //will to get ACK for our SYN now, ensured after the checks
                    
                }
                TCPState::Estab => {
                }
            }
            Ok(())
        }
}

fn is_between_wrapped(start: &u32, x: &u32, end: &u32) -> bool{
    //this check if exclusive of the endpoints start and end itself, x must be strictly between
    //start and end for the function to return true
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
