use std::io;

fn main() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;   //the virtual network card, attached to this process

    let mut buf = [0u8; 1504];    //buffer to recieve data coming into this virtual network card 
    //here each elements is of u8 type, hence a byte
    
    loop {
        let nbytes = nic.recv(&mut buf[..])?;   //what is recived is the frame, and the payload of the frame is the 
        //IP packet which we intend to get
        
        //these make sense wrt MTU, where apart from the first 4 bytes, the rest are the actual IP payload
        let frame_flags = u16::from_be_bytes([buf[0], buf[1]]);
        let frame_proto = u16::from_be_bytes([buf[2], buf[3]]);
        
        if frame_proto != 0x0800 {
            continue;
        }//only dealing with IPv4 addresses
        
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..nbytes]) {
            //here p is the TCP user datagram 
            Ok(p) => {
                let pkt_src = p.source_addr();
                let pkt_dest = p.destination_addr();
                let pkt_proto = p.protocol(); 
                let pkt_payload_len = p.payload_len();
                let pkt_header_len = p.slice().len();
                
                if pkt_proto != etherparse::IpNumber(0x06) {
                    continue;  
                }//only dealing with TCP user datagrams, if anything else comes up, ignore after capture
                
                //parsing TCP headers
                match etherparse::TcpHeaderSlice::from_slice(&buf[4 + pkt_header_len ..nbytes]) {
                    Ok(p) => {
                        let tcp_src = p.source_port();
                        let tcp_dest = p.destination_port();
                        
                        eprintln!("src port: {:?}\ndest port: {:?}", tcp_src, tcp_dest);
                    },
                    Err(e) => {eprintln!("TCP header slice error: {:?}", e)} 
                }
                eprintln!("IP packet source: {:?}\nIP packet dest: {:?}\nIP packet protocol: {:?}\nIP payload len: {:?}", pkt_src, pkt_dest, pkt_proto, pkt_payload_len);
                eprintln!("payload bytes: {} \nframe headers: {:x?} \nframe protocol: {:x?}\nIP packet(frame paylaod): {:x?}\n", nbytes-4, frame_flags, frame_proto, p);
            }
            Err(e) => eprintln!("IP header slice error: {:?}", e)
        }
        //here p is the IP packet
    } 
    
    Ok(())
}
