use std::io;
use std::collections::HashMap;
use std::net::Ipv4Addr;

mod tcp;

#[derive(Copy, Debug, PartialEq, Eq, Hash, Clone)]
struct Quad {
    src: (Ipv4Addr, u16),        //src IP and port
    dest: (Ipv4Addr, u16)
}


fn main() -> io::Result<()> {
    
    let mut connection: HashMap<Quad, tcp::Connection> = HashMap::new();
    
    let mut nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;   //the virtual network card, attached to this process

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
            Ok(ip) => {
                let pkt_src = ip.source_addr();
                let pkt_dest = ip.destination_addr();
                let pkt_proto = ip.protocol(); 
                let pkt_payload_len = ip.payload_len();
                let pkt_header_len = ip.slice().len();
                
                if pkt_proto != etherparse::IpNumber(0x06) {
                    continue;  
                }//only dealing with TCP user datagrams, if anything else comes up, ignore after capture
                
                //parsing TCP headers
                match etherparse::TcpHeaderSlice::from_slice(&buf[(4 + pkt_header_len)..nbytes]) {
                    Ok(ud) => {   //ud is the user datagram  
                        let tcp_header_len = ud.slice().len();
                        let tcp_data_offset = 4 + pkt_header_len + tcp_header_len;    //frame header offset + ip packet header offset + tcp header offset 
                        
                        let tcp_src = ud.source_port();
                        let tcp_dest = ud.destination_port();
                        
                        connection.entry(Quad {
                            src: (pkt_src, tcp_src),
                            dest: (pkt_dest, tcp_dest)
                        }).or_insert(tcp::Connection::default()).on_packet(&mut nic, ip, ud, &buf[tcp_data_offset..nbytes])?;
                        
                        //eprintln!("src port: {:?}\ndest port: {:?}", tcp_src, tcp_dest);
                    },
                    Err(e) => {eprintln!("TCP header slice error: {:?}", e)} 
                }  
                eprintln!("IP packet source: {:?}\nIP packet dest: {:?}\nIP packet protocol: {:?}\nIP payload len: {:?}", pkt_src, pkt_dest, pkt_proto, pkt_payload_len);
                eprintln!("payload bytes: {} \nframe headers: {:x?} \nframe protocol: {:x?}\nIP packet(frame paylaod): {:x?}\n", nbytes-4, frame_flags, frame_proto, ip);
            }
            Err(e) => eprintln!("IP header slice error: {:?}", e)
        }
        //here ip is the IP packet
    } 
    
    //Ok(())
}
