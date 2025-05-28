# Custom TCP Implementation in Rust

This project is a user-space implementation of the Transmission Control Protocol (TCP) written in Rust. It uses a virtual network interface (TUN) to intercept and process raw IP packets, enabling the construction and handling of TCP segments entirely outside the operating system’s kernel.

## Overview

- A virtual network interface (`tun0`) is created using the `tun-tap` crate.
- The Linux kernel routes relevant IP packets to this interface.
- The application receives these packets, parses the IP and TCP headers, and implements TCP logic manually in user space.

This approach provides a hands-on opportunity to understand and build TCP from the ground up, including:

- TCP connection management (e.g., SYN, ACK, FIN handling)
- Sequence and acknowledgment number tracking
- Segment parsing and response
- Potential retransmission and flow control logic

## References and Inspiration

- Inspired by Jon Gjenset’s series on writing a TCP stack in Rust
- Relevant RFCs:
  - [RFC 793: TCP Protocol Specification](https://datatracker.ietf.org/doc/html/rfc793)
  - [RFC 1180: TCP/IP Tutorial](https://datatracker.ietf.org/doc/html/rfc1180)
  - [RFC 2525: Known TCP Implementation Problems](https://datatracker.ietf.org/doc/html/rfc2525)
  - [RFC 7414: TCP Roadmap](https://datatracker.ietf.org/doc/html/rfc7414)