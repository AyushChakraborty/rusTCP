## A custom implementation of TCP with rust

### Uses tun/tap to open a virtual network interface to route all the intended frames in the kernel to our intended tun interface and then build the transport layer protocol in the user space, giving a chance to implement TCP from scratch

### inspiration from Jon Gjenset's videos on the same
### some handy RFCs: 793, 1180, 2525, 7414

