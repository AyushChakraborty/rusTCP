#!/bin/bash

cargo build
sudo setcap cap_net_admin=eip target/debug/tcp
target/debug/tcp &
pid=$!                                          #runs the above line in a background process, stores its pid
sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0
trap "kill $pid" INT TERM EXIT                  #if trap of signals SIGINT, SIGTERM, SIGEXIT occurs, kill the bg process
wait $pid                                       #wait for the bg process to exit in general
