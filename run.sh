#!/bin/bash

cargo build
prev_exit_stat=$?

#if compilation fails, stop this shell script entirely
if [[ $prev_exit_stat -ne 0 ]]; then 
    echo "exiting shell process with exit status: $prev_exit_stat"
    exit $prev_exit_stat                           #exits this shell process with this exit status
fi

sudo setcap cap_net_admin=eip target/debug/tcp
    
target/debug/tcp &
bg_pid=$!                                          #runs the above line in a background process, stores its pid

sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0
    
trap "kill $bg_pid" INT TERM EXIT                  #if trap of signals SIGINT, SIGTERM, SIGEXIT occurs, kill the bg process
wait $bg_pid                                       #wait for the bg process to exit in general
