#!/bin/bash

cargo b --release
sudo setcap cap_net_admin=eip ./target/release/tcp-rust
./target/release/tcp-rust &

pid=$!
sudo ip addr add 192.168.0.10/24 dev tun0
sudo ip link set up dev tun0
trap "kill $pid" INT TERM
wait $pid
