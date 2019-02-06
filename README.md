# Network-Router-with-Firewall
A custom network topology with firewall in Mininet, only allowing network traffic with ICMP packets while blocking untrusted hosts.
![network topology](https://user-images.githubusercontent.com/25523755/52326968-47a44e80-299f-11e9-884e-5e229bb4bd17.PNG)

This network topology has 5 hosts and 5 switches. Host 1, 2 and 3 are conncected via switch 1,2, and 3. Host 5 is the server which is connected to switch 4.
Host 4 is the untrusted host therefore, no ICMP packets are allowed to pass through.
IP packets from host 4 is allowed to other hosts except for our server, host  5.
All host from 1, 2, 3, and 5 are free to comunicate and send any type of packets.
