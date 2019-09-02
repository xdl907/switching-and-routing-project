## Commands for testbed simulation

Boot the controller

```bash
$ bin/ryu-manager --observe-links ryu/ryu/app/SDN_project5_LAB.py 
```

Manually turn on the switches and open a SSH session to two of the hosts in the network

```bash
$ ssh remote_username@remote_host_ip
```

Test rule addition by pinging another host
```bash
$ ping remote_host_ip
```
Open the browser and check rule installation on *http://localhost*

To establish a TCP connection, open a iperf server on the desired destination host
```bash
remote_username@remote_host_ip $ iperf -s
```
Ssh to the desired source host and launch iperf in client mode. Max message length (MTU) is set to 500 bytes to avoid packet truncation
```bash
remote_username@remote_host_ip $ iperf -c 10.0.0.2 -M 500
```

Link failures are simulated by manually unplugging the correct network cables.