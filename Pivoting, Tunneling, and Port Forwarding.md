## Pivoting, Tunneling, and Port Forwarding   
Once a foothold is gained during an assessment, it may be in scope to move laterally and vertically within a target network. Using one compromised machine to access another is called pivoting and allows us to access networks and resources that are not directly accessible to us through the compromised host. Port forwarding accepts the traffic on a given IP address and port and redirects it to a different IP address and port combination. Tunneling is a technique that allows us to encapsulate traffic within another protocol so that it looks like a benign traffic stream.

# Questions and Answers: 

## Dynamic Port Forwarding with SSH and SOCKS Tunneling

 *SSH with user "ubuntu" and password "HTB_@cademy_stdnt!"*

* **You have successfully captured credentials to an external facing Web Server. Connect to the target and list the network interfaces. How many network interfaces does the target web server have? (Including the loopback interface)**

I began by connecting to the SSH server using the following command:
```bash
ssh ubuntu@10.129.144.206
```
After successfully logging in, I enumerated the network interfaces with:
```bash
ubuntu@WEB01:~$ ifconfig

ens192: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.144.206  netmask 255.255.0.0  broadcast 10.129.255.255
        inet6 fe80::250:56ff:feb0:403a  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::250:56ff:feb0:403a  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:b0:40:3a  txqueuelen 1000  (Ethernet)
        RX packets 1350  bytes 117241 (117.2 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 155  bytes 16860 (16.8 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

ens224: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.5.129  netmask 255.255.254.0  broadcast 172.16.5.255
        inet6 fe80::250:56ff:feb0:2f8  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b0:02:f8  txqueuelen 1000  (Ethernet)
        RX packets 99  bytes 8340 (8.3 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 52  bytes 3910 (3.9 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 352  bytes 27739 (27.7 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 352  bytes 27739 (27.7 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

* **Apply the concepts taught in this section to pivot to the internal network and use RDP (credentials: victor:pass@123) to take control of the Windows target on 172.16.5.19. Submit the contents of Flag.txt located on the Desktop.**
