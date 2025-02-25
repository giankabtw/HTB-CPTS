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
