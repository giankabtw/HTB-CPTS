## Domain Trusts Primer 

>  RDP to 10.129.240.227 (ACADEMY-EA-MS01) with user "htb-student" and password "Academy_student_AD!"

 * **What is the child domain of INLANEFREIGHT.LOCAL? (format: FQDN, i.e., DEV.ACME.LOCAL)**

 I initiated an RDP connection to the target Windows host 10.129.240.227 using xfreerdp with the provided credentials:

 ```c
xfreerdp /v:10.129.240.227 /u:htb-student /p:Academy_student_AD! +aero -wallpaper -themes /bpp:16 /gdi:sw
```

Once connected, I launched PowerShell with administrative privileges and executed:

```c
PS C:\Tools> Import-Module activedirectory
PS C:\Tools> Get-ADTrust -Filter *

Direction               : BiDirectional
DisallowTransivity      : False
DistinguishedName       : CN=LOGISTICS.INLANEFREIGHT.LOCAL,CN=System,DC=INLANEFREIGHT,DC=LOCAL
ForestTransitive        : False
IntraForest             : True
IsTreeParent            : False
IsTreeRoot              : False
Name                    : LOGISTICS.INLANEFREIGHT.LOCAL
ObjectClass             : trustedDomain
ObjectGUID              : f48a1169-2e58-42c1-ba32-a6ccb10057ec
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=INLANEFREIGHT,DC=LOCAL
Target                  : LOGISTICS.INLANEFREIGHT.LOCAL
TGTDelegation           : False
TrustAttributes         : 32
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False

```

[![Screenshot-2025-03-25-091750.png](https://i.postimg.cc/W1V0mvYj/Screenshot-2025-03-25-091750.png)](https://postimg.cc/ZCf9Z1hD)
