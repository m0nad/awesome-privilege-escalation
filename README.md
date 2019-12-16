# Awesome Privilege Escalation
A curated list of awesome privilege escalation

## Table of Contents

* [Linux](#linux)
    * [Escape restricted shells](#escape-restricted-shells)
    * [SUDO and SUID](#sudo-and-suid)
    * [Capabilities](#capabilities)
    * [Tools](#tools)
        * [Find CVEs](#find-cves)
    * [Chkrootkit](#chkrootkit)
    * [NFS](#nfs)
    * [Presentations](#presentations)
* [Windows](#windows)
    * [Hot Potato](#hot-potato)
    * [Unquoted services with spaces](#unquoted-services-with-spaces)
    * [Groups.xml](#groupsxml)
    * [Tools](#tools-1)
    * [Presentations](#presentations-1)
* [Linux and Windows](#linux-and-windows)
* [Docker](#docker)
    * [Docker socks](#docker-socks)
* [AWS](#aws)

## Linux
 - [Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
 - [Linux elevation of privileges ToC](https://guif.re/linuxeop)
 - [Pentest Book - Privilege Escalation](https://chryzsh.gitbooks.io/pentestbook/privilege_escalation_-_linux.html): common Linux privilege escalation techniques.
 - [A guide to Linux Privilege Escalation](https://payatu.com/guide-linux-privilege-escalation/)
 - [Enumeration is the Key](https://medium.com/basic-linux-privilege-escalation/basic-linux-privilege-escalation-966de11f9997)
 - [My 5 Top Ways to Escalate Privileges](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/my-5-top-ways-to-escalate-privileges/): Bruno Oliveira's top 5 favorite ways for accomplishing privilege escalation in the most practical ways possible.
 - [Understanding Privilege Escalation](http://www.admin-magazine.com/Articles/Understanding-Privilege-Escalation):
 Some techniques malicious users employ to escalate their privileges on a Linux system.
 - [How privileges work in operating systems?](https://www.future-processing.pl/blog/privilege-escalation/)
 - [Linux Privilege Escalation via Dynamically Linked Shared Object Library](https://www.contextis.com/en/blog/linux-privilege-escalation-via-dynamically-linked-shared-object-library): How RPATH and Weak File Permissions can lead to a system compromise.
 - [Reach the root! How to gain privileges in Linux?](https://hackmag.com/security/reach-the-root/)
 - [Linux Privilege Escalation](https://percussiveelbow.github.io/linux-privesc/): an introduction to Linux escalation techniques, mainly focusing on file/process permissions, but along with some other stuff too.
 - [Local Linux Enumeration & Privilege Escalation Cheatsheet](https://www.rebootuser.com/?p=1623): a few Linux commands that may come in useful when trying to escalate privileges on a target system.
 - [PENETRATION TESTING PRACTICE LAB - VULNERABLE APPS / SYSTEMS](https://www.amanhardikar.com/mindmaps/Practice.html)
 - [Local Linux privilege escalation overview](https://myexperiments.io/linux-privilege-escalation.html): This article will give an overview of the basic Linux privilege escalation techniques. It separates the local Linux privilege escalation in different scopes: kernel, process, mining credentials, sudo, cron, NFS, and file permission.
 - [Attack and Defend: LinuxPrivilege Escalation Techniques of 2016](https://www.sans.org/reading-room/whitepapers/linux/attack-defend-linux-privilege-escalation-techniques-2016-37562): This paper will examine Linux privilege escalation techniques used throughout 2016 in detail, highlighting how these techniques work and how adversaries are using them.
 - [Local Linux Enumeration & Privilege Escalation](https://hackingandsecurity.blogspot.com/2016/05/local-linux-enumeration-privilege.html): a few Linux commands that may come in useful when trying to escalate privileges on a target system.
 - [Back To The Future: Unix Wildcards Gone Wild](https://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt): This article will cover one interesting
old-school Unix hacking technique, that will still work in 2013.
 - [POST CATEGORY : Privilege Escalation](https://www.hackingarticles.in/category/privilege-escalation/): Privilege escalation post category in Raj Chandel's Blog.
 - [Privilege Escalation & Post-Exploitation](https://github.com/rmusser01/Infosec_Reference/blob/master/Draft/PrivescPostEx.md)
 - [Linux - Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
 - [Privilege escalation: Linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
 - [Penetration-Testing-Grimoire/Privilege Escalation/linux.md](https://github.com/weaknetlabs/Penetration-Testing-Grimoire/blob/master/Privilege%20Escalation/linux.md)
 - [Privilege Escalation Cheatsheet (Vulnhub)](https://github.com/Ignitetechnologies/Privilege-Escalation): This cheasheet is aimed at the CTF Players and Beginners to help them understand the fundamentals of Privilege Escalation with examples.
 - [Hackers Hut](https://www.win.tue.nl/~aeb/linux/hh/hh.html): Some random hacking hints, mainly from a Linux point of view.
 - [Hacking Linux Part I: Privilege Escalation](http://www.dankalia.com/tutor/01005/0100501004.htm)
 

### Escape restricted shells
 - [Escaping Restricted Linux Shells](https://pen-testing.sans.org/blog/pen-testing/2012/06/06/escaping-restricted-linux-shells): Resource for penetration testers to assist them when confronted with a restricted shell.
 - [Restricted Linux Shell Escaping Techniques](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/): The focus of this article is on discussing and summarizing different techniques to escape common Linux restricted shells and also simple recommendations for administrators to protect against it.
 - [Linux Restricted Shell Bypass](https://www.exploit-db.com/docs/english/44592-linux-restricted-shell-bypass-guide.pdf)
 - [Escaping from Restricted Shell and Gaining Root Access to SolarWinds Log & Event Manager (SIEM) Product](https://pentest.blog/unexpected-journey-4-escaping-from-restricted-shell-and-gaining-root-access-to-solarwinds-log-event-manager-siem-product/)
 - [Breaking out of rbash using scp](http://pentestmonkey.net/blog/rbash-scp)

### SUDO and SUID
 - [GTFOBins](https://gtfobins.github.io/): GTFOBins is a curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions.
 - [Abusing SUDO](https://touhidshaikh.com/blog/?p=790): Some of the binary which helps you to escalate privilege using the sudo command.
 - [Sudo (LD_PRELOAD)](https://touhidshaikh.com/blog/?p=827): Privilege Escalation from an LD_PRELOAD environment variable. 
 - [How I got root with Sudo](https://www.securusglobal.com/community/2014/03/17/how-i-got-root-with-sudo/)
 - [Gaining a Root shell using MySQL User Defined Functions and SETUID Binaries](https://infamoussyn.wordpress.com/2014/07/11/gaining-a-root-shell-using-mysql-user-defined-functions-and-setuid-binaries/): How a MySQL User Defined Function (UDF) and a SETUID binary can be used to elevate user privilege to a root shell.

### Capabilities
 - [Exploiting capabilities](http://blog.sevagas.com/IMG/pdf/exploiting_capabilities_the_dark_side.pdf): Parcel root power,  the dark side of capabilities
 - [getcap, setcap and file capabilities](https://www.insecure.ws/linux/getcap_setcap.html)
 - [Capabilities](https://wiki.archlinux.org/index.php/Capabilities)
 - [Spicing up your own access with capabilities](https://www.redpill-linpro.com/sysadvent/2016/12/06/spicing-up-your-access.html)
 - [An Interesting Privilege Escalation vector (getcap/setcap)](https://nxnjz.net/2018/08/an-interesting-privilege-escalation-vector-getcap/)

### Tools
 - [LinEnum](https://github.com/rebootuser/LinEnum)
 - [pspy](https://github.com/DominicBreuker/pspy): unprivileged Linux process snooping
 - [LES](https://github.com/mzet-/linux-exploit-suggester): LES: Linux privilege escalation auditing tool
 - [Linux_Exploit_Suggester](https://github.com/InteliSecureLabs/Linux_Exploit_Suggester): Linux Exploit Suggester; based on operating system release number.
 - [Linux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2): Next-generation exploit suggester based on Linux_Exploit_Suggester
 - [linuxprivchecker.py](https://github.com/sleventyeleven/linuxprivchecker):  Linux Privilege Escalation Check Script
 - [linux-soft-exploit-suggester](https://github.com/belane/linux-soft-exploit-suggester): linux-soft-exploit-suggester finds exploits for all vulnerable software in a system helping with the privilege escalation.
 - [exploit-suggester](https://github.com/pentestmonkey/exploit-suggester): This tool reads the output of “showrev -p” on Solaris machines and outputs a list of exploits that you might want to try.
 - [unix-privesc-check](https://github.com/pentestmonkey/unix-privesc-check): Shell script to check for simple privilege escalation vectors on Unix systems
 - [BeRoot](https://github.com/AlessandroZ/BeRoot): BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
 - [kernelpop](https://github.com/spencerdodd/kernelpop): kernelpop is a framework for performing automated kernel vulnerability enumeration and exploitation.
 - [AutoLocalPrivilegeEscalation](https://github.com/ngalongc/AutoLocalPrivilegeEscalation): An automated script that download potential exploit for linux kernel from exploitdb, and compile them automatically.
 - [Linux Privilege Escalation Check Script](https://github.com/linted/linuxprivchecker): Originally forked from the linuxprivchecker.py (Mike Czumak), this script
is intended to be executed locally on a Linux box to enumerate basic system info and search for common privilege escalation vectors such as word writable files, misconfigurations, clear-text password and applicable
exploits.
 - [uptux](https://github.com/initstring/uptux): Specialized privilege escalation checks for Linux systems.
 - [Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack): Exploits for getting local root on Linux, BSD, AIX, HP-UX, Solaris, RHEL, SUSE etc.
 - [AutoLocalPrivilegeEscalation](https://github.com/ngalongc/AutoLocalPrivilegeEscalation): An automated script that download potential exploit for linux kernel from exploitdb, and compile them automatically
 - [PrivEsc](https://github.com/1N3/PrivEsc): A collection of Windows, Linux and MySQL privilege escalation scripts and exploits.
 - [linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration): Linux enumeration tools for pentesting and CTFs
 - [linux-kernel-exploits](https://github.com/SecWiki/linux-kernel-exploits)

#### Find CVEs
 - https://github.com/lwindolf/lpvs
 - https://github.com/davbo/active-cve-check
 - https://github.com/clearlinux/cve-check-tool
 - https://www.2daygeek.com/arch-audit-a-tool-to-check-vulnerable-packages-in-arch-linux/

### Chkrootkit
 - https://lepetithacker.wordpress.com/2017/04/30/local-root-exploit-in-chkrootkit/

### NFS
 - https://www.hackingarticles.in/linux-privilege-escalation-using-misconfigured-nfs/
 - https://www.computersecuritystudent.com/SECURITY_TOOLS/METASPLOITABLE/EXPLOIT/lesson4/index.html
 - https://blog.hackersonlineclub.com/2018/07/beroot-post-exploitation-tool-to-check.html
 - https://touhidshaikh.com/blog/?p=788

### Presentations
 - https://www.youtube.com/watch?v=oYHAi0cgur4
 - https://www.irongeek.com/i.php?page=videos/bsidesaugusta2016/its-too-funky-in-here04-linux-privilege-escalation-for-fun-profit-and-all-around-mischief-jake-williams
 - https://www.youtube.com/watch?v=yXe4X-AIbps

## Windows
 - https://www.fuzzysecurity.com/tutorials/16.html
 - https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html
 - https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
 - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
 - https://lolbas-project.github.io/
 - https://guif.re/windowseop
 - https://www.youtube.com/watch?v=DlJyKgfkoKQ
 - https://pt.slideshare.net/jakx_/level-up-practical-windows-privilege-escalation
 - https://github.com/chryzsh/awesome-windows-security
 - https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-windows
 - https://www.exploit-db.com/docs/46131
 - https://lolbas-project.github.io/#
 - https://github.com/frizb/Windows-Privilege-Escalation

### Hot Potato
 - https://foxglovesecurity.com/2016/01/16/hot-potato/
 - https://pentestlab.blog/2017/04/13/hot-potato/
 - https://securityonline.info/hot-potato-windows-privilege-escalation-metasploit-powershellhot-potato-windows-privilege-escalation/

### Unquoted services with spaces
 - https://medium.com/@SumitVerma101/windows-privilege-escalation-part-1-unquoted-service-path-c7a011a8d8ae
 - https://pentestlab.blog/2017/03/09/unquoted-service-path/
 - https://www.commonexploits.com/unquoted-service-paths/
 - https://hausec.com/2018/10/05/windows-privilege-escalation-via-unquoted-service-paths/
 - https://www.gracefulsecurity.com/privesc-unquoted-service-path/
 - https://trustfoundry.net/practical-guide-to-exploiting-the-unquoted-service-path-vulnerability-in-windows/
 - https://securityboulevard.com/2018/04/windows-privilege-escalation-unquoted-services/
 - https://www.ethicalhacker.net/community/windows-privilege-escalation-unquoted-services/

### Groups.xml
 - https://tools.kali.org/password-attacks/gpp-decrypt
 - https://adsecurity.org/?p=2288

### Tools
 - https://github.com/411Hall/JAWS
 - https://github.com/rasta-mouse/Sherlock/
 - https://github.com/PowerShellMafia/PowerSploit
 - https://github.com/foxglovesec/Potato
 - https://github.com/foxglovesec/RottenPotato
 - https://github.com/Kevin-Robertson/Tater
 - https://github.com/Arvanaghi/SessionGopher
 - https://github.com/pentestmonkey/windows-privesc-check
 - https://github.com/rootm0s/WinPwnage  
 - https://github.com/absolomb/WindowsEnum
 - https://github.com/ohpe/juicy-potato

### Presentations
 - https://www.youtube.com/watch?v=bAnohAiAQ7U
 - https://www.youtube.com/watch?v=G9yn3qNq7Vw
 - https://www.youtube.com/watch?v=jfZ8FKTFNTE
 - https://www.youtube.com/watch?v=RORaqh1DIco


## Linux and Windows
 - https://github.com/vitalysim/Awesome-Hacking-Resources#privilege-escalation


## Docker
 - https://gist.github.com/FrankSpierings/5c79523ba693aaa38bc963083f48456c
 - https://threatpost.com/hack-allows-escape-of-play-with-docker-containers/140831/
 - https://www.twistlock.com/labs-blog/escaping-docker-container-using-waitid-cve-2017-5123/
 - https://pt.slideshare.net/BorgHan/hacking-docker-the-easy-way
 - https://blog.secureideas.com/2018/05/escaping-the-whale-things-you-probably-shouldnt-do-with-docker-part-1.html

### Docker socks
 - https://www.lvh.io/posts/dont-expose-the-docker-socket-not-even-to-a-container.html
 - https://gist.github.com/FrankSpierings/5c79523ba693aaa38bc963083f48456c
 - https://www.bleepingcomputer.com/news/security/escaping-containers-to-execute-commands-on-play-with-docker-servers/
 - https://blog.paranoidsoftware.com/dirty-cow-cve-2016-5195-docker-container-escape/

## AWS
 - https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation
