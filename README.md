# Awesome Privilege Escalation
A curated list of awesome privilege escalation

Table of Contents
=================

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
 - https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
 - https://chryzsh.gitbooks.io/pentestbook/privilege_escalation_-_linux.html
 - https://www.win.tue.nl/~aeb/linux/hh/hh-12.html
 - http://www.dankalia.com/tutor/01005/0100501004.htm
 - https://payatu.com/guide-linux-privilege-escalation/
 - https://www.pentestpartners.com/security-blog/exploiting-suid-executables/
 - https://medium.com/basic-linux-privilege-escalation/basic-linux-privilege-escalation-966de11f9997
 - https://www.hackingarticles.in/linux-privilege-escalation-via-automated-script/
 - https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/my-5-top-ways-to-escalate-privileges/
 - http://www.admin-magazine.com/Articles/Understanding-Privilege-Escalation
 - https://www.future-processing.pl/blog/privilege-escalation/
 - https://www.contextis.com/en/blog/linux-privilege-escalation-via-dynamically-linked-shared-object-library
 - https://hackmag.com/security/reach-the-root/
 - https://guif.re/linuxeop
 - https://percussiveelbow.github.io/linux-privesc/
 - https://www.rebootuser.com/?page_id=1721
 - https://www.rebootuser.com/?p=1623
 - https://www.amanhardikar.com/mindmaps/Practice.html
 - https://myexperiments.io/linux-privilege-escalation.html
 - https://www.sans.org/reading-room/whitepapers/linux/attack-defend-linux-privilege-escalation-techniques-2016-37562
 - https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/
 - https://hackingandsecurity.blogspot.com/2016/05/local-linux-enumeration-privilege.html
 - https://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt
 - https://www.exploit-db.com/papers/33930
 - https://www.hackingarticles.in/category/privilege-escalation/
 - https://github.com/rmusser01/Infosec_Reference/blob/master/Draft/privesc.md
 - https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744
 - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md

### Escape restricted shells
 - https://pen-testing.sans.org/blog/pen-testing/2012/06/06/escaping-restricted-linux-shells
 - https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells
 - https://chryzsh.gitbooks.io/pentestbook/escaping_restricted_shell.html
 - https://www.exploit-db.com/docs/english/44592-linux-restricted-shell-bypass-guide.pdf
 - https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/
 - https://www.theitcareer.com/site/?p=1750
 - http://tldp.org/LDP/abs/html/restricted-sh.html
 - https://pentest.blog/unexpected-journey-4-escaping-from-restricted-shell-and-gaining-root-access-to-solarwinds-log-event-manager-siem-product/
 - https://linuxshellaccount.blogspot.com/2008/05/restricted-accounts-and-vim-tricks-in.html
 - https://airnesstheman.blogspot.com/2011/05/breaking-out-of-jail-restricted-shell.html
 - http://pentestmonkey.net/blog/rbash-scp

### SUDO and SUID
 - https://gtfobins.github.io/
 - https://touhidshaikh.com/blog/?cat=21
 - https://www.securusglobal.com/community/2014/03/17/how-i-got-root-with-sudo/
 - https://touhidshaikh.com/blog/?p=790

### Capabilities
 - http://blog.sevagas.com/?POSIX-file-capabilities-the-dark-side
 - http://blog.sevagas.com/IMG/pdf/exploiting_capabilities_the_dark_side.pdf
 - https://www.insecure.ws/linux/getcap_setcap.html
 - https://wiki.archlinux.org/index.php/Capabilities
 - https://www.redpill-linpro.com/sysadvent/2016/12/06/spicing-up-your-access.html
 - https://nxnjz.net/2018/08/an-interesting-privilege-escalation-vector-getcap/
 - https://infamoussyn.wordpress.com/2014/07/11/gaining-a-root-shell-using-mysql-user-defined-functions-and-setuid-binaries/
 - https://dl.packetstormsecurity.net/papers/attack/exploiting_capabilities_the_dark_side.pdf
 - https://github.com/weaknetlabs/Penetration-Testing-Grimoire/blob/master/Privilege%20Escalation/linux.md
 - https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux

### Tools
 - https://github.com/rebootuser/LinEnum
 - http://pentestmonkey.net/tools/audit/unix-privesc-check
 - https://github.com/mzet-/linux-exploit-suggester
 - https://github.com/InteliSecureLabs/Linux_Exploit_Suggester
 - https://github.com/jondonas/linux-exploit-suggester-2
 - https://github.com/sleventyeleven/linuxprivchecker
 - https://github.com/belane/linux-soft-exploit-suggester
 - https://github.com/pentestmonkey/exploit-suggester
 - https://github.com/AlessandroZ/BeRoot
 - https://github.com/spencerdodd/kernelpop
 - https://github.com/ngalongc/AutoLocalPrivilegeEscalation
 - https://github.com/linted/linuxprivchecker
 - https://github.com/initstring/uptux
 - https://github.com/Ignitetechnologies/Privilege-Escalation
 - https://github.com/AusJock/Privilege-Escalation
 - https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack
 - https://github.com/ngalongc/AutoLocalPrivilegeEscalation
 - https://github.com/1N3/PrivEsc
 - https://github.com/diego-treitos/linux-smart-enumeration
 - https://github.com/pentestmonkey/unix-privesc-check
 - https://github.com/SecWiki/linux-kernel-exploits

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
