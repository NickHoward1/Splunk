<h1>Splunk Lab</h1>

<h2>Objective</h2>
To triage various alerts using the Splunk SIEM to determine whether alerts are true positives or false positives. I will do this by filtering and analysing the logs provided to identify anomalies, suspicious behaviour, and indicators of potential security incidents.<br>

<h2>Environment</h2>
<ul>
 <li>Splunk</li>
 
</ul>
<h2>Tasks Completed</h2>
<ul>
 <li>Triaging a Brute Force attack</li>
 <li>Triaging an attack that has Persistence Identified</li>
 <li>Triaging a webshell attack</li>
</ul>

<h2>Screenshots</h2>

<h2>Alert Scenario:</h2>
<p></p>You’ve just started your first shift as a SOC analyst at an MSSP. Only a few minutes have passed since an alert about a possible brute force attack appeared on the platform.</p>

<b>Alert Details:</b><br>
<b>Alert Name:</b> Brute Force Activity Detection <br>
<b>Time:</b> 17/09/2025 9:00:21 AM <br>
<b>Target Host:</b> tryhackme-2404 <br>
<b>Source IP:</b> 10.10.242.248 <br>
<b>Your job is to investigate this activity and decide whether it should be considered suspicious.</b>

<b>Filters used:</b> 

index="linux-alert" sourcetype="linux_secure" 10.10.242.248 <br>
| search "Accepted password for" OR "Failed password for" OR "Invalid user"<br>
| sort + _time<br>

index="linux-alert" sourcetype="linux_secure" 10.10.242.248<br>
| rex field=_raw "^\d{4}-\d{2}-\d{2}T[^\s]+\s+(?<log_hostname>\S+)"<br>
| rex field=_raw "sshd\[\d+\]:\s*(?<action>Failed|Accepted)\s+\S+\s+for(?: invalid user)? (?<username>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"<br>
| eval process="sshd"<br>
| stats count values(src_ip) as src_ip values(log_hostname) as hostname values(process) as process by username<br>

index="linux-alert" sourcetype="linux_secure" "sudo"<br>

index="linux-alert" "*add*"<br>

 <p>
<img src= "https://github.com/NickHoward1/Splunk/blob/a0d3267627e038730a15d848de7b92c4d9618bd1/Screenshot%202026-05-09%20at%2018.05.51.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<img src= "https://github.com/NickHoward1/Splunk/blob/ed19ace4403fdbd9c271678049c0338729575c96/Screenshot%202026-05-09%20at%2019.54.41.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <img src= "https://github.com/NickHoward1/Splunk/blob/732a2d8a9b459c6a2fb62b6ba2618cda5ac05f89/Screenshot%202026-05-09%20at%2020.19.43.png" width="300" height="300" /> 
</p>

<h3>Questions</h3>

<b>How many failed login attempts were made on the user john.smith?</b><br>
<b>Answer:</b> 500 <br>
<b>Filter:</b> Second Filter provided (removed accepted action)<br>
<b>Why?:</b>

<b>What was the duration of the brute force attack in minutes?</b><br>
<b>Answer:</b> 5 minutes<br>
<b>Filter:</b> I compared the first failed log with the last which enabled me to get the answer<br>
<b>Why?:</b> 

<b>What username was the attacker able to privilege escalate to?</b><br>
<b>Answer:</b> Root <br>
<b>Filter:</b> Third Filter <br>
<b>Why?:</b> 

<b>What is the name of the user account created by the attacker for persistence?</b><br>
<b>Answer:</b> system-utm <br>
<b>Filter:</b> Last Filter <br>
<b>Why?:</b>

<h2>Alert Scenario:</h2>
<p></p>You are working as a Level 1 SOC Analyst on shift at an MSSP. An alert has come through indicating that a suspicious scheduled task was created on a host.</p>

<b>Alert Details:</b><br>
<b>Alert Name:</b> Potential Task Scheduler Persistence Identified <br>
<b>Time:</b> 30/08/2025 10:06:07 AM <br>
<b>Host:</b> WIN-H015 <br>
<b>User:</b> oliver.thompson <br>
<b>Task Name:</b> AssessmentTaskOne <br>
<b>Your job is to investigate this activity and decide whether it should be considered suspicious.</b>

<b>Filters used:</b> 

index="win-alert" EventCode=4698 AssessmentTaskOne<br>
| table _time EventCode user_name host Task_Name Message<br>

index="win-alert" ParentProcessId=4128<br>
| table _time "ParentCommandLine"<br>

index="win-alert" ParentProcessId=4128 "localgroup"<br>

index="win-alert" EventCode=4624 name="An account was successfully logged on" workstation "oliver.thompson"

 <p>
<img src= "https://github.com/NickHoward1/Splunk/blob/fc940558751e0a6571a0b489f22bd47baf52bb2c/Screenshot%202026-05-10%20at%2011.20.51.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <img src= "https://github.com/NickHoward1/Splunk/blob/4d61e5b43c81674bff6d66f71ecc6c854c00bdef/Screenshot%202026-05-10%20at%2012.07.46.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<img src= "https://github.com/NickHoward1/Splunk/blob/cc71fb2dd8eb4d6cf8dfa6d447a1db62fed69b73/Screenshot%202026-05-10%20at%2011.18.35.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
</p>

<h3>Questions</h3>

<b>What is the ProcessId of the process that created this malicious task?</b><br>
<b>Answer:</b> 5816<br> 
<b>Filter:</b> First Filter (Searched within messsage)<br> 
<b>Why?:</b> I was asked to search for the process ID, for a SOC analayst this will allow me to investigate further and see what executable launched it,
which user ran it, command-line arguments, parent/child processes, associated network connections, hashes and file paths. <br>

<b>What is the name of the parent process for the process that created this malicious task?</b><br>
<b>Answer:</b> cmd.exe<br> 
<b>Filter:</b>  Second Filter <br> 
<b>Why?:</b> Finding the parent process name will help me understand how the attack started, what launched the malware and whether it was user-driven, scripted, or automated.<br>         <b>Note:</b> The malicous attack will not appear by itself, something will have created it and will look like... cmd.exe, powershell.exe, xscript.exe.<br> Once I have found the Process ID search for: - Parent Process Name - Command Line - User account - File path - Hash - Network activity

<b>Which local group did the attacker enumerate during discovery?</b><br>
<b>Answer:</b> Administrators <br>
<b>Filter:</b> Third Filter<br>
<b>Why?:</b> The look up was to see which local group the attacker looked up to gather information about the system. Trying to discover who has admin access, what users exist, privileges and how the system is configured, this gives them a better position to move laterally once they are in. <br>
<b>Note:</b> Attackers usually run commands such as Get-LocalGroup or net Localgroup.

<b>What is the name of the workstation from which the Threat Actor logged into this host?</b><br>
<b>Answer:</b> DEV-QA-SERVER <br>
<b>Filter:</b> Last Filter <br>
<b>Why?:</b> It is important to identify the workstation name so we can determine the source system the attacker used to gain access to the environment. This workstation may already be compromised, contain malware, be the initial infection point, or be used for lateral movement across the network. As a SOC Level 1 Analyst, I would escalate the incident to the SOC Level 2 team and begin the remediation process by helping contain the threat, such as isolating the affected host to prevent further spread across the environment. This would then support the eradication and recovery phases of the incident response process.


<h2>Alert Scenario:</h2>
<p>Your shift as an L1 SOC analyst continues, and you’ve now received the next alert that needs to be investigated. This time, the activity is related to the web.</p>

<b>Alert Details:</b><br>
<b>Alert Name:</b> Potential Web Shell Upload Detected <br>
<b>Time:</b> 14/09/2025 09:31:51 AM <br>
<b>Resource:</b> http://web.trywinme.thm <br>
<b>Suspicious IP:</b> 171.251.232.40 <br>
<b>Your job is to investigate this activity and decide whether it should be considered suspicious.</b>

<b>Process:</b> The resource provided is the organisation’s website hosted on the web server. Next, we want to investigate the suspicious IP address. We can use tools such as VirusTotal or AbuseIPDB to check the reputation of the IP address and determine whether it is considered malicious. We then use the first filter below for deeper analysis.

Right away, we can detect a large number of requests associated with this IP address. The User-Agent is set to Hydra, a tool commonly used by attackers to carry out brute-force attacks, which is a strong indicator of malicious activity.

Next, we use the second filter below. A POST request was observed for admin-ajax.php with a referrer pointing to theme-editor.php?file=b374k.php. This is unusual because the theme editor should not normally reference arbitrary .php files. The presence of file=b374k.php strongly suggests that the attacker may have uploaded or is interacting with a web shell.

Finally, using the last filter, we detected that the threat actor successfully gained access to a possible web shell file named b374k.php. Following this, they began executing activity through the shell, where we observed four successful POST requests.


<b>Filters used:</b> 

index=web-alert 171.251.232.40<br>
| table _time clientip useragent uri_path method status<br> 
| sort + _time

index=web-alert 171.251.232.40 useragent!="Mozilla/5.0 (Hydra)"<br> 
| table  _time clientip useragent uri_path referer referer_domain method status<br> 

index=web-alert 171.251.232.40 b374k.php<br> 
| table _time clientip useragent uri_path referer referer_domain method status<br> 
| sort + _time

 <p>
<img src= "https://github.com/NickHoward1/Splunk/blob/471e40663e172b826ac082b1cb9ed577f6788589/Screenshot%202026-05-10%20at%2019.15.33.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <img src= "https://github.com/NickHoward1/Splunk/blob/5bc9613e4245e0da569a3e1198aeb68f163de2dc/Screenshot%202026-05-10%20at%2019.17.22.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<img src= "https://github.com/NickHoward1/Splunk/blob/a381ea1b71d7a00cb6ab6bfde72b6a29a1f3620f/Screenshot%202026-05-10%20at%2019.19.01.png"width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
</p>

<h3>Questions</h3>

<b>What time did the brute-force activity using Hydra begin?</b><br>
<b>Answer:</b>2025-09-14 21:20:27<br> 
<b>Filter:</b>First Filter<br> 
<b>Why?:</b>It's important to know the times of the attack so we can establish timelines and identify initial compromise attempts<br> 

<b>Which user agent did the attacker use when interacting with the web shell?</b><br>
<b>Answer:</b>Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36<br> 
<b>Filter:</b> Second Filter<br>  
<b>Why?:</b> knowing the user agent will help me as a SOC Level1 Analyst to understand how the attacker interacted with the compromised system<br> 

<b>What was the number of requests made by the attacker to the server via the web shell?</b><br>
<b>Answer:</b>4<br>  
<b>Filter:</b> Last Filter - 4 POST requests under method<br>  
<b>Why?:</b> Understand the number of POST requests allows me to understand how active the attacker was
what level of interaction occurred, whether commands were executed, possible data exfiltration, persistence or post-exploitation activity <br>  


<h2>Outcome</h2>

