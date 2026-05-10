<h1>Splunk Lab</h1>

<h2>Objective</h2>
To triage various alerts using the Splunk SIEM to determine whether alerts are true positives or false positives. I will do this by filtering and analysing the logs provided to identify anomalies, suspicious behaviour, and indicators of potential security incidents.

<h2>Environment</h2>
<ul>
 <li>Splunk</li>
 
</ul>
<h2>Tasks Completed</h2>
<ul>
 <li></li>
 <li></li>
 <li></li>
 <li></li>
 <li></li>
 <li></li>
</ul>

<h2>Screenshots</h2>

<h2>Alert Scenario:</h2>
You’ve just started your first shift as a SOC analyst at an MSSP. Only a few minutes have passed since an alert about a possible brute force attack appeared on the platform.<br>

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

index="linux-alert" sourcetype="linux_secure" 10.10.242.248<br>
| rex field=_raw "^\d{4}-\d{2}-\d{2}T[^\s]+\s+(?<log_hostname>\S+)"<br>
| rex field=_raw "sshd\[\d+\]:\s*(?<action>Failed|Accepted)\s+\S+\s+for(?: invalid user)? (?<username>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"<br>
| eval process="sshd"<br>
| stats count values(action) values(src_ip) as src_ip values(log_hostname) as hostname values(process) as process  by username<br>

 <p>
<img src= "https://github.com/NickHoward1/Splunk/blob/a0d3267627e038730a15d848de7b92c4d9618bd1/Screenshot%202026-05-09%20at%2018.05.51.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<img src= "https://github.com/NickHoward1/Splunk/blob/ed19ace4403fdbd9c271678049c0338729575c96/Screenshot%202026-05-09%20at%2019.54.41.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <img src= "https://github.com/NickHoward1/Splunk/blob/732a2d8a9b459c6a2fb62b6ba2618cda5ac05f89/Screenshot%202026-05-09%20at%2020.19.43.png" width="300" height="300" /> 
</p>

The first filter allowed me to see all successful and failed login attempt with the IP address 10.10.242.248, as well as 

<h3>Questions</h3>

<b>How many failed login attempts were made on the user john.smith?</b><br>
<b>Answer:</b>I used filter 2 and removed Accepted action which gave me the answer<br>

<b>What was the duration of the brute force attack in minutes?</b><br>
<b>Answer:</b> I compared the first failed log with the last which enabled me to get the answer<br>

<b>What username was the attacker able to privilege escalate to?</b><br>
<b>Answer:</b> I used filter index="linux-alert" sourcetype="linux_secure" "sudo"<br>

<b>What is the name of the user account created by the attacker for persistence?</b><br>
<b>Answer:</b> I used filter index="linux-alert" "*add*"<br>

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

index="win-alert" EventCode=4624 name="An account was successfully logged on" workstation "oliver.thompson"

 <p>
<img src= "https://github.com/NickHoward1/Splunk/blob/fc940558751e0a6571a0b489f22bd47baf52bb2c/Screenshot%202026-05-10%20at%2011.20.51.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<img src= "https://github.com/NickHoward1/Splunk/blob/cc71fb2dd8eb4d6cf8dfa6d447a1db62fed69b73/Screenshot%202026-05-10%20at%2011.18.35.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
</p>

<h3>Questions</h3>

<b>What is the ProcessId of the process that created this malicious task?</b><br>
<b>Answer:</b> 5816<br> <b>why?:</b> I was asked to search for the process ID, for a SOC analayst this will allow me to investiagte further and see what executable launched it,
which user ran it, command-line arguments, parent/child processes, associated network connections, hashes and file paths. <br>

<b>What is the name of the parent process for the process that created this malicious task?</b><br>
<b>Answer:</b> cmd.exe<br> <b>Why?:</b> Finding the parent process name will help me understand how the attack started, what launched the malware and whether it was user-driven, scripted, or automated.<br> <b>Note:</b> The malicous attack will not appear by itself, something will have created it and will look like... cmd.exe, powershell.exe, xscript.exe.<br>

<b>Process:</b> Once I have found the Process ID: search for - Parent Process Name - Command Line - User account - File path - Hash - Network activity

<b>Which local group did the attacker enumerate during discovery??</b><br>
<b>Answer:</b><br>

<b>What is the name of the user account created by the attacker for persistence?</b><br>
<b>Answer:</b> I used filter index="linux-alert" "*add*"<br>

<h2>Outcome</h2>

