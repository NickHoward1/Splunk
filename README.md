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

<b>Alert scenario:</b> You’ve just started your first shift as a SOC analyst at an MSSP. Only a few minutes have passed since an alert about a possible brute force attack appeared on the platform.

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
<b>Answer:</b> I used filter 2 and removed Accepted action which gave me the answer<br>

<b>What was the duration of the brute force attack in minutes?</b><br>
<b>Answer:</b> I compared the first failed log with the last which enabled me to get the answer<br>

<b>What username was the attacker able to privilege escalate to?</b><br>
<b>Answer:</b> I used filter index="linux-alert" sourcetype="linux_secure" "sudo" 

<b>What is the name of the user account created by the attacker for persistence?</b><br>
<b>Answer:</b> I used filter index="linux-alert" "*add*"

<h2>Outcome</h2>

