<h1>Alert Triage with Splunk Lab</h1>

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

<b>Filter used:</b> 
```spl
index="linux-alert" sourcetype="linux_secure" 10.10.242.248 
| search "Accepted password for" OR "Failed password for" OR "Invalid user"
| sort + _time </p>
```
 <p>
<img src= "https://github.com/NickHoward1/Splunk/blob/a0d3267627e038730a15d848de7b92c4d9618bd1/Screenshot%202026-05-09%20at%2018.05.51.png" width="300" height="600"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<img src= "" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <img src= "" width="300" height="300" /> 
</p>



<h2>Outcome</h2>

