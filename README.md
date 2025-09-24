# Analyzing a pcap file with Wireshark from-malware-traffic-analysis


## Introduction

You work as an analyst at a Security Operation Center (SOC). Someone contacts your team to report a coworker has downloaded a suspicious file after searching for Google Authenticator. The caller provides some information similar to social media posts at:

https://www.linkedin.com/posts/unit42_2025-01-22-wednesday-a-malicious-ad-led-activity-7288213662329192450-ky3V/
https://x.com/Unit42_Intel/status/1882448037030584611
Based on the caller's initial information, you confirm there was an infection.  You retrieve a packet capture (pcap) of the associated traffic.  Reviewing the traffic, you find several indicators matching details from a Github page referenced in the above social media posts.  After confirming an infection happened, you begin writing an incident report.

 ## Investigation

 We start by having an overview of the pcap file. It contains 39,427 packets : IPV4 represent 99.1% of the traffic, TCP 99.3%, TLS 17.2% and we also see some clear HTTP (3.2%) which can be interesting.

 <a href="https://i.postimg.cc/kgYKbJ2W/wireshark1.png" target="_blank">
  <img src="https://i.postimg.cc/kgYKbJ2W/wireshark1.png" width="550"/>
</a>

Next we filter HTTP and TLS to check the visited domains. ( with the filter `http or tls.handshake.type==1 and !(ssdp)` )
We know that the client downloaded a file after searching for **' google Authenticator '**
By scrolling, we can see 2 suspicious domains (`google-authenticator.burleson-appliance.net` and `authenticatoor.org` ). We check them with Virustotal and they look malicious.

![](https://i.postimg.cc/8cQfdwgS/wireshark3.png)
![](https://i.postimg.cc/GhRsHMjP/wireshark4.png)

We can suppose that the client clicked on a URL and was redirected to the malicious website ( as we also saw in the Twitter and Linkedin exemple from the caller )
We also see 2 succesful GET requests ( HTTP 200 OK ) with files : `264872` and `29842.ps1`

![](https://i.postimg.cc/13B9JBwQ/wireshark2.png)

Let's analyse these 2 files. To export HTTP files with Wireshark we go to -> File -> Export objects -> HTTP

We get the hash of the first file and we analyze it with Virustotal. The result shows it is malicious

![](https://i.postimg.cc/g2FC8Z7P/wireshark5.png)

By analyzing the HTTP stream, we can see the content is a VBScript that allows remote code execution. Here, the script runs Powershell in hidden mode and downloads another script ( `29842.ps1` ) from the server with IP : `5.252.153.241`

![](https://i.postimg.cc/dtx8xRYz/wireshark6.png)

The second file (`29842.ps1`) is also malicious, it contains obfuscated code encoded in Base64, we decode it with Cyberchef and we get this script : 

![](https://i.postimg.cc/rmGSz774/wireshark8.png)

The script retrieves the serial number of the **`C-Disk`**, builds a URL with this number, and if true, it tries to download the text content and execute the code with `Invoke-Expression`, the script loops every 5 seconds.

With this information, we can confirm that the C2 server has for principal IP : 5.252.153.241 ( this IP is also marked as malicious by Virustotal ) and the victim IP is : `10.1.17.215`. We can support this confirmation by looking at the **Conversations** with Wireshark : there are more than 9000 packets exchanged between these 2 IPs

![](https://i.postimg.cc/XNCPkgyD/wireshark10.png)
