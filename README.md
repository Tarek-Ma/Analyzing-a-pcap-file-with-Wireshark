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

Next we filter HTTP and TLS to check the visited domains.
