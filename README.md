# Intrusion Detection Packet Spoofer (iDPS)
## What it does
  This tool/script utilizes Snort rules and Snort configurations to "Play" network signatures. Using this tool you will be able to test if an IDS detects the malicious behaviors you are looking for. Let's say Log4J just came out, and all you have is a network signature, or an idea of how the traffic looks. Instead of having to execute the zero-day yourself, or find a pcap to verify that your tools will generate a detection you can use this tool. This tool is able to take a network signature and will play traffic that looks like the malicious code for you.\
  Applications:\
  --Verify a pay-to-play IDS has coverage over different exploits without having to actually perform the exploit.\
  --Verify that your detections are working the way you want.\
  --Quantifiably compare IDS solutions.\
  --Perform fuzzing of websites and web interfaces for randomized inputs.\
  --Fine tune your signature based detections.\
  [WARNING]There's no guarantee that this tool can't harm your environment[WARNING]
## Currently in Development.
## Setup/Dependencies
  Supported Operating Systems: Windows, Linux (Ubuntu Tested, unknown for other Linux flavors)  
  Ensure Python3 is installed with the following modules  
    --scapy, random, ipaddress, time, string, subprocess, re, base64, os, argparse  
  Ensure Perl is installed with the following modules:  
    --String::Random , File::Slurper  
## Usage
  Place your snort.conf file within the "config" folder. It MUST be named "Snort_config.txt".  I have a default one provided in there. Its text must be replaced if yours is different. Next place any rules you want to test in a file inside of the "Rules" folder. It will NOT care if a rule is commented out or not, all rules are treated equally. Then configure any IPs/Ports/MACs addresses that you DO NOT want to be generating traffic for. Next, navigate to the folder of your 'iDPS.py' file, and run it as-is.  Different options may/may not work. See output on use for more details. 
## Supported
### Snort Rule Headers
  --flow  
  --IP Src/Dst  
  --TCP/UDP  
  --Ports  
  --Direction  
  
### Currently Supported Snort Rule Options for Payloads
  --Depth  
  --offset  
  --distance  
  --within  
  --isdataat  
  --pcre (needs some enhancement)
  --http-header (parts of it)
 
### Currently Supported Services/Applications
  --Generic (Unknown apps, these default to pop3)  
  --pop3  
  --http  (Mostly)
### Supported L2/L3 modifications
#### blacklist IPs
  Add blacklisted IP addresses, or IP address ranges to the blacklist_ips.txt file and it will NOT allow IP randomization to use those IPs
#### Blacklist MAC addresses
  Add blacklisted MAC addresses to the blacklist_macs.txt file and it will NOT allow MAC address randomization to use those MACs
#### Blacklist ports
  Add blacklisted ports to the blacklist_ports.txt file and it will not allow Port randomization to use those ports.
#### Snort Configuration for MACs/IPs/Ports
  Currently, the tool takes a snort configuration file which forces the tool to follow a snort config for port and ip address selection.
## Planned:
### Planned L2/L3 Modification
  --Designate MACs on command-line  
  --Designate IPs on command-line  
  --Designate Src/Dst port on command-line  
  
### Currently Planned Service Modifiers
  --http_cookie  
  --http_raw_cookie  
  --http_stat_code  
  --urilen  
  --Any additional snort specific service identifiers I find while figurin out rulez.  
  --All scapy service options listed in scapy (Long-term)  
  
### Planned additional signature building
  --Yara   
  --PCAP building  
  --Signature Building
  --Suricata (rules are basically snort, but there's a few small processing differences)  

