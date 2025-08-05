##NSE Scripts README guide


This guide explains how to use four Nmap Scripting Engine (NSE) scripts designed for stealthy network reconnaissance and vulnerability scanning: cautious-banner-grab.nse, cautious-os-detect.nse, cautious-service-probe.nse, and cautious-vuln-check.nse. These scripts prioritize minimal network footprint and natural timing to avoid detection.
Overview

Prerequisites

Nmap: Install Nmap (version 7.0 or later recommended) from nmap.org or via package managers:
Linux: sudo apt install nmap (Debian/Ubuntu) or sudo yum install nmap (RHEL/CentOS).
macOS: brew install nmap.
Windows: Download and install from nmap.org/download.html.


Lua: Included with Nmap by default.
Permissions: Root or sudo privileges are required for certain scan types (e.g., SYN scan with -sS).
Legal Authorization: Ensure you have explicit permission to scan the target network.

Installation

Save the Scripts:

Copy each .nse file to a directory.
Ensure filenames match exactly as listed.


Move to Nmap Scripts Directory:

Place the .nse files in Nmap’s scripts directory:
Linux: /usr/share/nmap/scripts/ or /usr/local/share/nmap/scripts/
Windows: C:\Program Files (x86)\Nmap\scripts\
macOS: /usr/local/Cellar/nmap/<version>/share/nmap/scripts/ (adjust for your installation).


Example command:sudo cp *.nse /usr/share/nmap/scripts/


Alternatively, use a custom directory and specify the path when running Nmap (e.g., --script ./*nse).


Update Nmap Script Database:

Run the following to register the scripts with Nmap:sudo nmap --script-updatedb




Usage

Basic Command

Run a single script against a target (replace <target> with an IP address or hostname, e.g., 192.168.1.1 or target.com):
nmap --script cautious-banner-grab <target>

Stealthy Scan (Recommended)

For maximum stealth, use slow timing, SYN scan, packet fragmentation, and delays:
nmap -T1 -sS -f --scan-delay 15s --max-retries 1 --script cautious-banner-grab,cautious-service-probe <target>


Options:

-T1: Paranoid timing (very slow to avoid detection).
-sS: SYN scan (stealthy, requires root privileges).
-f: Fragment packets to evade intrusion detection systems.
--scan-delay 15s: 15-second delay between probes.
--max-retries 1: Limit retries to reduce traffic.
--script: Specify one or more scripts (comma-separated).



Target Specific Ports

Scan specific ports relevant to the script:
nmap -T1 -sS -p 21,22,80,443 --script cautious-vuln-check <target>

Combine Multiple Scripts

Run multiple scripts for comprehensive results:
nmap -T1 -sS -f --scan-delay 10s --script **** <target>

Save Output

Store results for analysis:

Normal: nmap ... -oN output.txt
XML (for parsing): nmap ... -oX output.xml
Grepable: nmap ... -oG output.grepExample:

nmap -T1 -sS --script * -oN scan_results.txt <target>


Best Practices

Stealth:

Use -T0 or -T1 for slowest scans.
Add --randomize-hosts for multiple targets.
Vary packet sizes with --data-length <number>.


Testing: 

Test scripts in a controlled environment (e.g., local VM) before scanning external networks.
Permissions: Always obtain explicit permission to scan targets to avoid legal issues.
Debugging: Use -d for verbose output if scripts fail:nmap -d --script cautious-banner-grab <target>



Troubleshooting

Script Not Found: Ensure scripts are in Nmap’s scripts directory or specify the full path (e.g., --script ./cautious-banner-grab.nse).
No Output: Verify target ports are open with nmap -p <port> <target>. Check for firewalls or unresponsive services.
Timeouts: Increase script timeout with --script-timeout 60s.
Errors: Validate script syntax with a Lua linter or check for missing NSE libraries.

Notes

These scripts are designed for stealth with random delays and minimal probes, but all network activity may be logged. Use responsibly.
Customize scripts (e.g., adjust delays or ports) by editing the Lua code, following NSE conventions (see nmap.org/nsedoc/).
For further assistance, refer to Nmap’s documentation or contact the script author.
