About Sublist3r
Sublist3r is a Python tool designed to enumerate subdomains of websites using OSINT. It helps penetration testers and bug hunters collect and gather subdomains for the domain they are targeting. Sublist3r enumerates subdomains using many search engines such as Google, Yahoo, Bing, Baidu, and Ask. Sublist3r also enumerates subdomains using Netcraft, VirusTotal, ThreatCrowd, DNSdumpster, ReverseDNS, BufferOverRun, and CertSpotter.
subbrute was integrated with Sublist3r to increase the possibility of finding more subdomains using bruteforce with an improved wordlist. The credit goes to TheRook who is the author of subbrute.
Enhanced to v3.0 by Shaheer Yasir (2025): Full Python 3 support, new passive engines (CertSpotter for CT logs, BufferOverRun for DNS intel), JSON output, improved performance, and VirusTotal API v3 integration.
Screenshots
<image-card alt="Sublist3r" src="http://www.secgeek.net/images/Sublist3r.png "Sublist3r in action"" >
Installation
textgit clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
pip install -r requirements.txt
Recommended Python Version:
Sublist3r v3.0 supports Python 3 only (Python 2 deprecated).

The recommended version is 3.6+ (tested up to 3.12).

Dependencies:
Sublist3r depends on the requests, dnspython, and colorama Python modules.
These dependencies can be installed using the requirements file:

Installation on any OS:

textpip install -r requirements.txt
Alternatively, each module can be installed independently.
Requests Module

Install using pip:

textpip install requests>=2.25.0
dnspython Module

Install using pip:

textpip install dnspython>=2.0.0
colorama Module

Install using pip:

textpip install colorama>=0.4.4
For enhanced VirusTotal support (optional): Set environment variable export VT_API_KEY=your_key for higher rate limits.
Usage




























































Short FormLong FormDescription-d--domainDomain name to enumerate subdomains of-b--bruteforceEnable the subbrute bruteforce module-p--portsScan the found subdomains against specific tcp ports-v--verboseEnable the verbose mode and display results in realtime-t--threadsNumber of threads to use for subbrute bruteforce-e--enginesSpecify a comma-separated list of search engines-o--outputSave the results to text file-j--jsonSave the results to JSON file-n--no-colorOutput without color-h--helpshow the help message and exit
Examples

To list all the basic options and switches use -h switch:

python* To enumerate subdomains of specific domain:

``python sublist3r.py -d example.com``

* To enumerate subdomains of specific domain and show only subdomains which have open ports 80 and 443 :

``python sublist3r.py -d example.com -p 80,443``

* To enumerate subdomains of specific domain and show the results in realtime:

``python sublist3r.py -v -d example.com``

* To enumerate subdomains and enable the bruteforce module:

``python sublist3r.py -b -d example.com``

* To enumerate subdomains and use specific engines such Google, Yahoo and Virustotal engines

``python sublist3r.py -e google,yahoo,virustotal -d example.com``

## Using Sublist3r as a module in your python scripts

**Example**

```python
import sublist3r 
subdomains = sublist3r.main(domain, no_threads, savefile, ports, silent, verbose, enable_bruteforce, engines)
The main function will return a set of unique subdomains found by Sublist3r
Function Usage:

domain: The domain you want to enumerate subdomains of.
savefile: save the output into text file.
ports: specify a comma-sperated list of the tcp ports to scan.
silent: set sublist3r to work in silent mode during the execution (helpful when you don't need a lot of noise).
verbose: display the found subdomains in real time.
enable_bruteforce: enable the bruteforce module.
engines: (Optional) to choose specific engines.

Example to enumerate subdomains of Yahoo.com:
pythonimport sublist3r 
subdomains = sublist3r.main('yahoo.com', 40, 'yahoo_subdomains.txt', ports= None, silent=False, verbose= False, enable_bruteforce= False, engines=None)
License
Sublist3r is licensed under the GNU GPL license. take a look at the LICENSE for more information.
Credits

TheRook - The bruteforce module was based on his script subbrute.
Bitquark - The Subbrute's wordlist was based on his research dnspop.
Shaheer Yasir - Enhanced to v3.0 with Python 3 support, new engines (CertSpotter, BufferOverRun), JSON output, and performance improvements.

Thanks

Special Thanks to Ibrahim Mosaad for his great contributions that helped in improving the tool.
Thanks to the open-source community for ongoing feedback and contributions.

Version
Current version is 3.0
