# 802.11_Availability_Attacker
Python script that was made for a research project. The goal of this project was to determine whether a 802.11 network was susceptible to certain attacks that threaten the availability.

# Workings:
attack.py [-h] -i [IFACE] -b [BSSID] -m [MAC] -t [TIME] [-r [INTERVAL]]
{ssidSpawner,discoverAPs,deauth,channelswitch,quiet,quietaction,associationRequestAttack}

# Requirements:
scapy==2.4.2
termcolor==1.1.0
prettytable==0.7.2


# Credits:
For creating this code examples / snippets and ideas were used from the book: Python Penetration Testing from Oreilly.
The book can be found at: https://learning.oreilly.com/library/view/python-penetration-testing/9781784399771/

These attacks were not invented by me but only implemented in python. For more information about the the attacks and the orginal creators/invetors of the attacks I would like to refer you to:

Channel switch & quiet attack: http://www.uni-ulm.de/fileadmin/website_uni_ulm/iui.inst.100/institut/mitarbeiterbereiche/schaub/2009-LCN-channel-switch.pdf

Deauthentication attack: https://www.usenix.org/legacy/event/sec03/tech/full_papers/bellardo/bellardo_html/

For the measurements I used the python libraries iperf3: https://pypi.org/project/iperf3/ and ping: https://pypi.org/
The tutorial I followed for Pyping: https://www.ictshore.com/python/python-ping-tutorial/
