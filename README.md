# 802.11_Availability_Attacker
Python script that was made for a research project. The goal of this project was to determine whether a 802.11 network was susceptible to certain attacks that threaten the availability.

# Note
These attacks were not invented by me but only implemented in python. For more information about the the attacks and the orginal creators/invetors of the attacks I would like to refer you to: [insert RP].


# Workings:
attack.py [-h] -i [IFACE] -b [BSSID] -m [MAC] -t [TIME] [-r [INTERVAL]]
{ssidSpawner,discoverAPs,deauth,channelswitch,quiet,quietaction,associationRequestAttack}

# Requirements:
scapy==2.4.2
termcolor==1.1.0
prettytable==0.7.2
