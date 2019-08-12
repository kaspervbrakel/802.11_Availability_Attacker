#!/usr/bin/python3
import paramiko, time, iperf3, os, json, pingparsing, datetime, multiprocessing, pymysql
from paramiko.py3compat import input
from pythonping import ping
from multiprocessing import Process
from textwrap import dedent

def getTime():
    ts = time.time()
    return datetime.datetime.fromtimestamp(ts).strftime('%H:%M:%S')

###               conf               ###
duration            = 60 ## in seconds
experiment_count    = 30 #how many times the experiment should be performed
attack_frame_rate   = 1.5
attack_type         = "deauth" #options: deauth, channelSwitch, quiet, or basetest
target_ssid         = "wips-test-802.1x"
client_mac          = "c8:f7:33:9e:d8:a1" #MAC of the client you are targetting
target_channel      = 11
target_bssid        = "34:85:84:09:80:94" #BSSID of the corresponding AP/SSID you are targeting.
exp_start_time      = getTime()
iperf_addr          = "145.100.180.44"
iperf_port          = 5003
ping_addr           = "145.100.180.44"
attack_interface    = "wlan0"
cmd = ""

def main():
    global attack_frame_rate
    global cmd
    if(attack_type == "deauth"):
        cmd = "python3 /home/kbrakel/scripts/beacons.py -i " + attack_interface + " -b " + target_bssid + " -m " + client_mac + " -r " + str(attack_frame_rate) + " -t " + str(duration+2) + " deauth -c " + str(target_channel) 
        test_id = 1
    elif(attack_type == "channelSwitch"):
        cmd = "python3 /home/kbrakel/scripts/beacons.py -i " + attack_interface + " -b " + target_bssid + " -m " + client_mac + " -t " + str(duration+2) + " -r " + str(attack_frame_rate) + " channelswitch -c " + str(target_channel) + " -s " + target_ssid
        test_id = 2
    elif(attack_type == "quiet"):
        cmd = "python3 /home/kbrakel/scripts/beacons.py -i " + attack_interface + " -b " + target_bssid + " -m " + client_mac + " -t " + str(duration+2) + " -r " + str(attack_frame_rate) + " quiet -c " + str(target_channel) + " -s " + target_ssid
        test_id = 4        
    elif(attack_type == "basetest"):
        test_id = 3
        attack_frame_rate = None

    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%H:%M:%S')
    filename = "ExperimentResults_" + attack_type + "_" + st


    def startAttack():
        global cmd
        print(cmd)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect("192.168.1.2", "22", "root", "*********")
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd)
        print("attack started\t" + getTime())
        time.sleep(2)


    def startPing():
        ping_parser = pingparsing.PingParsing()
        transmitter = pingparsing.PingTransmitter()
        transmitter.destination = ping_addr
        print(getTime() + "\tStarting ping test #" + str(i) + " with destination: " + transmitter.destination)
        #transmitter.count = 10
        transmitter.deadline = duration
        result = transmitter.ping()
        json.dumps(ping_parser.parse(result).as_dict(), indent=4)

        destination         = ping_parser.destination
        transmitted_pkt     = ping_parser.packet_transmit
        received_pkts       = ping_parser.packet_receive
        lost_pkts           = ping_parser.packet_loss_count
        pkt_loss_rate       = ping_parser.packet_loss_rate
        rtt_min             = ping_parser.rtt_min 
        rtt_avg             = ping_parser.rtt_avg
        rtt_max             = ping_parser.rtt_max
        rtt_mdev            = ping_parser.rtt_mdev
        pkt_duplicate       = ping_parser.packet_duplicate_count
        pkt_duplicate_rate  = ping_parser.packet_duplicate_rate

        #store results in DB.
        sql = ("INSERT INTO ping_results (test_id, attack_frame_rate, destination, transmitted_pkt, received_pkts, lost_pkts, pkt_loss_rate, rtt_min, rtt_avg, rtt_max, rtt_mdev, pkt_duplicate, pkt_duplicate_rate, duration, exp_start_time) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")
        values = (test_id, attack_frame_rate, destination, transmitted_pkt, received_pkts, lost_pkts, pkt_loss_rate, rtt_min, rtt_avg, rtt_max, rtt_mdev, pkt_duplicate, pkt_duplicate_rate, duration, exp_start_time)
        executeQuery(sql, values)
        print("end of ping\t" + getTime())


    def startIperf():
        client = iperf3.Client()
        client.duration = duration
        client.server_hostname = iperf_addr
        client.port = iperf_port
        client.protocol = 'tcp'

        print(getTime() + '\tStarting iperf test #' + str(i) + ' with destination to {0}:{1}'.format(client.server_hostname, client.port))
        result = client.run()

        if result.error:
            print(result.error)
        else: 
            sent_MB=(float("{0}".format(result.sent_bytes))*10**-6)
            avg_cpu_load="{0}".format(result.local_cpu_total)
            rcv_data_MB_s="{0}".format(result.received_MB_s)
            sent_data_MB_s="{0}".format(result.sent_MB_s)
            retransmits="{0}".format(result.retransmits)        
            #store results in DB.
            sql = ("INSERT INTO iperf_results (test_id, attack_frame_rate, avg_cpu_load, rcv_data_MB_s, sent_data_MB_s, sent_MB, retransmits, duration, exp_start_time) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)")
            values = (test_id, attack_frame_rate, avg_cpu_load, rcv_data_MB_s, sent_data_MB_s, sent_MB, retransmits, duration, exp_start_time)
            executeQuery(sql, values)
            print("end of iperf\t" + getTime())

    i = 0
    while (i < experiment_count):
        ping = Process(target=startPing)
        iperf = Process(target=startIperf)
        attack = Process(target=startAttack)
        print("Start experiment #" + str(i) + "\t" + getTime()) 
        #startAttack(cmd)
        attack.start()
        attack.join()
        ping.start()
        iperf.start()
        attack.join()
        ping.join()
        iperf.join()
        print("end of experiment #" + str(i) + "\t" + getTime() + "\n\n\n")
        print("\n=================sleep(5)=================\t" + getTime() + "\n")
        time.sleep(5)
        i += 1


def executeQuery(sql, values):
    # Open database connection
    connection = pymysql.connect(host="localhost",
                                 user="root",
                                 password="********",
                                 db="RP2")

    try:
        with connection.cursor() as cursor:
            # Create a new record
            cursor.execute(sql, (values))
        # connection is not autocommit by default. So you must commit to save
        # your changes.
        connection.commit()
    finally:
        connection.close()


def printTime():
    ts = time.time()
    print(datetime.datetime.fromtimestamp(ts).strftime('%H:%M:%S:%f')[:-3])


def getTime():
    ts = time.time()
    return datetime.datetime.fromtimestamp(ts).strftime('%H:%M:%S:%f')[:-3]

if __name__ == "__main__":
    main()  
