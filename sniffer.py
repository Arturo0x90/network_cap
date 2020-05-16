#!/usr/bin/env/python3.7
import pyshark as ps
from lists import whitelist
from lists import blacklist
from custom_lists import c_whitelist
from custom_lists import c_blacklist
import time
interface = str(input('Interfaz (wlan0, eth0, lo, etc.): '))
#Variable "i" is for debugging purposes
i = 1

#Detect function decides if the source/destination is trustable or not
def detect_dst(notapi):
    if notapi in whitelist or notapi in c_whitelist:
        print("Destination IP in whitelist!")
    elif notapi in blacklist or notapi in c_blacklist:
        print('Destination IP in blacklist!')
    else:
        print('Unknown destination IP!')

def detect_src(notapi):
    if notapi in whitelist or notapi in c_whitelist:
        print("Source IP in whitelist!")
    elif notapi in blacklist or notapi in c_blacklist:
        print('Source IP in blacklist!')
    else:
        print('Unknown source IP!')
#Sniffs net packets and calls the other functions
def live_sniffer():
    capture = ps.LiveCapture(interface=interface)
    capture.sniff(timeout=5)
    capture
    capture[3]
    #Variable "e" is for debugging purposes
    e = 1
    for packet in capture.sniff_continuously(packet_count=20000):
        #The packet_count limits the amount of packets captured every 5 seconds
        ipd = str(packet['ip'].dst)
        ips = str(packet['ip'].src)

        print('A packet arrived!!')
        print('Packet number: ' + str(e))
        print('Destination: ' + str(packet['ip'].dst))
        print('Source: ' + str(packet['ip'].src))
        #Variable "e" is for debugging purposes

        e = e+1

        #Checks the procedence of the packet
        notapi = ipd
        detect_dst(notapi)
        notapi = ips
        detect_src(notapi)

        #Loop of the main code
while True:
    try:
        print('Ejecucion numero: ' + str(i))
        live_sniffer()
        i = i+1
    except Exception as ex:
        print(ex)
        time.sleep(30)
        live_sniffer()
