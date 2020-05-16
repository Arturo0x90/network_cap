#!/usr/bin/env/python3.7
import pyshark as ps
import requests as r
from lists import whitelist
from lists import blacklist
from custom_lists import c_whitelist
from custom_lists import c_blacklist
interface = str(input('Interfaz (wlan0, eth0, lo, etc.): '))
#Variable "i" is for debugging purposes
i = 1
#Checker function gets whitelist/blacklist positives plus company info if existant
def checker(full):
    params = dict(
        whitelist="whitelist",
        blacklist="blacklist",
        company="company"
    )
    response = r.get(url=full, params=params)
    data = response.json()
    return data
#Detect function decides if the source/destination is trustable or not
def detect_dst(api, notapi):
    if notapi in whitelist or notapi in c_whitelist or api =={'whitelist': 'True'}:
        print("Destination IP in whitelist!")
    elif notapi in blacklist or notapi in c_blacklist or api =={'blacklist': 'True'}:
        print('Destination IP in blacklist!')
    else:
        print('Unknown destination IP!')

def detect_src(api, notapi):
    if notapi in whitelist or notapi in c_whitelist or api =={'whitelist': 'True'}:
        print("Source IP in whitelist!")
    elif notapi in blacklist or notapi in c_blacklist or api =={'blacklist': 'True'}:
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
        url = "http://95.131.161.12/api?q=" #API server url
        #If statement to avoid an infinite loop with the API server IP
        if ipd == "95.131.161.12" or ips == "95.131.161.12":
            pass
        else:
            print('A packet arrived!!')
            print('Packet number: ' + str(e))
            print('Destination: ' + str(packet['ip'].dst))
            print('Source: ' + str(packet['ip'].src))
            #Variable "e" is for debugging purposes

            e = e+1

            #Checks the procedence of the packet
            notapi = ipd
            api = checker(str(url)+str(ipd))
            detect_dst(api, notapi)
            notapi = ips
            api = checker(str(url)+str(ips))
            detect_src(api, notapi)

        #Loop of the main code
while True:
    try:
        print('Ejecucion numero: ' + str(i))
        live_sniffer()
        i = i+1
    except Exception as ex:
        print(ex)
        live_sniffer()
