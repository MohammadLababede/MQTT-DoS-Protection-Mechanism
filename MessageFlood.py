import paho.mqtt.client as mqtt
import time
import argparse
import uuid

# --- Default Settings ---
BROKER_ADDRESS = "127.0.0.1"
BROKER_PORT = 1883
TOPIC = "test/topic"
MESSAGE_COUNT = 500
DELAY = 0.01

# --- Argument Parser Setup ---
parser = argparse.ArgumentParser(description="MQTT Message Flood Tester")
parser.add_argument('-a', '--address', type=str, default=BROKER_ADDRESS, help=f"Broker address (default: {BROKER_ADDRESS})")
parser.add_argument('-p', '--port', type=int, default=BROKER_PORT, help=f"Broker port (default: {BROKER_PORT})")
parser.add_argument('-t', '--topic', type=str, default=TOPIC, help=f"Topic to publish to (default: {TOPIC})")
parser.add_argument('-c', '--count', type=int, default=MESSAGE_COUNT, help=f"Number of messages to send (default: {MESSAGE_COUNT})")
parser.add_argument('-d', '--delay', type=float, default=DELAY, help=f"Delay between messages in seconds (default: {DELAY})")

args = parser.parse_args()

# --- Script Logic ---
client_id = f"flood_tester_{uuid.uuid4()}"
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)

def on_connect(client, userdata, flags, rc, properties):
    if rc == 0:
        print(f"Connected to broker at {args.address}:{args.port}")
    else:
        print(f"Failed to connect, return code {rc}\n")
        exit()

def on_disconnect(client, userdata, rc, properties):
    print("Disconnected from broker.")

client.on_connect = on_connect
client.on_disconnect = on_disconnect

try:
    print("Attempting to connect...")
    client.connect(args.address, args.port, 60)
    client.loop_start()
    time.sleep(1)

    if not client.is_connected():
        print("Could not establish connection. Exiting.")
        exit()

    print(f"Starting to send {args.count} messages to topic '{args.topic}'...")
    for i in range(args.count):
        payload = f"Message {i+1} from {client_id}"
        result = client.publish(args.topic, payload)
        
        if result.rc != 0:
            print(f"\nFailed to publish message {i+1}. Connection might be dropped.")
            break
            
        print(f"Sent message {i+1}/{args.count}", end='\r')
        time.sleep(args.delay)

    print(f"\nFinished sending messages.")

except KeyboardInterrupt:
    print("\nScript interrupted by user.")
except Exception as e:
    print(f"\nAn error occurred: {e}")
finally:
    client.loop_stop()
    client.disconnect()
    print("Script finished.")
