import random
import time
import paho.mqtt.client as mqtt
import json

# --- MQTT Settings ---
MQTT_BROKER = "YOUR_SERVER_IP"  # IMPORTANT: Replace with your server IP
MQTT_PORT = 1883
MQTT_TOPIC = "home/gas_sensor"
MQTT_CLIENT_ID = "gas_sensor_py"

# Simulation variables
MIN_GAS_LEVEL = 0
MAX_GAS_LEVEL = 1000  # parts per million (ppm)
NORMAL_GAS_LEVEL = 50
ALARM_THRESHOLD = 300

# Connection status
connected = False

def on_connect(client, userdata, flags, rc, properties=None):
    global connected
    if rc == 0:
        print("Successfully connected to MQTT broker!")
        connected = True
    else:
        print(f"Failed to connect to MQTT broker, error code: {rc}")
        connected = False

def on_disconnect(client, userdata, rc, properties=None):
    global connected
    print("Disconnected from MQTT broker")
    connected = False

def simulate_gas_level():
    # Simulate gas level with random fluctuations
    base_level = NORMAL_GAS_LEVEL
    
    # 5% chance of gas leak
    if random.random() < 0.05:
        base_level = random.randint(ALARM_THRESHOLD, MAX_GAS_LEVEL)
    else:
        # Normal fluctuations
        base_level += random.randint(-20, 20)
        base_level = max(MIN_GAS_LEVEL, min(base_level, NORMAL_GAS_LEVEL * 2))
    
    return base_level

def publish_data(client):
    if connected:
        # Simulate sensor reading
        gas_level = simulate_gas_level()
        status = "normal" if gas_level < ALARM_THRESHOLD else "warning"
        
        # Create JSON message
        message = {
            "gas_level": gas_level,
            "status": status,
            "unit": "ppm",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "sensor_id": "gas_sensor_1"
        }
        
        # Publish message
        result = client.publish(MQTT_TOPIC, json.dumps(message))
        
        if result.rc == mqtt.MQTT_ERR_SUCCESS:
            print(f"Message sent: {message}")
        else:
            print(f"Failed to send, error code: {result.rc}")
    else:
        print("No connection, cannot publish data")

def main():
    while True:
        # Create new MQTT client for each cycle
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, MQTT_CLIENT_ID)
        client.on_connect = on_connect
        client.on_disconnect = on_disconnect

        try:
            # Connect to broker
            print("Connecting to MQTT broker...")
            client.connect(MQTT_BROKER, MQTT_PORT, 60)
            client.loop_start()
            
            # Wait for connection
            time.sleep(1)
            
            if connected:
                # Publish data
                publish_data(client)
                
                # Properly stop the client
                print("Disconnecting intentionally...")
                client.loop_stop()  # Stop the network loop first
                client.disconnect()  # Then disconnect
                time.sleep(1)  # Give time for clean disconnect
            
        except Exception as e:
            print(f"Error occurred: {e}")
        
        # Wait 5 seconds before reconnecting
        print("Waiting 5 seconds before reconnecting...")
        time.sleep(5)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Program stopped by user")
