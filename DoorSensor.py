import paho.mqtt.client as mqtt
import time
import random
import json

# --- MQTT Configuration ---
MQTT_BROKER = "YOUR_SERVER_IP" # IMPORTANT: Replace with your server IP
MQTT_PORT = 1883
MQTT_TOPIC = "home/security/door_sensor/entrance"
CLIENT_ID_PREFIX = "DoorSensorTransient"

# --- Sensor Simulation Settings ---
PUBLISH_INTERVAL_SECONDS = 5
safe_publication_count = 0
WARNING_THRESHOLD = 10

# --- MQTT Callback Functions ---
def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print(f"[{client._client_id.decode()}] INFO: Connected to MQTT Broker...")
    else:
        print(f"[{client._client_id.decode()}] ERROR: Failed to connect, return code: {rc}")

def on_publish(client, userdata, mid, reasonCode=None, properties=None):
    print(f"[{client._client_id.decode()}] INFO: Message {mid} published successfully.")

def on_disconnect(client, userdata, rc, properties=None, reason=None):
    print(f"[{client._client_id.decode()}] INFO: Disconnected from MQTT Broker.")

# --- Function to generate sensor status message ---
def generate_sensor_status_message():
    global safe_publication_count
    status = "SAFE"
    message = "No activity detected. All clear."
    
    if safe_publication_count >= WARNING_THRESHOLD:
        status = "WARNING"
        message = "Unusual activity detected! Please check."
        safe_publication_count = 0
    else:
        safe_publication_count += 1
        
    current_time = time.strftime('%Y-%m-%d %H:%M:%S')
    
    payload = {
        "timestamp": current_time,
        "sensor_id": CLIENT_ID_PREFIX,
        "location": "Main Entrance",
        "topic": MQTT_TOPIC,
        "status": status,
        "message": message,
    }
    return json.dumps(payload)

# --- Main simulation loop ---
def run_door_person_sensor_simulator():
    try:
        while True:
            client_id = f"{CLIENT_ID_PREFIX}"
            client = mqtt.Client(client_id=client_id, callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
            client.on_connect = on_connect
            client.on_publish = on_publish
            client.on_disconnect = on_disconnect
            try:
                client.connect(MQTT_BROKER, MQTT_PORT, 60)
                client.loop_start()
                time.sleep(0.5)
                if client.is_connected():
                    sensor_data = generate_sensor_status_message()
                    print(f"[{client_id}] Publishing message: {sensor_data}")
                    info = client.publish(MQTT_TOPIC, sensor_data, qos=1)
                    info.wait_for_publish()
                    client.disconnect()
                else:
                    print(f"[{client_id}] Connection not established.")
            except Exception as e:
                print(f"[{client_id}] AN UNEXPECTED ERROR OCCURRED: {e}")
            finally:
                client.loop_stop()
                if client.is_connected():
                    client.disconnect()
            
            time.sleep(PUBLISH_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        print("\n--- Simulator stopped by user (Ctrl+C). ---")

if __name__ == "__main__":
    run_door_person_sensor_simulator()
