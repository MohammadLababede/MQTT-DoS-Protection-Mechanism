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
