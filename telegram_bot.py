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
