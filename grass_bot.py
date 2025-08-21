import asyncio
import random
import ssl
import json
import time
import uuid
import base64
import requests
from loguru import logger
import websockets
import sqlite3
from datetime import datetime
import os
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from telegram import Bot, Update
from telegram.ext import Application, CommandHandler, ContextTypes

# For proxies
from websockets_proxy import Proxy, proxy_connect

# Configuration
DB_FILE = "grass_accounts.db"
LOG_FILE = "grass_farming.log"
BACKUP_DIR = "backups"
KEY_FILE = "encryption_key.key"
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "YOUR_TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "YOUR_CHAT_ID")

async def send_telegram_message(message, chat_id=None):
    try:
        bot = Bot(token=TELEGRAM_BOT_TOKEN)
        await bot.send_message(chat_id=chat_id or TELEGRAM_CHAT_ID, text=message)
    except Exception as e:
        logger.error(f"Failed to send Telegram message: {e}")

def get_encryption_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    else:
        key = secrets.token_bytes(32)
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
        logger.warning(f"New AES-256 key generated: {KEY_FILE}")
        asyncio.create_task(send_telegram_message(f"New AES-256 key generated: {KEY_FILE}"))
        return key

def encrypt_data(data, key):
    if not data:
        return None
    iv = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
    return base64.urlsafe_b64encode(iv + encryptor.tag + ct).decode('utf-8')

def decrypt_data(encrypted_data, key):
    if not encrypted_data:
        return None
    data = base64.urlsafe_b64decode(encrypted_data)
    iv = data[:12]
    tag = data[12:28]
    ct = data[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()
    return pt.decode('utf-8')

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS accounts (
            email TEXT PRIMARY KEY,
            user_id TEXT,
            bearer_token TEXT,
            status TEXT DEFAULT 'pending',
            last_update TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def add_or_update_account(email, user_id, bearer_token, key):
    encrypted_bearer = encrypt_data(bearer_token, key)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO accounts (email, user_id, bearer_token, status, last_update)
        VALUES (?, ?, ?, 'active', ?)
    ''', (email, user_id, encrypted_bearer, datetime.now()))
    conn.commit()
    conn.close()

def get_accounts():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT email, user_id, bearer_token, status FROM accounts')
    accounts = cursor.fetchall()
    conn.close()
    return accounts

async def farm_grass(socks5_proxy, user_id):
    device_id = str(uuid.uuid3(uuid.NAMESPACE_DNS, socks5_proxy if socks5_proxy else 'no_proxy'))
    logger.info(f"Connecting with Device ID: {device_id} for user {user_id}")
    await send_telegram_message(f"Starting farming for user {user_id}")
    while True:
        try:
            await asyncio.sleep(random.uniform(0.1, 1.0))
            custom_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
            }
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            uris = ["wss://proxy.wynd.network:4650/", "wss://proxy2.wynd.network:4650/", "wss://proxy.wynd.network:4444/"]
            uri = random.choice(uris)
            server_hostname = uri.split('//')[1].split(':')[0]
            if socks5_proxy:
                proxy = Proxy.from_url(socks5_proxy)
                async with proxy_connect(uri, proxy=proxy, ssl=ssl_context, server_hostname=server_hostname, extra_headers=custom_headers) as websocket:
                    await handle_connection(websocket, user_id, device_id, custom_headers)
            else:
                async with websockets.connect(uri, ssl=ssl_context, extra_headers=custom_headers, server_hostname=server_hostname) as websocket:
                    await handle_connection(websocket, user_id, device_id, custom_headers)
        except Exception as e:
            logger.error(f"Error with proxy {socks5_proxy} for user {user_id}: {e}")
            await send_telegram_message(f"Error with proxy {socks5_proxy} for user {user_id}: {e}")

async def handle_connection(websocket, user_id, device_id, custom_headers):
    async def send_ping():
        while True:
            send_message = json.dumps({"id": str(uuid.uuid4()), "version": "1.0.0", "action": "PING", "data": {}})
            logger.debug(send_message)
            await websocket.send(send_message)
            await asyncio.sleep(5)

    asyncio.create_task(send_ping())

    while True:
        response = await websocket.recv()
        message = json.loads(response)
        logger.info(message)
        if message.get("action") == "AUTH":
            auth_response = {
                "id": message["id"],
                "origin_action": "AUTH",
                "result": {
                    "browser_id": device_id,
                    "user_id": user_id,
                    "user_agent": custom_headers['User-Agent'],
                    "timestamp": int(time.time()),
                    "device_type": "extension",
                    "version": "4.30.0",
                    "extension_id": "lkbnfiajjmbhnfledhphioinpickokdi"
                }
            }
            logger.debug(auth_response)
            await websocket.send(json.dumps(auth_response))
        elif message.get("action") == "HTTP_REQUEST":
            try:
                url = message["data"]["url"]
                headers = message["data"]["headers"]
                fetch_response = requests.get(url, headers=headers, timeout=10)
                body = base64.b64encode(fetch_response.content).decode('utf-8')
                httpreq_response = {
                    "id": message["id"],
                    "origin_action": "HTTP_REQUEST",
                    "result": {
                        "status": fetch_response.status_code,
                        "status_text": "OK",
                        "headers": dict(fetch_response.headers),
                        "body": body
                    }
                }
                await websocket.send(json.dumps(httpreq_response))
            except Exception as e:
                logger.error(f"Error fetching {url}: {e}")
                await send_telegram_message(f"Error fetching {url}: {e}")
        elif message.get("action") == "PONG":
            pong_response = {"id": message["id"], "origin_action": "PONG"}
            logger.debug(pong_response)
            await websocket.send(json.dumps(pong_response))

def get_grass_balance(bearer_token):
    url = "https://api.getgrass.io/retrieveUser"
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            points = data.get('result', {}).get('data', {}).get('lifetimeScore', 0)
            logger.info(f"Current $GRASS balance: {points}")
            return points
        else:
            logger.error(f"Error fetching balance: {response.status_code} {response.text}")
            return None
    except Exception as e:
        logger.error(f"Exception fetching balance: {e}")
        return None

async def start_farming_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    email = context.args[0] if context.args else None
    if not email:
        await update.message.reply_text("Please provide an email: /start_farming <email>")
        return
    accounts = get_accounts()
    key = get_encryption_key()
    for acc_email, user_id, encrypted_bearer_token, status in accounts:
        if acc_email == email and status == 'active' and encrypted_bearer_token:
            bearer_token = decrypt_data(encrypted_bearer_token, key)
            if email in context.bot_data.get('account_tasks', {}):
                await update.message.reply_text(f"Farming already active for {email}")
                return
            proxies = context.bot_data.get('proxies', [])
            context.bot_data.setdefault('account_tasks', {})[email] = []
            context.bot_data.setdefault('account_states', {})[email] = {
                'previous_balance': get_grass_balance(bearer_token),
                'stagnant_count': 0,
                'bearer_token': bearer_token,
                'user_id': user_id
            }
            tasks = []
            if proxies:
                for proxy in proxies:
                    task = asyncio.create_task(farm_grass(proxy, user_id))
                    context.bot_data['account_tasks'][email].append(task)
                    tasks.append(task)
            else:
                task = asyncio.create_task(farm_grass(None, user_id))
                context.bot_data['account_tasks'][email].append(task)
                tasks.append(task)
            await update.message.reply_text(f"Started farming for {email}")
            return
    await update.message.reply_text(f"No active account found for {email}")

async def stop_farming_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    email = context.args[0] if context.args else None
    if not email:
        await update.message.reply_text("Please provide an email: /stop_farming <email>")
        return
    account_tasks = context.bot_data.get('account_tasks', {})
    if email in account_tasks:
        for task in account_tasks[email]:
            task.cancel()
        del account_tasks[email]
        await update.message.reply_text(f"Stopped farming for {email}")
    else:
        await update.message.reply_text(f"No active farming for {email}")

async def check_balance_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    email = context.args[0] if context.args else None
    if not email:
        await update.message.reply_text("Please provide an email: /check_balance <email>")
        return
    key = get_encryption_key()
    accounts = get_accounts()
    for acc_email, _, encrypted_bearer_token, status in accounts:
        if acc_email == email and status == 'active' and encrypted_bearer_token:
            bearer_token = decrypt_data(encrypted_bearer_token, key)
            balance = get_grass_balance(bearer_token)
            if balance is not None:
                await update.message.reply_text(f"Balance for {email}: {balance} $GRASS")
            else:
                await update.message.reply_text(f"Failed to fetch balance for {email}")
            return
    await update.message.reply_text(f"No active account found for {email}")

async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    key = get_encryption_key()
    accounts = get_accounts()
    if not accounts:
        await update.message.reply_text("No accounts in database")
        return
    status_msg = "Account Status:\n"
    for email, _, encrypted_bearer_token, status in accounts:
        balance = "Unknown"
        if encrypted_bearer_token and status == 'active':
            bearer_token = decrypt_data(encrypted_bearer_token, key)
            balance = get_grass_balance(bearer_token) or "Failed to fetch"
        status_msg += f"Email: {email}, Status: {status}, Balance: {balance} $GRASS\n"
    await update.message.reply_text(status_msg)

def restart_farming(email, account_tasks, user_id, proxies):
    logger.warning(f"Restarting farming for {email}")
    asyncio.create_task(send_telegram_message(f"Restarting farming for {email} due to no points earned"))
    for task in account_tasks.get(email, []):
        task.cancel()
    account_tasks[email] = []
    new_tasks = []
    if proxies:
        for proxy in proxies:
            task = asyncio.create_task(farm_grass(proxy, user_id))
            account_tasks[email].append(task)
            new_tasks.append(task)
    else:
        task = asyncio.create_task(farm_grass(None, user_id))
        account_tasks[email].append(task)
        new_tasks.append(task)
    return new_tasks

async def balance_checker(account_states, account_tasks, proxies):
    while True:
        for email, state in list(account_states.items()):
            bearer_token = state['bearer_token']
            current_balance = get_grass_balance(bearer_token)
            if current_balance == state['previous_balance']:
                state['stagnant_count'] += 1
                if state['stagnant_count'] >= 2:
                    logger.warning(f"No points earned for {email} in 60 minutes. Restarting process.")
                    new_tasks = restart_farming(email, account_tasks, state['user_id'], proxies)
                    state['stagnant_count'] = 0
            else:
                state['stagnant_count'] = 0
            state['previous_balance'] = current_balance
        await asyncio.sleep(1800)

async def backup_task():
    while True:
        await asyncio.sleep(3600)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        try:
            os.makedirs(BACKUP_DIR, exist_ok=True)
            shutil.copy(DB_FILE, f'{BACKUP_DIR}/{timestamp}_accounts.db')
            shutil.copy(LOG_FILE, f'{BACKUP_DIR}/{timestamp}_logs.log')
            logger.info(f"Backup completed: {timestamp}")
            await send_telegram_message(f"Backup completed: {timestamp}")
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            await send_telegram_message(f"Backup failed: {e}")

async def main():
    logger.add(LOG_FILE, rotation="500 MB")
    os.makedirs(BACKUP_DIR, exist_ok=True)
    init_db()
    key = get_encryption_key()

    # Initialize Telegram bot
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    application.add_handler(CommandHandler("start_farming", start_farming_command))
    application.add_handler(CommandHandler("stop_farming", stop_farming_command))
    application.add_handler(CommandHandler("check_balance", check_balance_command))
    application.add_handler(CommandHandler("status", status_command))
    await application.initialize()
    await application.start()
    await application.updater.start_polling()

    # Load proxies
    proxy_file = input("Enter proxy file path (or leave empty for no proxies): ")
    proxies = []
    if proxy_file:
        with open(proxy_file, 'r') as f:
            proxies = [line.strip() for line in f if line.strip()]
    application.bot_data['proxies'] = proxies

    # Load accounts
    accounts = get_accounts()
    if not accounts:
        print("No accounts in database. Please provide account details.")
        email = input("Enter email: ")
        user_id = input("Enter user_id (from localStorage 'userId' after login): ")
        bearer_token = input("Enter bearer_token (from network 'Authorization' header): ")
        add_or_update_account(email, user_id, bearer_token, key)
        accounts = get_accounts()

    tasks = []
    account_tasks = {}
    account_states = {}
    application.bot_data['account_tasks'] = account_tasks
    application.bot_data['account_states'] = account_states

    for email, user_id, encrypted_bearer_token, status in accounts:
        if status == 'active' and encrypted_bearer_token:
            bearer_token = decrypt_data(encrypted_bearer_token, key)
            initial_balance = get_grass_balance(bearer_token)
            account_states[email] = {
                'previous_balance': initial_balance,
                'stagnant_count': 0,
                'bearer_token': bearer_token,
                'user_id': user_id
            }
            account_tasks[email] = []
            if proxies:
                for proxy in proxies:
                    task = asyncio.create_task(farm_grass(proxy, user_id))
                    account_tasks[email].append(task)
                    tasks.append(task)
            else:
                task = asyncio.create_task(farm_grass(None, user_id))
                account_tasks[email].append(task)
                tasks.append(task)

    tasks.append(asyncio.create_task(balance_checker(account_states, account_tasks, proxies)))
    tasks.append(asyncio.create_task(backup_task()))

    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())