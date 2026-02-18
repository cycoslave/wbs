#!/usr/bin/env python3
# main.py
import asyncio
import json
import multiprocessing as mp
import sys
from pathlib import Path

from src.irc import start_irc_process
from src.core import WBSBot
from src.botnet import start_botnet_process
from src.db import init_db, seed_db


def load_config(config_path="config.json"):
    """Load configuration from JSON file."""
    with open(config_path) as f:
        return json.load(f)


async def setup_db(config):
    """Initialize and seed the database."""
    db_path = config['db_path']
    await init_db(db_path, schema_path="db/schema.sql")
    await seed_db(db_path, config)


def run_bot_process(config):
    """Run the main WBSBot in its own process."""
    server_list = [(config['server'], config['port'])]
    bot = WBSBot(
        server_list,
        config['nickname'],
        config['realname'],
        config['db_path'],
        config['channels']
    )
    asyncio.run(bot.init_db())  # Assuming this initializes bot's DB connection [web:6]
    bot.start()


if __name__ == "__main__":
    mp.set_start_method('spawn', force=True)  # Ensure spawn method for compatibility [web:17]

    config = load_config()
    asyncio.run(setup_db(config))  # Shared DB init before processes; SQLite handles multi-process [web:21]

    processes = []

    # Main bot process (core logic)
    bot_p = mp.Process(target=run_bot_process, args=(config,), name="bot")
    bot_p.start()
    processes.append(bot_p)

    # IRC process
    irc_p = mp.Process(target=start_irc_process, args=(config,), name="irc")
    irc_p.start()
    processes.append(irc_p)

    # Optional botnet process
    if config.get('botnet', {}).get('enabled'):
        botnet_p = mp.Process(target=start_botnet_process, args=(config,), name="botnet")
        botnet_p.start()
        processes.append(botnet_p)

    try:
        for p in processes:
            p.join()
    except KeyboardInterrupt:
        print("Shutting down processes...")
        for p in processes:
            p.terminate()
            p.join(timeout=5)
        sys.exit(0)
