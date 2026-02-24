# src/botcmds.py
"""
Bot-specific commands for botnet communication.
Similar to commands.py but for inter-bot operations.
"""

import logging
from typing import Callable, Dict, Any

log = logging.getLogger(__name__)

async def cmd_link(manager, from_bot: str, args: str, respond: Callable):
    """Link to another bot: .link <name> <host> <port> [flags]"""
    parts = args.split()
    if len(parts) < 3:
        await respond("Usage: .link <name> <host> <port> [flags]")
        return
    
    from .botnet import BotLink
    link = BotLink(
        name=parts[0],
        host=parts[1],
        port=int(parts[2]),
        flags=parts[3] if len(parts) > 3 else '',
        subnet_id=manager.subnet_id
    )
    
    manager.peers[link.name] = link
    await manager.connect_peer(link)
    await respond(f"Linking to {link.name} at {link.host}:{link.port}")

async def cmd_unlink(manager, from_bot: str, args: str, respond: Callable):
    """Unlink from bot: .unlink <name>"""
    if not args:
        await respond("Usage: .unlink <name>")
        return
    
    name = args.strip()
    if name in manager.links:
        _, writer = manager.links[name]
        writer.close()
        del manager.links[name]
        if name in manager.peers:
            del manager.peers[name]
        await respond(f"Unlinked from {name}")
    else:
        await respond(f"Not linked to {name}")

async def cmd_bots(manager, from_bot: str, args: str, respond: Callable):
    """List connected bots"""
    if not manager.links:
        await respond("No bots linked")
        return
    
    lines = ["Connected bots:"]
    for name, (reader, writer) in manager.links.items():
        peer = manager.peers.get(name)
        flags = peer.flags if peer else ''
        subnet = f"subnet:{peer.subnet_id}" if peer and peer.subnet_id else ''
        lines.append(f"  {name} [{flags}] {subnet}")
    
    await respond("\n".join(lines))

async def cmd_relay(manager, from_bot: str, args: str, respond: Callable):
    """Relay command to target: .relay <bot|subnet|all> <command>"""
    parts = args.split(maxsplit=1)
    if len(parts) < 2:
        await respond("Usage: .relay <bot|subnet|all> <command>")
        return
    
    target, command = parts
    
    cmd_data = {
        'cmd': command,
        'target': target,
        'from': from_bot
    }
    
    if target == 'all':
        await manager.broadcast_all(cmd_data)
        await respond(f"Broadcasting to all bots: {command}")
    elif target == 'subnet':
        await manager.broadcast_subnet(cmd_data)
        await respond(f"Broadcasting to subnet: {command}")
    else:
        # Specific bot
        if target in manager.links:
            _, writer = manager.links[target]
            import json
            msg = f"CMD:{json.dumps(cmd_data)}\n"
            await manager._safe_send(writer, msg)
            await respond(f"Sent to {target}: {command}")
        else:
            await respond(f"Bot '{target}' not linked")

async def cmd_share(manager, from_bot: str, args: str, respond: Callable):
    """Share data with specific bot: .share <botname> [users|channels|all]"""
    parts = args.split()
    if len(parts) < 1:
        await respond("Usage: .share <botname> [users|channels|all]")
        return
    
    target_bot = parts[0]
    share_type = parts[1] if len(parts) > 1 else 'all'
    
    if target_bot not in manager.links:
        await respond(f"Bot '{target_bot}' not linked")
        return
    
    _, writer = manager.links[target_bot]
    
    if share_type in ('users', 'all'):
        await manager.share_users(writer)
    if share_type in ('channels', 'all'):
        await manager.share_channels(writer)
    
    await respond(f"Shared {share_type} with {target_bot}")

async def cmd_botinfo(manager, from_bot: str, args: str, respond: Callable):
    """Get info about this bot or another bot"""
    if not args:
        # Info about this bot
        info = [
            f"Bot: {manager.my_handle}",
            f"Subnet: {manager.subnet_id}",
            f"Relay Port: {manager.config.get('botnet', {}).get('relay_port', 'N/A')}",
            f"Linked Bots: {len(manager.links)}"
        ]
        await respond("\n".join(info))
    else:
        # Info about specific bot
        bot_name = args.strip()
        if bot_name in manager.links:
            peer = manager.peers.get(bot_name)
            info = [
                f"Bot: {bot_name}",
                f"Host: {peer.host if peer else 'unknown'}:{peer.port if peer else ''}",
                f"Flags: {peer.flags if peer else 'none'}",
                f"Subnet: {peer.subnet_id if peer and peer.subnet_id else 'N/A'}"
            ]
            await respond("\n".join(info))
        else:
            await respond(f"Bot '{bot_name}' not linked")

async def cmd_subnet(manager, from_bot: str, args: str, respond: Callable):
    """List bots in current subnet or switch subnet"""
    if not args:
        # List current subnet
        subnet_bots = []
        for name, (_, _) in manager.links.items():
            peer = manager.peers.get(name)
            if peer and peer.subnet_id == manager.subnet_id:
                subnet_bots.append(name)
        
        if subnet_bots:
            await respond(f"Subnet {manager.subnet_id} bots: {', '.join(subnet_bots)}")
        else:
            await respond(f"No other bots in subnet {manager.subnet_id}")
    else:
        # Change subnet (requires restart or config update)
        await respond("Subnet changes require bot restart")

# Command registry
BOTCMDS: Dict[str, Callable] = {
    'link': cmd_link,
    'unlink': cmd_unlink,
    'bots': cmd_bots,
    'relay': cmd_relay,
    'share': cmd_share,
    'botinfo': cmd_botinfo,
    'subnet': cmd_subnet,
}
