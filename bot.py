"""
Discord moderation bot (Python / discord.py)
Features:
 - Detect links / invites / spam and delete messages
 - Auto actions configurable: timeout (duration selectable) or ban
 - Moderator slash commands: /timeout, /ban, /set_auto, /whitelist
 - Simple per-user rate tracking to detect rapid messages (spam)
Requirements:
 - Python 3.10+
 - pip install -U discord.py python-dotenv
Permissions required for the bot:
 - View Channels, Read Message History, Send Messages
 - Manage Messages (to delete), Moderate Members (to timeout), Ban Members (to ban)
"""

import re
import os
import asyncio
from datetime import datetime, timedelta
from collections import deque, defaultdict

import discord
from discord.ext import commands, tasks
from discord import app_commands

from dotenv import load_dotenv

load_dotenv()  # loads TOKEN, GUILD_ID, LOG_CHANNEL_ID optionally from .env

# ---------- Configuration (tweak these) ----------
TOKEN = os.getenv("DISCORD_TOKEN") or os.getenv("TOKEN")  # set in .env or environment
GUILD_ID = int(os.getenv("GUILD_ID") or 0)  # optional: for registering guild-only commands during dev
LOG_CHANNEL_ID = int(os.getenv("LOG_CHANNEL_ID") or 0)  # optional: channel id for moderation logs

# Auto-moderation default settings
AUTO_MOD_ENABLED = True
TIMEOUT_DEFAULT_SECONDS = 60 * 30  # 30 minutes default timeout for auto action
SPAM_MESSAGE_WINDOW_SECONDS = 8  # consider messages in last N seconds
SPAM_MESSAGE_THRESHOLD = 5       # if user sends >= this many messages within window -> spam
REPEAT_MESSAGE_THRESHOLD = 3    # same content repeated this many times -> spam

# Whitelist (role IDs or user IDs) - prevents auto-moderation
WHITELIST_ROLES = set()  # fill role ids here e.g. {1234567890123456}
WHITELIST_USERS = set()  # fill user ids here

INTENTS = discord.Intents.default()
INTENTS.message_content = True
INTENTS.members = True
INTENTS.guilds = True

# Regex patterns
URL_REGEX = re.compile(
    r"(https?://[^\s]+|www\.[^\s]+)", re.IGNORECASE
)
INVITE_REGEX = re.compile(
    r"(?:discord(?:\.gg|\.com\/invite)\/[A-Za-z0-9\-]+)", re.IGNORECASE
)

# ---------- Bot setup ----------
bot = commands.Bot(command_prefix="!", intents=INTENTS)
# We'll use app commands (slash commands)
tree = bot.tree

# Per-user recent messages store for spam detection
user_messages = defaultdict(lambda: deque(maxlen=50))  # user_id -> deque[(timestamp, content)]

# Simple in-memory config; you can persist this to file/db if you want
config = {
    "auto_mod_enabled": AUTO_MOD_ENABLED,
    "timeout_seconds": TIMEOUT_DEFAULT_SECONDS,
    "log_channel_id": LOG_CHANNEL_ID,
    "whitelist_roles": set(WHITELIST_ROLES),
    "whitelist_users": set(WHITELIST_USERS),
}

# ---------- Helper functions ----------
def is_whitelisted(member: discord.Member) -> bool:
    if member.id in config["whitelist_users"]:
        return True
    member_role_ids = {r.id for r in member.roles}
    if member_role_ids & config["whitelist_roles"]:
        return True
    # allow admins
    if member.guild_permissions.administrator:
        return True
    return False

async def send_log(guild: discord.Guild, message: str):
    if not config["log_channel_id"]:
        return
    ch = guild.get_channel(config["log_channel_id"])
    if ch:
        try:
            await ch.send(message)
        except Exception:
            # ignore log send failures
            pass

def contains_link_or_invite(content: str) -> bool:
    if not content:
        return False
    if URL_REGEX.search(content):
        return True
    if INVITE_REGEX.search(content):
        return True
    return False

def now_utc() -> datetime:
    return datetime.utcnow()

# ---------- Events ----------
@bot.event
async def on_ready():
    print(f"Logged in as {bot.user} (id: {bot.user.id})")
    print("Ready. Syncing commands...")
    if GUILD_ID:
        # register commands to guild for quick updates during development
        await tree.sync(guild=discord.Object(id=GUILD_ID))
        print(f"Slash commands synced to guild {GUILD_ID}")
    else:
        await tree.sync()
        print("Global slash commands synced.")
    print("Bot is ready.")

@bot.event
async def on_message(message: discord.Message):
    # ignore bot messages
    if message.author.bot:
        return

    guild = message.guild
    if not guild:
        return  # ignore DMs

    member: discord.Member = message.author

    # store message for spam detection
    user_messages[member.id].append((now_utc(), message.content or ""))

    # Quick whitelist check
    if is_whitelisted(member):
        return

    # Auto-moderation toggle
    if not config["auto_mod_enabled"]:
        return

    # 1) Link or invite detection
    if contains_link_or_invite(message.content):
        try:
            await message.delete()
        except discord.Forbidden:
            # bot lacks permission to delete
            await send_log(guild, f"🔒 Could not delete message by {member} containing link (missing Manage Messages).")
        else:
            await send_log(guild, f"🛡️ Deleted message by {member} (link/invite). Content: {message.content[:400]!r}")
            # optionally timeout or ban
            await take_auto_action(guild, member, reason="Posting links/invites (auto-moderation)")

        return  # done

    # 2) Spam detection: rapid messages within SPAM_MESSAGE_WINDOW_SECONDS
    now = now_utc()
    recent = [t for t, _ in user_messages[member.id] if (now - t).total_seconds() <= SPAM_MESSAGE_WINDOW_SECONDS]
    if len(recent) >= SPAM_MESSAGE_THRESHOLD:
        # consider spam
        await send_log(guild, f"⚠️ Detected spam by {member} — {len(recent)} msgs within {SPAM_MESSAGE_WINDOW_SECONDS}s.")
        await take_auto_action(guild, member, reason="Spam (auto-moderation)")
        return

    # 3) Repeat message detection
    contents = [c for _, c in user_messages[member.id] if c.strip()]
    if contents:
        last = contents[-1]
        repeat_count = sum(1 for c in contents[-REPEAT_MESSAGE_THRESHOLD*2:] if c == last)
        if repeat_count >= REPEAT_MESSAGE_THRESHOLD:
            await send_log(guild, f"⚠️ Detected repeated message spam by {member} (repeated {repeat_count} times).")
            await take_auto_action(guild, member, reason="Repeated messages (auto-moderation)")
            return

    # if no auto-moderation triggered, continue and allow commands
    await bot.process_commands(message)

# ---------- Auto action ----------
async def take_auto_action(guild: discord.Guild, member: discord.Member, reason: str = "Auto moderation"):
    """
    Default auto action: timeout for config["timeout_seconds"].
    If the bot lacks Moderate Members, it will attempt to ban if configured, else just log.
    You can modify this function to change the default auto behavior (ban instead of timeout).
    """
    # If bot can't moderate members, try ban (requires Ban Members) or only log.
    me = guild.me
    timeout_seconds = config.get("timeout_seconds") or TIMEOUT_DEFAULT_SECONDS

    # Safety: don't act on owner or on higher roles
    if member == guild.owner:
        await send_log(guild, f"⛔ Attempted auto-action on owner {member} — skipped.")
        return
    if member.top_role >= me.top_role and me != guild.owner:
        await send_log(guild, f"⛔ Cannot act on {member} due to role hierarchy (bot role too low).")
        return

    # Try to apply timeout
    if guild.me.guild_permissions.moderate_members:
        until = datetime.utcnow() + timedelta(seconds=timeout_seconds)
        try:
            await member.edit(timeout=until, reason=reason)
            await send_log(guild, f"⏱️ Timed out {member} until {until.isoformat()} for reason: {reason}")
            return
        except Exception as e:
            await send_log(guild, f"❗ Failed to timeout {member}: {e}")

    # Fallback: try ban if moderate_members not available and bot has ban permission
    if guild.me.guild_permissions.ban_members:
        try:
            await guild.ban(member, reason=f"{reason} (auto-ban fallback)")
            await send_log(guild, f"🔨 Banned {member} (fallback) for reason: {reason}")
            return
        except Exception as e:
            await send_log(guild, f"❗ Failed to ban {member}: {e}")

    # else just log
    await send_log(guild, f"ℹ️ Auto action needed for {member} but bot lacked permissions; manual action required. Reason: {reason}")

# ---------- Slash (app) commands for moderators ----------
def mod_only():
    def predicate(interaction: discord.Interaction) -> bool:
        # simple check: require Manage Messages or Moderation permission or Administrator
        perms = interaction.user.guild_permissions
        return perms.manage_messages or perms.moderate_members or perms.administrator
    return app_commands.check(predicate)

@tree.command(name="set_auto", description="Enable or disable auto-moderation", guild=discord.Object(id=GUILD_ID) if GUILD_ID else None)
@mod_only()
@app_commands.choices(state=[
    app_commands.Choice(name="on", value="on"),
    app_commands.Choice(name="off", value="off")
])
async def set_auto(interaction: discord.Interaction, state: app_commands.Choice[str]):
    config["auto_mod_enabled"] = (state.value == "on")
    await interaction.response.send_message(f"Auto-moderation set to **{state.value}**", ephemeral=True)

@tree.command(name="timeout", description="Timeout a member for a given number of minutes", guild=discord.Object(id=GUILD_ID) if GUILD_ID else None)
@mod_only()
@app_commands.describe(member="Member to timeout", minutes="Duration in minutes (set 0 to remove timeout)", reason="Reason (optional)")
async def timeout_cmd(interaction: discord.Interaction, member: discord.Member, minutes: int, reason: str = None):
    if minutes < 0:
        await interaction.response.send_message("Minutes must be 0 or positive.", ephemeral=True)
        return
    # check hierarchy
    if member == interaction.guild.owner:
        await interaction.response.send_message("Cannot timeout the server owner.", ephemeral=True)
        return
    if member.top_role >= interaction.guild.me.top_role and interaction.guild.me != interaction.guild.owner:
        await interaction.response.send_message("I cannot timeout that member due to role hierarchy.", ephemeral=True)
        return
    try:
        if minutes == 0:
            await member.edit(timeout=None, reason=reason or f"Timeout removed by {interaction.user}")
            await interaction.response.send_message(f"Removed timeout for {member.mention}", ephemeral=True)
            await send_log(interaction.guild, f"🔓 Timeout removed for {member} by {interaction.user}. Reason: {reason}")
        else:
            until = datetime.utcnow() + timedelta(minutes=minutes)
            await member.edit(timeout=until, reason=reason or f"Timed out by {interaction.user}")
            await interaction.response.send_message(f"Timed out {member.mention} for {minutes} minutes.", ephemeral=True)
            await send_log(interaction.guild, f"⏱️ {member} timed out by {interaction.user} until {until.isoformat()}. Reason: {reason}")
    except discord.Forbidden:
        await interaction.response.send_message("I don't have permission to timeout this member.", ephemeral=True)

@tree.command(name="ban", description="Ban a member", guild=discord.Object(id=GUILD_ID) if GUILD_ID else None)
@mod_only()
@app_commands.describe(member="Member to ban", reason="Reason (optional)", delete_days="Delete past N days of messages (0-7)")
async def ban_cmd(interaction: discord.Interaction, member: discord.Member, reason: str = None, delete_days: int = 0):
    if delete_days < 0 or delete_days > 7:
        await interaction.response.send_message("delete_days must be between 0 and 7.", ephemeral=True)
        return
    try:
        await interaction.guild.ban(member, reason=reason or f"Banned by {interaction.user}", delete_message_days=delete_days)
        await interaction.response.send_message(f"Banned {member.mention}.", ephemeral=True)
        await send_log(interaction.guild, f"🔨 {member} was banned by {interaction.user}. Reason: {reason}. delete_days={delete_days}")
    except discord.Forbidden:
        await interaction.response.send_message("I don't have permission to ban this member.", ephemeral=True)

@tree.command(name="whitelist", description="Manage whitelist for auto-moderation (roles/users)", guild=discord.Object(id=GUILD_ID) if GUILD_ID else None)
@mod_only()
@app_commands.describe(action="add/remove/list", role="Role to add/remove", user="User to add/remove")
async def whitelist_cmd(interaction: discord.Interaction, action: str, role: discord.Role = None, user: discord.Member = None):
    act = action.lower()
    if act == "list":
        roles = ", ".join(str(r) for r in (interaction.guild.get_role(rid) for rid in config["whitelist_roles"]) if r)
        users = ", ".join(str(interaction.guild.get_member(uid)) for uid in config["whitelist_users"] if interaction.guild.get_member(uid))
        await interaction.response.send_message(f"Whitelist roles: {roles or '—'}\nWhitelist users: {users or '—'}", ephemeral=True)
        return
    if act not in ("add", "remove"):
        await interaction.response.send_message("action must be 'add', 'remove' or 'list'.", ephemeral=True)
        return
    if role is None and user is None:
        await interaction.response.send_message("Provide a role or user to add/remove.", ephemeral=True)
        return

    if role:
        if act == "add":
            config["whitelist_roles"].add(role.id)
            await interaction.response.send_message(f"Added role {role.name} to whitelist.", ephemeral=True)
            await send_log(interaction.guild, f"✅ Role {role} added to whitelist by {interaction.user}")
        else:
            config["whitelist_roles"].discard(role.id)
            await interaction.response.send_message(f"Removed role {role.name} from whitelist.", ephemeral=True)
            await send_log(interaction.guild, f"❎ Role {role} removed from whitelist by {interaction.user}")
        return

    if user:
        if act == "add":
            config["whitelist_users"].add(user.id)
            await interaction.response.send_message(f"Added user {user.mention} to whitelist.", ephemeral=True)
            await send_log(interaction.guild, f"✅ User {user} added to whitelist by {interaction.user}")
        else:
            config["whitelist_users"].discard(user.id)
            await interaction.response.send_message(f"Removed user {user.mention} from whitelist.", ephemeral=True)
            await send_log(interaction.guild, f"❎ User {user} removed from whitelist by {interaction.user}")
        return

# ---------- Utility commands ----------
@bot.command(name="settimeout")
@commands.has_permissions(administrator=True)
async def settimeout(ctx: commands.Context, minutes: int):
    if minutes < 0:
        await ctx.send("Minutes must be non-negative.")
        return
    config["timeout_seconds"] = minutes * 60
    await ctx.send(f"Default auto timeout set to {minutes} minutes.")

@bot.command(name="autostatus")
@commands.has_permissions(administrator=True)
async def autostatus(ctx: commands.Context):
    await ctx.send(f"Auto-moderation: {config['auto_mod_enabled']}\nDefault timeout (seconds): {config['timeout_seconds']}")

# ---------- Simple background cleanup (optional) ----------
@tasks.loop(hours=1)
async def cleanup_old_users():
    # prune user_messages to keep memory small
    cutoff = now_utc() - timedelta(minutes=10)
    for uid, dq in list(user_messages.items()):
        # keep only messages newer than cutoff
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        if not dq:
            user_messages.pop(uid, None)

@cleanup_old_users.before_loop
async def before_cleanup():
    await bot.wait_until_ready()

cleanup_old_users.start()

# ---------- Run bot ----------
if not TOKEN:
    print("ERROR: DISCORD TOKEN not set. Put it in DISCORD_TOKEN env or in .env file as DISCORD_TOKEN.")
else:
    bot.run(TOKEN)
