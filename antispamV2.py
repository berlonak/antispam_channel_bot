#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# copyright by berlonak
# telegram: @Kilax123

"""
Anti-spam Telegram bot (python-telegram-bot v20+)
- Deletes messages with Telegram links/mentions (t.me/... or @username)
- Deletes messages containing forbidden words from a SINGLE GLOBAL LIST (applies to ALL chats)
- Allows bypass for specific users (user.id) or sender chats (sender_chat.id)
- Logs deletions to spam.log with detailed author info
- All commands are restricted: ONLY in private chat (DM) AND ONLY for admins in ADMIN_USER_IDS.
"""

from __future__ import annotations

import logging
import os
import re
import sys
import unicodedata
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

from telegram import Update, Chat
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# =======================
# Configuration & paths
# =======================

BASE_DIR = Path(__file__).resolve().parent

# Optional: load variables from .env next to this file (pip install python-dotenv)
try:
    from dotenv import load_dotenv
except ImportError:
    pass
else:
    load_dotenv(BASE_DIR / ".env")


def _ids_from_env(name: str) -> Set[int]:
    """Parse Telegram IDs separated by commas, spaces, ';' or newlines."""
    raw = os.getenv(name, "")
    try:
        return {int(part) for part in re.split(r"[\s,;]+", raw.strip()) if part}
    except ValueError:
        raise RuntimeError(f"{name}: expected numeric Telegram IDs") from None


BOT_TOKEN = os.getenv("TELEGRAM_TOKEN", "")

# If empty, bot works in any chat; else only in listed chat IDs
ALLOWED_CHAT_IDS: Set[int] = _ids_from_env("ALLOWED_CHAT_IDS")

# Delete by links/mentions
DELETE_LINKS: bool = True

# Verbose match logs
DEBUG_MATCH: bool = os.getenv("ANTISPAM_DEBUG", "0") == "1"

# --- Admins ---
# Only these Telegram user IDs can use ANY commands (DM-only)
ADMIN_USER_IDS: Set[int] = _ids_from_env("ADMIN_USER_IDS")

# --- BYPASS (whitelist authors) ---
# Users whose messages are NEVER deleted (777000 = Telegram service notifications)
BYPASS_USER_IDS: Set[int] = {777000} | _ids_from_env("BYPASS_USER_IDS")
# Channels/chats used as sender (message.sender_chat.id) that are NEVER deleted,
# e.g. your channel, or an admin posting "on behalf of" the chat
BYPASS_SENDER_CHAT_IDS: Set[int] = _ids_from_env("BYPASS_SENDER_CHAT_IDS")

DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

GLOBAL_WORDS_FILE = DATA_DIR / "forbidden_words.txt"
GLOBAL_WORDS_FILE.touch(exist_ok=True)

# =======================
# Logging
# =======================

logging.basicConfig(
    level=logging.INFO if not DEBUG_MATCH else logging.DEBUG,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("antispam")

spam_logger = logging.getLogger("spamlog")
spam_logger.setLevel(logging.INFO)
_spam_handler = logging.FileHandler(BASE_DIR / "spam.log", encoding="utf-8")
_spam_handler.setFormatter(logging.Formatter("%(message)s"))
spam_logger.addHandler(_spam_handler)

# =======================
# Link / mention detection
# =======================

USERNAME_REGEX = re.compile(r"^\+?[A-Za-z0-9_]+$")

URL_PATTERN_FLEX = re.compile(
    r"""
    (?:h\s*t\s*t\s*p\s*s?\s*:\s*/\s*/)?
    t\s*\.?\s*m\s*e\s*/\s*
    (?P<uname>[A-Za-z0-9_\+\s\u200b\u200c\u200d\u2060\uFEFF-]{1,64})
    """,
    re.IGNORECASE | re.VERBOSE,
)

MENTION_PATTERN_FLEX = re.compile(
    r"""
    @\s*
    (?P<uname>[A-Za-z0-9_\s\u200b\u200c\u200d\u2060\uFEFF-]{1,64})
    """,
    re.IGNORECASE | re.VERBOSE,
)

# =======================
# Text normalization against obfuscation
# =======================

MULTI_REPL: List[Tuple[str, str]] = [("rn", "m")]

CHAR_MAP: Dict[str, str] = {
    # Latin & Cyrillic pairs and common lookalikes
    "а": "a", "А": "a", "a": "a", "A": "a",
    "б": "b", "Б": "b",
    "в": "v", "В": "v",
    "c": "c", "C": "c", "с": "c", "С": "c",
    "д": "d", "Д": "d", "d": "d", "D": "d",
    "е": "e", "Е": "e", "e": "e", "E": "e", "€": "e", "3": "e",
    "ф": "f", "Ф": "f", "f": "f", "F": "f",
    "g": "g", "G": "g", "г": "g", "Г": "g", "6": "g", "9": "g",
    "h": "h", "H": "h",
    "i": "i", "I": "i", "і": "i", "І": "i", "l": "i", "ı": "i", "ɪ": "i", "|": "i", "!": "i", "1": "i", "Ӏ": "i",
    "j": "j", "J": "j",
    "k": "k", "K": "k", "к": "k", "К": "k",
    "l": "l", "L": "l",
    "m": "m", "M": "m", "м": "m", "М": "m",
    "n": "n", "N": "n", "н": "n", "Н": "n",
    "o": "o", "O": "o", "о": "o", "О": "o", "0": "o",
    "p": "p", "P": "p", "р": "p", "Р": "p",
    "q": "q", "Q": "q",
    "r": "r", "R": "r",
    "s": "s", "S": "s", "$": "s", "5": "s", "ш": "sh", "Ш": "sh", "щ": "shch", "Щ": "shch",
    "t": "t", "T": "t", "т": "t", "Т": "t", "+": "plus",
    "u": "u", "U": "u", "ю": "yu", "Ю": "yu",
    "v": "v", "V": "v",
    "w": "w", "W": "w",
    "x": "x", "X": "x", "х": "x", "Х": "x",
    "y": "y", "Y": "y", "у": "y", "У": "y", "й": "y", "Й": "y",
    "z": "z", "Z": "z", "з": "z", "З": "z", "2": "z",
    "/": "slash", "\\": "slash",
    "ь": "", "Ь": "", "ъ": "", "Ъ": "",
    "ё": "e", "Ё": "e", "я": "ya", "Я": "ya",
}

SEP_CHARS: Set[str] = {
    " ", "\t", "\n", "\r",
    "-", "_", ".", ",", ":", ";", "'", '"', "`", "´", "’", "“", "”", "«", "»",
    "(", ")", "[", "]", "{", "}", "<", ">",
    "~", "=", "–", "—", "•", "·",
    "?", "@", "#", "%", "^", "&", "*",
}
ZERO_WIDTH_CATEGORIES = {"Cf"}

_WORD_CHARS_CLASS = r"[a-z0-9/+]"

MORPH_TAILS: Dict[str, str] = {
    "konkurs": r"(?:a|e|u|y|om|ov|am|ah|ami|akh|y|i)?",
}

def _strip_diacritics(s: str) -> str:
    nfkd = unicodedata.normalize("NFKD", s)
    return "".join(ch for ch in nfkd if not unicodedata.combining(ch))

def normalize_for_match(s: str) -> str:
    if not s:
        return ""
    s = _strip_diacritics(s.casefold())
    for a, b in MULTI_REPL:
        s = s.replace(a, b)

    out: List[str] = []
    last_was_space = False
    for ch in s:
        cat = unicodedata.category(ch)
        if cat in ZERO_WIDTH_CATEGORIES:
            continue
        if ch in SEP_CHARS or cat.startswith("Z") or cat.startswith("P"):
            if not last_was_space:
                out.append(" ")
                last_was_space = True
            continue
        mapped = CHAR_MAP.get(ch, ch)
        if mapped == "":
            continue
        out.append(mapped)
        last_was_space = (mapped == " ")

    s2 = "".join(out)
    s2 = s2.replace("slash", "/").replace("plus", "+")
    s2 = re.sub(r"\s+", " ", s2).strip()
    s2 = "".join(c for c in s2 if c.isalnum() or c in "/+ ")
    return s2

def _word_boundary_pattern(nw: str) -> str:
    strict_token = len(nw) <= 3 and re.fullmatch(r"[a-z0-9]+", nw) is not None
    tail = MORPH_TAILS.get(nw, "")
    core = re.escape(nw) + (tail if tail else "")
    if strict_token:
        return rf"(?<!{_WORD_CHARS_CLASS}){core}(?!{_WORD_CHARS_CLASS})"
    return rf"(?<!{_WORD_CHARS_CLASS}){core}(?!{_WORD_CHARS_CLASS})"

# =======================
# GLOBAL forbidden words I/O
# =======================

def load_global_words() -> List[str]:
    words: List[str] = []
    try:
        with GLOBAL_WORDS_FILE.open("r", encoding="utf-8") as f:
            for line in f:
                t = line.strip()
                if not t or t.startswith("#"):
                    continue
                words.append(t)
    except Exception as e:
        logger.warning("Failed reading %s: %s", GLOBAL_WORDS_FILE, e)
    if DEBUG_MATCH:
        logger.debug("Loaded %d words from global list", len(words))
    return words

def save_global_words(words: Iterable[str]) -> None:
    dedup = sorted(set(w.strip() for w in words if w.strip()), key=str.casefold)
    try:
        with GLOBAL_WORDS_FILE.open("w", encoding="utf-8") as f:
            for w in dedup:
                f.write(w + "\n")
    except Exception as e:
        logger.error("Failed writing %s: %s", GLOBAL_WORDS_FILE, e)

def contains_forbidden(text: str) -> bool:
    norm_text = normalize_for_match(text)
    if not norm_text:
        return False
    for w in load_global_words():
        nw = normalize_for_match(w)
        if not nw:
            continue
        pat = _word_boundary_pattern(nw)
        if DEBUG_MATCH:
            logger.debug("Check word '%s' → '%s' with pattern %s", w, nw, pat)
            logger.debug("Normalized text: '%s'", norm_text)
        if re.search(pat, norm_text):
            if DEBUG_MATCH:
                logger.debug("Matched word '%s' in text '%s'", w, norm_text[:120])
            return True
    return False

# =======================
# Link / mention checks
# =======================

def _clean_uname(uname_raw: str) -> str:
    cleaned = "".join(
        ch for ch in uname_raw
        if unicodedata.category(ch) not in ZERO_WIDTH_CATEGORIES and not ch.isspace()
    )
    return cleaned

def contains_valid_link(text: str) -> bool:
    if not DELETE_LINKS or not text:
        return False
    for m in URL_PATTERN_FLEX.finditer(text):
        raw = m.group("uname") or ""
        uname = _clean_uname(raw)
        if USERNAME_REGEX.fullmatch(uname or ""):
            return True
    for m in MENTION_PATTERN_FLEX.finditer(text):
        raw = m.group("uname") or ""
        uname = _clean_uname(raw)
        if USERNAME_REGEX.fullmatch(uname or ""):
            return True
    return False

# =======================
# Permissions helpers
# =======================

def _check_allowed_chat(chat_id: int) -> bool:
    return not ALLOWED_CHAT_IDS or chat_id in ALLOWED_CHAT_IDS

def _is_private(update: Update) -> bool:
    chat = update.effective_chat
    return bool(chat and chat.type == Chat.PRIVATE)

def _is_admin(update: Update) -> bool:
    user = update.effective_user
    return bool(user and user.id in ADMIN_USER_IDS)

async def _require_admin_in_dm(update: Update) -> bool:
    if not _is_private(update):
        await update.effective_message.reply_text(
            "Эта команда доступна только в личном чате с ботом. "
            "Откройте ЛС с ботом и повторите команду."
        )
        return False
    if not _is_admin(update):
        await update.effective_message.reply_text(
            "Недостаточно прав: эта команда доступна только администраторам бота."
        )
        return False
    return True

# =======================
# Handlers (ALL admin-in-DM only)
# =======================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin_in_dm(update):
        return
    await update.effective_message.reply_text(
        "Привет! Я антиспам-бот.\n\n"
        "Удаляю:\n"
        "• t.me / @username (в т.ч. «рассыпанные»)\n"
        "• слова из ГЛОБАЛЬНОГО чёрного списка (для всех чатов)\n\n"
        "Белый список:\n"
        "• BYPASS_USER_IDS — user.id\n"
        "• BYPASS_SENDER_CHAT_IDS — sender_chat.id (каналы/анонимные админы)\n\n"
        "Команды (только ЛС и только для админов):\n"
        "/badwords — показать глобальный список\n"
        "/addbad слово1; слово2 — добавить\n"
        "/delbad слово1; слово2 — удалить\n"
        "/clearbad — очистить\n"
        "/whoami — показать ваш Telegram ID\n"
        "\nПодробные логи: ANTISPAM_DEBUG=1"
    )

async def whoami_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin_in_dm(update):
        return
    user = update.effective_user
    await update.effective_message.reply_text(f"Ваш Telegram ID: {user.id if user else 'неизвестен'}")

async def badwords_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin_in_dm(update):
        return
    words = load_global_words()
    if not words:
        await update.effective_message.reply_text(
            "Глобальный список пуст. Добавьте слова командой:\n/addbad слово1; слово2"
        )
        return
    out = []
    limit = 200
    for i, w in enumerate(words, 1):
        if i <= limit:
            out.append(f"• {w}")
    extra = len(words) - limit
    if extra > 0:
        out.append(f"… и ещё {extra}")
    await update.effective_message.reply_text("\n".join(out))

def _split_semicolon_arg(text: str) -> List[str]:
    if not text:
        return []
    parts = text.split(" ", 1)
    if len(parts) < 2:
        return []
    payload = parts[1]
    items = []
    for piece in re.split(r"[;\n]", payload):
        t = piece.strip()
        if t:
            items.append(t)
    return items

async def addbad_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin_in_dm(update):
        return
    args = _split_semicolon_arg(update.effective_message.text or "")
    if not args:
        await update.effective_message.reply_text(
            "Укажите слова через ';' после команды.\nПример:\n/addbad конкурс; rosigricb"
        )
        return
    current = load_global_words()
    new_set = set(current)
    before = len(new_set)
    for a in args:
        new_set.add(a)
    save_global_words(new_set)
    added = len(new_set) - before
    await update.effective_message.reply_text(
        f"Добавлено: {added}. В глобальном списке сейчас: {len(new_set)}."
    )

async def delbad_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin_in_dm(update):
        return
    args = _split_semicolon_arg(update.effective_message.text or "")
    if not args:
        await update.effective_message.reply_text(
            "Укажите слова через ';' после команды.\nПример:\n/delbad конкурс; rosigricb"
        )
        return
    current = load_global_words()
    cur_set = set(current)
    before = len(cur_set)
    for a in args:
        cur_set.discard(a)
    save_global_words(cur_set)
    deleted = before - len(cur_set)
    await update.effective_message.reply_text(
        f"Удалено: {deleted}. В глобальном списке осталось: {len(cur_set)}."
    )

async def clearbad_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin_in_dm(update):
        return
    save_global_words([])
    await update.effective_message.reply_text("Глобальный список очищен.")

# =======================
# Message filter
# =======================

def _is_bypassed(msg) -> bool:
    """Return True if author is in bypass whitelist."""
    uid = getattr(getattr(msg, "from_user", None), "id", None)
    scid = getattr(getattr(msg, "sender_chat", None), "id", None)
    if uid in BYPASS_USER_IDS:
        return True
    if scid in BYPASS_SENDER_CHAT_IDS:
        return True
    return False

async def check_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = update.effective_message
    if not msg:
        return

    # BYPASS: do not touch messages from whitelisted authors
    if _is_bypassed(msg):
        if DEBUG_MATCH:
            logger.debug("Bypass author: user_id=%s sender_chat_id=%s", 
                         getattr(getattr(msg, 'from_user', None), 'id', None),
                         getattr(getattr(msg, 'sender_chat', None), 'id', None))
        return

    text = msg.text or msg.caption
    if not text:
        return

    chat = update.effective_chat
    if not chat:
        return

    chat_id = chat.id
    if not _check_allowed_chat(chat_id):
        if DEBUG_MATCH:
            logger.debug("Chat %s not in whitelist, skipping", chat_id)
        return

    try_delete = False
    reasons: List[str] = []

    if contains_valid_link(text):
        try_delete = True
        reasons.append("link")

    if contains_forbidden(text):
        try_delete = True
        reasons.append("list")

    if try_delete:
        reason = "+".join(reasons)
        try:
            await msg.delete()
        except Exception as e:
            logger.warning("Failed to delete message in chat %s: %s", chat_id, e)

        user = msg.from_user
        sender_chat = msg.sender_chat
        uname = (
            f"@{user.username}" if user and user.username
            else (f"id:{user.id}" if user else "id:unknown")
        )
        # add sender_chat info (for channels / anonymous admins)
        if sender_chat:
            uname = f"{uname} (sender_chat:{sender_chat.title or sender_chat.username or sender_chat.id})"

        snippet = (text or "").replace("\n", " ")[:500]
        # Detailed IDs for easier whitelisting:
        uid = user.id if user else None
        scid = sender_chat.id if sender_chat else None
        extra_ids = f"user_id={uid} sender_chat_id={scid}"

        spam_logger.info(f"{uname} | {snippet} | {extra_ids} | reason={reason}")
        logger.info("Deleted in chat %s from %s | %s | reason=%s",
                    chat_id, uname, extra_ids, reason)

# =======================
# Main
# =======================

def main() -> None:
    if not BOT_TOKEN or BOT_TOKEN == "PUT_YOUR_TOKEN_HERE":
        raise RuntimeError("Set TELEGRAM_TOKEN env var (do not hardcode your token in code).")
    if not ADMIN_USER_IDS:
        logger.warning("ADMIN_USER_IDS is empty: nobody can use bot commands.")
    if not ALLOWED_CHAT_IDS:
        logger.warning("ALLOWED_CHAT_IDS is empty: bot will moderate ANY chat it is added to.")
    if not BYPASS_SENDER_CHAT_IDS:
        logger.warning("BYPASS_SENDER_CHAT_IDS is empty: posts sent on behalf of your channels may be deleted.")

    app = Application.builder().token(BOT_TOKEN).build()

    # Commands (ALL restricted by _require_admin_in_dm)
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("whoami", whoami_cmd))
    app.add_handler(CommandHandler("badwords", badwords_cmd))
    app.add_handler(CommandHandler("addbad", addbad_cmd))
    app.add_handler(CommandHandler("delbad", delbad_cmd))
    app.add_handler(CommandHandler("clearbad", clearbad_cmd))

    # Messages
    app.add_handler(MessageHandler(filters.ALL, check_message))

    logger.info("Bot is running. Press Ctrl+C to stop.")
    app.run_polling(allowed_updates=None)

if __name__ == "__main__":
    main()
