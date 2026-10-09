# antispam_channel_bot

Telegram anti-spam bot for groups and channel discussion chats. It deletes messages that
contain Telegram links or @mentions, or words from a global blocklist. Admins manage the
blocklist through commands in a private chat with the bot.

The bot's replies are in Russian.

## Features

- **Link and mention removal**: deletes messages containing `t.me/<name>` links or
  `@username` mentions, including obfuscated forms with spaces or zero-width characters
  (for example `t . me / name`, `@ name`). Text and media captions are both checked.
- **Global blocklist**: one word list shared by all chats, stored in
  `data/forbidden_words.txt`. Matching normalizes text against common obfuscation:
  Cyrillic/Latin look-alike letters, digits used as letters, diacritics, separators and
  zero-width characters.
- **Chat whitelist**: when `ALLOWED_CHAT_IDS` is set, only those chats are moderated.
- **Bypass lists**: messages from `BYPASS_USER_IDS` (plus 777000, Telegram service
  notifications) and from sender chats in `BYPASS_SENDER_CHAT_IDS` are never deleted.
- **Deletion log**: every deletion is appended to `spam.log` with the author, user and
  sender-chat IDs, a text snippet and the reason (`link`, `list` or both).
- **Admin-only commands**: all commands work only in a private chat and only for
  `ADMIN_USER_IDS`.

## Tech Stack

- Python 3
- [python-telegram-bot](https://python-telegram-bot.org/) v20+ (checked with 22.8)
- python-dotenv (optional, for loading `.env`)

## Requirements

- Python 3.8 or newer for the code itself. Recent python-telegram-bot releases may need
  a newer Python.
- A Telegram bot token from [@BotFather](https://t.me/BotFather)
- The bot must be an administrator with the "Delete messages" right in moderated chats.
  To see all group messages, either disable privacy mode in BotFather or make the bot an admin.

## Installation

```bash
git clone <repository-url>
cd antispam_channel_bot
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env   # then edit .env
```

## Configuration

Settings are read from environment variables. If python-dotenv is installed, they are
also loaded from `.env` next to `antispamV2.py`. IDs may be separated by commas, spaces,
`;` or newlines.

| Variable | Description |
|---|---|
| `TELEGRAM_TOKEN` | Bot token (required) |
| `ALLOWED_CHAT_IDS` | Chats to moderate. **If empty, the bot moderates every chat it is in** |
| `ADMIN_USER_IDS` | Users allowed to run commands. If empty, nobody can |
| `BYPASS_USER_IDS` | Extra users whose messages are never deleted (777000 is always included) |
| `BYPASS_SENDER_CHAT_IDS` | Channels/chats whose posts (`sender_chat`) are never deleted, e.g. your own channel |
| `ANTISPAM_DEBUG` | `1` enables verbose matching logs |

At startup the bot logs a warning if `ADMIN_USER_IDS`, `ALLOWED_CHAT_IDS` or
`BYPASS_SENDER_CHAT_IDS` is empty.

## Usage

```bash
python antispamV2.py
```

Commands (private chat, admins only):

| Command | Action |
|---|---|
| `/start` | Short help |
| `/badwords` | Show the global blocklist (first 200 entries) |
| `/addbad word1; word2` | Add words |
| `/delbad word1; word2` | Remove words |
| `/clearbad` | Clear the list |
| `/whoami` | Show your Telegram ID |

## Notes

- `data/` and `spam.log` are created next to the script at startup. They hold runtime data
  (the blocklist and logged message text) and are excluded from Git.
- There is no automated test suite.

## License

Copyright 2026 berlonak. Licensed under the [Apache License, Version 2.0](LICENSE).
