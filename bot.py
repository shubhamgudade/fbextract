from __future__ import annotations

import os
import re
import io
import json
import zipfile
import tempfile
import asyncio
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    filters,
    ContextTypes,
)

BOT_TOKEN = "8610317840:AAGOmZ3yPgqxxt-h1aLTyHOBf4RkPpyO90I"
BATCH_SIZE = 100
PROGRESS_INTERVAL = 10
SCAN_TIMEOUT = 120

FIREBASE_URL_RE = re.compile(
    r"https://[a-z0-9_-]+\.(?:firebaseio\.com|firebasedatabase\.app)",
    re.IGNORECASE,
)
API_KEY_RE = re.compile(r"AIza[A-Za-z0-9_-]{35}")

EXECUTOR = ThreadPoolExecutor(max_workers=8)
chat_state = defaultdict(lambda: {"queue": [], "queue_msg_id": None})

# store failed items per chat so retry/resend can access them
# key: chat_id, value: list of {"file_id": ..., "file_name": ...}
failed_store: dict[int, list] = defaultdict(list)


def extract_from_apk_bytes(data):
    fb_url = ""
    api_keys = []
    project_id = ""
    app_id = ""

    def add_key(k):
        k = k.strip()
        if k and k not in api_keys:
            api_keys.append(k)

    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            names = set(zf.namelist())

            if "resources.arsc" in names:
                text = zf.read("resources.arsc").decode("latin-1", errors="replace")
                u = FIREBASE_URL_RE.search(text)
                k = API_KEY_RE.search(text)
                if u:
                    fb_url = fb_url or u.group(0)
                if k:
                    add_key(k.group(0))

            for dex in ["classes.dex", "classes2.dex", "classes3.dex", "classes4.dex"]:
                if fb_url and api_keys:
                    break
                if dex in names:
                    text = zf.read(dex).decode("latin-1", errors="replace")
                    u = FIREBASE_URL_RE.search(text)
                    k = API_KEY_RE.search(text)
                    if u:
                        fb_url = fb_url or u.group(0)
                    if k:
                        add_key(k.group(0))

            gs_paths = [
                n for n in names
                if n == "google-services.json"
                or n == "assets/google-services.json"
                or n.endswith("/google-services.json")
            ]
            for path in gs_paths:
                try:
                    gs = json.loads(zf.read(path).decode("utf-8", errors="replace"))
                    pi = gs.get("project_info", {})
                    fb_url = fb_url or pi.get("firebase_url", "")
                    project_id = project_id or pi.get("project_id", "")
                    clients = gs.get("client", [])
                    if clients:
                        c = clients[0]
                        for entry in c.get("api_key", []):
                            ck = entry.get("current_key", "").strip()
                            if ck:
                                add_key(ck)
                        app_id = app_id or c.get("client_info", {}).get("mobilesdk_app_id", "")
                        for oc in c.get("oauth_client", []):
                            ck = oc.get("client_id", "").strip()
                            if ck:
                                add_key(ck)
                except Exception:
                    pass

            if not fb_url or not api_keys:
                for name in names:
                    if fb_url and api_keys:
                        break
                    try:
                        if zf.getinfo(name).is_dir():
                            continue
                        text = zf.read(name).decode("latin-1", errors="replace")
                        u = FIREBASE_URL_RE.search(text)
                        k = API_KEY_RE.search(text)
                        if u:
                            fb_url = fb_url or u.group(0)
                        if k:
                            add_key(k.group(0))
                    except Exception:
                        pass

    except zipfile.BadZipFile:
        return None

    if not fb_url:
        return None
    if not api_keys:
        api_keys = [""]

    return {
        "firebaseUrl": fb_url,
        "apiKeys": api_keys,
        "projectId": project_id,
        "appId": app_id,
    }


def url_to_name(url):
    host = url.split("//")[-1].split(".")[0]
    parts = host.replace("-", " ").split()
    return " ".join(p.capitalize() for p in parts)


def build_progress_bar(done, total, width=20):
    filled = int(width * done / total) if total else 0
    bar = "█" * filled + "░" * (width - filled)
    pct = int(100 * done / total) if total else 0
    return f"[{bar}] {pct}% ({done}/{total})"


def build_queue_text(queue):
    count = len(queue)
    remaining = BATCH_SIZE - count
    lines = [f"📋 Queue: {count}/{BATCH_SIZE} — {remaining} more to auto-process\n"]
    for i, item in enumerate(queue, 1):
        lines.append(f"  {i}. `{item['file_name']}`")
    return "\n".join(lines)


async def update_queue_message(chat_id, ctx, state):
    text = build_queue_text(state["queue"])
    msg_id = state.get("queue_msg_id")
    if msg_id:
        try:
            await ctx.bot.edit_message_text(
                text,
                chat_id=chat_id,
                message_id=msg_id,
                parse_mode="Markdown",
            )
            return
        except Exception:
            pass
    msg = await ctx.bot.send_message(chat_id, text, parse_mode="Markdown")
    state["queue_msg_id"] = msg.message_id


async def send_json_snapshot(chat_id, ctx, results, label):
    accounts = [
        {"name": d["name"], "url": d["url"], "key": d["keys"], "time": d["time"]}
        for d in results.values()
    ]
    output = {"accounts": accounts, "total": len(accounts)}
    output_json = json.dumps(output, indent=2, ensure_ascii=False)

    if len(output_json) < 3500:
        await ctx.bot.send_message(
            chat_id,
            f"📊 *{label}*\n```json\n{output_json}\n```",
            parse_mode="Markdown",
        )
    else:
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False, encoding="utf-8"
        ) as f:
            f.write(output_json)
            tmp_path = f.name
        with open(tmp_path, "rb") as f:
            await ctx.bot.send_document(
                chat_id,
                document=f,
                filename=f"firebase_{label.lower().replace(' ', '_')}.json",
                caption=f"📊 {label} — {len(accounts)} unique configs.",
            )
        os.unlink(tmp_path)


async def process_batch(chat_id, ctx, batch):
    total = len(batch)
    state = chat_state[chat_id]

    # clear queue message
    if state.get("queue_msg_id"):
        try:
            await ctx.bot.delete_message(chat_id, state["queue_msg_id"])
        except Exception:
            pass
        state["queue_msg_id"] = None

    progress_msg = await ctx.bot.send_message(
        chat_id,
        f"⚙️ Starting scan of {total} APKs...\n{build_progress_bar(0, total)}",
    )

    results = {}
    failed_items = []   # list of {"file_id", "file_name", "reason"}
    true_dupes = []
    done_count = 0
    last_snapshot_at = 0

    loop = asyncio.get_event_loop()
    semaphore = asyncio.Semaphore(10)
    lock = asyncio.Lock()
    now = datetime.now().strftime("%d/%m/%Y, %H:%M:%S")

    async def fetch_and_scan(item):
        nonlocal done_count, last_snapshot_at

        fname = item["file_name"]
        result = None
        fail_reason = None

        async with semaphore:
            # show: downloading
            try:
                await ctx.bot.edit_message_text(
                    f"⚙️ Scanning {total} APKs...\n"
                    f"{build_progress_bar(done_count, total)}\n"
                    f"📥 Downloading: `{fname}`\n"
                    f"✅ Found: {len(results)} | ❌ Failed: {len(failed_items)}",
                    chat_id=chat_id,
                    message_id=progress_msg.message_id,
                    parse_mode="Markdown",
                )
            except Exception:
                pass

            try:
                # no timeout on download
                tg_file = await ctx.bot.get_file(item["file_id"])
                data = bytes(await tg_file.download_as_bytearray())
            except Exception as e:
                fail_reason = f"download error: {e}"
                async with lock:
                    failed_items.append({
                        "file_id": item["file_id"],
                        "file_name": fname,
                        "reason": fail_reason,
                    })
                async with lock:
                    done_count += 1
                return

            # show: processing
            try:
                await ctx.bot.edit_message_text(
                    f"⚙️ Scanning {total} APKs...\n"
                    f"{build_progress_bar(done_count, total)}\n"
                    f"🔍 Processing: `{fname}`\n"
                    f"✅ Found: {len(results)} | ❌ Failed: {len(failed_items)}",
                    chat_id=chat_id,
                    message_id=progress_msg.message_id,
                    parse_mode="Markdown",
                )
            except Exception:
                pass

            try:
                result = await asyncio.wait_for(
                    loop.run_in_executor(EXECUTOR, extract_from_apk_bytes, data),
                    timeout=SCAN_TIMEOUT,
                )
            except asyncio.TimeoutError:
                fail_reason = "scan timeout (120s)"
            except Exception as e:
                fail_reason = f"scan error: {e}"

            if fail_reason:
                async with lock:
                    failed_items.append({
                        "file_id": item["file_id"],
                        "file_name": fname,
                        "reason": fail_reason,
                    })

        snapshot_results = None
        snapshot_label = None
        current_done = 0

        async with lock:
            if result is None:
                if fail_reason is None:
                    failed_items.append({
                        "file_id": item["file_id"],
                        "file_name": fname,
                        "reason": "no Firebase config found",
                    })
            else:
                fb_url_raw = result["firebaseUrl"].rstrip("/")
                fb_url_key = fb_url_raw.lower()
                found_keys = result["apiKeys"]

                if fb_url_key in results:
                    existing = results[fb_url_key]
                    new_keys = [k for k in found_keys if k not in existing["keys"]]
                    if not new_keys:
                        true_dupes.append(fname)
                    else:
                        existing["keys"].extend(new_keys)
                        existing["source_files"].append(fname)
                else:
                    results[fb_url_key] = {
                        "name": url_to_name(fb_url_raw),
                        "url": fb_url_raw,
                        "keys": list(found_keys),
                        "time": now,
                        "source_files": [fname],
                    }

            done_count += 1
            current_done = done_count

            should_snapshot = (
                current_done - last_snapshot_at >= PROGRESS_INTERVAL
                and current_done < total
            )
            if should_snapshot:
                last_snapshot_at = current_done
                snapshot_results = dict(results)
                snapshot_label = f"Snapshot at {current_done}/{total}"

        # update progress after finishing this APK
        try:
            await ctx.bot.edit_message_text(
                f"⚙️ Scanning {total} APKs...\n"
                f"{build_progress_bar(current_done, total)}\n"
                f"✅ Done: `{fname}`\n"
                f"✅ Found: {len(results)} | ❌ Failed: {len(failed_items)}",
                chat_id=chat_id,
                message_id=progress_msg.message_id,
                parse_mode="Markdown",
            )
        except Exception:
            pass

        if snapshot_results is not None:
            await send_json_snapshot(chat_id, ctx, snapshot_results, snapshot_label)

    tasks = [fetch_and_scan(item) for item in batch]
    await asyncio.gather(*tasks)

    # final progress
    try:
        await ctx.bot.edit_message_text(
            f"✅ Done! {build_progress_bar(total, total)}\n"
            f"Unique: {len(results)} | Failed: {len(failed_items)} | Dupes: {len(true_dupes)}",
            chat_id=chat_id,
            message_id=progress_msg.message_id,
        )
    except Exception:
        pass

    await send_json_snapshot(chat_id, ctx, results, f"Final — {total} APKs")

    # handle failed items
    if failed_items:
        # store them for retry/resend
        failed_store[chat_id] = failed_items

        lines = [f"• `{x['file_name']}` — {x['reason']}" for x in failed_items[:50]]
        if len(failed_items) > 50:
            lines.append(f"_...and {len(failed_items) - 50} more_")

        fail_text = f"⚠️ *{len(failed_items)} Failed:*\n" + "\n".join(lines)

        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("🔄 Retry failed", callback_data=f"retry:{chat_id}"),
                InlineKeyboardButton("📤 Send APKs back", callback_data=f"resend:{chat_id}"),
            ]
        ])

        await ctx.bot.send_message(
            chat_id,
            fail_text,
            parse_mode="Markdown",
            reply_markup=keyboard,
        )

    if true_dupes:
        dupe_text = "🔁 *Duplicates:*\n" + "\n".join(f"• `{x}`" for x in true_dupes[:30])
        if len(true_dupes) > 30:
            dupe_text += f"\n_{len(true_dupes) - 30} more..._"
        await ctx.bot.send_message(chat_id, dupe_text, parse_mode="Markdown")


async def handle_callback(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    data = query.data
    action, chat_id_str = data.split(":", 1)
    chat_id = int(chat_id_str)

    items = failed_store.get(chat_id, [])
    if not items:
        await query.edit_message_reply_markup(reply_markup=None)
        await ctx.bot.send_message(chat_id, "No failed APKs stored.")
        return

    if action == "retry":
        await query.edit_message_reply_markup(reply_markup=None)
        failed_store[chat_id] = []
        await ctx.bot.send_message(chat_id, f"🔄 Retrying {len(items)} failed APKs...")
        # strip reason, keep file_id + file_name
        batch = [{"file_id": x["file_id"], "file_name": x["file_name"]} for x in items]
        await process_batch(chat_id, ctx, batch)

    elif action == "resend":
        await query.edit_message_reply_markup(reply_markup=None)
        await ctx.bot.send_message(chat_id, f"📤 Sending back {len(items)} APKs...")
        for item in items:
            try:
                await ctx.bot.send_document(
                    chat_id,
                    document=item["file_id"],
                    caption=f"`{item['file_name']}` — {item['reason']}",
                    parse_mode="Markdown",
                )
            except Exception as e:
                await ctx.bot.send_message(
                    chat_id,
                    f"⚠️ Failed to resend `{item['file_name']}`: {e}",
                    parse_mode="Markdown",
                )


async def start(update, ctx):
    await update.message.reply_text(
        f"👋 Send APK files one by one.\n"
        f"Queue updates in a single message. Auto-fires at {BATCH_SIZE}.\n\n"
        f"/flush — process now\n"
        f"/status — queue size\n"
        f"/clear — wipe queue"
    )


async def handle_document(update, ctx):
    doc = update.message.document
    fname = doc.file_name or "unknown.apk"
    chat_id = update.effective_chat.id

    if not fname.lower().endswith((".apk", ".zip")):
        await update.message.reply_text("⚠️ Only .apk files are supported.")
        return

    try:
        await ctx.bot.delete_message(chat_id, update.message.message_id)
    except Exception:
        pass

    state = chat_state[chat_id]
    state["queue"].append({"file_id": doc.file_id, "file_name": fname})
    count = len(state["queue"])

    if count < BATCH_SIZE:
        await update_queue_message(chat_id, ctx, state)
        return

    batch = state["queue"][:BATCH_SIZE]
    state["queue"] = state["queue"][BATCH_SIZE:]
    await process_batch(chat_id, ctx, batch)

    if state["queue"]:
        await update_queue_message(chat_id, ctx, state)


async def flush(update, ctx):
    chat_id = update.effective_chat.id
    state = chat_state[chat_id]
    if not state["queue"]:
        await update.message.reply_text("Queue is empty.")
        return
    batch = state["queue"][:]
    state["queue"] = []
    await update.message.reply_text(f"🚀 Force-processing {len(batch)} APKs...")
    await process_batch(chat_id, ctx, batch)


async def status(update, ctx):
    chat_id = update.effective_chat.id
    count = len(chat_state[chat_id]["queue"])
    await update.message.reply_text(
        f"📋 Queue: {count}/{BATCH_SIZE}. Need {max(0, BATCH_SIZE - count)} more."
    )


async def clear(update, ctx):
    chat_id = update.effective_chat.id
    state = chat_state[chat_id]
    state["queue"] = []
    state["queue_msg_id"] = None
    await update.message.reply_text("🗑️ Queue cleared.")


def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("flush", flush))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(CommandHandler("clear", clear))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.add_handler(CallbackQueryHandler(handle_callback))
    print("Bot is running...")
    app.run_polling()


if __name__ == "__main__":
    main()
