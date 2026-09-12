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
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes,
)

BOT_TOKEN = "8610317840:AAG7w-evFhK1QIzxmgA-tMDlb-BA35mhVSA"
BATCH_SIZE = 100
PROGRESS_INTERVAL = 10  # send json snapshot every N processed

FIREBASE_URL_RE = re.compile(
    r"https://[a-z0-9_-]+\.(?:firebaseio\.com|firebasedatabase\.app)",
    re.IGNORECASE,
)
API_KEY_RE = re.compile(r"AIza[A-Za-z0-9_-]{35}")

EXECUTOR = ThreadPoolExecutor(max_workers=8)
chat_state: dict[int, dict] = defaultdict(lambda: {"queue": []})


# ─── APK scanning ─────────────────────────────────────────────────────────────

def extract_from_apk_bytes(data: bytes) -> dict | None:
    fb_url = ""
    api_keys: list[str] = []
    project_id = ""
    app_id = ""

    def add_key(k: str):
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
                if u: fb_url = fb_url or u.group(0)
                if k: add_key(k.group(0))

            for dex in ["classes.dex", "classes2.dex", "classes3.dex", "classes4.dex"]:
                if fb_url and api_keys:
                    break
                if dex in names:
                    text = zf.read(dex).decode("latin-1", errors="replace")
                    u = FIREBASE_URL_RE.search(text)
                    k = API_KEY_RE.search(text)
                    if u: fb_url = fb_url or u.group(0)
                    if k: add_key(k.group(0))

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
                            if ck: add_key(ck)
                        app_id = app_id or c.get("client_info", {}).get("mobilesdk_app_id", "")
                        for oc in c.get("oauth_client", []):
                            ck = oc.get("client_id", "").strip()
                            if ck: add_key(ck)
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
                        if u: fb_url = fb_url or u.group(0)
                        if k: add_key(k.group(0))
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


def url_to_name(url: str) -> str:
    host = url.split("//")[-1].split(".")[0]
    parts = host.replace("-", " ").split()
    return " ".join(p.capitalize() for p in parts)


def build_progress_bar(done: int, total: int, width: int = 20) -> str:
    filled = int(width * done / total) if total else 0
    bar = "█" * filled + "░" * (width - filled)
    pct = int(100 * done / total) if total else 0
    return f"[{bar}] {pct}% ({done}/{total})"


async def send_json_snapshot(
    chat_id: int,
    ctx: ContextTypes.DEFAULT_TYPE,
    results: dict,
    label: str,
):
    accounts = [
        {
            "name": d["name"],
            "url": d["url"],
            "key": d["keys"],
            "time": d["time"],
        }
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
                caption=f"📊 {label} — {len(accounts)} unique configs so far.",
            )
        os.unlink(tmp_path)


# ─── Batch processor ──────────────────────────────────────────────────────────

async def process_batch(
    chat_id: int,
    ctx: ContextTypes.DEFAULT_TYPE,
    batch: list[dict],
):
    total = len(batch)

    # Single progress message — we'll keep editing this one
    progress_msg = await ctx.bot.send_message(
        chat_id,
        f"⚙️ Starting scan of {total} APKs...\n{build_progress_bar(0, total)}",
    )

    results: dict[str, dict] = {}
    failed: list[str] = []
    true_dupes: list[str] = []
    done_count = 0
    last_snapshot_at = 0  # track when we last sent a snapshot

    loop = asyncio.get_event_loop()
    semaphore = asyncio.Semaphore(10)
    now = datetime.now().strftime("%d/%m/%Y, %H:%M:%S")

    # Lock so concurrent completions don't race on done_count / results
    lock = asyncio.Lock()

    async def fetch_and_scan(item: dict):
        nonlocal done_count, last_snapshot_at

        async with semaphore:
            result = None
            try:
                tg_file = await ctx.bot.get_file(item["file_id"])
                data = bytes(await tg_file.download_as_bytearray())
                result = await loop.run_in_executor(
                    EXECUTOR, extract_from_apk_bytes, data
                )
            except Exception as e:
                async with lock:
                    failed.append(f"{item['file_name']} (error: {e})")

        async with lock:
            fname = item["file_name"]

            if result is None:
                if not any(fname in f for f in failed):
                    failed.append(f"{fname} (no Firebase config found)")
            else:
                fb_url_raw = result["firebaseUrl"].rstrip("/")
                fb_url_key = fb_url_raw.lower()
                found_keys: list[str] = result["apiKeys"]

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
            current_results_snapshot = dict(results)  # shallow copy for snapshot
            should_snapshot = (
                current_done - last_snapshot_at >= PROGRESS_INTERVAL
                and current_done < total  # final snapshot sent separately
            )
            if should_snapshot:
                last_snapshot_at = current_done

        # Edit progress message (outside lock — non-critical)
        try:
            await ctx.bot.edit_message_text(
                f"⚙️ Scanning {total} APKs...\n{build_progress_bar(current_done, total)}\n"
                f"✅ Found: {len(current_results_snapshot)} unique configs | "
                f"❌ Failed: {len(failed)}",
                chat_id=chat_id,
                message_id=progress_msg.message_id,
            )
        except Exception:
            pass

        # Per-10 JSON snapshot (outside lock)
        if should_snapshot:
            await send_json_snapshot(
                chat_id,
                ctx,
                current_results_snapshot,
                f"Snapshot at {current_done}/{total}",
            )

    tasks = [fetch_and_scan(item) for item in batch]
    await asyncio.gather(*tasks)

    # ── Final progress edit ──
    try:
        await ctx.bot.edit_message_text(
            f"✅ Done! {build_progress_bar(total, total)}\n"
            f"Unique configs: {len(results)} | Failed: {len(failed)} | Dupes: {len(true_dupes)}",
            chat_id=chat_id,
            message_id=progress_msg.message_id,
        )
    except Exception:
        pass

    # ── Final JSON ──
    await send_json_snapshot(chat_id, ctx, results, f"Final — {total} APKs")

    if failed:
        fail_text = "⚠️ *Failed:*\n" + "\n".join(f"• `{x}`" for x in failed[:50])
        if len(failed) > 50:
            fail_text += f"\n_...and {len(failed) - 50} more_"
        await ctx.bot.send_message(chat_id, fail_text, parse_mode="Markdown")

    if true_dupes:
        dupe_text = (
            "🔁 *Duplicates* (same URL + keys already captured):\n"
            + "\n".join(f"• `{x}`" for x in true_dupes[:30])
        )
        if len(true_dupes) > 30:
            dupe_text += f"\n_...and {len(true_dupes) - 30} more_"
        await ctx.bot.send_message(chat_id, dupe_text, parse_mode="Markdown")


# ─── Handlers ─────────────────────────────────────────────────────────────────

async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        f"👋 Send me APK files one by one.\n"
        f"Auto-processes every {BATCH_SIZE} APKs. "
        f"Snapshots sent every {PROGRESS_INTERVAL} processed.\n\n"
        f"/flush — process queue now\n"
        f"/status — queue size\n"
        f"/clear — wipe queue"
    )


async def handle_document(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document
    fname = doc.file_name or "unknown.apk"
    chat_id = update.effective_chat.id

    if not fname.lower().endswith((".apk", ".zip")):
        await update.message.reply_text("⚠️ Only .apk files are supported.")
        return

    # Delete the user's APK message to keep chat clean
    try:
        await ctx.bot.delete_message(chat_id, update.message.message_id)
    except Exception:
        pass

    state = chat_state[chat_id]
    state["queue"].append({"file_id": doc.file_id, "file_name": fname})
    count = len(state["queue"])
    remaining = BATCH_SIZE - count

    if remaining > 0:
        # Single queue-status message — send fresh (no old message to edit)
        await ctx.bot.send_message(
            chat_id,
            f"📥 `{fname}` added. Queue: **{count}/{BATCH_SIZE}** — {remaining} more to auto-process.",
            parse_mode="Markdown",
        )
        return

    batch = state["queue"][:BATCH_SIZE]
    state["queue"] = state["queue"][BATCH_SIZE:]
    leftover = len(state["queue"])

    await ctx.bot.send_message(chat_id, f"✅ {BATCH_SIZE} APKs queued. Firing scan...")
    await process_batch(chat_id, ctx, batch)

    if leftover > 0:
        await ctx.bot.send_message(
            chat_id,
            f"📂 {leftover} APK(s) still queued. Send {BATCH_SIZE - leftover} more for next batch.",
        )


async def flush(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    state = chat_state[chat_id]
    if not state["queue"]:
        await update.message.reply_text("Queue is empty.")
        return
    batch = state["queue"][:]
    state["queue"] = []
    await update.message.reply_text(f"🚀 Force-processing {len(batch)} queued APKs...")
    await process_batch(chat_id, ctx, batch)


async def status(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    count = len(chat_state[chat_id]["queue"])
    await update.message.reply_text(
        f"📋 Queue: {count}/{BATCH_SIZE}. Need {max(0, BATCH_SIZE - count)} more to auto-process."
    )


async def clear(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    chat_state[chat_id]["queue"] = []
    await update.message.reply_text("🗑️ Queue cleared.")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("flush", flush))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(CommandHandler("clear", clear))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    print("Bot is running...")
    app.run_polling()


if __name__ == "__main__":
    main()    api_keys: list[str] = []
    project_id = ""
    app_id = ""

    def add_key(k: str):
        k = k.strip()
        if k and k not in api_keys:
            api_keys.append(k)

    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            names = set(zf.namelist())

            # Pass 1 — resources.arsc
            if "resources.arsc" in names:
                text = zf.read("resources.arsc").decode("latin-1", errors="replace")
                u = FIREBASE_URL_RE.search(text)
                k = API_KEY_RE.search(text)
                if u: fb_url = fb_url or u.group(0)
                if k: add_key(k.group(0))

            # Pass 2 — classes*.dex
            for dex in ["classes.dex", "classes2.dex", "classes3.dex", "classes4.dex"]:
                if fb_url and api_keys:
                    break
                if dex in names:
                    text = zf.read(dex).decode("latin-1", errors="replace")
                    u = FIREBASE_URL_RE.search(text)
                    k = API_KEY_RE.search(text)
                    if u: fb_url = fb_url or u.group(0)
                    if k: add_key(k.group(0))

            # Pass 3 — google-services.json
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
                            if ck: add_key(ck)
                        app_id = app_id or c.get("client_info", {}).get("mobilesdk_app_id", "")
                        for oc in c.get("oauth_client", []):
                            ck = oc.get("client_id", "").strip()
                            if ck: add_key(ck)
                except Exception:
                    pass

            # Pass 4 — brute force everything
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
                        if u: fb_url = fb_url or u.group(0)
                        if k: add_key(k.group(0))
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


# ─── Helpers ──────────────────────────────────────────────────────────────────

def url_to_name(url: str) -> str:
    host = url.split("//")[-1].split(".")[0]
    parts = host.replace("-", " ").split()
    return " ".join(p.capitalize() for p in parts)


# ─── Batch processor ──────────────────────────────────────────────────────────

async def process_batch(
    chat_id: int,
    ctx: ContextTypes.DEFAULT_TYPE,
    batch: list[dict],
):
    status_msg = await ctx.bot.send_message(
        chat_id, f"⚙️ Processing {len(batch)} APKs..."
    )

    results: dict[str, dict] = {}
    failed: list[str] = []
    true_dupes: list[str] = []

    loop = asyncio.get_event_loop()
    semaphore = asyncio.Semaphore(10)  # max 10 concurrent Telegram downloads

    async def fetch_and_scan(i: int, item: dict) -> tuple[int, str, dict | None]:
        async with semaphore:
            try:
                tg_file = await ctx.bot.get_file(item["file_id"])
                data = bytes(await tg_file.download_as_bytearray())
                result = await loop.run_in_executor(
                    EXECUTOR, extract_from_apk_bytes, data
                )
                return (i, item["file_name"], result)
            except Exception as e:
                failed.append(f"{item['file_name']} (error: {e})")
                return (i, item["file_name"], None)

    try:
        await ctx.bot.edit_message_text(
            f"📥 Downloading + scanning {len(batch)} APKs in parallel...",
            chat_id=chat_id,
            message_id=status_msg.message_id,
        )
    except Exception:
        pass

    tasks = [fetch_and_scan(i, item) for i, item in enumerate(batch)]
    scanned = await asyncio.gather(*tasks)
    scanned_sorted = sorted(scanned, key=lambda x: x[0])

    # ── Merge results ──
    now = datetime.now().strftime("%d/%m/%Y, %H:%M:%S")

    for _, fname, result in scanned_sorted:
        if not result:
            if not any(fname in f for f in failed):
                failed.append(f"{fname} (no Firebase config found)")
            continue

        fb_url_raw = result["firebaseUrl"].rstrip("/")
        fb_url_key = fb_url_raw.lower()
        found_keys: list[str] = result["apiKeys"]

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

    # ── Build output JSON ──
    accounts = [
        {
            "name": d["name"],
            "url": d["url"],
            "key": d["keys"],
            "time": d["time"],
        }
        for d in results.values()
    ]

    output = {"accounts": accounts, "total": len(accounts)}
    output_json = json.dumps(output, indent=2, ensure_ascii=False)

    try:
        await ctx.bot.delete_message(chat_id, status_msg.message_id)
    except Exception:
        pass

    # Send result — inline if small, file if large
    if len(output_json) < 3500:
        await ctx.bot.send_message(
            chat_id,
            f"```json\n{output_json}\n```",
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
                filename="firebase_results.json",
                caption=f"✅ {len(accounts)} unique Firebase configs from {len(batch)} APKs.",
            )
        os.unlink(tmp_path)

    if failed:
        fail_text = "⚠️ *Failed:*\n" + "\n".join(f"• `{x}`" for x in failed)
        await ctx.bot.send_message(chat_id, fail_text, parse_mode="Markdown")

    if true_dupes:
        dupe_text = (
            "🔁 *Duplicate APKs* (same Firebase URL + same keys already captured):\n"
            + "\n".join(f"• `{x}`" for x in true_dupes)
        )
        await ctx.bot.send_message(chat_id, dupe_text, parse_mode="Markdown")


# ─── Handlers ─────────────────────────────────────────────────────────────────

async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        f"👋 Send me APK files one by one.\n"
        f"I'll process automatically every {BATCH_SIZE} APKs.\n\n"
        f"Commands:\n"
        f"/flush — process whatever is queued now\n"
        f"/status — how many APKs are queued\n"
        f"/clear — clear the queue"
    )


async def handle_document(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document
    fname = doc.file_name or "unknown.apk"
    chat_id = update.effective_chat.id

    if not fname.lower().endswith((".apk", ".zip")):
        await update.message.reply_text("⚠️ Only .apk files are supported.")
        return

    state = chat_state[chat_id]
    state["queue"].append({"file_id": doc.file_id, "file_name": fname})

    count = len(state["queue"])
    remaining = BATCH_SIZE - count

    if remaining > 0:
        await update.message.reply_text(
            f"📥 `{fname}` added. Queue: **{count}/{BATCH_SIZE}** — send {remaining} more.",
            parse_mode="Markdown",
        )
        return

    # Hit 100 — fire
    batch = state["queue"][:BATCH_SIZE]
    state["queue"] = state["queue"][BATCH_SIZE:]
    leftover = len(state["queue"])

    await update.message.reply_text(f"✅ {BATCH_SIZE} APKs received. Scanning now...")
    await process_batch(chat_id, ctx, batch)

    if leftover > 0:
        await ctx.bot.send_message(
            chat_id,
            f"📂 {leftover} APK(s) still queued. Send {BATCH_SIZE - leftover} more to trigger next batch.",
        )


async def flush(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    state = chat_state[chat_id]
    if not state["queue"]:
        await update.message.reply_text("Queue is empty.")
        return
    batch = state["queue"][:]
    state["queue"] = []
    await update.message.reply_text(f"🚀 Force-processing {len(batch)} queued APKs...")
    await process_batch(chat_id, ctx, batch)


async def status(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    count = len(chat_state[chat_id]["queue"])
    await update.message.reply_text(
        f"📋 Queue: {count}/{BATCH_SIZE}. Need {max(0, BATCH_SIZE - count)} more to auto-process."
    )


async def clear(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    chat_state[chat_id]["queue"] = []
    await update.message.reply_text("🗑️ Queue cleared.")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("flush", flush))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(CommandHandler("clear", clear))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    print("Bot is running...")
    app.run_polling()


if __name__ == "__main__":
    main()
