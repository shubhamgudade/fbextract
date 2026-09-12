from __future__ import annotations

import io
import json
import logging
import os
import re
import signal
import zipfile
import asyncio
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.request import HTTPXRequest
from telegram.ext import (
    ApplicationBuilder,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# ─── Logging (shows up in Railway's log stream) ───────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    force=True,
)
logger = logging.getLogger("main")

# ─── Config (all overridable via Railway env vars) ────────────────────────────
BATCH_SIZE        = int(os.environ.get("BATCH_SIZE", "100"))
PROGRESS_INTERVAL = int(os.environ.get("PROGRESS_INTERVAL", "10"))
SCAN_TIMEOUT      = int(os.environ.get("SCAN_TIMEOUT", "120"))
PROGRESS_TICK     = 1.5   # seconds between Telegram progress-message edits

FIREBASE_URL_RE = re.compile(
    r"https://[a-z0-9_-]+\.(?:firebaseio\.com|firebasedatabase\.app)",
    re.IGNORECASE,
)
API_KEY_RE = re.compile(r"AIza[A-Za-z0-9_-]{35}")
EXECUTOR   = ThreadPoolExecutor(max_workers=8)


# ─── Token loading ────────────────────────────────────────────────────────────

BOT_TOKENS = [
    "8885508557:AAHFC5KuCOzA4F6fpCN60dX0_Nbe4_5OcE8",
    "8767058395:AAF_OythHpW_MSWrOtUBb0nHwVarp_OnVm0",
    "8823028845:AAFWvYVMVs5WW62ktKBKwM1ResVSUBHQV5U",
    "8987736690:AAFOGLM9vSL9i5DTklQZ23tBWXI9we1ZuMU",
    "8749725075:AAFlmwFwWtySRhICaqMXKcyMw5oJul3ttsY",
]


def load_tokens() -> list[str]:
    logger.info("Loaded %d bot token(s)", len(BOT_TOKENS))
    return BOT_TOKENS


# ─── APK extraction ───────────────────────────────────────────────────────────

def extract_from_apk_bytes(data: bytes) -> dict | None:
    fb_url     = ""
    api_keys: list[str] = []
    project_id = ""
    app_id     = ""

    def add_key(k: str) -> None:
        k = k.strip()
        if k and k not in api_keys:
            api_keys.append(k)

    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            names = set(zf.namelist())

            if "resources.arsc" in names:
                text = zf.read("resources.arsc").decode("latin-1", errors="replace")
                if m := FIREBASE_URL_RE.search(text):
                    fb_url = fb_url or m.group(0)
                if m := API_KEY_RE.search(text):
                    add_key(m.group(0))

            for dex in ("classes.dex", "classes2.dex", "classes3.dex", "classes4.dex"):
                if fb_url and api_keys:
                    break
                if dex in names:
                    text = zf.read(dex).decode("latin-1", errors="replace")
                    if m := FIREBASE_URL_RE.search(text):
                        fb_url = fb_url or m.group(0)
                    if m := API_KEY_RE.search(text):
                        add_key(m.group(0))

            gs_paths = [
                n for n in names
                if n in ("google-services.json", "assets/google-services.json")
                or n.endswith("/google-services.json")
            ]
            for path in gs_paths:
                try:
                    gs = json.loads(zf.read(path).decode("utf-8", errors="replace"))
                    pi = gs.get("project_info", {})
                    fb_url     = fb_url     or pi.get("firebase_url", "")
                    project_id = project_id or pi.get("project_id",  "")
                    for c in gs.get("client", [])[:1]:
                        for entry in c.get("api_key", []):
                            add_key(entry.get("current_key", ""))
                        app_id = app_id or c.get("client_info", {}).get("mobilesdk_app_id", "")
                        for oc in c.get("oauth_client", []):
                            add_key(oc.get("client_id", ""))
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
                        if m := FIREBASE_URL_RE.search(text):
                            fb_url = fb_url or m.group(0)
                        if m := API_KEY_RE.search(text):
                            add_key(m.group(0))
                    except Exception:
                        pass

    except zipfile.BadZipFile:
        return None

    if not fb_url:
        return None
    return {
        "firebaseUrl": fb_url,
        "apiKeys":     api_keys or [""],
        "projectId":   project_id,
        "appId":       app_id,
    }


# ─── Helpers ──────────────────────────────────────────────────────────────────

def url_to_name(url: str) -> str:
    host = url.split("//")[-1].split(".")[0]
    return " ".join(p.capitalize() for p in host.replace("-", " ").split())


def build_progress_bar(done: int, total: int, width: int = 20) -> str:
    filled = int(width * done / total) if total else 0
    pct    = int(100  * done / total) if total else 0
    return f"[{'█' * filled}{'░' * (width - filled)}] {pct}% ({done}/{total})"


def build_queue_text(queue: list) -> str:
    count = len(queue)
    lines = [f"📋 Queue: {count}/{BATCH_SIZE} — {BATCH_SIZE - count} more to auto-process\n"]
    for i, item in enumerate(queue, 1):
        lines.append(f"  {i}. `{item['file_name']}`")
    return "\n".join(lines)


async def send_with_retry(coro_fn, retries: int = 3, delay: float = 5.0):
    for attempt in range(retries):
        try:
            return await coro_fn()
        except Exception as e:
            err = str(e).lower()
            if any(x in err for x in ("timed out", "timeout", "readtimeout", "network")):
                if attempt < retries - 1:
                    await asyncio.sleep(delay)
                    continue
            raise
    return None


async def send_json_snapshot(
    chat_id: int, ctx, results: dict, label: str, log: logging.Logger
) -> None:
    accounts = [
        {"name": d["name"], "url": d["url"], "key": d["keys"], "time": d["time"]}
        for d in results.values()
    ]
    output_json = json.dumps(
        {"accounts": accounts, "total": len(accounts)}, indent=2, ensure_ascii=False
    )
    log.info("Snapshot '%s': %d unique configs", label, len(accounts))

    try:
        if len(output_json) < 3500:
            await send_with_retry(lambda: ctx.bot.send_message(
                chat_id,
                f"📊 *{label}*\n```json\n{output_json}\n```",
                parse_mode="Markdown",
            ))
        else:
            fname = f"firebase_{label.lower().replace(' ', '_')}.json"
            raw   = output_json.encode()
            await send_with_retry(lambda: ctx.bot.send_document(
                chat_id,
                document=io.BytesIO(raw),   # fresh buffer each retry
                filename=fname,
                caption=f"📊 {label} — {len(accounts)} unique configs.",
            ))
    except Exception as e:
        log.error("Snapshot upload failed for '%s': %s", label, e)
        try:
            await ctx.bot.send_message(
                chat_id,
                f"⚠️ *{label}* — upload failed. Total unique: {len(accounts)}",
                parse_mode="Markdown",
            )
        except Exception:
            pass


# ─── Progress state & updater ─────────────────────────────────────────────────
# The key fix: instead of every concurrent task calling edit_message_text
# (which causes conflicts and stale data), a single background coroutine
# reads shared ProgressState every PROGRESS_TICK seconds and does the edit.
# Tasks only mutate ProgressState under the batch lock — never touch Telegram.

class ProgressState:
    """
    Shared mutable state for one batch scan.
    Updated under the caller's asyncio lock; read by the updater coroutine.
    No internal lock needed — asyncio is single-threaded and all mutations
    happen inside lock blocks that contain no awaits, so they're atomic.
    """

    def __init__(self, total: int):
        self.total        = total
        self.done         = 0
        self.found        = 0
        self.failed_count = 0
        self.active: set[str] = set()   # files currently downloading / scanning

    def render(self) -> str:
        bar   = build_progress_bar(self.done, self.total)
        lines = [f"⚙️ Scanning {self.total} APKs…", bar]
        for fname in sorted(self.active):
            lines.append(f"  🔄 `{fname}`")
        lines.append(f"✅ Found: {self.found} | ❌ Failed: {self.failed_count}")
        return "\n".join(lines)


async def _progress_updater(
    ctx, chat_id: int, msg_id: int, state: ProgressState, stop: asyncio.Event
) -> None:
    """
    Background task: edits the Telegram progress message at a fixed rate.
    Only one task ever calls edit_message_text → no conflicts.
    """
    last = ""
    while not stop.is_set():
        await asyncio.sleep(PROGRESS_TICK)
        if stop.is_set():
            break
        text = state.render()
        if text != last:
            try:
                await ctx.bot.edit_message_text(
                    text, chat_id=chat_id, message_id=msg_id, parse_mode="Markdown"
                )
                last = text
            except Exception:
                pass  # "message not modified" or rate-limit — both harmless


# ─── Bot instance (one per token) ─────────────────────────────────────────────

class BotInstance:
    """
    Encapsulates all state and handlers for a single bot token.
    Multiple BotInstances run concurrently; they share no mutable globals.
    """

    def __init__(self, token: str, index: int):
        self.token = token
        self.index = index
        self.log   = logging.getLogger(f"bot{index}")
        # Per-chat queue state
        self._chat_state: dict  = defaultdict(lambda: {"queue": [], "queue_msg_id": None})
        # Per-chat failed APK store (for retry / resend)
        self._failed_store: dict = defaultdict(list)

    # ── App builder ──────────────────────────────────────────────────────────

    def build_app(self):
        req = HTTPXRequest(
            read_timeout=300, write_timeout=300,
            connect_timeout=30, pool_timeout=60,
        )
        app = ApplicationBuilder().token(self.token).request(req).build()
        app.add_handler(CommandHandler("start",  self._cmd_start))
        app.add_handler(CommandHandler("flush",  self._cmd_flush))
        app.add_handler(CommandHandler("status", self._cmd_status))
        app.add_handler(CommandHandler("clear",  self._cmd_clear))
        app.add_handler(MessageHandler(filters.Document.ALL, self._on_document))
        app.add_handler(CallbackQueryHandler(self._on_callback))
        return app

    # ── Queue message helper ─────────────────────────────────────────────────

    async def _refresh_queue_msg(self, chat_id: int, ctx, state: dict) -> None:
        text   = build_queue_text(state["queue"])
        msg_id = state.get("queue_msg_id")
        if msg_id:
            try:
                await ctx.bot.edit_message_text(
                    text, chat_id=chat_id, message_id=msg_id, parse_mode="Markdown"
                )
                return
            except Exception:
                pass
        msg = await ctx.bot.send_message(chat_id, text, parse_mode="Markdown")
        state["queue_msg_id"] = msg.message_id

    # ── Batch processor ──────────────────────────────────────────────────────

    async def _process_batch(self, chat_id: int, ctx, batch: list) -> None:
        total = len(batch)
        state = self._chat_state[chat_id]
        self.log.info("[chat=%d] Batch start: %d APKs", chat_id, total)

        # Remove old queue message
        if state.get("queue_msg_id"):
            try:
                await ctx.bot.delete_message(chat_id, state["queue_msg_id"])
            except Exception:
                pass
            state["queue_msg_id"] = None

        # Send the progress message (one, stays pinned, gets edited by updater)
        pm   = await ctx.bot.send_message(
            chat_id,
            f"⚙️ Starting scan of {total} APKs…\n{build_progress_bar(0, total)}",
        )
        pmid = pm.message_id

        # Shared batch state
        progress     = ProgressState(total)
        stop_event   = asyncio.Event()
        updater_task = asyncio.create_task(
            _progress_updater(ctx, chat_id, pmid, progress, stop_event)
        )

        results:      dict = {}
        failed_items: list = []
        true_dupes:   list = []
        last_snapshot_at   = 0
        now = datetime.now().strftime("%d/%m/%Y, %H:%M:%S")

        semaphore = asyncio.Semaphore(10)
        lock      = asyncio.Lock()
        loop      = asyncio.get_event_loop()

        # ── Per-file coroutine ───────────────────────────────────────────────
        async def fetch_and_scan(item: dict) -> None:
            nonlocal last_snapshot_at
            fname       = item["file_name"]
            result:      dict | None = None
            fail_reason: str  | None = None

            async with semaphore:
                # Mark active only when we actually start (respects semaphore limit)
                async with lock:
                    progress.active.add(fname)

                # ── Download ──
                self.log.info("[chat=%d] Downloading %s", chat_id, fname)
                try:
                    tg_file = await ctx.bot.get_file(item["file_id"])
                    data    = bytes(await tg_file.download_as_bytearray())
                    self.log.info(
                        "[chat=%d] Downloaded  %s  (%s B)",
                        chat_id, fname, f"{len(data):,}"
                    )
                except Exception as e:
                    fail_reason = f"download error: {e}"
                    self.log.warning("[chat=%d] %s: %s", chat_id, fname, fail_reason)
                    data = None

                # ── Scan ──
                if data is not None:
                    self.log.info("[chat=%d] Scanning   %s", chat_id, fname)
                    try:
                        result = await asyncio.wait_for(
                            loop.run_in_executor(EXECUTOR, extract_from_apk_bytes, data),
                            timeout=SCAN_TIMEOUT,
                        )
                    except asyncio.TimeoutError:
                        fail_reason = "scan timeout (120s)"
                        self.log.warning("[chat=%d] %s: %s", chat_id, fname, fail_reason)
                    except Exception as e:
                        fail_reason = f"scan error: {e}"
                        self.log.warning("[chat=%d] %s: %s", chat_id, fname, fail_reason)

            # ── Collate under lock (no Telegram calls inside) ────────────────
            snapshot_results: dict | None = None
            snapshot_label:   str  | None = None

            async with lock:
                progress.active.discard(fname)
                progress.done += 1

                if result is None:
                    reason = fail_reason or "no Firebase config found"
                    failed_items.append({"file_id": item["file_id"], "file_name": fname, "reason": reason})
                    progress.failed_count += 1
                    self.log.info("[chat=%d] ✗ %s — %s", chat_id, fname, reason)
                else:
                    fb_url_raw = result["firebaseUrl"].rstrip("/")
                    key        = fb_url_raw.lower()
                    if key in results:
                        existing = results[key]
                        new_keys = [k for k in result["apiKeys"] if k not in existing["keys"]]
                        if not new_keys:
                            true_dupes.append(fname)
                            self.log.info("[chat=%d] dup %s → %s", chat_id, fname, fb_url_raw)
                        else:
                            existing["keys"].extend(new_keys)
                            existing["source_files"].append(fname)
                            progress.found += 1
                            self.log.info("[chat=%d] ✓ (updated) %s → %s", chat_id, fname, fb_url_raw)
                    else:
                        results[key] = {
                            "name":         url_to_name(fb_url_raw),
                            "url":          fb_url_raw,
                            "keys":         list(result["apiKeys"]),
                            "time":         now,
                            "source_files": [fname],
                        }
                        progress.found += 1
                        self.log.info("[chat=%d] ✓ (new)     %s → %s", chat_id, fname, fb_url_raw)

                # Periodic snapshot?
                cur = progress.done
                if cur - last_snapshot_at >= PROGRESS_INTERVAL and cur < total and results:
                    last_snapshot_at = cur
                    snapshot_results = dict(results)
                    snapshot_label   = f"Snapshot at {cur}/{total}"

            # Snapshot sent outside the lock so we don't block other tasks
            if snapshot_results is not None:
                await send_json_snapshot(chat_id, ctx, snapshot_results, snapshot_label, self.log)

        # ── Run all concurrently ─────────────────────────────────────────────
        await asyncio.gather(*[fetch_and_scan(item) for item in batch])

        # Stop the progress updater background task
        stop_event.set()
        updater_task.cancel()
        try:
            await updater_task
        except asyncio.CancelledError:
            pass

        # Final status edit
        try:
            await ctx.bot.edit_message_text(
                f"✅ Scan complete!  {build_progress_bar(total, total)}\n"
                f"Unique: {len(results)} | Failed: {len(failed_items)} | Dupes: {len(true_dupes)}",
                chat_id=chat_id,
                message_id=pmid,
            )
        except Exception:
            pass

        self.log.info(
            "[chat=%d] Batch done — unique=%d  failed=%d  dupes=%d",
            chat_id, len(results), len(failed_items), len(true_dupes),
        )

        # Send final JSON
        await send_json_snapshot(chat_id, ctx, results, f"Final — {total} APKs", self.log)

        # Failed report + retry buttons
        if failed_items:
            self._failed_store[chat_id] = failed_items
            lines = [f"• `{x['file_name']}` — {x['reason']}" for x in failed_items[:50]]
            if len(failed_items) > 50:
                lines.append(f"_…and {len(failed_items) - 50} more_")
            kb = InlineKeyboardMarkup([[
                InlineKeyboardButton("🔄 Retry failed",   callback_data=f"retry:{chat_id}"),
                InlineKeyboardButton("📤 Send APKs back", callback_data=f"resend:{chat_id}"),
            ]])
            try:
                await ctx.bot.send_message(
                    chat_id,
                    f"⚠️ *{len(failed_items)} Failed:*\n" + "\n".join(lines),
                    parse_mode="Markdown",
                    reply_markup=kb,
                )
            except Exception:
                pass

        # Duplicates report
        if true_dupes:
            dupe_text = "🔁 *Duplicates:*\n" + "\n".join(f"• `{x}`" for x in true_dupes[:30])
            if len(true_dupes) > 30:
                dupe_text += f"\n_{len(true_dupes) - 30} more…_"
            try:
                await ctx.bot.send_message(chat_id, dupe_text, parse_mode="Markdown")
            except Exception:
                pass

    # ── Callback handler ─────────────────────────────────────────────────────

    async def _on_callback(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        query = update.callback_query
        await query.answer()
        action, chat_id_str = query.data.split(":", 1)
        chat_id = int(chat_id_str)
        items   = self._failed_store.get(chat_id, [])

        if not items:
            await query.edit_message_reply_markup(reply_markup=None)
            await ctx.bot.send_message(chat_id, "No failed APKs stored.")
            return

        if action == "retry":
            await query.edit_message_reply_markup(reply_markup=None)
            self._failed_store[chat_id] = []
            await ctx.bot.send_message(chat_id, f"🔄 Retrying {len(items)} failed APKs…")
            batch = [{"file_id": x["file_id"], "file_name": x["file_name"]} for x in items]
            await self._process_batch(chat_id, ctx, batch)

        elif action == "resend":
            await query.edit_message_reply_markup(reply_markup=None)
            await ctx.bot.send_message(chat_id, f"📤 Sending back {len(items)} APKs…")
            for item in items:
                try:
                    await send_with_retry(lambda i=item: ctx.bot.send_document(
                        chat_id,
                        document=i["file_id"],
                        caption=f"`{i['file_name']}` — {i['reason']}",
                        parse_mode="Markdown",
                    ))
                except Exception as e:
                    try:
                        await ctx.bot.send_message(
                            chat_id,
                            f"⚠️ Failed to resend `{item['file_name']}`: {e}",
                            parse_mode="Markdown",
                        )
                    except Exception:
                        pass

    # ── Command handlers ─────────────────────────────────────────────────────

    async def _cmd_start(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        await update.message.reply_text(
            f"👋 Send APK files one by one.\n"
            f"Queue fills to {BATCH_SIZE} then auto-fires.\n\n"
            f"/flush — process queue now\n"
            f"/status — show queue size\n"
            f"/clear — wipe queue"
        )

    async def _on_document(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        doc     = update.message.document
        fname   = doc.file_name or "unknown.apk"
        chat_id = update.effective_chat.id

        if not fname.lower().endswith((".apk", ".zip")):
            await update.message.reply_text("⚠️ Only .apk / .zip files are supported.")
            return

        try:
            await ctx.bot.delete_message(chat_id, update.message.message_id)
        except Exception:
            pass

        state = self._chat_state[chat_id]
        state["queue"].append({"file_id": doc.file_id, "file_name": fname})
        count = len(state["queue"])
        self.log.info("[chat=%d] Queued %s (%d/%d)", chat_id, fname, count, BATCH_SIZE)

        if count < BATCH_SIZE:
            await self._refresh_queue_msg(chat_id, ctx, state)
            return

        batch          = state["queue"][:BATCH_SIZE]
        state["queue"] = state["queue"][BATCH_SIZE:]
        await self._process_batch(chat_id, ctx, batch)

        if state["queue"]:
            await self._refresh_queue_msg(chat_id, ctx, state)

    async def _cmd_flush(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        chat_id = update.effective_chat.id
        state   = self._chat_state[chat_id]
        if not state["queue"]:
            await update.message.reply_text("Queue is empty.")
            return
        batch          = state["queue"][:]
        state["queue"] = []
        self.log.info("[chat=%d] /flush — %d APKs", chat_id, len(batch))
        await update.message.reply_text(f"🚀 Force-processing {len(batch)} APKs…")
        await self._process_batch(chat_id, ctx, batch)

    async def _cmd_status(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        chat_id = update.effective_chat.id
        count   = len(self._chat_state[chat_id]["queue"])
        await update.message.reply_text(
            f"📋 Queue: {count}/{BATCH_SIZE}. Need {max(0, BATCH_SIZE - count)} more to auto-fire."
        )

    async def _cmd_clear(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        chat_id = update.effective_chat.id
        state   = self._chat_state[chat_id]
        state["queue"]        = []
        state["queue_msg_id"] = None
        self.log.info("[chat=%d] Queue cleared", chat_id)
        await update.message.reply_text("🗑️ Queue cleared.")


# ─── Runner ───────────────────────────────────────────────────────────────────

async def _run_one(bot: BotInstance, shutdown: asyncio.Event) -> None:
    app = bot.build_app()
    bot.log.info("Bot #%d starting  (token: …%s)", bot.index, bot.token[-8:])
    async with app:
        await app.start()
        await app.updater.start_polling()
        bot.log.info("Bot #%d is live and polling", bot.index)
        await shutdown.wait()
        bot.log.info("Bot #%d shutting down", bot.index)
        await app.updater.stop()
        await app.stop()


async def amain() -> None:
    tokens   = load_tokens()
    bots     = [BotInstance(tok, i + 1) for i, tok in enumerate(tokens)]
    shutdown = asyncio.Event()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, shutdown.set)
        except (NotImplementedError, RuntimeError):
            pass  # Windows / restricted environments

    logger.info("Launching %d bot(s)…", len(bots))
    await asyncio.gather(*[_run_one(b, shutdown) for b in bots])
    logger.info("All bots stopped.")


if __name__ == "__main__":
    asyncio.run(amain())
