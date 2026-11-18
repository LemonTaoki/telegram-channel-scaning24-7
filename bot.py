"""
Telegram channel ZIP repo analyzer (Gemini)

Flow:
  channel me naya .zip aaye -> queue me daalo -> ek-ek karke download (memory me)
  -> zip padho (kuch run nahi hota) -> Gemini se analysis -> report file + console
  (+ optional Telegram DM)

Telegram API usage kam rakhne ke liye:
  - Polling nahi, history fetch nahi. Sirf Telegram ke push updates sunta hai.
  - Sirf .zip messages pe action, ek time pe ek download, beech me delay.
  - Same zip dobara process nahi hota (processed.json).
  - FloodWait aaye to khud ruk kar wapas try karta hai.
  - Report default me local file me save hoti hai (Telegram pe kuch send nahi).
"""
import asyncio
import io
import json
import logging
import os
import re
import zipfile
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from google import genai
from aiohttp import ClientSession, ClientTimeout, web
from telethon import TelegramClient, events
from telethon.sessions import StringSession
from telethon.errors import FloodWaitError

load_dotenv()

# ---------------- Config ----------------
API_ID = int(os.environ["TG_API_ID"])
API_HASH = os.environ["TG_API_HASH"]
CHANNEL = os.environ["TG_CHANNEL"].lstrip("@")  # public channel username
GEMINI_KEY = os.environ["GEMINI_API_KEY"]
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

SEND_TO_TELEGRAM = os.getenv("SEND_TO_TELEGRAM", "0") == "1"  # 1 = Saved Messages me bhi bhejo
MAX_ZIP_MB = int(os.getenv("MAX_ZIP_MB", "50"))
DELAY_BETWEEN_ZIPS = int(os.getenv("DELAY_BETWEEN_ZIPS", "20"))  # seconds

MAX_UNPACKED_MB = 300          # zip bomb guard
MAX_FILES_IN_ZIP = 5000
MAX_CHARS_PER_FILE = 8000
MAX_TOTAL_CHARS = 150_000      # Gemini ko kitna code bhejna hai
README_CHARS = 10_000

BASE = Path(__file__).parent
REPORT_DIR = BASE / "reports"
REPORT_DIR.mkdir(exist_ok=True)
STATE_FILE = BASE / "processed.json"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("zipbot")

TG_SESSION = os.getenv("TG_SESSION", "")  # gen_session.py se milti hai (Render ke liye zaroori)
tg = TelegramClient(
    StringSession(TG_SESSION) if TG_SESSION else str(BASE / "session"),
    API_ID,
    API_HASH,
)
gemini = genai.Client(api_key=GEMINI_KEY)
queue: asyncio.Queue = asyncio.Queue()

# ---------------- State (dedupe) ----------------
def load_state() -> set:
    if STATE_FILE.exists():
        try:
            return set(json.loads(STATE_FILE.read_text()))
        except Exception:
            pass
    return set()


def save_state(done: set):
    STATE_FILE.write_text(json.dumps(sorted(done)))


processed = load_state()

# ---------------- Zip reading ----------------
TEXT_EXT = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".kt", ".c", ".h", ".cpp", ".cs",
    ".go", ".rs", ".php", ".rb", ".sh", ".bat", ".cmd", ".ps1", ".vbs", ".lua",
    ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".txt", ".md", ".html", ".sql",
}
SKIP_DIRS = ("node_modules/", ".git/", "vendor/", "dist/", "build/", "venv/", ".venv/",
             "__pycache__/", "site-packages/", ".idea/", ".vscode/")
SKIP_FILES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "cargo.lock")
BINARY_EXT = (".exe", ".dll", ".bin", ".so", ".dylib", ".apk", ".msi", ".jar", ".scr", ".pyc")
IMPORTANT_NAMES = ("main", "index", "app", "server", "bot", "run", "start", "setup", "install",
                   "build", "config", "package.json", "requirements", "dockerfile", "makefile",
                   "manifest", "__init__")
SCRIPT_EXT = (".sh", ".bat", ".cmd", ".ps1", ".vbs")

SUSPICIOUS = {
    "eval/exec": r"\b(eval|exec)\s*\(",
    "base64 decode": r"(base64\.b64decode|atob\(|FromBase64String|b64decode)",
    "subprocess/shell": r"(subprocess\.|os\.system|child_process|Runtime\.getRuntime|Invoke-Expression|\biex\b)",
    "network send": r"(requests\.(post|put)|urllib|http\.client|fetch\(|axios\.|XMLHttpRequest|WebClient|curl |wget )",
    "telegram bot token": r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b",
    "discord webhook": r"discord(app)?\.com/api/webhooks/",
    "raw IP url": r"https?://\d{1,3}(\.\d{1,3}){3}",
    "browser/wallet data": r"(Login Data|Local State|wallet\.dat|metamask|\\\\Cookies|logins\.json|key4\.db)",
    "curl|bash": r"(curl|wget)[^\n|]*\|\s*(ba)?sh",
    "persistence": r"(CurrentVersion\\\\Run|crontab|schtasks|systemctl enable|startup)",
}


def score_file(name: str, size: int) -> tuple:
    low = name.lower()
    base = low.rsplit("/", 1)[-1]
    s = 0
    if any(base.startswith(k) or k in base for k in IMPORTANT_NAMES):
        s += 5
    if low.endswith(SCRIPT_EXT):
        s += 6
    if low.count("/") <= 1:
        s += 2
    return (-s, size)


def read_zip(data: bytes) -> dict:
    z = zipfile.ZipFile(io.BytesIO(data))
    infos = [i for i in z.infolist() if not i.is_dir()]

    if len(infos) > MAX_FILES_IN_ZIP:
        raise ValueError(f"Zip me bahut files ({len(infos)}), skip")
    if sum(i.file_size for i in infos) > MAX_UNPACKED_MB * 1024 * 1024:
        raise ValueError("Unpack hone par bahut bada (zip bomb ho sakta hai), skip")
    if any(i.flag_bits & 0x1 for i in infos):
        raise ValueError("Zip password-protected hai, padh nahi sakte")

    names = [i.filename for i in infos]
    binaries = [n for n in names if n.lower().endswith(BINARY_EXT)]

    readme_info = next(
        (i for i in sorted(infos, key=lambda x: x.filename.count("/"))
         if i.filename.lower().rsplit("/", 1)[-1].startswith("readme")),
        None,
    )
    readme_text = "README nahi mila"
    if readme_info:
        with z.open(readme_info) as f:
            readme_text = f.read(README_CHARS * 2).decode("utf-8", "ignore")[:README_CHARS]

    cands = []
    for i in infos:
        low = i.filename.lower()
        if i is readme_info or any(d in low for d in SKIP_DIRS):
            continue
        if low.rsplit("/", 1)[-1] in SKIP_FILES:
            continue
        if os.path.splitext(low)[1] in TEXT_EXT or low.rsplit("/", 1)[-1] in IMPORTANT_NAMES:
            cands.append(i)
    cands.sort(key=lambda i: score_file(i.filename, i.file_size))

    files, total, hits = {}, 0, {}
    for i in cands:
        if total >= MAX_TOTAL_CHARS:
            break
        with z.open(i) as f:
            raw = f.read(MAX_CHARS_PER_FILE * 2)
        if b"\x00" in raw[:1024]:  # binary nikla
            continue
        text = raw.decode("utf-8", "ignore")[:MAX_CHARS_PER_FILE]
        files[i.filename] = text
        total += len(text)
        for label, pat in SUSPICIOUS.items():
            if re.search(pat, text, re.IGNORECASE):
                hits.setdefault(label, []).append(i.filename)

    return {
        "names": names,
        "binaries": binaries,
        "readme": readme_text,
        "files": files,
        "hits": hits,
        "skipped": max(0, len(cands) - len(files)),
    }


# ---------------- Gemini ----------------
PROMPT = """Tum ek code security + code review expert ho. Neeche ek repo ke ZIP ka content hai.
Jawab Hinglish me do (simple language), aur seedha point pe raho.

ZIP ka naam: {zip_name}
Total files: {n_files}
Binary/exe files: {binaries}
Jin files ko code padhne me nahi bheja gaya: {skipped}

Automatic pre-scan ke suspicious signals (ye sirf hints hain, khud verify karo):
{hits}

File list (pehli 200):
{file_list}

===== README =====
{readme}

===== CODE FILES =====
{code}

Ye format follow karo:

## 1. Repo asal me kya karta hai
(sirf code dekh kar batao, README ko sach mane bina)

## 2. README me kya likha hai
(chhota summary)

## 3. README vs code
(README ke claims code se match karte hain ya nahi? Kaunsa claim jhootha, adhura ya missing hai? Agar README nahi hai to likho.)

## 4. Suspicious / khatarnak cheezein
(obfuscation, hidden network calls, token ya password chori, browser data/wallet access, persistence, exe bina source ke. Har cheez ke saath file ka naam do. Agar kuch nahi mila to saaf likho.)

## 5. Final verdict
Sahi / Shaky / Galat-Dangerous me se ek chuno, confidence (low/medium/high) aur 2-3 line reason.
Agar zaroori files padhi nahi gayi to ye bhi batao ki verdict kitna bharosemand hai.
"""


def build_prompt(zip_name: str, info: dict) -> str:
    code = "\n\n".join(f"### FILE: {n}\n{c}" for n, c in info["files"].items())
    hits = "\n".join(f"- {k}: {', '.join(v[:5])}" for k, v in info["hits"].items()) or "Koi signal nahi mila"
    return PROMPT.format(
        zip_name=zip_name,
        n_files=len(info["names"]),
        binaries=info["binaries"][:20] or "koi nahi",
        skipped=info["skipped"],
        hits=hits,
        file_list="\n".join(info["names"][:200]),
        readme=info["readme"],
        code=code or "(koi readable code file nahi mili)",
    )


def ask_gemini(prompt: str) -> str:
    last_err = None
    for attempt in range(4):
        try:
            resp = gemini.models.generate_content(model=GEMINI_MODEL, contents=prompt)
            return resp.text or "(Gemini ne khali jawab diya)"
        except Exception as e:  # 429 / 503 etc.
            last_err = e
            wait = 15 * (attempt + 1)
            log.warning("Gemini error (%s), %ss baad retry", e, wait)
            import time
            time.sleep(wait)
    raise RuntimeError(f"Gemini fail: {last_err}")


# ---------------- Telegram handlers ----------------
@tg.on(events.NewMessage(chats=CHANNEL))
async def on_message(event):
    f = event.message.file
    if not f or not (f.name or "").lower().endswith(".zip"):
        return
    if f.size and f.size > MAX_ZIP_MB * 1024 * 1024:
        log.info("Skip %s (bada hai: %.1f MB)", f.name, f.size / 1024 / 1024)
        return
    key = f"{CHANNEL}:{event.id}"
    if key in processed:
        return
    link = f"https://t.me/{CHANNEL}/{event.id}"
    log.info("Naya zip mila: %s -> %s", f.name, link)
    await queue.put((key, event.message, f.name, link))


async def download_with_retry(message):
    for _ in range(3):
        try:
            return await tg.download_media(message, file=bytes)
        except FloodWaitError as e:
            log.warning("FloodWait: %ss ruk raha hu", e.seconds)
            await asyncio.sleep(e.seconds + 5)
    raise RuntimeError("Telegram download baar-baar fail hua")


def split_text(text: str, n: int = 3800):
    return [text[i:i + n] for i in range(0, len(text), n)]


async def worker():
    while True:
        key, message, zip_name, link = await queue.get()
        try:
            data = await download_with_retry(message)
            info = await asyncio.to_thread(read_zip, data)
            analysis = await asyncio.to_thread(ask_gemini, build_prompt(zip_name, info))

            report = (
                f"# {zip_name}\n\n"
                f"Message link: {link}\n"
                f"Time: {datetime.now():%Y-%m-%d %H:%M}\n\n"
                f"---\n\n{analysis}\n"
            )
            safe = re.sub(r"[^\w.-]+", "_", zip_name)
            out = REPORT_DIR / f"{message.id}_{safe}.md"
            out.write_text(report, encoding="utf-8")
            print("\n" + "=" * 70 + "\n" + report + "=" * 70 + "\n")
            log.info("Report saved: %s", out)

            if SEND_TO_TELEGRAM:
                for part in split_text(report):
                    await tg.send_message("me", part)
                    await asyncio.sleep(2)

            processed.add(key)
            save_state(processed)
        except Exception as e:
            log.exception("Process fail (%s): %s", zip_name, e)
        finally:
            queue.task_done()
            await asyncio.sleep(DELAY_BETWEEN_ZIPS)  # Telegram ko aaram


# ---------------- Render keep-alive ----------------
PORT = int(os.getenv("PORT", "10000"))              # Render ye khud set karta hai
PUBLIC_URL = os.getenv("RENDER_EXTERNAL_URL", "")   # Render ye bhi khud set karta hai
PING_EVERY = int(os.getenv("PING_EVERY", "600"))    # 600s = 10 minute


async def health(_request):
    return web.Response(text="ok")


async def start_web_server():
    app = web.Application()
    app.router.add_get("/", health)
    app.router.add_get("/health", health)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", PORT).start()
    log.info("Health server port %s pe chalu", PORT)


async def keep_alive():
    """Har 10 minute me apne hi PUBLIC url ko hit karta hai.
    localhost pe ping bekaar hai, request Render ke bahar se hoke andar aani chahiye."""
    if not PUBLIC_URL:
        log.info("RENDER_EXTERNAL_URL nahi mila, keep-alive skip (local run)")
        return
    timeout = ClientTimeout(total=30)
    async with ClientSession(timeout=timeout) as http:
        while True:
            await asyncio.sleep(PING_EVERY)
            try:
                async with http.get(f"{PUBLIC_URL}/health") as r:
                    log.info("Keep-alive ping: %s", r.status)
            except Exception as e:
                log.warning("Keep-alive fail: %s", e)


async def main():
    await start_web_server()
    await tg.start()  # StringSession ho to OTP nahi maangega
    log.info("Chal raha hai. Channel: @%s | Model: %s", CHANNEL, GEMINI_MODEL)
    asyncio.create_task(worker())
    asyncio.create_task(keep_alive())
    await tg.run_until_disconnected()


if __name__ == "__main__":
    asyncio.run(main())
