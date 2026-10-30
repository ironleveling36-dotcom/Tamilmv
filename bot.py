# language: Python 3.11, file: bot.py, target: owner-locked Telegram bot scraping 1tamilmv.style
# flow: text -> search -> pick movie -> pick size -> magnet text + .torrent document
# ad blocker: host blocklist + manual redirect guard + DOM sanitize + size cap + status check
import os, io, re, hashlib, logging
from urllib.parse import quote, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup, Comment
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler, CallbackQueryHandler,
    ContextTypes, filters,
)

BASE     = os.environ.get("BASE", "https://www.1tamilmv.style")
TOKEN    = os.environ["BOT_TOKEN"]
OWNER_ID = int(os.environ["OWNER_ID"])
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
SIZE_RE = re.compile(r"\d+(?:\.\d+)?\s?(?:MB|GB|MiB|GiB)", re.I)
MAX_RESULTS       = 10
MAX_TORRENTS      = 12
MAX_REDIRECT_HOPS = 6
MAX_HTML_BYTES    = 4 * 1024 * 1024
MAX_TORRENT_BYTES = 2 * 1024 * 1024

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("tmb")

# ---------------- owner gate ----------------
def owner_only(fn):
    async def wrapper(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
        uid = update.effective_user.id if update.effective_user else 0
        if uid != OWNER_ID:
            try:
                if update.callback_query:
                    await update.callback_query.answer("this bot is private", show_alert=False)
                elif update.effective_message:
                    await update.effective_message.reply_text("this bot is private")
            except Exception:
                pass
            return
        return await fn(update, ctx)
    return wrapper

# ---------------- ad blocker ----------------
AD_HOSTS = frozenset({
    "popads.net", "popcash.net", "propellerads.com", "propellerclick.com",
    "adcash.com", "exoclick.com", "exosrv.com", "juicyads.com", "trafficjunky.com",
    "trafficfactory.biz", "clickadu.com", "hilltopads.net", "adsterra.com",
    "adsterranetwork.com", "revenuehits.com", "mgid.com", "zedo.com",
    "revcontent.com", "taboola.com", "outbrain.com",
    "go.link", "shortlink.in", "shrinkme.io", "shorte.st", "adf.ly",
    "bit.ly", "tinyurl.com", "cutt.ly", "rebrand.ly",
    "google-analytics.com", "googletagmanager.com", "doubleclick.net",
    "facebook.com/tr", "scorecardresearch.com", "quantserve.com",
    "hotjar.com", "mc.yandex.ru",
    "pagead2.googlesyndication.com", "adservice.google.com",
    "s.adroll.com", "static.criteo.net", "cdn.taboola.com",
    "cloudsdelivery.com", "acscdn.com", "shophine.net",
})
VET_ATTRS = ("href", "src", "data-src", "action", "formaction", "data-href",
             "data-url", "poster", "srcset")
STRIP_TAGS = ("script", "iframe", "noscript", "ins", "embed", "object",
              "applet", "frame", "frameset", "meta", "link", "style",
              "video", "audio", "canvas", "svg", "form", "input", "button")
AD_CLASS_TOKENS = ("ad", "ads", "advert", "banner", "sponsor", "promo",
                   "popup", "popunder", "overlay", "modal", "interstitial",
                   "tracking", "pixel", "taboola", "outbrain")

def _host_blocked(host: str) -> bool:
    if not host: return True
    h = host.lower().split(":")[0]
    if h in AD_HOSTS: return True
    for b in AD_HOSTS:
        if "/" in b: continue
        if h.endswith("." + b): return True
    return False

def url_blocked(url: str) -> bool:
    if not url: return False
    low = url.strip().lower()
    if low.startswith(("javascript:", "data:", "vbscript:", "blob:")):
        return True
    try:
        p = urlparse(low)
    except ValueError:
        return True
    if p.scheme in ("http", "https") and _host_blocked(p.netloc):
        return True
    for rule in AD_HOSTS:
        if "/" in rule and rule in low:
            return True
    return False

def same_site(url: str, base: str) -> bool:
    try:
        return urlparse(url).netloc == urlparse(base).netloc
    except ValueError:
        return False

def sanitize_html(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
        c.extract()
    for tag in soup(list(STRIP_TAGS)):
        tag.decompose()
    for tag in soup.find_all(True):
        if tag.attrs is None: continue
        cls = " ".join(tag.get("class", [])).lower()
        tid = (tag.get("id") or "").lower()
        if any(tok in f"{cls} {tid}" for tok in AD_CLASS_TOKENS):
            tag.decompose()
    for tag in soup.find_all(True):
        if tag.attrs is None: continue
        for attr in list(tag.attrs.keys()):
            val = tag.attrs[attr]
            if attr.lower().startswith("on"):
                del tag.attrs[attr]; continue
            if attr.lower() in VET_ATTRS:
                if isinstance(val, list):
                    kept = [v for v in val
                            if not url_blocked(urljoin(BASE, v if isinstance(v, str) else ""))]
                    if not kept: tag.decompose(); break
                    tag.attrs[attr] = kept
                elif isinstance(val, str):
                    if url_blocked(urljoin(BASE, val)): tag.decompose(); break
    return str(soup)

async def safe_get(http: httpx.AsyncClient, url: str,
                   max_bytes: int = MAX_HTML_BYTES,
                   expect: tuple = ("text/html", "application/xhtml")) -> httpx.Response:
    cur = url
    for hop in range(MAX_REDIRECT_HOPS):
        if url_blocked(cur):
            raise httpx.HTTPError(f"blocked host on hop {hop}: {cur}")
        r = await http.get(cur, follow_redirects=False)
        if 300 <= r.status_code < 400:
            nxt = urljoin(cur, r.headers.get("location", ""))
            if url_blocked(nxt):
                raise httpx.HTTPError(f"blocked redirect: {nxt}")
            if not same_site(nxt, BASE) and not same_site(nxt, cur):
                raise httpx.HTTPError(f"off-site redirect blocked: {nxt}")
            cur = nxt
            continue
        if r.status_code >= 400:
            raise httpx.HTTPError(f"HTTP {r.status_code} on {cur}")
        ctype = (r.headers.get("content-type") or "").lower()
        if ctype and expect and not any(e in ctype for e in expect):
            raise httpx.HTTPError(f"unexpected content-type: {ctype}")
        if len(r.content) > max_bytes:
            raise httpx.HTTPError(f"body too large: {len(r.content)}B")
        return r
    raise httpx.HTTPError(f"redirect chain exceeded {MAX_REDIRECT_HOPS} hops")

# ---------------- bencode ----------------
def _bdec(raw: bytes, i: int = 0):
    c = raw[i:i+1]
    if c == b"i":
        j = raw.index(b"e", i); return int(raw[i+1:j]), j+1
    if c == b"l":
        i += 1; out = []
        while raw[i:i+1] != b"e":
            v, i = _bdec(raw, i); out.append(v)
        return out, i+1
    if c == b"d":
        i += 1; out = {}
        while raw[i:i+1] != b"e":
            k, i = _bdec(raw, i); v, i = _bdec(raw, i); out[k] = v
        return out, i+1
    j = raw.index(b":", i); n = int(raw[i:j])
    return raw[j+1:j+1+n], j+1+n

def _info_slice(raw: bytes) -> bytes:
    if raw[0:1] != b"d": raise ValueError("not a torrent")
    i, start, end = 1, None, None
    while raw[i:i+1] != b"e":
        k, i = _bdec(raw, i); vs = i
        _, i = _bdec(raw, i)
        if k == b"info": start, end = vs, i
    if start is None: raise ValueError("no info dict")
    return raw[start:end]

def torrent_meta(raw: bytes):
    d, _ = _bdec(raw)
    info = d.get(b"info", {})
    name = info.get(b"name", b"torrent")
    name = name.decode("utf-8", "replace") if isinstance(name, bytes) else str(name)
    trackers = []
    if isinstance(d.get(b"announce"), bytes):
        trackers.append(d[b"announce"].decode())
    al = d.get(b"announce-list", [])
    if isinstance(al, list):
        for tier in al:
            if isinstance(tier, list):
                for t in tier:
                    if isinstance(t, bytes): trackers.append(t.decode())
    seen, uniq = set(), []
    for t in trackers:
        if t and t not in seen:
            seen.add(t); uniq.append(t)
    ih = hashlib.sha1(_info_slice(raw)).hexdigest()
    return name, ih, uniq

def build_magnet(name: str, infohash: str, trackers: list) -> str:
    m = f"magnet:?xt=urn:btih:{infohash}&dn={quote(name)}"
    for t in trackers:
        m += f"&tr={quote(t, safe='')}"
    return m

# ---------------- scrapers ----------------
def parse_search(html: str) -> list:
    soup = BeautifulSoup(sanitize_html(html), "html.parser")
    out, seen = [], set()
    for li in soup.select("li.ipsStreamItem, li.ipsStreamItem_contentBlock"):
        a = li.select_one("a[href*='/topic/']")
        if not a: continue
        href = urljoin(BASE, a["href"])
        if url_blocked(href): continue
        title = a.get_text(" ", strip=True)
        if title and href not in seen:
            seen.add(href); out.append({"title": title[:80], "url": href})
    if not out:
        for a in soup.select("a[href*='/topic/']"):
            href = urljoin(BASE, a["href"])
            if url_blocked(href): continue
            title = a.get_text(" ", strip=True)
            if len(title) > 4 and href not in seen:
                seen.add(href); out.append({"title": title[:80], "url": href})
    return out[:MAX_RESULTS]

def _label_for(a) -> str:
    txt = a.get_text(" ", strip=True)
    if txt.lower().endswith(".torrent"):
        txt = txt[:-8]
    for anc in (a.parent, getattr(a.parent, "parent", None)):
        if anc is None: continue
        m = SIZE_RE.search(anc.get_text(" ", strip=True))
        if m:
            return f"{m.group(0).upper()} · {txt[:38]}" if txt else m.group(0).upper()
    return (txt or "torrent")[:56]

def parse_topic(html: str) -> list:
    soup = BeautifulSoup(sanitize_html(html), "html.parser")
    out, seen = [], set()
    for a in soup.select("a[href$='.torrent'], a[href*='attachment.php'], a[href*='dl.1tamilmv']"):
        href = urljoin(BASE, a["href"])
        if href in seen or url_blocked(href): continue
        if not same_site(href, BASE): continue
        seen.add(href); out.append({"label": _label_for(a), "url": href})
    if not out:
        for a in soup.select("a[href^='magnet:']"):
            href = a["href"]
            if href in seen: continue
            seen.add(href); out.append({"label": _label_for(a), "url": href})
    return out[:MAX_TORRENTS]

# ---------------- keyboards ----------------
def kb_results(results: list) -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(f"{i+1}. {x['title'][:55]}", callback_data=f"res:{i}")]
            for i, x in enumerate(results)]
    rows.append([
        InlineKeyboardButton("🔁 new search", callback_data="new"),
        InlineKeyboardButton("✖ close",      callback_data="close"),
    ])
    return InlineKeyboardMarkup(rows)

def kb_sizes(torrents: list) -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(x["label"][:60], callback_data=f"tor:{i}")]
            for i, x in enumerate(torrents)]
    rows.append([
        InlineKeyboardButton("⬅ back",       callback_data="back"),
        InlineKeyboardButton("🔁 new search", callback_data="new"),
    ])
    return InlineKeyboardMarkup(rows)

def kb_done() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[
        InlineKeyboardButton("🔁 new search", callback_data="new"),
        InlineKeyboardButton("✖ close",      callback_data="close"),
    ]])

# ---------------- handlers ----------------
@owner_only
async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data.clear()
    ctx.user_data["state"] = "searching"
    await update.effective_message.reply_text(
        "send a movie name — I'll come back with results, you pick size, I hand you magnet + file."
    )

@owner_only
async def on_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    term = (update.effective_message.text or "").strip()
    if not term:
        return
    ctx.user_data["state"] = "searching"
    http: httpx.AsyncClient = ctx.bot_data["http"]
    url = f"{BASE}/index.php?/search/&q={quote(term)}&quick=1"
    try:
        r = await safe_get(http, url)
    except httpx.HTTPError as e:
        log.warning("search failed: %s", e)
        await update.effective_message.reply_text("search failed — site unreachable or blocked")
        return
    results = parse_search(r.text)
    if not results:
        log.info("empty search html len=%d head=%r", len(r.text), r.text[:300])
        await update.effective_message.reply_text("no results (mirror may have changed selectors)")
        return
    ctx.user_data["results"] = results
    ctx.user_data["state"] = "picking_result"
    await update.effective_message.reply_text(
        f"{len(results)} results — pick one:", reply_markup=kb_results(results)
    )

@owner_only
async def on_pick_result(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    results = ctx.user_data.get("results") or []
    i = int(q.data.split(":", 1)[1])
    if i >= len(results):
        await q.edit_message_text("stale button — send a new search")
        ctx.user_data["state"] = "searching"
        return
    item = results[i]
    http: httpx.AsyncClient = ctx.bot_data["http"]
    await q.edit_message_text(f"opening: {item['title'][:60]}…")
    try:
        r = await safe_get(http, item["url"])
    except httpx.HTTPError as e:
        await q.edit_message_text(f"failed to open topic: {e}")
        return
    torrents = parse_topic(r.text)
    if not torrents:
        await q.edit_message_text("no torrent/magnet links found in topic")
        return
    ctx.user_data["torrents"] = torrents
    ctx.user_data["topic_title"] = item["title"]
    ctx.user_data["state"] = "picking_torrent"
    await q.edit_message_text(
        f"{item['title']}\n\npick a size:", reply_markup=kb_sizes(torrents)
    )

@owner_only
async def on_pick_torrent(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    torrents = ctx.user_data.get("torrents") or []
    i = int(q.data.split(":", 1)[1])
    if i >= len(torrents):
        await q.edit_message_text("stale button — send a new search")
        ctx.user_data["state"] = "searching"
        return
    t = torrents[i]
    await q.edit_message_text(f"fetching: {t['label']}")
    if t["url"].startswith("magnet:"):
        await q.message.reply_text(t["url"], disable_web_page_preview=True)
        await q.edit_message_text("✓ magnet sent", reply_markup=kb_done())
        ctx.user_data["state"] = "searching"
        return
    http: httpx.AsyncClient = ctx.bot_data["http"]
    try:
        r = await safe_get(http, t["url"], max_bytes=MAX_TORRENT_BYTES,
                           expect=("application/x-bittorrent", "application/octet-stream",
                                   "binary/octet-stream", "text/plain"))
    except httpx.HTTPError as e:
        await q.edit_message_text(f"download failed: {e}")
        return
    raw = r.content
    if raw[:1] != b"d":
        await q.edit_message_text("server returned non-torrent payload (ad redirect?)")
        return
    try:
        name, ih, trackers = torrent_meta(raw)
    except Exception as e:
        await q.edit_message_text(f"could not parse torrent: {e}")
        return
    magnet = build_magnet(name, ih, trackers)
    safe = re.sub(r"[^\w.\-]+", "_", name)[:60] or "torrent"
    await q.message.reply_text(f"magnet:\n{magnet}", disable_web_page_preview=True)
    await q.message.reply_document(
        document=io.BytesIO(raw), filename=f"{safe}.torrent", caption=t["label"]
    )
    await q.edit_message_text("✓ magnet + .torrent sent", reply_markup=kb_done())
    ctx.user_data["state"] = "searching"

@owner_only
async def on_back(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    results = ctx.user_data.get("results") or []
    if not results:
        await q.edit_message_text("session expired — send a new search")
        ctx.user_data["state"] = "searching"
        return
    ctx.user_data["state"] = "picking_result"
    await q.edit_message_text(
        f"{len(results)} results — pick one:", reply_markup=kb_results(results)
    )

@owner_only
async def on_new(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    ctx.user_data.clear()
    ctx.user_data["state"] = "searching"
    await q.edit_message_text("send a movie name")

@owner_only
async def on_close(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    try:
        await q.message.delete()
    except Exception:
        await q.edit_message_text("closed")

# ---------------- app ----------------
async def post_init(app: Application):
    kwargs = dict(
        timeout=httpx.Timeout(25.0, connect=5.0),
        follow_redirects=False,
        limits=httpx.Limits(max_keepalive_connections=10, max_connections=50,
                            keepalive_expiry=30.0),
        headers={
            "User-Agent": UA,
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "text/html,application/xhtml+xml,application/x-bittorrent,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Referer": BASE,
            "DNT": "1",
            "Sec-GPC": "1",
        },
    )
    try:
        client = httpx.AsyncClient(http2=True, **kwargs)
    except Exception:
        client = httpx.AsyncClient(**kwargs)
    app.bot_data["http"] = client
    # pre-warm TLS so the first real search is fast
    try:
        await client.get(BASE, follow_redirects=True)
    except Exception as e:
        log.info("pre-warm skipped: %s", e)

async def post_shutdown(app: Application):
    try:
        await app.bot_data["http"].aclose()
    except Exception:
        pass

def main():
    app = (Application.builder().token(TOKEN)
           .post_init(post_init).post_shutdown(post_shutdown).build())
    app.add_handler(CommandHandler("start",  cmd_start))
    app.add_handler(CommandHandler("search", cmd_start))
    app.add_handler(CallbackQueryHandler(on_pick_result,  pattern=r"^res:"))
    app.add_handler(CallbackQueryHandler(on_pick_torrent, pattern=r"^tor:"))
    app.add_handler(CallbackQueryHandler(on_back,         pattern=r"^back$"))
    app.add_handler(CallbackQueryHandler(on_new,          pattern=r"^new$"))
    app.add_handler(CallbackQueryHandler(on_close,        pattern=r"^close$"))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
