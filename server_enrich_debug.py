
import asyncio, os, json, time, math, traceback
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
import geoip2.database
import uvicorn
import ipaddress
import requests
import shelve
from typing import Optional

# ---------- CONFIG ----------
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "f3c6d74c7d0529710d6d7535f548476b18d269404785c47c5b9e12852341b9c53530c16f7dfe46d9")  # set before starting to use AbuseIPDB
# absolute path to your GeoLite2-City.mmdb (use raw string r"...")
MAXMIND_DB_PATH = r"C:\Users\PIYUSH SAKHUJA\OneDrive\Desktop\ddos attack\DDoS-attack-moniter\data\GeoLite2-City.mmdb"
INCOMING_QUEUE = "incoming_ips.jsonl"
CACHE_TTL = 24 * 3600
PUBLISH_THRESHOLD = float(os.getenv("PUBLISH_THRESHOLD", "0.5"))
# debug env var: if "1" we'll always publish to frontend (useful while testing)
DEBUG_FORCE_PUBLISH = os.getenv("DEBUG_FORCE_PUBLISH", "1") == "1"
# how many recent events to keep to replay to new clients
RECENT_EVENTS_MAX = 200
# ----------------------------

# global container
geo_reader = None
clients = set()
recent_events = []  # in-memory buffer of recent events for replay

# ---- Lifespan (startup/shutdown) ----
@asynccontextmanager
async def lifespan(app: FastAPI):
    global geo_reader
    # startup
    try:
        if os.path.exists(MAXMIND_DB_PATH):
            geo_reader = geoip2.database.Reader(MAXMIND_DB_PATH)
            print(f"[GEO] MaxMind DB initialized from: {MAXMIND_DB_PATH}")
        else:
            print(f"[GEO] MaxMind DB NOT FOUND at: {MAXMIND_DB_PATH}. Geolocation will return (0,0).")
    except Exception as e:
        print(f"[GEO] CRITICAL ERROR during GeoIP Reader setup: {e}")

    # start background processing
    task = asyncio.create_task(watch_queue_and_process())
    print("[WATCHER] Background queue watcher started.")
    yield

    # shutdown
    if geo_reader:
        try:
            geo_reader.close()
            print("[GEO] MaxMind DB closed.")
        except Exception:
            pass
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        print("[WATCHER] Background task cancelled cleanly.")

app = FastAPI(lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def root():
    return FileResponse("static/index.html")

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    clients.add(ws)
    print("[WS] client connected; total:", len(clients))
    # replay recent events to new client so they see previously processed events
    try:
        for evt in recent_events:
            try:
                await ws.send_text(json.dumps(evt))
            except Exception:
                pass
        while True:
            try:
                await ws.receive_text()
            except WebSocketDisconnect:
                break
            except Exception:
                await asyncio.sleep(1.0)
    finally:
        if ws in clients:
            clients.remove(ws)
        print("[WS] client disconnected; total:", len(clients))

# ---- cache helpers ----
CACHE_FILE = "ip_cache.db"
def cache_get(ip):
    try:
        with shelve.open(CACHE_FILE) as db:
            item = db.get(ip)
            if not item:
                return None
            if time.time() - item.get("ts", 0) > CACHE_TTL:
                try:
                    del db[ip]
                except Exception:
                    pass
                return None
            return item["value"]
    except Exception:
        return None

def cache_set(ip, value):
    try:
        with shelve.open(CACHE_FILE) as db:
            db[ip] = {"ts": time.time(), "value": value}
    except Exception:
        pass

# ---- AbuseIPDB single check ----
def abuseipdb_check(ip: str) -> Optional[dict]:
    if not ABUSEIPDB_KEY:
        print(f"[ABUSE] No AbuseIPDB key set; skipping check for {ip}")
        return None
    try:
        print(f"[ABUSE-DEBUG] Checking AbuseIPDB for {ip} ...")

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip}
        r = requests.get(url, headers=headers, params=params, timeout=10)
        if r.status_code != 200:
            print(f"[ABUSE] AbuseIPDB error for {ip}: {r.status_code} {r.text}")
            return None
        data = r.json().get("data", {})
        return {
            "abuseConfidence": data.get("abuseConfidenceScore", 0),
            "totalReports": data.get("totalReports", 0),
            "lastReportedAt": data.get("lastReportedAt")
        }
    except Exception as e:
        print(f"[ABUSE] Exception checking {ip}:", e)
        return None

# ---- GeoIP via MaxMind (uses global geo_reader) ----
def geolocate_ip(ip: str) -> dict:
    global geo_reader
    if geo_reader is None:
        # fast fallback
        return {"lat": 0.0, "lon": 0.0, "country": "Unknown", "asn": "unknown"}
    try:
        rec = geo_reader.city(ip)
        lat = rec.location.latitude or 0.0
        lon = rec.location.longitude or 0.0
        country = rec.country.name or rec.country.iso_code or "Unknown"
        # GeoLite2-City doesn't include ASN data – leave 'unknown' unless you also load ASN DB
        return {"lat": lat, "lon": lon, "country": country, "asn": "unknown"}
    except Exception as e:
        print(f"[GEO] GeoIP lookup failed for {ip}: {e}")
        return {"lat": 0.0, "lon": 0.0, "country": "Unknown", "asn": "unknown"}

# ---- scoring ----
def compute_score(abuse_info: Optional[dict], magnitude: int = 1, packet_rate: Optional[int] = None, geoinfo: dict = None) -> float:
    abuse_score = 0.0
    if abuse_info and abuse_info.get("abuseConfidence") is not None:
        try:
            abuse_score = min(100.0, float(abuse_info.get("abuseConfidence", 0))) / 100.0
        except Exception:
            abuse_score = 0.0
    mag_score = math.tanh(math.log1p(max(0, magnitude)) / 8.0)
    pkt_score = 0.0
    if packet_rate:
        try:
            pkt_score = math.tanh(math.log1p(float(packet_rate)) / 8.0)
        except Exception:
            pkt_score = 0.0
    provider_penalty = 0.0
    if geoinfo and geoinfo.get("asn"):
        asn = str(geoinfo["asn"]).lower()
        if asn != "unknown" and any(k in asn for k in ["amazon", "aws", "google", "azure", "microsoft", "digitalocean", "cloudflare"]):
            provider_penalty = 0.1
    score = 0.6 * abuse_score + 0.25 * mag_score + 0.1 * pkt_score + provider_penalty
    return max(0.0, min(1.0, score))

# ---- publish helper with logging & replay buffer ----
async def publish_event(event: dict):
    # append to recent_events (and trim)
    recent_events.append(event)
    if len(recent_events) > RECENT_EVENTS_MAX:
        recent_events.pop(0)
    if not clients:
        print("[PUBLISH] No connected clients; skipping send for", event.get("ip"))
        return
    msg = json.dumps(event)
    to_send = list(clients)
    results = await asyncio.gather(*[c.send_text(msg) for c in to_send], return_exceptions=True)
    print(f"[PUBLISH] Sent event for {event.get('ip')} to {len(to_send)} clients; results:", results)

# ---- main watcher ----
async def watch_queue_and_process():
    open(INCOMING_QUEUE, "a").close()
    seen = 0
    print(f"[WATCHER] Starting watcher on {INCOMING_QUEUE} (threshold={PUBLISH_THRESHOLD}, debug_force={DEBUG_FORCE_PUBLISH})")
    while True:
        try:
            with open(INCOMING_QUEUE, "r", encoding="utf-8") as f:
                lines = f.readlines()
            while seen < len(lines):
                raw = lines[seen]
                seen += 1
                raw_stripped = raw.strip()
                if not raw_stripped:
                    continue
                try:
                    rec = json.loads(raw_stripped)
                except json.JSONDecodeError as e:
                    print("[WATCHER] failed parse/process line:", e, "line:", raw_stripped)
                    continue
                except Exception as e:
                    print("[WATCHER] Unknown parse error:", e, "line:", raw_stripped)
                    continue
                try:
                    ip = rec.get("ip")
                    if not ip:
                        print("[WATCHER] no ip field; skipping line:", raw_stripped)
                        continue
                    magnitude = int(rec.get("magnitude", 1))
                    packet_rate = rec.get("packet_rate")
                    ts = rec.get("ts", int(time.time()))
                    print(f"[WATCHER] Processing line -> ip={ip} magnitude={magnitude} packet_rate={packet_rate} ts={ts}")
                    # --- Enrichment flow (replace old cached logic) ---
                    enrich = get_enrich_cache(ip)
                    if enrich:
                        abuse = enrich.get("abuse")
                        geo = enrich.get("geo")
                        print(f"[CACHE] Hit for {ip}: abuse={abuse} geo={geo}")
                    else:
                        abuse = abuseipdb_check(ip)
                        geo = geolocate_with_fallback(ip)
                        # store unified enrichment
                        set_enrich_cache(ip, abuse, geo)
                        print(f"[ENRICH] For {ip}: abuse={abuse} geo={geo}")

                    score = compute_score(abuse, magnitude, packet_rate, geo)
                    print(f"[SCORE] ip={ip} computed_score={score}")
                    should_publish = (score >= PUBLISH_THRESHOLD) or DEBUG_FORCE_PUBLISH
                    print(f"[DECIDE] ip={ip} publish? {should_publish} (threshold={PUBLISH_THRESHOLD})")
                    if should_publish:
                        evt = {
                            "ip": ip,
                            "lat": geo.get("lat"),       # keep None if unknown
                            "lon": geo.get("lon"),       # keep None if unknown
                            "lng": geo.get("lon"),       # duplicate for frontend flexibility
                            "confidence": round(score, 3),
                            "magnitude": magnitude,
                            "abuse": abuse or {},
                            "geo": {"country": geo.get("country"), "asn": geo.get("asn")},
                            "ts": ts
                        }
                        print("[EVENT] publishing:", evt)
                        await publish_event(evt)
                except Exception as e:
                    print("[PROCESSING ERROR]", e)
                    traceback.print_exc()
        except Exception as e:
            print("[WATCHER ERROR]", e)
            traceback.print_exc()
        await asyncio.sleep(1.0)

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def geo_fallback_ipapi(ip: str) -> dict:
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,lat,lon,org,message"
        r = requests.get(url, timeout=5)
        j = r.json()
        if j.get("status") != "success":
            return {"lat": None, "lon": None, "country": None, "asn": j.get("org")}
        return {"lat": float(j.get("lat")), "lon": float(j.get("lon")), "country": j.get("country"), "asn": j.get("org")}
    except Exception as e:
        print(f"[GEO-FALLBACK] error for {ip}: {e}")
        return {"lat": None, "lon": None, "country": None, "asn": None}

# helper: unified cache key
def enrich_cache_key(ip: str) -> str:
    return f"enrich:{ip}"

# call this instead of cache_get(ip)
def get_enrich_cache(ip: str):
    item = cache_get(enrich_cache_key(ip))
    return item  # item is expected { "abuse":..., "geo": {...}, "ts": ... } or None

# set unified enrichment cache
def set_enrich_cache(ip: str, abuse, geo):
    cache_set(enrich_cache_key(ip), {"abuse": abuse, "geo": geo})

# patched geolocate_with_fallback that defers to cache properly
def geolocate_with_fallback(ip: str) -> dict:
    # 1) private/reserved
    if is_private_ip(ip):
        return {"lat": None, "lon": None, "country": "private", "asn": None}

    # 2) check unified enrichment cache first
    cached = get_enrich_cache(ip)
    if cached:
        geo = cached.get("geo", {})
        # treat 0.0 or None as missing -> force re-resolve
        lat = geo.get("lat")
        lon = geo.get("lon")
        if lat is not None and lon is not None and not (lat == 0.0 and lon == 0.0):
            return geo

    # 3) local GeoLite
    geo = geolocate_ip(ip)
    if geo.get("lat") is not None and geo.get("lon") is not None and not (geo.get("lat") == 0.0 and geo.get("lon") == 0.0):
        return geo

    # 4) external fallback (ip-api)
    fb = geo_fallback_ipapi(ip)
    if fb.get("lat") is not None and fb.get("lon") is not None:
        return fb

    # 5) last resort: return partial info (None coords)
    return {"lat": None, "lon": None, "country": fb.get("country") or geo.get("country"), "asn": fb.get("asn") or geo.get("asn") or None}


if __name__ == "__main__":
    uvicorn.run("server_enrich_debug:app", host="0.0.0.0", port=8000, reload=False)
