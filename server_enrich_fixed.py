# server_enrich_fixed.py
import asyncio, os, json, time, math
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uvicorn
import requests
import shelve
from typing import Optional

# CONFIG
ABUSEIPDB_KEY = os.getenv("f3c6d74c7d0529710d6d7535f548476b18d269404785c47c5b9e12852341b9c53530c16f7dfe46d9", "")
MAXMIND_DB_PATH = os.getenv("MAXMIND_DB_PATH", "data/GeoLite2-City.mmdb")
INCOMING_QUEUE = "incoming_ips.jsonl"
CACHE_TTL = 24 * 3600
PUBLISH_THRESHOLD = 0.1

app = FastAPI()

# Serve index.html at root, and mount other static assets under /static
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def root():
    # serve the main page
    return FileResponse("static/index.html")

clients = set()

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    clients.add(ws)
    try:
        while True:
            # wait for pings from client to keep connection alive;
            # if client doesn't send, this will wait here — client in our frontend pings periodically.
            try:
                await ws.receive_text()
            except WebSocketDisconnect:
                break
            except Exception:
                # ignore other receive errors and continue
                await asyncio.sleep(1.0)
    finally:
        # cleanup
        if ws in clients:
            clients.remove(ws)

# --- cache helpers using shelve ---
CACHE_FILE = "ip_cache.db"
def cache_get(ip):
    try:
        with shelve.open(CACHE_FILE) as db:
            item = db.get(ip)
            if not item: return None
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

# --- AbuseIPDB check (single-check; consider bulk for production) ---
def abuseipdb_check(ip: str) -> Optional[dict]:
    if not ABUSEIPDB_KEY:
        return None
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip}
        r = requests.get(url, headers=headers, params=params, timeout=10)
        if r.status_code != 200:
            print("AbuseIPDB error:", r.status_code, r.text)
            return None
        data = r.json().get("data", {})
        return {
            "abuseConfidence": data.get("abuseConfidenceScore", 0),
            "totalReports": data.get("totalReports", 0),
            "lastReportedAt": data.get("lastReportedAt")
        }
    except Exception as e:
        print("AbuseIPDB exception:", e)
        return None

# --- GeoIP (optional) ---
def geolocate_ip(ip: str) -> dict:
    try:
        import geoip2.database
        if not os.path.exists(MAXMIND_DB_PATH):
            raise FileNotFoundError
        reader = geoip2.database.Reader(MAXMIND_DB_PATH)
        rec = reader.city(ip)
        lat = rec.location.latitude or 0.0
        lon = rec.location.longitude or 0.0
        country = rec.country.name or rec.country.iso_code or "Unknown"
        asn = "unknown"
        try:
            asn = rec.traits.autonomous_system_organization or rec.traits.autonomous_system_number or "unknown"
        except Exception:
            pass
        reader.close()
        return {"lat": lat, "lon": lon, "country": country, "asn": asn}
    except Exception:
        return {"lat": 0.0, "lon": 0.0, "country": "Unknown", "asn": "unknown"}

# --- scoring function ---
def compute_score(abuse_info: Optional[dict], magnitude: int = 1, packet_rate: Optional[int] = None, geoinfo: dict = None) -> float:
    abuse_score = 0.0
    if abuse_info and abuse_info.get("abuseConfidence") is not None:
        # AbuseIPDB gives 0..100
        try:
            abuse_score = min(100.0, float(abuse_info.get("abuseConfidence", 0))) / 100.0
        except Exception:
            abuse_score = 0.0
    mag_score = math.tanh(math.log1p(max(0, magnitude)) / 8.0)
    pkt_score = 0.0
    if packet_rate:
        pkt_score = math.tanh(math.log1p(packet_rate) / 8.0)
    provider_penalty = 0.0
    if geoinfo and geoinfo.get("asn"):
        asn = str(geoinfo["asn"]).lower()
        if any(k in asn for k in ["amazon", "aws", "google", "azure", "microsoft", "digitalocean", "cloudflare"]):
            provider_penalty = 0.1
    score = 0.6 * abuse_score + 0.25 * mag_score + 0.1 * pkt_score + provider_penalty
    return max(0.0, min(1.0, score))

# publish helper
async def publish_event(event: dict):
    if not clients: return
    msg = json.dumps(event)
    # copy clients list to avoid set changed during iteration
    to_send = list(clients)
    await asyncio.gather(*[c.send_text(msg) for c in to_send], return_exceptions=True)

# --- safe ingestion from newline-delimited JSON file ---
async def watch_queue_and_process():
    open(INCOMING_QUEUE, "a").close()
    seen = 0
    while True:
        try:
            with open(INCOMING_QUEUE, "r", encoding="utf-8") as f:
                lines = f.readlines()
            # process only new lines
            while seen < len(lines):
                raw = lines[seen]
                seen += 1
                if not raw:
                    continue
                raw_stripped = raw.strip()
                if raw_stripped == "":
                    continue
                # try to parse JSON, ignore lines that fail to parse
                try:
                    rec = json.loads(raw_stripped)
                except Exception as e:
                    print("failed parse/process line:", e)
                    continue
                try:
                    ip = rec.get("ip")
                    if not ip:
                        continue
                    magnitude = int(rec.get("magnitude", 1))
                    packet_rate = rec.get("packet_rate")
                    ts = rec.get("ts", int(time.time()))
                    cached = cache_get(ip)
                    if cached:
                        abuse = cached.get("abuse")
                        geo = cached.get("geo")
                    else:
                        abuse = abuseipdb_check(ip)
                        geo = geolocate_ip(ip)
                        cache_set(ip, {"abuse": abuse, "geo": geo})
                    score = compute_score(abuse, magnitude, packet_rate, geo)
                    if score >= PUBLISH_THRESHOLD:
                        evt = {
                            "ip": ip,
                            "lat": geo.get("lat", 0.0),
                            "lon": geo.get("lon", 0.0),
                            "confidence": round(score, 3),
                            "magnitude": magnitude,
                            "abuse": abuse or {},
                            "geo": {"country": geo.get("country"), "asn": geo.get("asn")},
                            "ts": ts
                        }
                        await publish_event(evt)
                except Exception as e:
                    print("processing error:", e)
        except Exception as e:
            print("watch_queue error:", e)
        await asyncio.sleep(1.0)

# use FastAPI startup lifespan
@app.on_event("startup")
async def startup_event():
    asyncio.create_task(watch_queue_and_process())

if __name__ == "__main__":
    uvicorn.run("server_enrich_fixed:app", host="0.0.0.0", port=8000)
