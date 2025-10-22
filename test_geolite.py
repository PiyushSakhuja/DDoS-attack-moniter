# test_geolite.py
import os
import sys
import geoip2.database

# Put the full path to your GeoLite2-City.mmdb here (use raw string or forward slashes)
DB_PATH = r"C:\Users\PIYUSH SAKHUJA\OneDrive\Desktop\ddos attack\data\GeoLite2-City.mmdb"

if not os.path.exists(DB_PATH):
    print("ERROR: DB file not found at:", DB_PATH)
    sys.exit(2)

print("Using GeoLite DB:", DB_PATH)
reader = None
try:
    reader = geoip2.database.Reader(DB_PATH)
except Exception as e:
    print("ERROR: could not open GeoLite DB:", e)
    sys.exit(3)

# A small set of test IPs:
ips = [
    "8.8.8.8",        # Google DNS (public) -> should geolocate
    "1.1.1.1",        # Cloudflare DNS -> should geolocate
    "203.0.113.1",    # TEST-NET-3 (reserved) -> may NOT geolocate
    "198.51.100.5",   # TEST-NET-2 (reserved) -> may NOT geolocate
    "172.31.255.1",   # private RFC1918 -> will NOT geolocate (expected)
]

for ip in ips:
    try:
        rec = reader.city(ip)
        lat = rec.location.latitude
        lon = rec.location.longitude
        country = rec.country.name or rec.country.iso_code
        print(f"{ip:16} -> lat={lat}, lon={lon}, country={country}")
    except Exception as e:
        print(f"{ip:16} -> lookup failed: {e}")

if reader:
    reader.close()
