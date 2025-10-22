# test_geolite_fast.py
import os
import sys
try:
    import geoip2.database
except Exception as e:
    print("ERROR: geoip2 not installed or import failed:", e)
    print("-> Install with: pip install geoip2")
    sys.exit(1)

# ====== EDIT THIS PATH to the exact location of your GeoLite2-City.mmdb ======
DB_PATH = r"C:\Users\PIYUSH SAKHUJA\OneDrive\Desktop\ddos attack\DDoS-attack-moniter\data\GeoLite2-City.mmdb"
# ==========================================================================

def check_db_path(path):
    if not os.path.exists(path):
        print("ERROR: DB file not found at:", path)
        return False
    size = os.path.getsize(path)
    print(f"Using GeoLite DB: {path} (size={size:,} bytes)")
    return True

def test_ips(reader, ips):
    from geoip2.errors import AddressNotFoundError
    for ip in ips:
        try:
            rec = reader.city(ip)
            lat = rec.location.latitude
            lon = rec.location.longitude
            country = rec.country.name or rec.country.iso_code
            print(f"{ip:16} -> lat={lat}, lon={lon}, country={country}")
        except AddressNotFoundError:
            print(f"{ip:16} -> lookup failed: AddressNotFoundError (not in DB)")
        except Exception as e:
            print(f"{ip:16} -> lookup failed: {type(e).__name__}: {e}")

def main():
    if not check_db_path(DB_PATH):
        sys.exit(2)

    try:
        reader = geoip2.database.Reader(DB_PATH)
    except Exception as e:
        print("ERROR: could not open GeoLite DB:", e)
        sys.exit(3)

    # Public IPs (should usually return coords), reserved/private IPs (expected to fail)
    ips = [
        "8.8.8.8",        # Google DNS - expected to geolocate
        "1.1.1.1",        # Cloudflare DNS - sometimes partial/no coords
        "203.0.113.1",    # TEST-NET-3 - expected NOT in DB
        "198.51.100.5",   # TEST-NET-2 - expected NOT in DB
        "172.31.255.1"    # RFC1918 private - expected NOT in DB
    ]

    test_ips(reader, ips)
    reader.close()
    print("Done.")

if __name__ == "__main__":
    main()
