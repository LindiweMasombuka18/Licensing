import hashlib
from datetime import datetime

def generate_license_key(mac_address, serial_number):
    raw = f"{mac_address}-{serial_number}-{datetime.utcnow().isoformat()}"
    return hashlib.sha256(raw.encode()).hexdigest()
