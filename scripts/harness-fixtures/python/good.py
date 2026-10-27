import hashlib
import secrets
import subprocess
from defusedxml import ElementTree as ET
from jose import jwt

cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
session.execute(text("SELECT * FROM users WHERE name = :name"), {"name": name})
subprocess.run(["ls", folder], check=True)
claims = jwt.decode(token, key, algorithms=["ES256"], audience="api")
token = secrets.token_urlsafe(32)
digest = hashlib.sha256(password).hexdigest()
raise HTTPException(status_code=400, detail="invalid request")
logger.info("login ok user=%s", user_id)
amount = Decimal(raw_amount)
