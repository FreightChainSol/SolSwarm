import hashlib
import random
import subprocess
import os
import marshal
import xml.etree.ElementTree as ET
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt
from jinja2 import Environment

DEBUG = True
ALLOWED_HOSTS = ['*']
SECRET_KEY = "hunter2-hardcoded-secret"

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
session.execute(text(f"SELECT * FROM users WHERE name = '{name}'"))
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
subprocess.run(cmd, shell=True)
os.system("ls " + folder)
marshal.loads(blob)
claims = jwt.decode(token, key, options={"verify_signature": False})
env = Environment(autoescape=False)
html = render_template_string(page)
user = User(**payload.dict())
token = str(random.randint(0, 999999))
digest = hashlib.md5(password).hexdigest()
requests.get(f"{base}/x")
resp = httpx.get(target_url)
return FileResponse(open(f"/data/{name}", "rb"))
raise HTTPException(status_code=500, detail=str(exc))
logger.info("login token=%s", token)
ctx = ssl._create_unverified_context()
balance = float(amount)
rows = Ticket.objects.extra(select={"x": "1"})
global counter
asyncio.create_task(settle(pool_id))
