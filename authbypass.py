# authbypass.py
# Usage: mitmweb -s authbypass_fix.py --listen-port 6969

from mitmproxy import http
from urllib.parse import parse_qs, urlencode
import json
import threading

# --- Configurable policy ---
TARGET_HOST_FRAGMENT = "keyauth.win/api/1."   # matches api/1.2 and api/1.3

# values enforced for login requests/responses
NEW_USERNAME = "TheGreen"
NEW_PASSWORD = "xxx"
NEW_APP_NAME = "Sangampaudel999's Application"
NEW_OWNERID = "tTsZ5ZpwTh"

# values enforced for init *requests*
INIT_REQUEST_APP_NAME = "Sangampaudel999's Application"
INIT_REQUEST_OWNERID = "tTsZ5ZpwTh"
INIT_REQUEST_VER = "1.3"

# If client uses different param names for password/username, list them here:
PASSWORD_KEYS = ("pass", "password", "pwd")
USERNAME_KEYS = ("username", "user", "login")
# ----------------------------

# Module-level storage for the latest init sessionid (and a simple lock)
_saved = {
    "sessionid": None
}
_lock = threading.Lock()

def _set_param(params, key, value):
    """Set or replace a param (params is dict of lists)."""
    params[key] = [value]

def _save_sessionid(sessionid):
    with _lock:
        _saved["sessionid"] = sessionid

def _get_saved_sessionid():
    with _lock:
        return _saved["sessionid"]

def _mutate_form_params_for_login(params):
    # set username (try to pick the first key present, else create username)
    found_user = False
    for k in USERNAME_KEYS:
        if k in params:
            _set_param(params, k, NEW_USERNAME)
            found_user = True
            break
    if not found_user:
        _set_param(params, USERNAME_KEYS[0], NEW_USERNAME)

    # set password under all likely keys (ensures coverage)
    for k in PASSWORD_KEYS:
        if k in params:
            _set_param(params, k, NEW_PASSWORD)
    # also ensure at least one password param exists
    if not any(k in params for k in PASSWORD_KEYS):
        _set_param(params, PASSWORD_KEYS[0], NEW_PASSWORD)

    # enforce name and ownerid fields as requested
    _set_param(params, "name", NEW_APP_NAME)
    _set_param(params, "ownerid", NEW_OWNERID)

    # If we have a saved init sessionid, inject or replace sessionid param
    saved = _get_saved_sessionid()
    if saved:
        _set_param(params, "sessionid", saved)

def _mutate_form_params_for_init(params):
    # Remove any existing sessionid from init requests
    if "sessionid" in params:
        del params["sessionid"]
        print(f"[authbypass_fix] removed sessionid from init request")
    
    # Inject the requested init request name/ownerid
    _set_param(params, "name", INIT_REQUEST_APP_NAME)
    _set_param(params, "ownerid", INIT_REQUEST_OWNERID)
    # Always set version to 1.3 for init requests
    _set_param(params, "ver", INIT_REQUEST_VER)

def _mutate_json_for_login(data):
    # enforce fields in JSON for login
    data["username"] = NEW_USERNAME
    data["name"] = NEW_APP_NAME
    data["ownerid"] = NEW_OWNERID
    # best-effort password key
    data["password"] = NEW_PASSWORD
    saved = _get_saved_sessionid()
    if saved:
        data["sessionid"] = saved

def _mutate_json_for_init_request(data):
    # Remove any existing sessionid from init requests
    if "sessionid" in data:
        del data["sessionid"]
        print(f"[authbypass_fix] removed sessionid from init request")
    
    # enforce init request name/ownerid values
    data["name"] = INIT_REQUEST_APP_NAME
    data["ownerid"] = INIT_REQUEST_OWNERID
    # Always set version to 1.3 for init requests
    data["ver"] = INIT_REQUEST_VER

def request(flow: http.HTTPFlow) -> None:
    req = flow.request
    # quick scope filter
    if TARGET_HOST_FRAGMENT not in req.pretty_url:
        return
    if req.method.upper() != "POST":
        return

    ctype = req.headers.get("Content-Type", "")

    # Handle x-www-form-urlencoded
    if "application/x-www-form-urlencoded" in ctype:
        try:
            body = req.content.decode(errors="ignore")
            params = parse_qs(body, keep_blank_values=True)
            type_val = params.get("type", [""])[0].lower()

            if type_val == "login":
                _mutate_form_params_for_login(params)
                new_body = urlencode(params, doseq=True)
                req.content = new_body.encode()
                if "Content-Length" in req.headers:
                    req.headers["Content-Length"] = str(len(req.content))
                print(f"[authbypass_fix] request mutated (form login): username={NEW_USERNAME}, pass=[redacted], ownerid={NEW_OWNERID} for {req.pretty_url}")

            elif type_val == "init":
                _mutate_form_params_for_init(params)
                new_body = urlencode(params, doseq=True)
                req.content = new_body.encode()
                if "Content-Length" in req.headers:
                    req.headers["Content-Length"] = str(len(req.content))
                print(f"[authbypass_fix] request mutated (form init): name={INIT_REQUEST_APP_NAME}, ownerid={INIT_REQUEST_OWNERID}, ver={INIT_REQUEST_VER} for {req.pretty_url}")

        except Exception as e:
            print(f"[authbypass_fix] request (form) error: {e} for {req.pretty_url}")
        return

    # Handle JSON bodies (application/json) or bare JSON
    if "application/json" in ctype or req.content.strip().startswith(b"{"):
        try:
            text = req.get_text()
            data = json.loads(text) if text else {}
            type_val = str(data.get("type", "")).lower()

            if type_val == "login":
                _mutate_json_for_login(data)
                new_text = json.dumps(data)
                req.set_text(new_text)
                if "Content-Length" in req.headers:
                    req.headers["Content-Length"] = str(len(req.content))
                print(f"[authbypass_fix] request mutated (json login): username={NEW_USERNAME}, pass=[redacted], ownerid={NEW_OWNERID} for {req.pretty_url}")

            elif type_val == "init":
                _mutate_json_for_init_request(data)
                new_text = json.dumps(data)
                req.set_text(new_text)
                if "Content-Length" in req.headers:
                    req.headers["Content-Length"] = str(len(req.content))
                print(f"[authbypass_fix] request mutated (json init): name={INIT_REQUEST_APP_NAME}, ownerid={INIT_REQUEST_OWNERID}, ver={INIT_REQUEST_VER} for {req.pretty_url}")

        except Exception as e:
            print(f"[authbypass_fix] request (json) error: {e} for {req.pretty_url}")
        return

    # other content types ignored
    return

def response(flow: http.HTTPFlow) -> None:
    req = flow.request
    resp = flow.response

    if TARGET_HOST_FRAGMENT not in req.pretty_url:
        return

    # decode compressed responses (gzip/deflate)
    try:
        resp.decode()
    except Exception:
        # can't decode -> skip
        return

    ctype = resp.headers.get("Content-Type", "")
    if "application/json" not in ctype and "text/" not in ctype:
        return

    # Try to parse response JSON; if not JSON, skip further mutation
    try:
        text = resp.get_text()
        data = json.loads(text)
    except Exception:
        return

    modified = False
    try:
        # detect request 'type' from original request (form OR json)
        req_type = ""
        try:
            if "application/x-www-form-urlencoded" in req.headers.get("Content-Type", ""):
                params = parse_qs(req.content.decode(errors="ignore"), keep_blank_values=True)
                req_type = params.get("type", [""])[0].lower()
            elif "application/json" in req.headers.get("Content-Type", "") or req.content.strip().startswith(b"{"):
                rtext = req.get_text()
                rdata = json.loads(rtext) if rtext else {}
                req_type = str(rdata.get("type", "")).lower()
        except Exception:
            req_type = ""

        # capture sessionid from init responses
        if req_type == "init":
            # try a few common places for sessionid
            session_candidate = None
            if isinstance(data.get("sessionid"), str):
                session_candidate = data.get("sessionid")
            elif isinstance(data.get("info"), dict) and isinstance(data["info"].get("sessionid"), str):
                session_candidate = data["info"].get("sessionid")
            elif isinstance(data.get("data"), dict) and isinstance(data["data"].get("sessionid"), str):
                session_candidate = data["data"].get("sessionid")

            if session_candidate:
                _save_sessionid(session_candidate)
                print(f"[authbypass_fix] captured init sessionid: {session_candidate} for {req.pretty_url}")

        # Mutate response universally (keep ownerid/name/username forced)
        data["ownerid"] = NEW_OWNERID
        if not isinstance(data.get("info"), dict):
            data["info"] = {}
        data["info"]["username"] = NEW_USERNAME
        data["info"]["name"] = NEW_APP_NAME
        modified = True

        if modified:
            new_text = json.dumps(data)
            resp.set_text(new_text)
            if "Content-Length" in resp.headers:
                resp.headers["Content-Length"] = str(len(resp.content))
            if "Content-Encoding" in resp.headers:
                del resp.headers["Content-Encoding"]
            print(f"[authbypass_fix] response mutated for {req.pretty_url}")
    except Exception as e:
        print(f"[authbypass_fix] response error: {e} for {req.pretty_url}")
