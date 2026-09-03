from __future__ import annotations

import argparse
import hmac
import json
import secrets
import threading
import webbrowser
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .settings_store import (
    delete_gemini_key,
    delete_xai_key,
    save_gemini_key,
    save_preferences,
    save_xai_key,
    settings_status,
    test_gemini_connection,
    test_xai_connection,
)


MAX_BODY_BYTES = 8192


PAGE = r"""<!doctype html>
<html lang="sk">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>CCG &amp; ITHZ MCP — nastavenia</title>
  <style nonce="__NONCE__">
    :root { color-scheme: light; --ink:#12251f; --muted:#63736d; --paper:#f5f1e7; --card:#fffdf8; --line:#d9d3c5; --green:#0b7968; --green-dark:#07584d; --gold:#d79a3b; --danger:#a63d40; --shadow:0 24px 70px rgba(24,48,39,.12); }
    * { box-sizing:border-box; }
    body { margin:0; min-height:100vh; font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif; color:var(--ink); background:radial-gradient(circle at 10% 5%,rgba(215,154,59,.16),transparent 28rem),linear-gradient(145deg,#f8f5ed 0%,#eef3ed 100%); }
    body:before { content:""; position:fixed; inset:0; pointer-events:none; background-image:linear-gradient(rgba(18,37,31,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(18,37,31,.025) 1px,transparent 1px); background-size:32px 32px; mask-image:linear-gradient(to bottom,black,transparent 75%); }
    main { position:relative; width:min(1060px,calc(100% - 32px)); margin:0 auto; padding:52px 0 70px; }
    .hero { display:grid; grid-template-columns:1.35fr .65fr; gap:24px; align-items:end; margin-bottom:26px; }
    .eyebrow { display:flex; align-items:center; gap:10px; color:var(--green); text-transform:uppercase; letter-spacing:.13em; font-size:12px; font-weight:800; }
    .eyebrow:before { content:""; width:38px; height:2px; background:var(--green); }
    h1 { margin:16px 0 10px; font-size:clamp(38px,6vw,68px); line-height:.95; letter-spacing:-.055em; max-width:760px; }
    .lead { margin:0; color:var(--muted); font-size:17px; line-height:1.55; max-width:720px; }
    .trust { border:1px solid rgba(11,121,104,.2); background:rgba(255,253,248,.72); backdrop-filter:blur(10px); border-radius:22px; padding:20px; }
    .trust strong { display:block; font-size:14px; margin-bottom:6px; }
    .trust span { color:var(--muted); font-size:13px; line-height:1.45; }
    .grid { display:grid; grid-template-columns:1.08fr .92fr; gap:24px; }
    .card { background:rgba(255,253,248,.94); border:1px solid var(--line); border-radius:28px; padding:28px; box-shadow:var(--shadow); }
    .card h2 { margin:0 0 6px; font-size:24px; letter-spacing:-.025em; }
    .card-intro { margin:0 0 24px; color:var(--muted); font-size:14px; line-height:1.5; }
    .status-row { display:flex; flex-wrap:wrap; gap:8px; margin:18px 0 22px; }
    .badge { display:inline-flex; align-items:center; gap:7px; border:1px solid var(--line); border-radius:999px; padding:7px 11px; background:white; font-size:12px; font-weight:700; }
    .dot { width:8px; height:8px; border-radius:50%; background:#9aa7a1; box-shadow:0 0 0 4px rgba(154,167,161,.13); }
    .badge.ok .dot { background:#19a974; box-shadow:0 0 0 4px rgba(25,169,116,.13); }
    label { display:block; margin:0 0 8px; font-size:13px; font-weight:800; }
    .field { margin-bottom:18px; }
    input,select { width:100%; min-height:48px; border:1px solid #cfc8b9; border-radius:14px; padding:0 14px; color:var(--ink); background:#fff; font:inherit; outline:none; transition:border-color .18s,box-shadow .18s; }
    input:focus,select:focus { border-color:var(--green); box-shadow:0 0 0 4px rgba(11,121,104,.11); }
    .hint { display:block; color:var(--muted); font-size:12px; line-height:1.4; margin-top:7px; }
    .two { display:grid; grid-template-columns:1fr 1fr; gap:14px; }
    .actions { display:flex; flex-wrap:wrap; gap:10px; margin-top:6px; }
    button { border:0; border-radius:14px; min-height:44px; padding:0 16px; font:inherit; font-size:13px; font-weight:800; cursor:pointer; transition:transform .15s,background .15s,opacity .15s; }
    button:hover { transform:translateY(-1px); }
    button:disabled { opacity:.55; cursor:wait; transform:none; }
    .primary { color:white; background:var(--green); }
    .primary:hover { background:var(--green-dark); }
    .secondary { color:var(--green-dark); background:#e5f1ed; }
    .danger { color:var(--danger); background:#f7e7e5; }
    .ghost { color:var(--muted); background:transparent; border:1px solid var(--line); }
    .note { margin-top:22px; padding:16px 17px; border-radius:16px; background:#f0ede3; color:var(--muted); font-size:12px; line-height:1.55; }
    .flow { display:grid; gap:12px; margin:22px 0 0; padding:0; list-style:none; counter-reset:flow; }
    .flow li { counter-increment:flow; display:grid; grid-template-columns:34px 1fr; gap:12px; align-items:start; padding:14px; border:1px solid #e3ddcf; border-radius:16px; background:#fff; }
    .flow li:before { content:counter(flow); display:grid; place-items:center; width:30px; height:30px; border-radius:10px; color:white; background:var(--ink); font-size:12px; font-weight:900; }
    .flow strong { display:block; font-size:13px; margin:1px 0 3px; }
    .flow span { color:var(--muted); font-size:12px; line-height:1.42; }
    #message { display:none; margin-top:16px; padding:13px 15px; border-radius:14px; font-size:13px; line-height:1.45; }
    #message.show { display:block; }
    #message.ok { color:#075c45; background:#dff3e9; }
    #message.error { color:#8a292c; background:#f8dddd; }
    .footer { display:flex; justify-content:space-between; align-items:center; gap:18px; margin-top:22px; color:var(--muted); font-size:12px; }
    code { font-family:ui-monospace,SFMono-Regular,Consolas,monospace; color:var(--green-dark); }
    @media (max-width:820px) { main{padding-top:34px}.hero,.grid{grid-template-columns:1fr}.trust{display:none}.two{grid-template-columns:1fr}.card{padding:22px;border-radius:22px}.footer{align-items:flex-start;flex-direction:column} }
  </style>
</head>
<body>
<main>
  <section class="hero">
    <div>
      <div class="eyebrow">Lokálna správa dôvery</div>
      <h1>CCG &amp; ITHZ MCP nastavenia</h1>
      <p class="lead">Pripojte nezávislých oponentov Gemini a xAI bez uloženia API kľúčov do projektu, Git-u alebo pamäte ITHZ.</p>
    </div>
    <aside class="trust"><strong>Len tento počítač</strong><span>Stránka počúva iba na 127.0.0.1. Kľúč chráni Windows DPAPI pre aktuálneho používateľa.</span></aside>
  </section>

  <section class="grid">
    <article class="card">
      <h2>Modely a prístup</h2>
      <p class="card-intro">Gemini 3.7 Flash je predvolený druhý oponent, Grok alternatíva a Daybreak adaptívny bezpečnostný oponent.</p>
      <div class="status-row">
        <span id="geminiBadge" class="badge"><i class="dot"></i><span>Gemini sa kontroluje…</span></span>
        <span id="xaiBadge" class="badge"><i class="dot"></i><span>xAI sa kontroluje…</span></span>
      </div>

      <div class="field">
        <label for="geminiKey">Gemini API kľúč</label>
        <input id="geminiKey" type="password" autocomplete="new-password" spellcheck="false" placeholder="AIza…">
        <span class="hint">Predvolený cross-lab oponent. Existujúci kľúč sa nikdy neposiela späť do prehliadača.</span>
      </div>

      <div class="field">
        <label for="xaiKey">xAI API kľúč</label>
        <input id="xaiKey" type="password" autocomplete="new-password" spellcheck="false" placeholder="xai-…">
        <span class="hint">Existujúci kľúč sa nikdy neposiela späť do prehliadača. Prázdne pole ho nemení.</span>
      </div>

      <div class="two">
        <div class="field">
          <label for="codexModel">Codex model</label>
          <input id="codexModel" autocomplete="off" spellcheck="false">
        </div>
        <div class="field">
          <label for="geminiModel">Gemini model</label>
          <input id="geminiModel" autocomplete="off" spellcheck="false">
        </div>
      </div>
      <div class="two">
        <div class="field"><label for="grokModel">Grok model</label><input id="grokModel" autocomplete="off" spellcheck="false"></div>
        <div class="field"><label for="daybreakModel">Daybreak model</label><input id="daybreakModel" autocomplete="off" spellcheck="false"></div>
      </div>
      <div class="two">
        <div class="field">
          <label for="effort">Reasoning effort</label>
          <select id="effort"><option>low</option><option>medium</option><option>high</option><option>xhigh</option></select>
        </div>
        <div class="field">
          <label for="timeout">Timeout jednej roly (s)</label>
          <input id="timeout" type="number" min="30" max="1800" step="10">
        </div>
      </div>
      <div class="two">
        <div class="field"><label for="opponent2">Predvolený druhý oponent</label><select id="opponent2"><option value="gemini">Gemini</option><option value="grok">Grok</option></select></div>
        <div class="field"><label for="daybreakPolicy">Daybreak politika</label><select id="daybreakPolicy"><option value="high_and_critical">high + critical</option><option value="always">vždy</option><option value="off">vypnuté</option></select></div>
      </div>

      <div class="actions">
        <button id="save" class="primary">Uložiť nastavenia</button>
        <button id="testGemini" class="secondary">Overiť Gemini</button>
        <button id="test" class="secondary">Overiť xAI</button>
        <button id="removeGemini" class="danger">Odstrániť Gemini kľúč</button>
        <button id="remove" class="danger">Odstrániť kľúč</button>
      </div>
      <div id="message" role="status" aria-live="polite"></div>
      <div class="note"><strong>Priorita konfigurácie:</strong> <code>GEMINI_API_KEY</code> a <code>XAI_API_KEY</code> majú prednosť pred DPAPI. Modelové premenné <code>CCG_*</code> majú prednosť pred touto stránkou.</div>
    </article>

    <aside class="card">
      <h2>Čo sa stane po uložení</h2>
      <p class="card-intro">Nie je potrebné kopírovať kľúč do MCP konfigurácie.</p>
      <ol class="flow">
        <li><div><strong>Windows zašifruje kľúč</strong><span>Zašifrovaný blob vie otvoriť iba aktuálny používateľ.</span></div></li>
        <li><div><strong>MCP ho načíta pri štarte</strong><span>Stav ukáže „xAI pripojené“, nikdy však samotnú hodnotu.</span></div></li>
        <li><div><strong>Externý model dostane iba námietkovú rolu</strong><span>Gemini ani Grok nemajú broker, token alebo schopnosť vykonať akciu.</span></div></li>
        <li><div><strong>Rozhodca zostáva anonymný</strong><span>Nevidí laboratórium, model ani informáciu o fallbacku.</span></div></li>
      </ol>
    </aside>
  </section>

  <div class="footer"><span>Nastavenia sú používateľské a platia pre všetky projekty CCG &amp; ITHZ MCP.</span><button id="shutdown" class="ghost">Zavrieť stránku nastavení</button></div>
</main>
<script nonce="__NONCE__">
  const csrf = "__CSRF__";
  const $ = id => document.getElementById(id);
  const message = (text, ok=true) => { const box=$("message"); box.textContent=text; box.className="show " + (ok?"ok":"error"); };
  const busy = state => ["save","testGemini","test","removeGemini","remove"].forEach(id => $(id).disabled=state);
  async function api(path, options={}) {
    const response = await fetch(path, { ...options, headers:{"Content-Type":"application/json","X-CCG-CSRF":csrf,...(options.headers||{})}, credentials:"same-origin" });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Požiadavka zlyhala.");
    return data;
  }
  function paint(data) {
    const stored=data.stored_preferences, xai=data.xai, gemini=data.gemini;
    $("codexModel").value=stored.codex_model; $("geminiModel").value=stored.gemini_model; $("grokModel").value=stored.grok_model; $("daybreakModel").value=stored.daybreak_model; $("effort").value=stored.codex_effort; $("timeout").value=stored.codex_timeout; $("opponent2").value=stored.opponent_2_provider; $("daybreakPolicy").value=stored.daybreak_policy;
    $("geminiBadge").classList.toggle("ok",gemini.configured); $("geminiBadge").querySelector("span").textContent=gemini.configured?"Gemini kľúč je nastavený":"Gemini kľúč chýba";
    $("xaiBadge").classList.toggle("ok",xai.configured); $("xaiBadge").querySelector("span").textContent=xai.configured?"xAI kľúč je nastavený":"xAI kľúč chýba";
  }
  async function load(){ try{ paint(await api("/api/status")); }catch(error){ message(error.message,false); } }
  $("save").addEventListener("click",async()=>{ busy(true); try{ const data=await api("/api/settings",{method:"POST",body:JSON.stringify({gemini_key:$("geminiKey").value,xai_key:$("xaiKey").value,preferences:{codex_model:$("codexModel").value,gemini_model:$("geminiModel").value,grok_model:$("grokModel").value,daybreak_model:$("daybreakModel").value,opponent_2_provider:$("opponent2").value,daybreak_policy:$("daybreakPolicy").value,codex_effort:$("effort").value,codex_timeout:Number($("timeout").value)}})}); $("geminiKey").value=""; $("xaiKey").value=""; paint(data); message("Nastavenia boli bezpečne uložené."); }catch(error){message(error.message,false)}finally{busy(false)}});
  $("testGemini").addEventListener("click",async()=>{ busy(true); message("Overujem spojenie s Gemini…"); try{const data=await api("/api/test-gemini",{method:"POST",body:"{}"}); message(data.message + (data.model_visible===false?" Model nie je v zozname účtu.":""),data.ok)}catch(error){message(error.message,false)}finally{busy(false)}});
  $("test").addEventListener("click",async()=>{ busy(true); message("Overujem spojenie s xAI…"); try{const data=await api("/api/test-xai",{method:"POST",body:"{}"}); message(data.message + (data.model_visible===false?" Model nie je v zozname účtu.":""),data.ok)}catch(error){message(error.message,false)}finally{busy(false)}});
  $("removeGemini").addEventListener("click",async()=>{ if(!confirm("Odstrániť uložený Gemini kľúč z MCP?"))return; busy(true); try{paint(await api("/api/delete-gemini-key",{method:"POST",body:"{}"}));message("Uložený Gemini kľúč bol odstránený.")}catch(error){message(error.message,false)}finally{busy(false)}});
  $("remove").addEventListener("click",async()=>{ if(!confirm("Odstrániť uložený xAI kľúč z MCP?"))return; busy(true); try{paint(await api("/api/delete-key",{method:"POST",body:"{}"}));message("Uložený kľúč bol odstránený.")}catch(error){message(error.message,false)}finally{busy(false)}});
  $("shutdown").addEventListener("click",async()=>{ try{await api("/api/shutdown",{method:"POST",body:"{}"}); document.body.innerHTML="<main><section class='card'><h2>Stránka nastavení je zatvorená.</h2><p class='card-intro'>Môžete zavrieť túto kartu.</p></section></main>"}catch(error){message(error.message,false)} });
  load();
</script>
</body>
</html>"""


class SettingsHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int]) -> None:
        self.session_token = secrets.token_urlsafe(32)
        self.csrf_token = secrets.token_urlsafe(32)
        self.csp_nonce = secrets.token_urlsafe(18)
        super().__init__(address, SettingsHandler)

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"

    @property
    def bootstrap_url(self) -> str:
        return f"{self.origin}/?token={self.session_token}"


class SettingsHandler(BaseHTTPRequestHandler):
    server: SettingsHTTPServer

    def log_message(self, format: str, *args: Any) -> None:
        del format, args

    def _host_valid(self) -> bool:
        return self.headers.get("Host", "") == f"127.0.0.1:{self.server.server_address[1]}"

    def _session_valid(self) -> bool:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except Exception:
            return False
        value = cookie.get("ccg_settings_session")
        return bool(value and hmac.compare_digest(value.value, self.server.session_token))

    def _csrf_valid(self) -> bool:
        origin = self.headers.get("Origin", "")
        token = self.headers.get("X-CCG-CSRF", "")
        return (
            origin == self.server.origin
            and token
            and hmac.compare_digest(token, self.server.csrf_token)
        )

    def _headers(self, status: int, content_type: str, length: int) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            f"default-src 'none'; style-src 'nonce-{self.server.csp_nonce}'; "
            f"script-src 'nonce-{self.server.csp_nonce}'; connect-src 'self'; "
            "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        )
        self.end_headers()

    def _json(self, value: Any, status: int = HTTPStatus.OK) -> None:
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(encoded))
        self.wfile.write(encoded)

    def _error(self, status: int, message: str) -> None:
        self._json({"error": message}, status)

    def _read_json(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid_content_length") from exc
        if length < 0 or length > MAX_BODY_BYTES:
            raise ValueError("request_body_too_large")
        if self.headers.get_content_type() != "application/json":
            raise ValueError("content_type_must_be_application_json")
        value = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        if not isinstance(value, dict):
            raise ValueError("json_body_must_be_object")
        return value

    def _discard_bounded_body(self) -> None:
        """Drain small rejected POST bodies so Windows can deliver the error response before close."""

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return
        if 0 < length <= MAX_BODY_BYTES:
            self.rfile.read(length)

    def do_GET(self) -> None:
        if not self._host_valid():
            self._error(HTTPStatus.BAD_REQUEST, "invalid_host")
            return
        parsed = urlparse(self.path)
        if parsed.path == "/" and parse_qs(parsed.query).get("token", [""])[0]:
            token = parse_qs(parsed.query).get("token", [""])[0]
            if not hmac.compare_digest(token, self.server.session_token):
                self._error(HTTPStatus.FORBIDDEN, "invalid_session")
                return
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/")
            self.send_header(
                "Set-Cookie",
                f"ccg_settings_session={self.server.session_token}; Path=/; HttpOnly; SameSite=Strict",
            )
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return
        if not self._session_valid():
            self._error(HTTPStatus.FORBIDDEN, "settings_session_required")
            return
        if parsed.path == "/":
            page = PAGE.replace("__NONCE__", self.server.csp_nonce).replace("__CSRF__", self.server.csrf_token)
            encoded = page.encode("utf-8")
            self._headers(HTTPStatus.OK, "text/html; charset=utf-8", len(encoded))
            self.wfile.write(encoded)
            return
        if parsed.path == "/api/status":
            self._json(settings_status())
            return
        if parsed.path == "/favicon.ico":
            self._headers(HTTPStatus.NO_CONTENT, "image/x-icon", 0)
            return
        self._error(HTTPStatus.NOT_FOUND, "not_found")

    def do_POST(self) -> None:
        if not self._host_valid():
            self._discard_bounded_body()
            self._error(HTTPStatus.BAD_REQUEST, "invalid_host")
            return
        if not self._session_valid() or not self._csrf_valid():
            self._discard_bounded_body()
            self._error(HTTPStatus.FORBIDDEN, "csrf_or_session_invalid")
            return
        try:
            payload = self._read_json()
            if self.path == "/api/settings":
                preferences = payload.get("preferences", {})
                if not isinstance(preferences, dict):
                    raise ValueError("preferences_must_be_object")
                save_preferences(preferences)
                key = payload.get("xai_key", "")
                if not isinstance(key, str):
                    raise ValueError("xai_key_must_be_string")
                if key.strip():
                    save_xai_key(key)
                gemini_key = payload.get("gemini_key", "")
                if not isinstance(gemini_key, str):
                    raise ValueError("gemini_key_must_be_string")
                if gemini_key.strip():
                    save_gemini_key(gemini_key)
                self._json(settings_status())
                return
            if self.path == "/api/delete-key":
                delete_xai_key()
                self._json(settings_status())
                return
            if self.path == "/api/delete-gemini-key":
                delete_gemini_key()
                self._json(settings_status())
                return
            if self.path == "/api/test-xai":
                self._json(test_xai_connection())
                return
            if self.path == "/api/test-gemini":
                self._json(test_gemini_connection())
                return
            if self.path == "/api/shutdown":
                self._json({"stopping": True})
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return
            self._error(HTTPStatus.NOT_FOUND, "not_found")
        except (ValueError, json.JSONDecodeError) as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
        except RuntimeError as exc:
            self._error(HTTPStatus.NOT_IMPLEMENTED, str(exc))


def create_settings_server(port: int = 0) -> SettingsHTTPServer:
    if not 0 <= int(port) <= 65535:
        raise ValueError("invalid_settings_port")
    return SettingsHTTPServer(("127.0.0.1", int(port)))


def run_settings_server(port: int = 0, open_browser: bool = True) -> int:
    server = create_settings_server(port)
    print(f"CCG & ITHZ settings: {server.bootstrap_url}", flush=True)
    if open_browser:
        webbrowser.open(server.bootstrap_url, new=2)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Open the local CCG & ITHZ MCP settings page.")
    parser.add_argument("--port", type=int, default=0, help="Loopback port; 0 selects an available port.")
    parser.add_argument("--no-open", action="store_true", help="Print the protected URL without opening a browser.")
    args = parser.parse_args(argv)
    return run_settings_server(args.port, not args.no_open)


if __name__ == "__main__":
    raise SystemExit(main())
