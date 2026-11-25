"""Sistema Academico SecureDev - version remediada.

Correcciones respecto al codigo original (ver informe EV3):
  V1 SQL Injection           -> consultas parametrizadas
  V2 XSS almacenado          -> plantillas Jinja con autoescape (sin f-strings en HTML)
  V3 SSTI (inyeccion Jinja)  -> los datos nunca forman parte del codigo de la plantilla
  V4 CSRF                    -> token aleatorio por sesion en todos los POST
  V5 Sesion falsificable     -> sesion firmada de Flask (SECRET_KEY) + flags HttpOnly/SameSite
  V6 Passwords en claro      -> hash PBKDF2/scrypt (werkzeug.security)
  V7 Fuerza bruta            -> bloqueo temporal tras 5 intentos fallidos
  V8 Debug en produccion     -> debug desactivado, servidor gunicorn
  V9 Cabeceras ausentes      -> CSP, X-Frame-Options, nosniff, etc.
Ademas expone metricas de seguridad para Prometheus/Grafana y registra eventos de auditoria.
"""
import json
import logging
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque

from flask import Flask, abort, g, redirect, render_template_string, request, session
from prometheus_client import Counter, Histogram, start_http_server
from werkzeug.security import check_password_hash

DATABASE = os.environ.get('DATABASE', 'securedev.db')
MAX_FAILED = 5
LOCK_WINDOW = 300  # segundos
BIO_MAX = 280

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY') or secrets.token_hex(32),
    SESSION_COOKIE_NAME='sd_session',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE', '0') == '1',
    PERMANENT_SESSION_LIFETIME=1800,
    MAX_CONTENT_LENGTH=16 * 1024,
)

# --- Auditoria y metricas ------------------------------------------------------
audit = logging.getLogger('audit')
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter('%(message)s'))
audit.addHandler(_handler)
audit.setLevel(logging.INFO)

LOGIN_ATTEMPTS = Counter('securedev_login_attempts', 'Intentos de login', ['result'])
SUSPICIOUS = Counter('securedev_suspicious_input', 'Entradas con patrones de ataque', ['type'])
CSRF_REJECTED = Counter('securedev_csrf_rejected', 'Peticiones rechazadas por token CSRF invalido')
HTTP_REQUESTS = Counter('securedev_http_requests', 'Peticiones HTTP', ['endpoint', 'method', 'status'])
HTTP_LATENCY = Histogram('securedev_http_request_duration_seconds', 'Latencia HTTP', ['endpoint'])

ATTACK_PATTERNS = {
    'sqli': re.compile(r"('|--|;|/\*|\b(union|select|or|and)\b\s.*(=|from|select))", re.I),
    'xss': re.compile(r'(<\s*script|javascript:|on\w+\s*=|<\s*iframe|<\s*img)', re.I),
    'ssti': re.compile(r'(\{\{|\{%|\$\{)'),
}

_metrics_port = int(os.environ.get('METRICS_PORT', '9102'))
if _metrics_port:
    # Puerto interno: solo accesible desde la red de Docker (Prometheus), no se publica al host
    start_http_server(_metrics_port)


def log_event(event, **data):
    data.update(event=event, ip=request.remote_addr, ts=time.strftime('%Y-%m-%dT%H:%M:%S'))
    audit.info(json.dumps(data, ensure_ascii=False))


def inspect_input(field, value):
    for kind, pattern in ATTACK_PATTERNS.items():
        if value and pattern.search(value):
            SUSPICIOUS.labels(type=kind).inc()
            log_event('entrada_sospechosa', campo=field, tipo=kind, muestra=value[:60])


# --- Base de datos (V1: siempre parametrizada) -----------------------------------
def db_query(query, params=(), one=False):
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute(query, params)
        rows = cur.fetchall()
        conn.commit()
    finally:
        conn.close()
    return (rows[0] if rows else None) if one else rows


# --- CSRF (V4) -----------------------------------------------------------------
def csrf_token():
    if '_csrf' not in session:
        session['_csrf'] = secrets.token_urlsafe(32)
    return session['_csrf']


@app.before_request
def before():
    g.start = time.perf_counter()
    if request.method == 'POST':
        sent = request.form.get('_csrf', '')
        if not sent or not secrets.compare_digest(sent, session.get('_csrf', '')):
            CSRF_REJECTED.inc()
            log_event('csrf_rechazado', ruta=request.path)
            abort(403)


# --- Cabeceras de seguridad (V9) -------------------------------------------------
@app.after_request
def security_headers(resp):
    resp.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'none'; style-src 'self'; img-src 'self'; "
        "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    resp.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    resp.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    resp.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    resp.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    resp.headers['Cache-Control'] = 'no-store'
    resp.headers['Server'] = 'SecureDev'
    endpoint = request.url_rule.rule if request.url_rule else 'desconocido'
    HTTP_REQUESTS.labels(endpoint, request.method, resp.status_code).inc()
    HTTP_LATENCY.labels(endpoint).observe(time.perf_counter() - g.get('start', time.perf_counter()))
    return resp


# --- Fuerza bruta (V7) -----------------------------------------------------------
_failures = defaultdict(deque)


def is_locked(key):
    q = _failures[key]
    while q and q[0] < time.time() - LOCK_WINDOW:
        q.popleft()
    return len(q) >= MAX_FAILED


# --- Vistas (V2/V3: plantillas fijas, datos como variables escapadas) -----------
LOGIN_HTML = '''<!doctype html><title>Login</title>
<h2>Login del Sistema Académico</h2>
{% if error %}<p><b>{{ error }}</b></p>{% endif %}
<form method="post">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  Usuario: <input type="text" name="username" maxlength="50" required><br>
  Password: <input type="password" name="password" maxlength="128" required><br>
  <input type="submit" value="Ingresar">
</form>'''

DASHBOARD_HTML = '''<!doctype html><title>Panel</title>
<h1>Panel de {{ u['username'] }}</h1>
<p><b>Rol:</b> {{ u['rol'] }}</p>
<p><b>Biografía:</b> {{ u['bio'] }}</p>
<hr>
<h3>Actualizar Biografía</h3>
<form action="/update_bio" method="POST">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  <input type="text" name="nueva_bio" maxlength="{{ bio_max }}" placeholder="Escribe algo...">
  <input type="submit" value="Guardar Cambios">
</form>
<form action="/logout" method="POST">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  <input type="submit" value="Cerrar Sesión">
</form>'''


@app.route('/login', methods=['GET', 'POST'])
def login():
    error, status = None, 200
    if request.method == 'POST':
        user = (request.form.get('username') or '').strip()[:50]
        pw = request.form.get('password') or ''
        inspect_input('username', user)
        key = f'{request.remote_addr}|{user.lower()}'
        if is_locked(key):
            LOGIN_ATTEMPTS.labels(result='blocked').inc()
            log_event('login_bloqueado', usuario=user)
            return render_template_string(LOGIN_HTML, csrf=csrf_token(),
                                          error='Demasiados intentos. Espere 5 minutos.'), 429
        row = db_query('SELECT * FROM usuarios WHERE username = ?', (user,), one=True)
        if row and check_password_hash(row['password'], pw):
            _failures.pop(key, None)
            session.clear()  # evita fijacion de sesion
            session['uid'] = row['id']
            session.permanent = True
            LOGIN_ATTEMPTS.labels(result='success').inc()
            log_event('login_exitoso', usuario=user)
            return redirect('/dashboard')
        _failures[key].append(time.time())
        LOGIN_ATTEMPTS.labels(result='failure').inc()
        log_event('login_fallido', usuario=user)
        error, status = 'Acceso denegado', 401
    return render_template_string(LOGIN_HTML, csrf=csrf_token(), error=error), status


def current_user():
    uid = session.get('uid')
    return db_query('SELECT id, username, rol, bio FROM usuarios WHERE id = ?', (uid,), one=True) if uid else None


@app.route('/dashboard')
def dashboard():
    u = current_user()
    if not u:
        return redirect('/login')
    return render_template_string(DASHBOARD_HTML, u=u, csrf=csrf_token(), bio_max=BIO_MAX)


@app.route('/update_bio', methods=['POST'])
def update_bio():
    u = current_user()
    if not u:
        return redirect('/login')
    bio = (request.form.get('nueva_bio') or '').strip()
    if len(bio) > BIO_MAX:
        abort(400)
    inspect_input('nueva_bio', bio)
    db_query('UPDATE usuarios SET bio = ? WHERE id = ?', (bio, u['id']))
    log_event('bio_actualizada', usuario=u['username'])
    return redirect('/dashboard')


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect('/login')


@app.route('/')
def home():
    return redirect('/login')


if __name__ == '__main__':
    # Solo desarrollo local; en produccion se usa gunicorn (ver Dockerfile). Nunca debug=True.
    app.run(host='127.0.0.1', port=5000, debug=False)
