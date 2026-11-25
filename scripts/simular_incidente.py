"""Simula un incidente de seguridad contra produccion para validar el monitoreo (Grafana).

Fases: 1) trafico normal  2) fuerza bruta sobre 'admin'  3) inyecciones SQLi/XSS/SSTI  4) CSRF
Uso: python scripts/simular_incidente.py [http://127.0.0.1:5000]
Solo usar contra el laboratorio propio.
"""
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

BASE = sys.argv[1] if len(sys.argv) > 1 else 'http://127.0.0.1:5000'


def client():
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))


def req(op, path, data=None):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    try:
        with op.open(BASE + path, body, timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def token(html):
    m = re.search(r'name="_csrf" value="([^"]+)"', html)
    return m.group(1) if m else ''


def login(op, user, pw):
    _, html = req(op, '/login')
    return req(op, '/login', {'username': user, 'password': pw, '_csrf': token(html)})[0]


def fase(nombre):
    print(f'\n[{time.strftime("%H:%M:%S")}] === {nombre} ===')


fase('1. Trafico normal (usuario legitimo)')
for _ in range(5):
    op = client()
    print(' login alumno ->', login(op, 'alumno', '12345'), '| dashboard ->', req(op, '/dashboard')[0])
    time.sleep(1)

fase('2. Fuerza bruta contra admin (diccionario)')
op = client()
for pw in ['123456', 'password', 'admin', 'qwerty', 'letmein', 'root', 'toor', 'secret', 'admin1', 'pass']:
    print(f' admin/{pw:<9} ->', login(op, 'admin', pw))
    time.sleep(0.5)

fase('3. Inyecciones (SQLi / XSS / SSTI)')
for payload in ["admin' --", "x' OR '1'='1", "' UNION SELECT 1,2,3,4,5 --"]:
    print(f' SQLi {payload!r} ->', login(client(), payload, 'x'))
op = client()
login(op, 'alumno', '12345')
for bio in ['<script>alert(document.cookie)</script>', '<img src=x onerror=alert(1)>', '{{7*7}}',
            '{{cycler.__init__.__globals__.os.popen(request.args.c).read()}}']:
    _, html = req(op, '/dashboard')
    status, _ = req(op, '/update_bio', {'nueva_bio': bio, '_csrf': token(html)})
    print(f' bio {bio[:40]!r} ->', status)
_, html = req(op, '/dashboard')
req(op, '/update_bio', {'nueva_bio': 'Soy un estudiante aprendiendo hacking.', '_csrf': token(html)})

fase('4. CSRF (formulario externo sin token)')
for _ in range(3):
    print(' POST /update_bio sin token ->', req(op, '/update_bio', {'nueva_bio': 'ESTA CUENTA FUE HACKEADA'})[0])

print('\nListo. Revisar Grafana: http://localhost:3000 (dashboard SecureDev) y docker logs securedev-app')
