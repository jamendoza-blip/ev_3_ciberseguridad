"""Pruebas de seguridad automatizadas (se ejecutan en la etapa 'Security Tests' del pipeline).

Cada prueba expresa un requisito de seguridad. Sobre el codigo vulnerable original
fallan; despues de la remediacion deben pasar todas.
"""
import importlib
import inspect
import os
import re
import sqlite3
import sys

import pytest

APP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'app')
sys.path.insert(0, APP_DIR)

PASSWORDS = {'admin': 'admin123', 'alumno': '12345'}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('DATABASE', str(tmp_path / 'test.db'))
    monkeypatch.setenv('SECRET_KEY', 'clave-solo-para-pruebas')
    monkeypatch.setenv('METRICS_PORT', '0')  # no abrir puerto de metricas en pruebas
    for mod in ('app', 'init_db'):
        sys.modules.pop(mod, None)
    init_db = importlib.import_module('init_db')
    init_db.crear_base_de_datos()
    app_module = importlib.import_module('app')
    app_module.app.config['TESTING'] = True
    with app_module.app.test_client() as c:
        c.db_path = os.environ['DATABASE'] if os.path.exists(os.environ['DATABASE']) else str(tmp_path / 'vulnerable.db')
        yield c


def csrf_from(html):
    m = re.search(r'name="_csrf" value="([^"]+)"', html)
    return m.group(1) if m else ''


def login(client, username, password):
    token = csrf_from(client.get('/login').get_data(as_text=True))
    return client.post('/login', data={'username': username, 'password': password, '_csrf': token})


def update_bio(client, bio):
    token = csrf_from(client.get('/dashboard').get_data(as_text=True))
    return client.post('/update_bio', data={'nueva_bio': bio, '_csrf': token})


# --- A03 Inyeccion -----------------------------------------------------------
def test_sqli_no_permite_saltar_login(client):
    resp = login(client, "admin' --", 'cualquiera')
    assert resp.status_code != 302, 'SQL injection permite iniciar sesion sin password'


def test_sqli_or_1_1(client):
    resp = login(client, "x' OR '1'='1", "x' OR '1'='1")
    assert resp.status_code != 302


def test_xss_almacenado_se_escapa(client):
    assert login(client, 'alumno', PASSWORDS['alumno']).status_code == 302
    update_bio(client, '<script>alert(1)</script>')
    body = client.get('/dashboard').get_data(as_text=True)
    assert '<script>alert(1)</script>' not in body


def test_ssti_no_se_evalua(client):
    assert login(client, 'alumno', PASSWORDS['alumno']).status_code == 302
    update_bio(client, '{{7*7}}')
    body = client.get('/dashboard').get_data(as_text=True)
    assert '49' not in body, 'La biografia se evalua como plantilla Jinja (SSTI)'


# --- A01 / CSRF --------------------------------------------------------------
def test_csrf_sin_token_es_rechazado(client):
    assert login(client, 'alumno', PASSWORDS['alumno']).status_code == 302
    resp = client.post('/update_bio', data={'nueva_bio': 'ESTA CUENTA FUE HACKEADA'})
    assert resp.status_code in (400, 403)
    assert 'HACKEADA' not in client.get('/dashboard').get_data(as_text=True)


# --- A07 Autenticacion y sesiones -------------------------------------------
def test_cookie_de_sesion_no_es_falsificable(client):
    # Un atacante fija a mano la cookie del original ('user_session=admin')
    if 'server_name' in inspect.signature(client.set_cookie).parameters:  # Werkzeug < 2.3
        client.set_cookie('localhost', 'user_session', 'admin')
    else:
        client.set_cookie('user_session', 'admin')
    resp = client.get('/dashboard')
    assert resp.status_code == 302 and '/login' in resp.headers['Location']


def test_cookie_con_flags_de_seguridad(client):
    resp = login(client, 'alumno', PASSWORDS['alumno'])
    cookie = ' '.join(resp.headers.getlist('Set-Cookie'))
    assert 'HttpOnly' in cookie
    assert 'SameSite' in cookie


def test_bloqueo_por_fuerza_bruta(client):
    for _ in range(5):
        login(client, 'admin', 'incorrecta')
    resp = login(client, 'admin', PASSWORDS['admin'])
    assert resp.status_code == 429, 'No hay limite de intentos fallidos'


# --- A02 Fallas criptograficas ----------------------------------------------
def test_passwords_no_en_texto_plano(client):
    conn = sqlite3.connect(client.db_path)
    rows = conn.execute('SELECT username, password FROM usuarios').fetchall()
    conn.close()
    for username, stored in rows:
        assert stored != PASSWORDS.get(username), f'Password de {username} en texto plano'


# --- A05 Configuracion de seguridad -----------------------------------------
def test_cabeceras_de_seguridad(client):
    resp = client.get('/login')
    for header in ('Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options'):
        assert header in resp.headers, f'Falta cabecera {header}'
