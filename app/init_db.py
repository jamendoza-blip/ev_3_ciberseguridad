"""Crea la base de datos con passwords hasheadas (V6).

Las passwords de los usuarios de laboratorio pueden sobreescribirse por variables de entorno.
"""
import os
import sqlite3

from werkzeug.security import generate_password_hash

DATABASE = os.environ.get('DATABASE', 'securedev.db')


def crear_base_de_datos():
    conexion = sqlite3.connect(DATABASE)
    cursor = conexion.cursor()
    cursor.execute('DROP TABLE IF EXISTS usuarios')
    cursor.execute('''
        CREATE TABLE usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            rol TEXT NOT NULL CHECK (rol IN ('admin', 'user')),
            bio TEXT
        )
    ''')
    usuarios = [
        ('admin', os.environ.get('SEED_ADMIN_PASSWORD', 'admin123'), 'admin', 'Cuenta de administrador del sistema.'),
        ('alumno', os.environ.get('SEED_ALUMNO_PASSWORD', '12345'), 'user', 'Soy un estudiante aprendiendo hacking.'),
    ]
    cursor.executemany(
        'INSERT INTO usuarios (username, password, rol, bio) VALUES (?, ?, ?, ?)',
        [(u, generate_password_hash(p), r, b) for u, p, r, b in usuarios],
    )
    conexion.commit()
    conexion.close()
    print('Base de datos inicializada con passwords hasheadas.')


if __name__ == '__main__':
    crear_base_de_datos()
