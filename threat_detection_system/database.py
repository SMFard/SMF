import sqlite3
from datetime import datetime

DB_NAME = 'threat_detection.db'

def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    # Create tables if not exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blacklist_urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            added_on TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS suspicious_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            added_on TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            target_type TEXT,
            description TEXT,
            severity TEXT,
            analyzed_on TEXT
        )
    ''')
    conn.commit()
    conn.close()

def add_blacklist_url(url):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT OR IGNORE INTO blacklist_urls (url, added_on) VALUES (?, ?)', (url, datetime.utcnow().isoformat()))
        conn.commit()
    finally:
        conn.close()

def get_blacklist_urls():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT url FROM blacklist_urls')
    rows = cursor.fetchall()
    conn.close()
    return [row['url'] for row in rows]

def add_suspicious_ip(ip):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT OR IGNORE INTO suspicious_ips (ip, added_on) VALUES (?, ?)', (ip, datetime.utcnow().isoformat()))
        conn.commit()
    finally:
        conn.close()

def get_suspicious_ips():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT ip FROM suspicious_ips')
    rows = cursor.fetchall()
    conn.close()
    return [row['ip'] for row in rows]

def save_analysis_report(target, target_type, description, severity):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO analysis_reports (target, target_type, description, severity, analyzed_on)
            VALUES (?, ?, ?, ?, ?)
        ''', (target, target_type, description, severity, datetime.utcnow().isoformat()))
        conn.commit()
    finally:
        conn.close()
