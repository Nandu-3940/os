import os
import hashlib
import secrets
import sqlite3
import base64
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import re
import pyotp
import jwt
import time
import uuid
import tempfile

class SecureFileManagementSystem:
    def __init__(self, database_path='secure_file_system.db'):
        logging.basicConfig(level=logging.INFO, 
                            format='%(asctime)s - %(levelname)s: %(message)s')
        self.logger = logging.getLogger(__name__)

        self.conn = sqlite3.connect(database_path)
        self.cursor = self.conn.cursor()

        self._create_tables()
        self._migrate_database_schema()

        self.temp_storage = tempfile.mkdtemp(prefix='secure_file_system_')

    def _migrate_database_schema(self):
        try:
            self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            if not self.cursor.fetchone():
                self.logger.info("Users table not found; skipping migration")
                return

            self.cursor.execute("PRAGMA table_info(users)")
            columns = [column[1] for column in self.cursor.fetchall()]
            
            if 'two_factor_enabled' not in columns:
                self.logger.info("Adding two_factor_enabled column to users table")
                self.cursor.execute('''
                    ALTER TABLE users 
                    ADD COLUMN two_factor_enabled BOOLEAN DEFAULT 0
                ''')
                self.conn.commit()

        except sqlite3.OperationalError as e:
            self.logger.error(f"Database migration error: {e}")
            raise

    def _create_tables(self):
        self.cursor.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                two_factor_secret TEXT,
                two_factor_enabled BOOLEAN DEFAULT 0,
                is_admin BOOLEAN DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS files (
                file_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                owner TEXT NOT NULL,
                encrypted_key TEXT NOT NULL,
                metadata TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                permissions TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS file_access_log (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id TEXT,
                username TEXT,
                access_type TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        ''')
        self.conn.commit()

    def _hash_password(self, password, salt=None):
        if salt is None:
            salt = secrets.token_hex(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode(),
            iterations=100000
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key.decode(), salt

    def register_user(self, username, password, is_admin=False, enable_two_factor=False):
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            raise ValueError("Invalid username format")
        if (len(password) < 12 or 
            not re.search(r'[A-Z]', password) or 
            not re.search(r'[a-z]', password) or 
            not re.search(r'\d', password) or 
            not re.search(r'[!@#$%^&*(),.?":{}|<>]', password)):
            raise ValueError("Password does not meet complexity requirements")

        hashed_password, salt = self._hash_password(password)
        two_factor_secret = pyotp.random_base32() if enable_two_factor else None

        try:
            self.cursor.execute('''
                INSERT INTO users 
                (username, password_hash, salt, two_factor_secret, two_factor_enabled, is_admin) 
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, hashed_password, salt, two_factor_secret, enable_two_factor, is_admin))
            self.conn.commit()
            self.logger.info(f"User {username} registered successfully")
            return two_factor_secret
        except sqlite3.IntegrityError:
            raise ValueError("Username already exists")

    def authenticate_user(self, username, password):
        self.cursor.execute('''
            SELECT password_hash, salt 
            FROM users 
            WHERE username = ?
        ''', (username,))
        result = self.cursor.fetchone()
        
        if not result:
            raise ValueError("User not found")
        
        stored_hash, salt = result
        hashed_input, _ = self._hash_password(password, salt)
        
        if hashed_input != stored_hash:
            raise ValueError("Incorrect password")
        
        payload = {
            'username': username,
            'exp': time.time() + 3600
        }
        token = jwt.encode(payload, 'secret_key', algorithm='HS256')
        self.logger.info(f"User {username} authenticated successfully")
        return token

    def enable_two_factor(self, username):
        self.cursor.execute('''
            SELECT two_factor_enabled 
            FROM users 
            WHERE username = ?
        ''', (username,))
        result = self.cursor.fetchone()
        
        if not result:
            raise ValueError("User not found")
        
        if result[0]:
            raise ValueError("Two-factor authentication already enabled")
        
        two_factor_secret = pyotp.random_base32()
        self.cursor.execute('''
            UPDATE users 
            SET two_factor_secret = ?, two_factor_enabled = 1 
            WHERE username = ?
        ''', (two_factor_secret, username))
        self.conn.commit()
        
        self.logger.info(f"Two-factor authentication enabled for {username}")
        return two_factor_secret

    def cleanup(self):
        import shutil
        shutil.rmtree(self.temp_storage, ignore_errors=True)
        self.conn.close()
        self.logger.info("System cleanup completed")

def main():
    if os.path.exists('secure_file_system.db'):
        os.remove('secure_file_system.db')

    file_system = SecureFileManagementSystem()
    print("Welcome to the Secure File Management System!")
    
    while True:
        print("\nOptions:")
        print("1. Register a new user")
        print("2. Authenticate a user")
        print("3. Enable two-factor authentication")
        print("4. Exit")
        
        choice = input("Enter your choice (1-4): ").strip()
        
        if choice == '1':
            username = input("Enter username: ").strip()
            password = input("Enter password: ").strip()
            is_admin = input("Is this user an admin? (y/n): ").strip().lower() == 'y'
            enable_2fa = input("Enable two-factor authentication? (y/n): ").strip().lower() == 'y'
            
            try:
                two_factor_secret = file_system.register_user(username, password, is_admin, enable_2fa)
                if two_factor_secret:
                    print(f"Two-factor secret: {two_factor_secret}")
            except ValueError as e:
                print(f"Error: {e}")

        elif choice == '2':
            username = input("Enter username: ").strip()
            password = input("Enter password: ").strip()
            
            try:
                token = file_system.authenticate_user(username, password)
                print(f"Authentication successful! Token: {token}")
            except ValueError as e:
                print(f"Error: {e}")

        elif choice == '3':
            username = input("Enter username: ").strip()
            
            try:
                two_factor_secret = file_system.enable_two_factor(username)
                print(f"Two-factor authentication enabled! Secret: {two_factor_secret}")
            except ValueError as e:
                print(f"Error: {e}")

        elif choice == '4':
            print("Exiting...")
            file_system.cleanup()
            break
        
        else:
            print("Invalid choice. Please enter a number between 1 and 4.")

if __name__ == '__main__':
    main()