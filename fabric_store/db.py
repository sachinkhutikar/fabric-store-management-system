import sqlite3
from werkzeug.security import generate_password_hash
from datetime import datetime


def get_conn(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: str):
    conn = get_conn(db_path)
    cur = conn.cursor()

    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin','customer')),
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS fabrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        category TEXT,
        description TEXT,
        price REAL NOT NULL,
        stock INTEGER NOT NULL DEFAULT 0,
        image_path TEXT,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS fabric_images (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fabric_id INTEGER NOT NULL,
        image_path TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(fabric_id) REFERENCES fabrics(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS cart_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        fabric_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL,
        customization_json TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(fabric_id) REFERENCES fabrics(id) ON DELETE CASCADE
    );

    -- (Optional but recommended) Prevent duplicates of same fabric + same customization.
    CREATE UNIQUE INDEX IF NOT EXISTS ux_cart_user_fabric_custom
    ON cart_items(user_id, fabric_id, COALESCE(customization_json,''));

    CREATE TABLE IF NOT EXISTS wishlist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        fabric_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(user_id, fabric_id),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(fabric_id) REFERENCES fabrics(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS coupons (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT NOT NULL UNIQUE,
        discount_percent INTEGER NOT NULL CHECK(discount_percent >= 1 AND discount_percent <= 90),
        expiry_date TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        order_status TEXT NOT NULL CHECK(order_status IN (
            'ORDER_PLACED','PROCESSING','SHIPPED','OUT_FOR_DELIVERY','DELIVERED','CANCELLED'
        )),
        subtotal REAL NOT NULL,
        discount_amount REAL NOT NULL DEFAULT 0,
        coupon_code TEXT,
        total_amount REAL NOT NULL,
        shipping_name TEXT NOT NULL,
        shipping_phone TEXT NOT NULL,
        shipping_address TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        fabric_id INTEGER NOT NULL,
        fabric_name_snapshot TEXT NOT NULL,
        unit_price_snapshot REAL NOT NULL,
        quantity INTEGER NOT NULL,
        customization_json TEXT,
        line_total REAL NOT NULL,
        FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE,
        FOREIGN KEY(fabric_id) REFERENCES fabrics(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        method TEXT NOT NULL CHECK(method IN ('UPI','CARD','COD')),
        status TEXT NOT NULL CHECK(status IN ('PENDING','PAID','FAILED')),
        amount REAL NOT NULL,
        transaction_id TEXT,
        provider_order_id TEXT,
        provider_signature TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        fabric_id INTEGER NOT NULL,
        rating INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5),
        review_text TEXT,
        is_deleted INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(fabric_id) REFERENCES fabrics(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        message TEXT NOT NULL,
        is_read INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS stock_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fabric_id INTEGER NOT NULL,
        change_qty INTEGER NOT NULL,
        note TEXT,
        created_by INTEGER,
        created_at TEXT NOT NULL,
        FOREIGN KEY(fabric_id) REFERENCES fabrics(id) ON DELETE CASCADE,
        FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS order_status_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        status TEXT NOT NULL CHECK(status IN (
            'ORDER_PLACED','PROCESSING','SHIPPED','OUT_FOR_DELIVERY','DELIVERED','CANCELLED'
        )),
        note TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE
    );
    """)

    conn.commit()

    # Seed admin if not exists
    cur.execute("SELECT id FROM users WHERE role='admin' LIMIT 1")
    admin = cur.fetchone()
    if not admin:
        now = datetime.utcnow().isoformat()
        cur.execute("""
            INSERT INTO users (name, email, password_hash, role, created_at)
            VALUES (?, ?, ?, 'admin', ?)
        """, ("Admin", "tanvi@gmail.com", generate_password_hash("tanvi123"), now))
        conn.commit()

    conn.close()