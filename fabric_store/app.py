import os
import json
from io import BytesIO
from datetime import datetime, date
from functools import wraps
import re
import sqlite3

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    abort,
    send_file,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4

from fabric_store.config import Config
from fabric_store.db import init_db, get_conn


ALLOWED_IMG = {"png", "jpg", "jpeg", "webp"}
ALLOWED_DESIGN = {"png", "jpg", "jpeg", "pdf"}

ORDER_STATUSES = [
    "ORDER_PLACED",
    "PROCESSING",
    "SHIPPED",
    "OUT_FOR_DELIVERY",
    "DELIVERED",
    "CANCELLED",
]

STATUS_LABELS = {
    "ORDER_PLACED": "Order Placed",
    "PROCESSING": "Processing",
    "SHIPPED": "Shipped",
    "OUT_FOR_DELIVERY": "Out for Delivery",
    "DELIVERED": "Delivered",
    "CANCELLED": "Cancelled",
}

# ✅ Password rule used ONLY for REGISTER
PASSWORD_RE = re.compile(r"^(?=.*[^A-Za-z0-9]).{8,}$")  # 8+ chars, 1+ special char


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Ensure upload dirs exist
    os.makedirs(app.config["FABRIC_UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(app.config["DESIGN_UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(
        app.config.get("FABRIC_GALLERY_UPLOAD_FOLDER", "static/uploads/fabric_gallery"),
        exist_ok=True,
    )
    os.makedirs(app.config.get("QR_UPLOAD_FOLDER", "static/uploads/qr"), exist_ok=True)

    init_db(app.config["DB_PATH"])

    # -----------------------------
    # Helpers
    # -----------------------------
    def now_iso():
        return datetime.utcnow().isoformat()

    def db():
        return get_conn(app.config["DB_PATH"])

    def get_meters_from_customization(customization_json) -> float:
        """Extract length_m (meters) from customization_json. Default 1.0"""
        custom = {}
        if customization_json:
            try:
                custom = json.loads(customization_json)
            except Exception:
                custom = {}

        try:
            meters = float(custom.get("length_m") or 1)
        except Exception:
            meters = 1.0

        if meters <= 0:
            meters = 1.0

        return meters

    def current_user():
        uid = session.get("user_id")
        if not uid:
            return None
        conn = db()
        u = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        conn.close()
        return u

    def login_required(role=None):
        def decorator(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                if "user_id" not in session:
                    return redirect(url_for("login"))
                if role:
                    u = current_user()
                    if not u or u["role"] != role:
                        abort(403)
                return fn(*args, **kwargs)

            return wrapper

        return decorator

    def allowed_file(filename, allowed_set):
        return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_set

    def add_notification(n_type, message):
        conn = db()
        conn.execute(
            "INSERT INTO notifications (type, message, is_read, created_at) VALUES (?,?,0,?)",
            (n_type, message, now_iso()),
        )
        conn.commit()
        conn.close()

    def send_email(to_email, subject, body):
        # optional
        if not app.config.get("EMAIL_ENABLED"):
            return
        import smtplib
        from email.mime.text import MIMEText

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = app.config.get("FROM_EMAIL", "")
        msg["To"] = to_email

        with smtplib.SMTP(app.config["SMTP_HOST"], app.config["SMTP_PORT"]) as server:
            server.starttls()
            server.login(app.config["SMTP_USERNAME"], app.config["SMTP_PASSWORD"])
            server.sendmail(msg["From"], [to_email], msg.as_string())

    def check_low_stock_and_notify(fabric_id):
        conn = db()
        f = conn.execute(
            "SELECT id,name,stock FROM fabrics WHERE id=?", (fabric_id,)
        ).fetchone()
        conn.close()
        if f and f["stock"] < 10:
            add_notification("LOW_STOCK", f"Low stock: {f['name']} (Stock: {f['stock']})")

            admin_email = app.config.get("ADMIN_ALERT_EMAIL")
            if app.config.get("EMAIL_ENABLED") and admin_email:
                try:
                    send_email(
                        admin_email,
                        "Low Stock Alert",
                        f"Low stock alert for {f['name']}. Current stock: {f['stock']}",
                    )
                except Exception:
                    pass

    def cart_count(uid):
        conn = db()
        c = conn.execute(
            "SELECT COALESCE(SUM(quantity),0) AS qty FROM cart_items WHERE user_id=?",
            (uid,),
        ).fetchone()
        conn.close()
        return int(c["qty"] or 0)

    # ✅ FIXED: correct logic for cancellable & PAID check
    def is_order_cancellable(order_row, payment_row):
        if not order_row:
            return False

        if order_row["order_status"] in ("SHIPPED", "OUT_FOR_DELIVERY", "DELIVERED", "CANCELLED"):
            return False

        # If already paid, do NOT allow customer cancel (typical rule)
        if payment_row and payment_row["status"] == "PAID":
            return False

        return True

    @app.context_processor
    def inject_globals():
        u = current_user()
        return {
            "current_user": u,
            "cart_qty": cart_count(u["id"]) if u and u["role"] == "customer" else 0,
            "ORDER_STATUSES": ORDER_STATUSES,
            "STATUS_LABELS": STATUS_LABELS,
        }

    # -----------------------------
    # Auth
    # -----------------------------
    @app.get("/register")
    def register():
        return render_template("auth/register.html")

    # ✅ FIXED: register_post try/except/commit structure
    @app.post("/register")
    def register_post():
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        if not name or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return redirect(url_for("register"))

        if not PASSWORD_RE.match(password):
            flash("Password must contain at least 1 special character.", "danger")
            return redirect(url_for("register"))

        conn = db()
        try:
            conn.execute(
                "INSERT INTO users (name,email,password_hash,role,created_at) VALUES (?,?,?,?,?)",
                (name, email, generate_password_hash(password), "customer", now_iso()),
            )
            conn.commit()

        except sqlite3.IntegrityError as e:
            msg = str(e).lower()
            if "unique" in msg and "email" in msg:
                flash("Email already exists.", "danger")
            else:
                flash("Registration failed. Please try again.", "danger")
            return redirect(url_for("register"))

        except Exception:
            flash("Something went wrong. Please try again.", "danger")
            return redirect(url_for("register"))

        finally:
            conn.close()

        flash("Account created. Please login.", "success")
        return redirect(url_for("login"))

    @app.get("/login")
    def login():
        return render_template("auth/login.html")

    # ✅ Login kept SIMPLE (no password format checks)
    @app.post("/login")
    def login_post():
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        if not email or not password:
            flash("Email and password are required.", "danger")
            return redirect(url_for("login"))

        conn = db()
        try:
            u = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        finally:
            conn.close()

        if not u or not check_password_hash(u["password_hash"], password):
            flash("Invalid email/password.", "danger")
            return redirect(url_for("login"))

        session["user_id"] = u["id"]
        session["role"] = u["role"]

        flash("Logged in successfully.", "success")
        if u["role"] == "admin":
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("catalog"))

    @app.get("/logout")
    def logout():
        session.clear()
        flash("Logged out.", "info")
        return redirect(url_for("login"))

    # -----------------------------
    # Customer: Catalog + Fabric detail + Reviews + Gallery + Wishlist
    # -----------------------------
    @app.get("/")
    def home():
        return redirect(url_for("catalog"))

    @app.get("/catalog")
    def catalog():
        q = request.args.get("q", "").strip()
        category = request.args.get("category", "").strip()

        conn = db()
        sql = "SELECT * FROM fabrics WHERE is_active=1"
        params = []
        if q:
            sql += " AND (name LIKE ? OR description LIKE ?)"
            params += [f"%{q}%", f"%{q}%"]
        if category:
            sql += " AND category=?"
            params.append(category)

        sql += " ORDER BY id DESC"
        fabrics = conn.execute(sql, tuple(params)).fetchall()
        cats = conn.execute(
            "SELECT DISTINCT category FROM fabrics WHERE category IS NOT NULL AND category<>''"
        ).fetchall()
        conn.close()
        return render_template(
            "customer/catalog.html", fabrics=fabrics, cats=cats, q=q, category=category
        )

    @app.get("/fabric/<int:fabric_id>")
    def fabric_detail(fabric_id):
        conn = db()
        f = conn.execute(
            "SELECT * FROM fabrics WHERE id=? AND is_active=1", (fabric_id,)
        ).fetchone()
        if not f:
            conn.close()
            abort(404)

        images = conn.execute(
            "SELECT * FROM fabric_images WHERE fabric_id=? ORDER BY id DESC",
            (fabric_id,),
        ).fetchall()

        reviews = conn.execute(
            """
            SELECT r.*, u.name as user_name
            FROM reviews r
            JOIN users u ON u.id=r.user_id
            WHERE r.fabric_id=? AND r.is_deleted=0
            ORDER BY r.id DESC
            """,
            (fabric_id,),
        ).fetchall()

        avg = conn.execute(
            """
            SELECT ROUND(AVG(rating),1) as avg_rating, COUNT(*) as cnt
            FROM reviews
            WHERE fabric_id=? AND is_deleted=0
            """,
            (fabric_id,),
        ).fetchone()

        wished = False
        uid = session.get("user_id")
        role = session.get("role")
        if uid and role == "customer":
            w = conn.execute(
                "SELECT 1 FROM wishlist WHERE user_id=? AND fabric_id=?",
                (uid, fabric_id),
            ).fetchone()
            wished = bool(w)

        conn.close()
        return render_template(
            "customer/fabric_detail.html",
            fabric=f,
            images=images,
            reviews=reviews,
            avg=avg,
            wished=wished,
        )

    @app.post("/review/<int:fabric_id>")
    @login_required(role="customer")
    def add_review(fabric_id):
        rating = int(request.form.get("rating", "0") or 0)
        review_text = request.form.get("review_text", "").strip()

        if rating < 1 or rating > 5:
            flash("Rating must be 1 to 5.", "danger")
            return redirect(url_for("fabric_detail", fabric_id=fabric_id))

        uid = session["user_id"]
        conn = db()

        delivered = conn.execute(
            """
            SELECT 1
            FROM orders o
            JOIN order_items oi ON oi.order_id=o.id
            WHERE o.user_id=? AND o.order_status='DELIVERED' AND oi.fabric_id=?
            LIMIT 1
            """,
            (uid, fabric_id),
        ).fetchone()

        if not delivered:
            conn.close()
            flash("You can review only after delivery.", "warning")
            return redirect(url_for("fabric_detail", fabric_id=fabric_id))

        conn.execute(
            """
            INSERT INTO reviews (user_id, fabric_id, rating, review_text, is_deleted, created_at)
            VALUES (?,?,?,?,0,?)
            """,
            (uid, fabric_id, rating, review_text, now_iso()),
        )
        conn.commit()
        conn.close()

        flash("Review submitted.", "success")
        return redirect(url_for("fabric_detail", fabric_id=fabric_id))

    # -----------------------------
    # Wishlist
    # -----------------------------
    @app.get("/wishlist")
    @login_required(role="customer")
    def wishlist():
        uid = session["user_id"]
        conn = db()
        rows = conn.execute(
            """
            SELECT f.*
            FROM wishlist w
            JOIN fabrics f ON f.id=w.fabric_id
            WHERE w.user_id=? AND f.is_active=1
            ORDER BY w.id DESC
            """,
            (uid,),
        ).fetchall()
        conn.close()
        return render_template("customer/wishlist.html", rows=rows)

    @app.post("/wishlist/add/<int:fabric_id>")
    @login_required(role="customer")
    def wishlist_add(fabric_id):
        uid = session["user_id"]
        conn = db()
        try:
            conn.execute(
                "INSERT INTO wishlist (user_id, fabric_id, created_at) VALUES (?,?,?)",
                (uid, fabric_id, now_iso()),
            )
            conn.commit()
        except Exception:
            pass
        conn.close()
        flash("Added to wishlist.", "success")
        return redirect(request.referrer or url_for("fabric_detail", fabric_id=fabric_id))

    @app.post("/wishlist/remove/<int:fabric_id>")
    @login_required(role="customer")
    def wishlist_remove(fabric_id):
        uid = session["user_id"]
        conn = db()
        conn.execute("DELETE FROM wishlist WHERE user_id=? AND fabric_id=?", (uid, fabric_id))
        conn.commit()
        conn.close()
        flash("Removed from wishlist.", "info")
        return redirect(request.referrer or url_for("wishlist"))

    # -----------------------------
    # Cart + Customization
    # -----------------------------
    @app.post("/cart/add/<int:fabric_id>")
    @login_required(role="customer")
    def cart_add(fabric_id):
        uid = session["user_id"]

        color = request.form.get("color", "").strip()
        pattern = request.form.get("pattern", "").strip()

        try:
            meters = float(request.form.get("length_m", "1") or 1)
        except ValueError:
            meters = 1.0
        if meters <= 0:
            meters = 1.0

        design_file = request.files.get("design_file")
        design_path = None
        if design_file and design_file.filename:
            if not allowed_file(design_file.filename, ALLOWED_DESIGN):
                flash("Design file must be png/jpg/jpeg/pdf.", "danger")
                return redirect(url_for("fabric_detail", fabric_id=fabric_id))

            fn = secure_filename(design_file.filename)
            save_name = f"{uid}_{int(datetime.utcnow().timestamp())}_{fn}"
            full_path = os.path.join(app.config["DESIGN_UPLOAD_FOLDER"], save_name)
            design_file.save(full_path)
            design_path = f"uploads/designs/{save_name}"

        conn = db()
        f = conn.execute(
            "SELECT * FROM fabrics WHERE id=? AND is_active=1", (fabric_id,)
        ).fetchone()
        if not f:
            conn.close()
            abort(404)

        if float(f["stock"]) <= 0:
            conn.close()
            flash("Out of stock.", "danger")
            return redirect(url_for("fabric_detail", fabric_id=fabric_id))

        if meters > float(f["stock"]):
            conn.close()
            flash("Selected length exceeds stock.", "danger")
            return redirect(url_for("fabric_detail", fabric_id=fabric_id))

        # ✅ Merge rule: same fabric + same color + same pattern + same design_path
        # We will merge meters by updating customization_json length_m
        rows = conn.execute(
            """
            SELECT * FROM cart_items
            WHERE user_id=? AND fabric_id=?
            ORDER BY id DESC
            """,
            (uid, fabric_id),
        ).fetchall()

        matched_item = None
        matched_custom = None

        for r in rows:
            try:
                c = json.loads(r["customization_json"] or "{}")
            except Exception:
                c = {}

            if (c.get("color") or "") == color and (c.get("pattern") or "") == pattern and (c.get("design_path") or None) == design_path:
                matched_item = r
                matched_custom = c
                break

        if matched_item:
            old_m = 1.0
            try:
                old_m = float(matched_custom.get("length_m") or 1)
            except Exception:
                old_m = 1.0

            new_m = old_m + meters

            # stock check again for merged meters
            if new_m > float(f["stock"]):
                conn.close()
                flash("Total length in cart exceeds stock.", "danger")
                return redirect(url_for("fabric_detail", fabric_id=fabric_id))

            matched_custom["length_m"] = new_m
            matched_custom["color"] = color
            matched_custom["pattern"] = pattern
            matched_custom["design_path"] = design_path

            conn.execute(
                "UPDATE cart_items SET customization_json=? WHERE id=?",
                (json.dumps(matched_custom, ensure_ascii=False), matched_item["id"]),
            )
        else:
            customization = {
                "color": color,
                "pattern": pattern,
                "length_m": meters,
                "design_path": design_path,
            }
            conn.execute(
                """
                INSERT INTO cart_items (user_id,fabric_id,quantity,customization_json,created_at)
                VALUES (?,?,?,?,?)
                """,
                (uid, fabric_id, 1, json.dumps(customization, ensure_ascii=False), now_iso()),
            )

        conn.commit()
        conn.close()

        flash("Added to cart.", "success")
        return redirect(url_for("cart"))


    @app.get("/cart")
    @login_required(role="customer")
    def cart():
        uid = session["user_id"]
        conn = db()
        items = conn.execute(
            """
            SELECT ci.*, f.name, f.price, f.stock, f.image_path
            FROM cart_items ci
            JOIN fabrics f ON f.id=ci.fabric_id
            WHERE ci.user_id=?
            ORDER BY ci.id DESC
            """,
            (uid,),
        ).fetchall()
        conn.close()

        subtotal = 0.0
        parsed = []

        for it in items:
            custom = {}
            if it["customization_json"]:
                try:
                    custom = json.loads(it["customization_json"])
                except Exception:
                    custom = {}

            meters = get_meters_from_customization(it["customization_json"])
            line = round(float(it["price"]) * meters, 2)
            subtotal += line

            parsed.append((it, custom, line))

        return render_template("customer/cart.html", items=parsed, subtotal=round(subtotal, 2))


    @app.post("/cart/update/<int:item_id>")
    @login_required(role="customer")
    def cart_update(item_id):
        uid = session["user_id"]

        try:
            meters = float(request.form.get("length_m", "1") or 1)
        except ValueError:
            meters = 1.0
        if meters <= 0:
            meters = 1.0

        conn = db()
        it = conn.execute(
            "SELECT * FROM cart_items WHERE id=? AND user_id=?",
            (item_id, uid),
        ).fetchone()
        if not it:
            conn.close()
            abort(404)

        f = conn.execute("SELECT stock FROM fabrics WHERE id=?", (it["fabric_id"],)).fetchone()
        if f and meters > float(f["stock"]):
            conn.close()
            flash("Selected length exceeds stock.", "danger")
            return redirect(url_for("cart"))

        # Update customization_json length_m
        try:
            custom = json.loads(it["customization_json"] or "{}")
        except Exception:
            custom = {}
        custom["length_m"] = meters

        conn.execute(
            "UPDATE cart_items SET customization_json=? WHERE id=?",
            (json.dumps(custom, ensure_ascii=False), item_id),
        )
        conn.commit()
        conn.close()

        flash("Cart updated.", "success")
        return redirect(url_for("cart"))


    @app.post("/cart/remove/<int:item_id>")
    @login_required(role="customer")
    def cart_remove(item_id):
        uid = session["user_id"]
        conn = db()
        conn.execute("DELETE FROM cart_items WHERE id=? AND user_id=?", (item_id, uid))
        conn.commit()
        conn.close()
        flash("Item removed.", "info")
        return redirect(url_for("cart"))
    # -----------------------------
    # Checkout + Coupon + Order create (UPI + COD ONLY)
    # -----------------------------
    def validate_coupon(code: str):
        if not code:
            return None
        conn = db()
        c = conn.execute(
            "SELECT * FROM coupons WHERE code=? AND is_active=1",
            (code.strip().upper(),),
        ).fetchone()
        conn.close()
        if not c:
            return None
        try:
            exp = date.fromisoformat(c["expiry_date"])
            if exp < date.today():
                return None
        except Exception:
            return None
        return c

    @app.get("/checkout")
    @login_required(role="customer")
    def checkout():
        uid = session["user_id"]
        conn = db()
        items = conn.execute(
            """
            SELECT ci.*, f.name, f.price, f.stock
            FROM cart_items ci
            JOIN fabrics f ON f.id=ci.fabric_id
            WHERE ci.user_id=?
            """,
            (uid,),
        ).fetchall()
        conn.close()

        if not items:
            flash("Your cart is empty.", "warning")
            return redirect(url_for("catalog"))

        parsed_items = []
        subtotal = 0.0

        for it in items:
            custom = {}
            if it["customization_json"]:
                try:
                    custom = json.loads(it["customization_json"])
                except Exception:
                    custom = {}

            try:
                meters = float(custom.get("length_m") or 1)
            except Exception:
                meters = 1.0

            if meters <= 0:
                meters = 1.0

            line_total = round(float(it["price"]) * meters, 2)
            subtotal += line_total

            parsed_items.append((it, custom, meters, line_total))

        subtotal = round(subtotal, 2)

        return render_template(
            "customer/checkout.html",
            items=parsed_items,   # ✅ now it is tuples
            subtotal=subtotal
        )

    @app.post("/checkout/place-order")
    @login_required(role="customer")
    def place_order():
        uid = session["user_id"]
        shipping_name = request.form.get("shipping_name", "").strip()
        shipping_phone = request.form.get("shipping_phone", "").strip()
        shipping_address = request.form.get("shipping_address", "").strip()
        coupon_code = (request.form.get("coupon_code", "") or "").strip().upper()
        payment_method = (request.form.get("payment_method", "") or "").strip().upper()

        if payment_method not in ("UPI", "COD"):
            flash("Select a payment method (UPI / COD).", "danger")
            return redirect(url_for("checkout"))

        if not shipping_name or not shipping_phone or not shipping_address:
            flash("Shipping details required.", "danger")
            return redirect(url_for("checkout"))

        conn = db()
        items = conn.execute(
            """
            SELECT ci.*, f.name, f.price, f.stock
            FROM cart_items ci
            JOIN fabrics f ON f.id=ci.fabric_id
            WHERE ci.user_id=?
            """,
            (uid,),
        ).fetchall()

        if not items:
            conn.close()
            flash("Cart empty.", "warning")
            return redirect(url_for("catalog"))

        # ✅ Validate stock based on meters
        for it in items:
            meters = get_meters_from_customization(it["customization_json"])
            if meters > float(it["stock"]):
                conn.close()
                flash(f"Not enough stock for {it['name']} (need {meters}m).", "danger")
                return redirect(url_for("cart"))

        # ✅ Subtotal = sum(price * meters)
        subtotal = 0.0
        for it in items:
            meters = get_meters_from_customization(it["customization_json"])
            subtotal += float(it["price"]) * meters
        subtotal = round(subtotal, 2)

        cpn = validate_coupon(coupon_code) if coupon_code else None
        discount_amount = 0.0
        if cpn:
            discount_amount = round(subtotal * (int(cpn["discount_percent"]) / 100.0), 2)

        total = round(subtotal - discount_amount, 2)
        if total < 0:
            total = 0.0

        order_status = "ORDER_PLACED"
        cur = conn.cursor()

        cur.execute(
            """
            INSERT INTO orders (
                user_id, order_status, subtotal, discount_amount, coupon_code, total_amount,
                shipping_name, shipping_phone, shipping_address, created_at
            )
            VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            (
                uid,
                order_status,
                subtotal,
                discount_amount,
                coupon_code if cpn else None,
                total,
                shipping_name,
                shipping_phone,
                shipping_address,
                now_iso(),
            ),
        )
        order_id = cur.lastrowid

        cur.execute(
            """
            INSERT INTO order_status_history (order_id, status, note, created_at)
            VALUES (?,?,?,?)
            """,
            (order_id, order_status, "Order placed by customer", now_iso()),
        )

        # ✅ Insert order items + reduce stock by meters
        for it in items:
            meters = get_meters_from_customization(it["customization_json"])
            line_total = round(float(it["price"]) * meters, 2)

            cur.execute(
                """
                INSERT INTO order_items (
                    order_id, fabric_id, fabric_name_snapshot, unit_price_snapshot,
                    quantity, customization_json, line_total
                )
                VALUES (?,?,?,?,?,?,?)
                """,
                (
                    order_id,
                    it["fabric_id"],
                    it["name"],
                    it["price"],
                    1,  # quantity stays 1 (meters are inside customization_json)
                    it["customization_json"],
                    line_total,
                ),
            )

            cur.execute(
                "UPDATE fabrics SET stock=stock-? WHERE id=?",
                (meters, it["fabric_id"]),
            )

        # payment row
        cur.execute(
            """
            INSERT INTO payments (
                order_id, method, status, amount,
                transaction_id, provider_order_id, provider_signature, created_at
            )
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (order_id, payment_method, "PENDING", total, None, None, None, now_iso()),
        )

        cur.execute("DELETE FROM cart_items WHERE user_id=?", (uid,))
        conn.commit()
        conn.close()

        for it in items:
            check_low_stock_and_notify(it["fabric_id"])

        add_notification("ORDER", f"New order placed: #{order_id}")

        u = current_user()
        if u:
            try:
                send_email(
                    u["email"],
                    f"Order Placed - #{order_id}",
                    f"Your order #{order_id} has been placed.\nTotal: ₹{total}\nPayment: {payment_method} (Pending)",
                )
            except Exception:
                pass

        flash(f"Order placed. Order ID: {order_id}", "success")

        if payment_method == "UPI":
            return redirect(url_for("upi_pay", order_id=order_id))
        return redirect(url_for("order_detail", order_id=order_id))

    # -----------------------------
    # Payment: UPI (QR Manual)
    # -----------------------------
    @app.get("/payment/upi/<int:order_id>")
    @login_required(role="customer")
    def upi_pay(order_id):
        uid = session["user_id"]
        conn = db()
        o = conn.execute(
            "SELECT * FROM orders WHERE id=? AND user_id=?", (order_id, uid)
        ).fetchone()
        p = conn.execute(
            "SELECT * FROM payments WHERE order_id=? ORDER BY id DESC LIMIT 1",
            (order_id,),
        ).fetchone()
        conn.close()

        if not o or not p or p["method"] != "UPI":
            abort(404)

        if p["status"] == "PAID":
            flash("Payment already completed.", "info")
            return redirect(url_for("order_detail", order_id=order_id))

        return render_template(
            "customer/upi_pay.html",
            order=o,
            payment=p,
            qr_path=app.config.get("QR_IMAGE_PATH", "uploads/qr/upi_qr.png"),
        )

    @app.post("/payment/upi/submit/<int:order_id>")
    @login_required(role="customer")
    def upi_submit(order_id):
        uid = session["user_id"]
        txn = (request.form.get("transaction_id") or "").strip()

        if not txn:
            flash("Please enter transaction ID.", "danger")
            return redirect(url_for("upi_pay", order_id=order_id))

        conn = db()
        o = conn.execute(
            "SELECT * FROM orders WHERE id=? AND user_id=?", (order_id, uid)
        ).fetchone()
        p = conn.execute(
            "SELECT * FROM payments WHERE order_id=? ORDER BY id DESC LIMIT 1",
            (order_id,),
        ).fetchone()

        if not o or not p or p["method"] != "UPI":
            conn.close()
            abort(404)

        conn.execute(
            "UPDATE payments SET status='PAID', transaction_id=? WHERE id=?",
            (txn, p["id"]),
        )
        conn.commit()
        conn.close()

        add_notification("PAYMENT", f"UPI Payment PAID for order #{order_id} (TXN: {txn})")

        u = current_user()
        if u:
            try:
                send_email(
                    u["email"],
                    f"Payment Successful - #{order_id}",
                    f"UPI Payment received for order #{order_id}.\nTxn ID: {txn}\nAmount: ₹{o['total_amount']}",
                )
            except Exception:
                pass

        flash("UPI payment updated as PAID.", "success")
        return redirect(url_for("order_detail", order_id=order_id))

    # -----------------------------
    # Orders + Cancel + Tracking + Invoice + Payments page
    # -----------------------------
    @app.get("/orders")
    @login_required(role="customer")
    def orders():
        uid = session["user_id"]
        conn = db()
        rows = conn.execute(
            "SELECT * FROM orders WHERE user_id=? ORDER BY id DESC", (uid,)
        ).fetchall()
        conn.close()
        return render_template("customer/orders.html", rows=rows)

    @app.get("/order/<int:order_id>")
    @login_required(role="customer")
    def order_detail(order_id):
        uid = session["user_id"]
        conn = db()
        o = conn.execute(
            "SELECT * FROM orders WHERE id=? AND user_id=?", (order_id, uid)
        ).fetchone()
        if not o:
            conn.close()
            abort(404)

        items = conn.execute(
            "SELECT * FROM order_items WHERE order_id=?", (order_id,)
        ).fetchall()
        pay = conn.execute(
            "SELECT * FROM payments WHERE order_id=? ORDER BY id DESC LIMIT 1",
            (order_id,),
        ).fetchone()
        hist = conn.execute(
            """
            SELECT * FROM order_status_history
            WHERE order_id=?
            ORDER BY id ASC
            """,
            (order_id,),
        ).fetchall()
        conn.close()

        parsed_items = []
        for it in items:
            custom = {}
            if it["customization_json"]:
                try:
                    custom = json.loads(it["customization_json"])
                except Exception:
                    custom = {}
            parsed_items.append((it, custom))

        cancellable = is_order_cancellable(o, pay)

        return render_template(
            "customer/order_detail.html",
            order=o,
            items=parsed_items,
            payment=pay,
            history=hist,
            cancellable=cancellable,
        )

    @app.post("/order/<int:order_id>/cancel")
    @login_required(role="customer")
    def cancle_order(order_id):
        uid = session["user_id"]
        reason = (request.form.get("reason") or "").strip()

        conn = db()
        o = conn.execute(
            "SELECT * FROM orders WHERE id=? AND user_id=?", (order_id, uid)
        ).fetchone()
        if not o:
            conn.close()
            abort(404)

        pay = conn.execute(
            "SELECT * FROM payments WHERE order_id=? ORDER BY id DESC LIMIT 1",
            (order_id,),
        ).fetchone()

        if not is_order_cancellable(o, pay):
            conn.close()
            flash("Order cannot be cancelled now.", "warning")
            return redirect(url_for("order_detail", order_id=order_id))

        items = conn.execute(
            "SELECT * FROM order_items WHERE order_id=?", (order_id,)
        ).fetchall()
        for it in items:
            conn.execute(
                "UPDATE fabrics SET stock=stock+? WHERE id=?",
                (it["quantity"], it["fabric_id"]),
            )

        conn.execute("UPDATE orders SET order_status='CANCELLED' WHERE id=?", (order_id,))
        conn.execute(
            """
            INSERT INTO order_status_history (order_id, status, note, created_at)
            VALUES (?,?,?,?)
            """,
            (order_id, "CANCELLED", reason or "Cancelled by customer", now_iso()),
        )

        # ✅ FIXED: don't mark PAID as FAILED
        if pay and pay["status"] != "PAID":
            conn.execute("UPDATE payments SET status='FAILED' WHERE id=?", (pay["id"],))

        conn.commit()
        conn.close()

        add_notification("ORDER", f"Order #{order_id} cancelled by customer")

        u = current_user()
        if u:
            try:
                send_email(
                    u["email"],
                    f"Order Cancelled - #{order_id}",
                    f"Your order #{order_id} has been cancelled.",
                )
            except Exception:
                pass

        flash("Order cancelled successfully.", "success")
        return redirect(url_for("orders"))

    @app.get("/invoice/<int:order_id>")
    @login_required(role="customer")
    def invoice(order_id):
        uid = session["user_id"]
        conn = db()

        o = conn.execute(
            "SELECT * FROM orders WHERE id=? AND user_id=?",
            (order_id, uid),
        ).fetchone()
        if not o:
            conn.close()
            abort(404)

        items = conn.execute(
            "SELECT * FROM order_items WHERE order_id=?",
            (order_id,),
        ).fetchall()

        pay = conn.execute(
            "SELECT * FROM payments WHERE order_id=? ORDER BY id DESC LIMIT 1",
            (order_id,),
        ).fetchone()

        conn.close()

        parsed_items = []
        for it in items:
            custom = {}
            if it["customization_json"]:
                try:
                    custom = json.loads(it["customization_json"])
                except Exception:
                    custom = {}
            parsed_items.append((it, custom))

        return render_template(
            "customer/invoice.html",
            order=o,
            items=parsed_items,
            payment=pay,
        )

    @app.get("/invoice/<int:order_id>/pdf")
    @login_required(role="customer")
    def invoice_pdf(order_id):
        uid = session["user_id"]
        conn = db()

        o = conn.execute(
            "SELECT * FROM orders WHERE id=? AND user_id=?",
            (order_id, uid),
        ).fetchone()
        if not o:
            conn.close()
            abort(404)

        items = conn.execute(
            "SELECT * FROM order_items WHERE order_id=?",
            (order_id,),
        ).fetchall()

        pay = conn.execute(
            "SELECT * FROM payments WHERE order_id=? ORDER BY id DESC LIMIT 1",
            (order_id,),
        ).fetchone()

        conn.close()

        buffer = BytesIO()
        c = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4

        y = height - 50
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, y, f"Invoice - Order #{o['id']}")
        y -= 22

        c.setFont("Helvetica", 11)
        c.drawString(50, y, f"Date: {o['created_at']}")
        y -= 16
        c.drawString(50, y, f"Name: {o['shipping_name']}   Phone: {o['shipping_phone']}")
        y -= 16
        addr = (o["shipping_address"] or "").replace("\n", " ")
        c.drawString(50, y, f"Address: {addr[:95]}")
        y -= 22

        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Items")
        y -= 16

        c.setFont("Helvetica", 10)
        for it in items:
            meters = 1.0
            try:
                meters = get_meters_from_customization(it["customization_json"])
            except Exception:
                meters = 1.0

            line = (
                f"{it['fabric_name_snapshot']}  ({meters}m)  "
                f"@ ₹{it['unit_price_snapshot']}/m  = ₹{it['line_total']}"
            )
            c.drawString(50, y, line[:110])
            y -= 14
            if y < 80:
                c.showPage()
                y = height - 50
                c.setFont("Helvetica", 10)

        y -= 10
        c.setFont("Helvetica-Bold", 11)
        c.drawString(50, y, f"Subtotal: ₹{o['subtotal']}")
        y -= 14
        c.drawString(50, y, f"Discount: ₹{o['discount_amount']}")
        y -= 14
        c.drawString(50, y, f"Total: ₹{o['total_amount']}")
        y -= 16

        if pay:
            c.setFont("Helvetica", 10)
            c.drawString(
                50,
                y,
                f"Payment: {pay['method']}  Status: {pay['status']}  TXN: {pay['transaction_id'] or '-'}",
            )

        c.showPage()
        c.save()

        buffer.seek(0)
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"invoice_order_{order_id}.pdf",
            mimetype="application/pdf",
        )

    @app.get("/payments")
    @login_required()
    def payments():
        role = session.get("role")
        uid = session.get("user_id")
        conn = db()

        if role == "admin":
            rows = conn.execute(
                """
                SELECT p.*, o.user_id, o.total_amount, o.created_at as order_created_at
                FROM payments p
                JOIN orders o ON o.id=p.order_id
                ORDER BY p.id DESC
                LIMIT 200
                """
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT p.*, o.total_amount, o.created_at as order_created_at
                FROM payments p
                JOIN orders o ON o.id=p.order_id
                WHERE o.user_id=?
                ORDER BY p.id DESC
                LIMIT 200
                """,
                (uid,),
            ).fetchall()

        conn.close()
        return render_template("payments.html", rows=rows)

    # Tracking
    @app.get("/track")
    def track():
        order_id = (request.args.get("order_id") or "").strip()
        if order_id.isdigit():
            return redirect(url_for("track_order", order_id=int(order_id)))
        return render_template("customer/track.html", order=None, history=[], steps=[], progress_index=-1)

    @app.get("/track/<int:order_id>")
    def track_order(order_id):
        conn = db()
        order = conn.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
        history = []
        if order:
            history = conn.execute(
                """
                SELECT * FROM order_status_history
                WHERE order_id=?
                ORDER BY id ASC
                """,
                (order_id,),
            ).fetchall()
        conn.close()

        steps = ["ORDER_PLACED", "PROCESSING", "SHIPPED", "OUT_FOR_DELIVERY", "DELIVERED"]
        current = order["order_status"] if order else None
        progress_index = -1
        if current in steps:
            progress_index = steps.index(current)

        return render_template(
            "customer/track.html",
            order=order,
            history=history,
            steps=steps,
            progress_index=progress_index,
        )

    # -----------------------------
    # Admin area
    # -----------------------------
    @app.get("/admin/login")
    def admin_login():
        return render_template("admin/login.html")

    @app.post("/admin/login")
    def admin_login_post():
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        conn = db()
        u = conn.execute(
            "SELECT * FROM users WHERE email=? AND role='admin'", (email,)
        ).fetchone()
        conn.close()

        if not u or not check_password_hash(u["password_hash"], password):
            flash("Invalid admin credentials.", "danger")
            return redirect(url_for("admin_login"))

        session["user_id"] = u["id"]
        session["role"] = "admin"
        flash("Welcome admin.", "success")
        return redirect(url_for("admin_dashboard"))

    @app.get("/admin/dashboard")
    @login_required(role="admin")
    def admin_dashboard():
        conn = db()

        low_stock = conn.execute(
            """
            SELECT * FROM fabrics
            WHERE is_active=1 AND stock < 10
            ORDER BY stock ASC
            """
        ).fetchall()

        notif = conn.execute(
            """
            SELECT * FROM notifications
            ORDER BY id DESC
            LIMIT 8
            """
        ).fetchall()

        total_orders = conn.execute("SELECT COUNT(*) as c FROM orders").fetchone()["c"]
        total_revenue = conn.execute(
            """
            SELECT COALESCE(SUM(o.total_amount),0) as s
            FROM orders o
            JOIN payments p ON p.order_id=o.id
            WHERE p.status='PAID'
            """
        ).fetchone()["s"]

        most_sold = conn.execute(
            """
            SELECT fabric_name_snapshot, SUM(quantity) as qty
            FROM order_items
            GROUP BY fabric_name_snapshot
            ORDER BY qty DESC
            LIMIT 1
            """
        ).fetchone()

        monthly = conn.execute(
            """
            SELECT substr(o.created_at,1,7) as ym, COALESCE(SUM(o.total_amount),0) as revenue
            FROM orders o
            JOIN payments p ON p.order_id=o.id
            WHERE p.status='PAID'
            GROUP BY ym
            ORDER BY ym ASC
            """
        ).fetchall()

        conn.close()

        labels = [m["ym"] for m in monthly]
        values = [float(m["revenue"]) for m in monthly]

        return render_template(
            "admin/dashboard.html",
            low_stock=low_stock,
            notif=notif,
            total_orders=total_orders,
            total_revenue=total_revenue,
            most_sold=most_sold,
            chart_labels=json.dumps(labels),
            chart_values=json.dumps(values),
        )

    # Admin Fabrics
    @app.get("/admin/fabrics")
    @login_required(role="admin")
    def admin_fabrics():
        conn = db()
        rows = conn.execute("SELECT * FROM fabrics ORDER BY id DESC").fetchall()
        conn.close()
        return render_template("admin/fabrics.html", rows=rows)

    @app.get("/admin/fabrics/add")
    @login_required(role="admin")
    def admin_fabric_add():
        return render_template("admin/fabric_form.html", fabric=None, images=[])

    @app.post("/admin/fabrics/add")
    @login_required(role="admin")
    def admin_fabric_add_post():
        name = request.form.get("name", "").strip()
        category = request.form.get("category", "").strip()
        description = request.form.get("description", "").strip()
        price = float(request.form.get("price", "0") or 0)
        stock = int(request.form.get("stock", "0") or 0)
        is_active = 1 if request.form.get("is_active") == "on" else 0

        image = request.files.get("image")
        image_path = None
        if image and image.filename:
            if not allowed_file(image.filename, ALLOWED_IMG):
                flash("Image must be png/jpg/jpeg/webp.", "danger")
                return redirect(url_for("admin_fabric_add"))
            fn = secure_filename(image.filename)
            save_name = f"{int(datetime.utcnow().timestamp())}_{fn}"
            full_path = os.path.join(app.config["FABRIC_UPLOAD_FOLDER"], save_name)
            image.save(full_path)
            image_path = f"uploads/fabrics/{save_name}"

        if not name or price <= 0:
            flash("Name and valid price required.", "danger")
            return redirect(url_for("admin_fabric_add"))

        conn = db()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO fabrics (name,category,description,price,stock,image_path,is_active,created_at)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (name, category, description, price, stock, image_path, is_active, now_iso()),
        )
        fabric_id = cur.lastrowid
        conn.commit()
        conn.close()

        flash("Fabric added.", "success")
        return redirect(url_for("admin_fabric_edit", fabric_id=fabric_id))

    @app.get("/admin/fabrics/edit/<int:fabric_id>")
    @login_required(role="admin")
    def admin_fabric_edit(fabric_id):
        conn = db()
        f = conn.execute("SELECT * FROM fabrics WHERE id=?", (fabric_id,)).fetchone()
        images = conn.execute(
            "SELECT * FROM fabric_images WHERE fabric_id=? ORDER BY id DESC",
            (fabric_id,),
        ).fetchall()
        conn.close()
        if not f:
            abort(404)
        return render_template("admin/fabric_form.html", fabric=f, images=images)

    @app.post("/admin/fabrics/edit/<int:fabric_id>")
    @login_required(role="admin")
    def admin_fabric_edit_post(fabric_id):
        name = request.form.get("name", "").strip()
        category = request.form.get("category", "").strip()
        description = request.form.get("description", "").strip()
        price = float(request.form.get("price", "0") or 0)
        stock = int(request.form.get("stock", "0") or 0)
        is_active = 1 if request.form.get("is_active") == "on" else 0

        image = request.files.get("image")
        new_image_path = None
        if image and image.filename:
            if not allowed_file(image.filename, ALLOWED_IMG):
                flash("Image must be png/jpg/jpeg/webp.", "danger")
                return redirect(url_for("admin_fabric_edit", fabric_id=fabric_id))
            fn = secure_filename(image.filename)
            save_name = f"{int(datetime.utcnow().timestamp())}_{fn}"
            full_path = os.path.join(app.config["FABRIC_UPLOAD_FOLDER"], save_name)
            image.save(full_path)
            new_image_path = f"uploads/fabrics/{save_name}"

        if not name or price <= 0:
            flash("Name and valid price required.", "danger")
            return redirect(url_for("admin_fabric_edit", fabric_id=fabric_id))

        conn = db()
        if new_image_path:
            conn.execute(
                """
                UPDATE fabrics
                SET name=?, category=?, description=?, price=?, stock=?, image_path=?, is_active=?
                WHERE id=?
                """,
                (name, category, description, price, stock, new_image_path, is_active, fabric_id),
            )
        else:
            conn.execute(
                """
                UPDATE fabrics
                SET name=?, category=?, description=?, price=?, stock=?, is_active=?
                WHERE id=?
                """,
                (name, category, description, price, stock, is_active, fabric_id),
            )

        conn.commit()
        conn.close()

        check_low_stock_and_notify(fabric_id)
        flash("Fabric updated.", "success")
        return redirect(url_for("admin_fabric_edit", fabric_id=fabric_id))

    # ✅ NEW: DELETE FABRIC (also deletes fabric_images + tries to delete files from disk)
    @app.post("/admin/fabrics/<int:fabric_id>/delete")
    @login_required(role="admin")
    def admin_fabric_delete(fabric_id):
        conn = db()

        # get fabric + related images first (to remove files after DB delete)
        f = conn.execute(
            "SELECT id, image_path FROM fabrics WHERE id=?",
            (fabric_id,),
        ).fetchone()

        if not f:
            conn.close()
            abort(404)

        imgs = conn.execute(
            "SELECT id, image_path FROM fabric_images WHERE fabric_id=?",
            (fabric_id,),
        ).fetchall()

        # delete children then parent
        conn.execute("DELETE FROM fabric_images WHERE fabric_id=?", (fabric_id,))
        conn.execute("DELETE FROM fabrics WHERE id=?", (fabric_id,))
        conn.commit()
        conn.close()

        # safely remove files (ignore errors)
        def _safe_remove(rel_path):
            if not rel_path:
                return
            try:
                abs_path = os.path.join(app.root_path, rel_path)
                if os.path.exists(abs_path):
                    os.remove(abs_path)
            except Exception as e:
                print("File remove failed:", rel_path, e)

        _safe_remove(f["image_path"])
        for im in imgs:
            _safe_remove(im["image_path"])

        flash(f"Fabric #{fabric_id} deleted.", "success")
        return redirect(url_for("admin_fabrics"))

    # Stock In/Out
    @app.post("/admin/fabrics/<int:fabric_id>/stock-adjust")
    @login_required(role="admin")
    def admin_stock_adjust(fabric_id):
        change_qty = int(request.form.get("change_qty", "0") or 0)
        note = (request.form.get("note") or "").strip()

        if change_qty == 0:
            flash("Enter a non-zero stock change value.", "warning")
            return redirect(url_for("admin_fabric_edit", fabric_id=fabric_id))

        admin_id = session.get("user_id")

        conn = db()
        f = conn.execute("SELECT * FROM fabrics WHERE id=?", (fabric_id,)).fetchone()
        if not f:
            conn.close()
            abort(404)

        new_stock = int(f["stock"]) + change_qty
        if new_stock < 0:
            conn.close()
            flash("Stock cannot go below 0.", "danger")
            return redirect(url_for("admin_fabric_edit", fabric_id=fabric_id))

        meters = get_meters_from_customization(["customization_json"])
        conn.execute("UPDATE fabrics SET stock=stock+? WHERE id=?", (meters, ["fabric_id"]))

        try:
            conn.execute(
                """
                INSERT INTO stock_history (fabric_id, change_qty, note, created_by, created_at)
                VALUES (?,?,?,?,?)
                """,
                (fabric_id, change_qty, note if note else None, admin_id, now_iso()),
            )
        except Exception:
            pass

        conn.commit()
        conn.close()

        check_low_stock_and_notify(fabric_id)
        flash(f"Stock updated. New stock: {new_stock}", "success")
        return redirect(url_for("admin_fabric_edit", fabric_id=fabric_id))

    # Multiple Images
    @app.post("/admin/fabrics/<int:fabric_id>/images/add")
    @login_required(role="admin")
    def admin_fabric_image_add(fabric_id):
        files = request.files.getlist("images")
        style_name = (request.form.get("style_name") or "").strip() or None

        if not files:
            flash("No images selected.", "warning")
            return redirect(url_for("admin_fabric_edit", fabric_id=fabric_id))

        conn = db()
        f = conn.execute("SELECT id FROM fabrics WHERE id=?", (fabric_id,)).fetchone()
        if not f:
            conn.close()
            abort(404)

        folder = app.config.get("FABRIC_GALLERY_UPLOAD_FOLDER", "static/uploads/fabric_gallery")

        saved_any = False
        for img in files:
            if not img or not img.filename:
                continue
            if not allowed_file(img.filename, ALLOWED_IMG):
                continue

            fn = secure_filename(img.filename)
            save_name = f"{fabric_id}_{int(datetime.utcnow().timestamp())}_{fn}"
            full_path = os.path.join(folder, save_name)
            img.save(full_path)

            rel_path = f"uploads/fabric_gallery/{save_name}"
            conn.execute(
                """
                INSERT INTO fabric_images (fabric_id, image_path, style_name, created_at)
                VALUES (?,?,?,?)
                """,
                (fabric_id, rel_path, style_name, now_iso()),
            )
            saved_any = True

        conn.commit()
        conn.close()

        flash(
            "Gallery images added." if saved_any else "No valid images were added.",
            "success" if saved_any else "warning",
        )
        return redirect(url_for("admin_fabric_edit", fabric_id=fabric_id))

    @app.post("/admin/fabric-image/<int:image_id>/delete")
    @login_required(role="admin")
    def admin_fabric_image_delete(image_id):
        conn = db()
        img = conn.execute("SELECT * FROM fabric_images WHERE id=?", (image_id,)).fetchone()
        if not img:
            conn.close()
            abort(404)

        fabric_id = img["fabric_id"]
        conn.execute("DELETE FROM fabric_images WHERE id=?", (image_id,))
        conn.commit()
        conn.close()

        flash("Image deleted.", "info")
        return redirect(url_for("admin_fabric_edit", fabric_id=fabric_id))

    # Admin Orders
    @app.get("/admin/orders")
    @login_required(role="admin")
    def admin_orders():
        conn = db()
        rows = conn.execute(
            """
            SELECT o.*, u.name as customer_name, u.email as customer_email
            FROM orders o
            JOIN users u ON u.id=o.user_id
            ORDER BY o.id DESC
            """
        ).fetchall()
        conn.close()
        return render_template("admin/orders.html", rows=rows)

    @app.get("/admin/order/<int:order_id>")
    @login_required(role="admin")
    def admin_order_manage(order_id):
        conn = db()
        o = conn.execute(
            """
            SELECT o.*, u.name as customer_name, u.email as customer_email
            FROM orders o
            JOIN users u ON u.id=o.user_id
            WHERE o.id=?
            """,
            (order_id,),
        ).fetchone()
        if not o:
            conn.close()
            abort(404)

        items = conn.execute("SELECT * FROM order_items WHERE order_id=?", (order_id,)).fetchall()
        pay = conn.execute(
            "SELECT * FROM payments WHERE order_id=? ORDER BY id DESC LIMIT 1",
            (order_id,),
        ).fetchone()
        hist = conn.execute(
            "SELECT * FROM order_status_history WHERE order_id=? ORDER BY id ASC",
            (order_id,),
        ).fetchall()
        conn.close()
        return render_template(
            "admin/order_manage.html",
            order=o,
            items=items,
            payment=pay,
            history=hist,
        )

    @app.post("/admin/order/<int:order_id>/status")
    @login_required(role="admin")
    def admin_update_status(order_id):
        status = (request.form.get("status") or "").strip().upper()
        note = (request.form.get("note") or "").strip()

        if status not in ORDER_STATUSES:
            flash("Invalid status.", "danger")
            return redirect(url_for("admin_order_manage", order_id=order_id))

        conn = db()
        o = conn.execute(
            """
            SELECT o.*, u.email as customer_email
            FROM orders o
            JOIN users u ON u.id=o.user_id
            WHERE o.id=?
            """,
            (order_id,),
        ).fetchone()
        if not o:
            conn.close()
            abort(404)

        conn.execute("UPDATE orders SET order_status=? WHERE id=?", (status, order_id))
        conn.execute(
            """
            INSERT INTO order_status_history (order_id, status, note, created_at)
            VALUES (?,?,?,?)
            """,
            (order_id, status, note if note else None, now_iso()),
        )
        conn.commit()
        conn.close()

        add_notification("ORDER", f"Order #{order_id} status updated to {status}")

        if status == "SHIPPED":
            try:
                send_email(
                    o["customer_email"],
                    f"Order Shipped - #{order_id}",
                    f"Your order #{order_id} has been shipped.",
                )
            except Exception:
                pass

        flash("Order status updated.", "success")
        return redirect(url_for("admin_order_manage", order_id=order_id))

    # Admin Coupons
    @app.get("/admin/coupons")
    @login_required(role="admin")
    def admin_coupons():
        conn = db()
        rows = conn.execute("SELECT * FROM coupons ORDER BY id DESC").fetchall()
        conn.close()
        return render_template("admin/coupons.html", rows=rows)

    @app.post("/admin/coupons/add")
    @login_required(role="admin")
    def admin_coupons_add():
        code = (request.form.get("code") or "").strip().upper()
        discount_percent = int(request.form.get("discount_percent", "0") or 0)
        expiry_date = (request.form.get("expiry_date") or "").strip()
        is_active = 1 if request.form.get("is_active") == "on" else 0

        if not code or discount_percent < 1 or discount_percent > 90:
            flash("Invalid coupon data.", "danger")
            return redirect(url_for("admin_coupons"))
        try:
            date.fromisoformat(expiry_date)
        except Exception:
            flash("Expiry date must be YYYY-MM-DD.", "danger")
            return redirect(url_for("admin_coupons"))

        conn = db()
        try:
            conn.execute(
                """
                INSERT INTO coupons (code,discount_percent,expiry_date,is_active,created_at)
                VALUES (?,?,?,?,?)
                """,
                (code, discount_percent, expiry_date, is_active, now_iso()),
            )
            conn.commit()
        except Exception:
            conn.close()
            flash("Coupon code already exists.", "danger")
            return redirect(url_for("admin_coupons"))
        conn.close()

        flash("Coupon created.", "success")
        return redirect(url_for("admin_coupons"))

    @app.post("/admin/coupons/toggle/<int:coupon_id>")
    @login_required(role="admin")
    def admin_coupon_toggle(coupon_id):
        conn = db()
        cpn = conn.execute("SELECT * FROM coupons WHERE id=?", (coupon_id,)).fetchone()
        if not cpn:
            conn.close()
            abort(404)
        new_val = 0 if cpn["is_active"] else 1
        conn.execute("UPDATE coupons SET is_active=? WHERE id=?", (new_val, coupon_id))
        conn.commit()
        conn.close()
        flash("Coupon updated.", "success")
        return redirect(url_for("admin_coupons"))

    # Admin Reviews moderation
    @app.get("/admin/reviews")
    @login_required(role="admin")
    def admin_reviews():
        conn = db()
        rows = conn.execute(
            """
            SELECT r.*, u.name as user_name, f.name as fabric_name
            FROM reviews r
            JOIN users u ON u.id=r.user_id
            JOIN fabrics f ON f.id=r.fabric_id
            ORDER BY r.id DESC
            """
        ).fetchall()
        conn.close()
        return render_template("admin/reviews.html", rows=rows)

    @app.post("/admin/review/<int:review_id>/delete")
    @login_required(role="admin")
    def admin_review_delete(review_id):
        conn = db()
        conn.execute("UPDATE reviews SET is_deleted=1 WHERE id=?", (review_id,))
        conn.commit()
        conn.close()
        flash("Review deleted.", "info")
        return redirect(url_for("admin_reviews"))

    # Admin Notifications
    @app.get("/admin/notifications")
    @login_required(role="admin")
    def admin_notifications():
        conn = db()
        rows = conn.execute("SELECT * FROM notifications ORDER BY id DESC").fetchall()
        conn.close()
        return render_template("admin/notifications.html", rows=rows)

    @app.post("/admin/notifications/mark-read/<int:notif_id>")
    @login_required(role="admin")
    def admin_notifications_mark_read(notif_id):
        conn = db()
        conn.execute("UPDATE notifications SET is_read=1 WHERE id=?", (notif_id,))
        conn.commit()
        conn.close()
        flash("Marked read.", "success")
        return redirect(url_for("admin_notifications"))

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)