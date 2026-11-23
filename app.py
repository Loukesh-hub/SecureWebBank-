"""SecureWebBank: a simulated Flask banking project with SQLite/PostgreSQL support."""
from __future__ import annotations

import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from functools import wraps
from hashlib import pbkdf2_hmac
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from flask import Flask, abort, flash, g, jsonify, redirect, render_template, request, session, url_for

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "securewebbank.sqlite3")
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
DEPLOY_ENV = (os.environ.get("APP_ENV") or os.environ.get("ENVIRONMENT") or os.environ.get("FLASK_ENV") or "development").lower()
IS_PRODUCTION = DEPLOY_ENV in {"prod", "production"}
_default_demo_mode = "false" if DEPLOY_ENV in {"prod", "production"} or DATABASE_URL else "true"
DEMO_MODE = os.environ.get("DEMO_MODE", _default_demo_mode).strip().lower() in {"1", "true", "yes", "on"}
if IS_PRODUCTION and not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is required in production so the app does not use ephemeral SQLite storage.")
SECRET_KEY = os.environ.get("SECRET_KEY")
if IS_PRODUCTION and not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is required in production. Set it as a secret environment variable.")
app = Flask(__name__)
app.secret_key = SECRET_KEY or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = IS_PRODUCTION


def now_text() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    """Small qmark-compatible adapter for SQLite and PostgreSQL."""
    def __init__(self, raw, postgres=False):
        self.raw = raw
        self.postgres = postgres

    def execute(self, sql, params=()):
        return self.raw.execute(sql.replace("?", "%s") if self.postgres else sql, params)

    def executescript(self, sql):
        for statement in sql.split(";"):
            if statement.strip():
                self.execute(statement)

    def __enter__(self):
        self.raw.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        return self.raw.__exit__(exc_type, exc, tb)

    def close(self):
        self.raw.close()


def connect_db() -> Database:
    if DATABASE_URL:
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise RuntimeError("DATABASE_URL is set for PostgreSQL, but psycopg is missing. Install requirements.txt.") from exc
        return Database(psycopg.connect(DATABASE_URL, row_factory=dict_row), postgres=True)
    raw = sqlite3.connect(DATABASE, timeout=10)
    raw.row_factory = sqlite3.Row
    raw.execute("PRAGMA foreign_keys = ON")
    return Database(raw)


def begin_atomic_update(db: Database) -> None:
    # A SQLite writer lock plus a conditional balance update prevents overspending.
    # PostgreSQL's connection context already wraps the update pair in a transaction.
    if not db.postgres:
        db.execute("BEGIN IMMEDIATE")


def init_db() -> None:
    with connect_db() as db:
        identity = "BIGSERIAL PRIMARY KEY" if DATABASE_URL else "INTEGER PRIMARY KEY AUTOINCREMENT"
        db.executescript(f"""
        CREATE TABLE IF NOT EXISTS customers (
            customer_id {identity},
            name TEXT NOT NULL,
            phone TEXT NOT NULL DEFAULT '',
            address TEXT NOT NULL DEFAULT '',
            email_notifications INTEGER NOT NULL DEFAULT 1,
            transfer_notifications INTEGER NOT NULL DEFAULT 1,
            security_notifications INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS users (
            user_id {identity},
            customer_id INTEGER NOT NULL UNIQUE REFERENCES customers(customer_id),
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS accounts (
            account_id {identity},
            customer_id INTEGER NOT NULL REFERENCES customers(customer_id),
            account_number TEXT NOT NULL UNIQUE,
            balance INTEGER NOT NULL DEFAULT 0 CHECK(balance >= 0),
            status TEXT NOT NULL DEFAULT 'Active',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS transactions (
            transaction_id {identity},
            account_id INTEGER NOT NULL REFERENCES accounts(account_id),
            type TEXT NOT NULL,
            amount INTEGER NOT NULL CHECK(amount > 0),
            description TEXT NOT NULL DEFAULT '',
            reference TEXT NOT NULL,
            flagged INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS transfers (
            transfer_id {identity},
            reference TEXT NOT NULL UNIQUE,
            sender_account_id INTEGER NOT NULL REFERENCES accounts(account_id),
            receiver_account_id INTEGER REFERENCES accounts(account_id),
            sender_name TEXT NOT NULL,
            sender_account TEXT NOT NULL,
            receiver_name TEXT NOT NULL,
            receiver_account TEXT NOT NULL,
            amount INTEGER NOT NULL CHECK(amount > 0),
            description TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL CHECK(status IN ('Successful','Pending','Failed')),
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_transactions_account_date
            ON transactions(account_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_accounts_customer ON accounts(customer_id);
        CREATE INDEX IF NOT EXISTS idx_transfers_sender_date ON transfers(sender_account_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_transfers_receiver_date ON transfers(receiver_account_id, created_at DESC);
        """)
        if DATABASE_URL:
            for column in ("email_notifications", "transfer_notifications", "security_notifications"):
                db.execute(f"ALTER TABLE customers ADD COLUMN IF NOT EXISTS {column} INTEGER NOT NULL DEFAULT 1")
        else:
            existing = {row["name"] for row in db.execute("PRAGMA table_info(customers)").fetchall()}
            for column in ("email_notifications", "transfer_notifications", "security_notifications"):
                if column not in existing:
                    db.execute(f"ALTER TABLE customers ADD COLUMN {column} INTEGER NOT NULL DEFAULT 1")
        # Sample recipients are seeded only for the clearly labelled local demo.
        samples = [
            ("Ava Bennett", "ava.demo@securewebbank.test", "SB-2048-1101", "+919900000101", 18425000),
            ("Noah Williams", "noah.demo@securewebbank.test", "SB-2048-1102", "+919900000102", 9325000),
            ("Mia Chen", "mia.demo@securewebbank.test", "SB-2048-1103", "+919900000103", 27600000),
        ]
        for name, email, number, phone, balance in samples:
            exists = db.execute("SELECT 1 FROM accounts WHERE account_number=?", (number,)).fetchone()
            if DEMO_MODE:
                if not exists:
                    cur = db.execute("INSERT INTO customers(name,phone,address,created_at) VALUES(?,?,?,?) RETURNING customer_id",
                                     (name, phone, "Demo address", now_text())).fetchone()
                    db.execute("INSERT INTO accounts(customer_id,account_number,balance,created_at) VALUES(?,?,?,?)",
                               (cur["customer_id"], number, balance, now_text()))
                else:
                    db.execute("UPDATE customers SET phone=? WHERE customer_id=(SELECT customer_id FROM accounts WHERE account_number=?)",
                               (phone, number))
                    db.execute("UPDATE accounts SET status='Active' WHERE account_number=? AND status='Demo only'", (number,))
            elif exists:
                # Do not expose demo recipients when reusing a demo database in production.
                db.execute("UPDATE accounts SET status='Demo only' WHERE account_number=?", (number,))


def password_digest(password: str) -> str:
    salt = secrets.token_bytes(16)
    hashed = pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    return f"{salt.hex()}:{hashed.hex()}"


def check_password(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split(":", 1)
        expected = pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 260_000)
        return secrets.compare_digest(expected.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


def current_user():
    if "user_id" not in session:
        return None
    return get_db().execute("""SELECT u.user_id,u.email,c.customer_id,c.name,c.phone,
        c.email_notifications,c.transfer_notifications,c.security_notifications,
        a.account_id,a.account_number,a.balance FROM users u
        JOIN customers c ON c.customer_id=u.customer_id
        JOIN accounts a ON a.customer_id=c.customer_id WHERE u.user_id=?""",
        (session["user_id"],)).fetchone()


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect_db()
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.context_processor
def inject_user():
    csrf_token = session.setdefault("csrf_token", secrets.token_urlsafe(24))
    return {"current_user": current_user(), "csrf_token": csrf_token, "demo_mode": DEMO_MODE}


@app.before_request
def protect_posts():
    if request.method != "POST":
        return
    if request.path.startswith("/api/"):
        if request.path in ("/api/v1/auth/register", "/api/v1/auth/login"):
            return
        supplied = request.headers.get("X-CSRF-Token", "")
    else:
        supplied = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    if not expected or not secrets.compare_digest(supplied, expected):
        abort(400, description="Form expired or security token is invalid. Refresh and try again.")


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not current_user():
            if request.path.startswith("/api/"):
                return jsonify(error="Authentication required"), 401
            flash("Sign in to open your demo account.", "info")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped


def cents_from_input(value: str) -> int:
    try:
        parsed = Decimal(str(value).strip())
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError("Enter a valid amount.")
    if not parsed.is_finite() or parsed.as_tuple().exponent < -2:
        raise ValueError("Enter an amount with no more than two decimal places.")
    amount = int(parsed * 100)
    if amount <= 0 or amount > 100_000_000:
        raise ValueError("Amount must be greater than ₹0 and no more than ₹1,000,000.")
    return amount


def account_for_user(user):
    if not user:
        return None
    return get_db().execute("SELECT * FROM accounts WHERE account_id=? AND customer_id=?",
                            (user["account_id"], user["customer_id"])).fetchone()


def record_transaction(db, account_id, kind, amount, description, reference, flagged=False):
    db.execute("INSERT INTO transactions(account_id,type,amount,description,reference,flagged,created_at) VALUES(?,?,?,?,?,?,?)",
               (account_id, kind, amount, description, reference, int(flagged), now_text()))


def make_flag(db, account_id: int, amount: int) -> bool:
    # Explanatory review flags for this academic demo; no automated fraud decision is made.
    since = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(timespec="seconds")
    recent = db.execute("SELECT COUNT(*) AS n FROM transactions WHERE account_id=? AND type IN ('Transfer out','Transfer in') AND created_at>=?",
                        (account_id, since)).fetchone()["n"]
    return amount >= 1_000_000 or recent >= 4


def normalized_phone(value: str) -> str:
    return "+" + re.sub(r"\D", "", value)


def integrity_error(exc: Exception) -> bool:
    if isinstance(exc, sqlite3.IntegrityError):
        return True
    try:
        import psycopg
        return isinstance(exc, psycopg.IntegrityError)
    except ImportError:
        return False


def history_rows(user, search="", kind="", status=""):
    db = get_db()
    account_id = user["account_id"]
    transfers = db.execute("""SELECT t.*, sc.name AS sender_customer, rc.name AS receiver_customer
        FROM transfers t
        LEFT JOIN accounts ra ON ra.account_id=t.receiver_account_id
        LEFT JOIN customers rc ON rc.customer_id=ra.customer_id
        LEFT JOIN accounts sa ON sa.account_id=t.sender_account_id
        LEFT JOIN customers sc ON sc.customer_id=sa.customer_id
        WHERE t.sender_account_id=? OR (t.receiver_account_id=? AND t.status='Successful')
        ORDER BY t.created_at DESC,t.transfer_id DESC LIMIT 500""", (account_id, account_id)).fetchall()
    rows = []
    for item in transfers:
        rows.append({"id": f"TR-{item['transfer_id']:06d}", "reference": item["reference"], "sender": item["sender_customer"] or item["sender_name"],
                     "sender_account": item["sender_account"], "receiver": item["receiver_customer"] or item["receiver_name"],
                     "receiver_account": item["receiver_account"], "amount": item["amount"],
                     "created_at": item["created_at"], "status": item["status"], "type": "Transfer",
                     "description": item["description"]})
    legacy = db.execute("""SELECT * FROM transactions WHERE account_id=? AND type IN ('Transfer out','Transfer in')
        AND reference NOT IN (SELECT reference FROM transfers) ORDER BY created_at DESC LIMIT 500""", (account_id,)).fetchall()
    for item in legacy:
        outbound = item["type"] == "Transfer out"
        counterparty_number = (item["description"] or "").replace("To ", "", 1) if outbound else (item["description"] or "").replace("From ", "", 1)
        counterparty = db.execute("""SELECT c.name,a.account_number FROM accounts a JOIN customers c USING(customer_id)
            WHERE a.account_number=?""", (counterparty_number,)).fetchone()
        other_name = counterparty["name"] if counterparty else "Demo account"
        rows.append({"id": item["reference"] or f"TX-{item['transaction_id']}", "reference": item["reference"],
                     "sender": user["name"] if outbound else other_name,
                     "sender_account": user["account_number"] if outbound else counterparty_number,
                     "receiver": other_name if outbound else user["name"],
                     "receiver_account": counterparty_number if outbound else user["account_number"],
                     "amount": item["amount"], "created_at": item["created_at"], "status": "Successful",
                     "type": "Transfer", "description": item["description"]})
    txs = db.execute("SELECT * FROM transactions WHERE account_id=? AND type NOT IN ('Transfer out','Transfer in') ORDER BY created_at DESC,transaction_id DESC LIMIT 500", (account_id,)).fetchall()
    for item in txs:
        rows.append({"id": item["reference"] or f"TX-{item['transaction_id']}",
                     "sender": "Cash service" if item["type"] == "Deposit" else user["name"],
                     "sender_account": "SecureWebBank demo" if item["type"] == "Deposit" else user["account_number"],
                     "receiver": user["name"] if item["type"] == "Deposit" else "Cash service",
                     "receiver_account": user["account_number"] if item["type"] == "Deposit" else "SecureWebBank demo",
                     "amount": item["amount"], "created_at": item["created_at"], "status": "Successful",
                     "type": item["type"], "description": item["description"]})
    rows.sort(key=lambda row: (row["created_at"], row["id"]), reverse=True)
    q = search.casefold().strip()
    return [row for row in rows if (not kind or row["type"].casefold() == kind.casefold())
            and (not status or row["status"].casefold() == status.casefold())
            and (not q or q in " ".join(str(row.get(k, "")) for k in ("id", "sender", "sender_account", "receiver", "receiver_account", "type", "description")).casefold())]


@app.get("/")
def home():
    user = current_user()
    if not user:
        return render_template("index.html", page="home", transactions=[], customers=[], recipients=[])
    db = get_db()
    txs = db.execute("""SELECT t.*,a.account_number FROM transactions t JOIN accounts a USING(account_id)
        WHERE t.account_id=? ORDER BY t.created_at DESC,t.transaction_id DESC LIMIT 8""", (user["account_id"],)).fetchall()
    recipients = db.execute("SELECT account_number,c.name FROM accounts a JOIN customers c USING(customer_id) WHERE a.account_id<>? AND a.status='Active' ORDER BY c.name", (user["account_id"],)).fetchall()
    return render_template("index.html", page="dashboard", transactions=txs, recipients=recipients, customers=[])


@app.get("/customers")
def customers():
    if not DEMO_MODE:
        return redirect(url_for("home"))
    if not current_user():
        flash("Sign in to open the demo customer directory.", "info")
        return redirect(url_for("login"))
    rows = get_db().execute("""SELECT c.name,c.phone,a.account_number,a.balance,a.status
        FROM customers c LEFT JOIN accounts a USING(customer_id) ORDER BY c.name""").fetchall()
    return render_template("index.html", page="customers", customers=rows, transactions=[], recipients=[])


@app.get("/transactions")
@login_required
def transactions():
    user = current_user()
    rows = history_rows(user, request.args.get("q", ""), request.args.get("type", ""), request.args.get("status", ""))
    return render_template("index.html", page="transactions", transactions=rows, customers=[], recipients=[], search=request.args.get("q", ""), filter_type=request.args.get("type", ""), filter_status=request.args.get("status", ""))


@app.get("/account")
@login_required
def personal_account():
    user = current_user()
    return render_template("index.html", page="account", transactions=[], customers=[], recipients=[], account=user)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        if len(name) < 2 or len(name) > 80:
            flash("Enter a name between 2 and 80 characters.", "error")
        elif not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            flash("Enter a valid email address.", "error")
        elif len(password) < 8:
            flash("Use at least 8 characters for your password.", "error")
        elif phone and not re.fullmatch(r"\+?[0-9 ()-]{10,20}", phone):
            flash("Enter a valid mobile number or leave it blank.", "error")
        else:
            db = get_db()
            try:
                with db:
                    cur = db.execute("INSERT INTO customers(name,phone,address,created_at) VALUES(?,?,?,?) RETURNING customer_id", (name, normalized_phone(phone) if phone else "", "", now_text())).fetchone()
                    db.execute("INSERT INTO users(customer_id,email,password_hash,created_at) VALUES(?,?,?,?)", (cur["customer_id"], email, password_digest(password), now_text()))
                    number = "SB-" + secrets.token_hex(5).upper()
                    initial_balance = 250_000 if DEMO_MODE else 0
                    db.execute("INSERT INTO accounts(customer_id,account_number,balance,created_at) VALUES(?,?,?,?)", (cur["customer_id"], number, initial_balance, now_text()))
                session.clear()
                session["user_id"] = db.execute("SELECT user_id FROM users WHERE email=?", (email,)).fetchone()["user_id"]
                flash("Your demo account is ready. It starts with ₹2,500 in simulated funds." if DEMO_MODE else "Your account profile is ready. No funds have been added.", "success")
                return redirect(url_for("home"))
            except Exception as exc:
                if not integrity_error(exc):
                    raise
                flash("An account with that email already exists.", "error")
    return render_template("index.html", page="register", transactions=[], customers=[], recipients=[])


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = get_db().execute("SELECT user_id,password_hash FROM users WHERE email=?", (email,)).fetchone()
        if user and check_password(password, user["password_hash"]):
            session.clear()
            session["user_id"] = user["user_id"]
            return redirect(url_for("home"))
        flash("Email or password did not match.", "error")
    return render_template("index.html", page="login", transactions=[], customers=[], recipients=[])


@app.post("/logout")
def logout():
    session.clear()
    flash("You have been securely signed out.", "success")
    return redirect(url_for("login"))


@app.post("/action/<kind>")
@login_required
def banking_action(kind):
    if kind == "transfer":
        flash("Please use the recipient verification and confirmation flow to send demo transfers.", "info")
        return redirect(url_for("home"))
    user = current_user()
    db = get_db()
    try:
        amount = cents_from_input(request.form.get("amount", ""))
        if kind not in ("deposit", "withdraw", "transfer"):
            abort(404)
        with db:
            begin_atomic_update(db)
            account = account_for_user(user)
            reference = "SWB-" + secrets.token_hex(4).upper()
            flagged = make_flag(db, account["account_id"], amount)
            if kind == "deposit":
                db.execute("UPDATE accounts SET balance=balance+? WHERE account_id=?", (amount, account["account_id"]))
                record_transaction(db, account["account_id"], "Deposit", amount, "Cash deposit", reference, flagged)
                message = "Deposit added to your demo balance."
            elif kind == "withdraw":
                cur = db.execute("UPDATE accounts SET balance=balance-? WHERE account_id=? AND balance>=?", (amount, account["account_id"], amount))
                if cur.rowcount != 1:
                    raise ValueError("There are not enough demo funds for that withdrawal.")
                record_transaction(db, account["account_id"], "Withdrawal", amount, "Cash withdrawal", reference, flagged)
                message = "Withdrawal recorded."
            else:
                recipient_number = request.form.get("recipient", "").strip().upper()
                recipient = db.execute("SELECT account_id,account_number FROM accounts WHERE account_number=? AND status='Active'", (recipient_number,)).fetchone()
                if not recipient or recipient["account_id"] == account["account_id"]:
                    raise ValueError("Choose a valid demo recipient account.")
                cur = db.execute("UPDATE accounts SET balance=balance-? WHERE account_id=? AND balance>=?", (amount, account["account_id"], amount))
                if cur.rowcount != 1:
                    raise ValueError("There are not enough demo funds for that transfer.")
                db.execute("UPDATE accounts SET balance=balance+? WHERE account_id=?", (amount, recipient["account_id"]))
                record_transaction(db, account["account_id"], "Transfer out", amount, f"To {recipient_number}", reference, flagged)
                record_transaction(db, recipient["account_id"], "Transfer in", amount, f"From {account['account_number']}", reference, flagged)
                message = "Demo transfer completed. Both account entries were saved together."
            if flagged:
                flash("This activity was also marked for demo review.", "info")
        flash(message, "success")
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("home"))


recipient_signer = URLSafeTimedSerializer(app.secret_key, salt="securewebbank-recipient-confirmation")


def recipient_token(user, account, customer_name):
    return recipient_signer.dumps({"user_id": user["user_id"], "account_id": account["account_id"], "name": customer_name})


@app.post("/api/v1/recipients/verify-account")
@login_required
def verify_account_recipient():
    data = request.get_json(silent=True) or {}
    account_number = str(data.get("account_number", "")).strip().upper()
    receiver_name = " ".join(str(data.get("receiver_name", "")).split())
    if not account_number or len(receiver_name) < 2:
        return jsonify(error="Enter an account number and recipient name."), 400
    recipient = get_db().execute("""SELECT a.account_id,a.account_number,a.status,c.name
        FROM accounts a JOIN customers c USING(customer_id) WHERE a.account_number=?""", (account_number,)).fetchone()
    user = current_user()
    if not recipient or recipient["status"] != "Active" or recipient["account_id"] == user["account_id"]:
        return jsonify(error="We couldn't verify that recipient account."), 404
    if recipient["name"].casefold() != receiver_name.casefold():
        return jsonify(error="The recipient name does not match the account holder."), 409
    token = recipient_token(user, recipient, recipient["name"])
    return jsonify(verified=True, recipient_name=recipient["name"], account_number=recipient["account_number"], masked_account="•••• " + recipient["account_number"][-4:], recipient_token=token)


@app.post("/api/v1/recipients/verify-mobile")
@login_required
def verify_mobile_recipient():
    data = request.get_json(silent=True) or {}
    phone = normalized_phone(str(data.get("mobile", "")))
    digits = phone[1:]
    if not 10 <= len(digits) <= 15:
        return jsonify(error="Enter a valid registered mobile number."), 400
    user = current_user()
    candidates = get_db().execute("""SELECT a.account_id,a.account_number,a.status,c.name,c.phone
        FROM accounts a JOIN customers c USING(customer_id) WHERE a.status='Active' AND c.phone<>''""").fetchall()
    matches = [row for row in candidates if normalized_phone(row["phone"]) == phone and row["account_id"] != user["account_id"]]
    if len(matches) != 1:
        return jsonify(error="No unique active demo account is registered to that mobile number."), 404
    recipient = matches[0]
    token = recipient_token(user, recipient, recipient["name"])
    return jsonify(verified=True, recipient_name=recipient["name"], masked_mobile="••• ••• " + digits[-4:], masked_account="•••• " + recipient["account_number"][-4:], recipient_token=token)


@app.post("/transfers")
@login_required
def create_transfer():
    user = current_user()
    try:
        amount = cents_from_input(request.form.get("amount", ""))
        description = request.form.get("description", "").strip()[:180]
        raw_token = request.form.get("recipient_token", "")
        recipient_claim = recipient_signer.loads(raw_token, max_age=300)
        if recipient_claim.get("user_id") != user["user_id"]:
            raise ValueError("Please verify the recipient again before transferring.")
    except (ValueError, BadSignature, SignatureExpired) as exc:
        flash(str(exc) if isinstance(exc, ValueError) else "Recipient confirmation expired. Please verify the details again.", "error")
        return redirect(url_for("home"))

    db = get_db()
    reference = "SWB-" + secrets.token_hex(5).upper()
    failed_message = None
    with db:
        begin_atomic_update(db)
        account = account_for_user(user)
        recipient = db.execute("""SELECT a.account_id,a.account_number,a.status,c.name
            FROM accounts a JOIN customers c USING(customer_id) WHERE a.account_id=?""",
            (recipient_claim.get("account_id"),)).fetchone()
        if not recipient or recipient["status"] != "Active" or recipient["name"] != recipient_claim.get("name") or recipient["account_id"] == account["account_id"]:
            flash("The verified recipient is no longer available. Verify the details again.", "error")
            return redirect(url_for("home"))
        flagged = make_flag(db, account["account_id"], amount)
        debit = db.execute("UPDATE accounts SET balance=balance-? WHERE account_id=? AND balance>=?", (amount, account["account_id"], amount))
        if debit.rowcount != 1:
            db.execute("INSERT INTO transfers(reference,sender_account_id,receiver_account_id,sender_name,sender_account,receiver_name,receiver_account,amount,description,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,'Failed',?)",
                       (reference, account["account_id"], recipient["account_id"], user["name"], user["account_number"], recipient["name"], recipient["account_number"], amount, description, now_text()))
            failed_message = "Transfer failed: your available demo balance is too low. The failed attempt is recorded in Transfer History."
        else:
            db.execute("UPDATE accounts SET balance=balance+? WHERE account_id=?", (amount, recipient["account_id"]))
            db.execute("INSERT INTO transfers(reference,sender_account_id,receiver_account_id,sender_name,sender_account,receiver_name,receiver_account,amount,description,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,'Successful',?)",
                       (reference, account["account_id"], recipient["account_id"], user["name"], user["account_number"], recipient["name"], recipient["account_number"], amount, description, now_text()))
            record_transaction(db, account["account_id"], "Transfer out", amount, f"To {recipient['account_number']}", reference, flagged)
            record_transaction(db, recipient["account_id"], "Transfer in", amount, f"From {account['account_number']}", reference, flagged)
    if failed_message:
        flash(failed_message, "error")
    else:
        flash(f"Transfer complete: ₹{amount / 100:,.2f} sent to {recipient['name']}.", "success")
        if flagged:
            flash("This simulated transfer was also marked for demo review.", "info")
    return redirect(url_for("transactions"))


@app.post("/account/profile")
@login_required
def update_profile():
    user = current_user()
    name = " ".join(request.form.get("name", "").split())
    email = request.form.get("email", "").strip().lower()
    phone = request.form.get("phone", "").strip()
    if len(name) < 2 or len(name) > 80 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        flash("Enter a valid name and email address.", "error")
    elif phone and (not re.fullmatch(r"\+?[0-9 ()-]{10,20}", phone) or not 10 <= len(re.sub(r"\D", "", phone)) <= 15):
        flash("Enter a valid mobile number.", "error")
    else:
        try:
            with get_db() as db:
                db.execute("UPDATE customers SET name=?,phone=? WHERE customer_id=?", (name, normalized_phone(phone) if phone else "", user["customer_id"]))
                db.execute("UPDATE users SET email=? WHERE user_id=?", (email, user["user_id"]))
            flash("Personal details saved.", "success")
        except Exception as exc:
            if not integrity_error(exc):
                raise
            flash("That email address is already in use.", "error")
    return redirect(url_for("personal_account"))


@app.post("/account/password")
@login_required
def update_password():
    user = current_user()
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")
    stored = get_db().execute("SELECT password_hash FROM users WHERE user_id=?", (user["user_id"],)).fetchone()["password_hash"]
    if not check_password(current_password, stored):
        flash("Current password is incorrect.", "error")
    elif len(new_password) < 8:
        flash("New password must be at least 8 characters.", "error")
    elif new_password != confirm:
        flash("New password entries do not match.", "error")
    else:
        with get_db() as db:
            db.execute("UPDATE users SET password_hash=? WHERE user_id=?", (password_digest(new_password), user["user_id"]))
        session.clear()
        flash("Password changed. Sign in again to continue.", "success")
        return redirect(url_for("login"))
    return redirect(url_for("personal_account"))


@app.post("/account/notifications")
@login_required
def update_notifications():
    user = current_user()
    with get_db() as db:
        db.execute("UPDATE customers SET email_notifications=?,transfer_notifications=?,security_notifications=? WHERE customer_id=?",
                   (int("email_notifications" in request.form), int("transfer_notifications" in request.form), int("security_notifications" in request.form), user["customer_id"]))
    flash("Notification preferences saved.", "success")
    return redirect(url_for("personal_account"))


# Small JSON API, matching the milestones' basic REST contract.
@app.get("/api/v1/health")
def api_health():
    return jsonify(status="ok", application="SecureWebBank demo", simulated=True)


@app.post("/api/v1/auth/register")
def api_register():
    data = request.get_json(silent=True) or {}
    required = [str(data.get(k, "")).strip() for k in ("name", "email", "password")]
    if not all(required) or len(required[2]) < 8:
        return jsonify(error="Name, email and a password of at least 8 characters are required."), 400
    try:
        with get_db() as db:
            cur = db.execute("INSERT INTO customers(name,created_at) VALUES(?,?) RETURNING customer_id", (required[0], now_text())).fetchone()
            db.execute("INSERT INTO users(customer_id,email,password_hash,created_at) VALUES(?,?,?,?)", (cur["customer_id"], required[1].lower(), password_digest(required[2]), now_text()))
            number = "SB-" + secrets.token_hex(5).upper()
            initial_balance = 250_000 if DEMO_MODE else 0
            db.execute("INSERT INTO accounts(customer_id,account_number,balance,created_at) VALUES(?,?,?,?)", (cur["customer_id"], number, initial_balance, now_text()))
        return jsonify(message="Demo user created", account_number=number), 201
    except Exception as exc:
        if not integrity_error(exc):
            raise
        return jsonify(error="Email already exists."), 409


@app.post("/api/v1/auth/login")
def api_login():
    data = request.get_json(silent=True) or {}
    user = get_db().execute("SELECT user_id,password_hash FROM users WHERE email=?", (str(data.get("email", "")).strip().lower(),)).fetchone()
    if not user or not check_password(str(data.get("password", "")), user["password_hash"]):
        return jsonify(error="Invalid email or password."), 401
    session.clear()
    session["user_id"] = user["user_id"]
    session["csrf_token"] = secrets.token_urlsafe(24)
    return jsonify(message="Signed in", authenticated=True, csrf_token=session["csrf_token"])


@app.get("/api/v1/banking/balance")
@login_required
def api_balance():
    user = current_user()
    return jsonify(account_number=user["account_number"], balance=user["balance"] / 100, currency="INR", simulated=True)


@app.post("/api/v1/banking/<kind>")
@login_required
def api_banking(kind):
    if kind not in ("deposit", "withdraw"):
        return jsonify(error="Supported actions: deposit, withdraw."), 404
    data = request.get_json(silent=True) or {}
    try:
        amount = cents_from_input(str(data.get("amount", "")))
        user = current_user()
        db = get_db()
        with db:
            begin_atomic_update(db)
            account = account_for_user(user)
            if kind == "withdraw":
                cur = db.execute("UPDATE accounts SET balance=balance-? WHERE account_id=? AND balance>=?", (amount, account["account_id"], amount))
                if cur.rowcount != 1:
                    return jsonify(error="Insufficient demo balance."), 400
            else:
                db.execute("UPDATE accounts SET balance=balance+? WHERE account_id=?", (amount, account["account_id"]))
            record_transaction(db, account["account_id"], "Deposit" if kind == "deposit" else "Withdrawal", amount, "API request", "API-" + secrets.token_hex(4).upper())
        return jsonify(message=f"{kind.title()} recorded", amount=amount / 100)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400


@app.get("/api/v1/banking/transactions")
@login_required
def api_transactions():
    user = current_user()
    rows = history_rows(user)[:100]
    return jsonify(transactions=[{**row, "amount": row["amount"] / 100} for row in rows])


init_db()

if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        debug=os.environ.get("FLASK_DEBUG") == "1",
        port=int(os.environ.get("PORT", "5055")),
    )
