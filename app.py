import os
import secrets
import hashlib
import smtplib
import ssl
import traceback

from datetime import datetime, timedelta
from email.message import EmailMessage

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv


load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv(
    'SECRET_KEY',
    'dev-only-change-this-secret-before-deployment'
)

database_url = os.getenv('DATABASE_URL', 'sqlite:///myhousehold.db')

if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.getenv('COOKIE_SECURE', '0') == '1'

db = SQLAlchemy(app)


# ---------------------------------------------------------
# DATABASE MODELS
# ---------------------------------------------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    verified = db.Column(db.Boolean, default=False, nullable=False)
    budget = db.Column(db.Float, default=0.0, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class VerificationCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, index=True)
    code_hash = db.Column(db.String(64), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    name = db.Column(db.String(160), nullable=False)
    description = db.Column(db.String(255), default='')
    quantity = db.Column(db.Integer, default=1, nullable=False)
    available = db.Column(db.Boolean, default=True, nullable=False)
    category = db.Column(db.String(80), default='Groceries', nullable=False)


with app.app_context():
    db.create_all()


# ---------------------------------------------------------
# EMAIL VERIFICATION
# ---------------------------------------------------------

def send_code(email, code):
    host = os.getenv('SMTP_HOST')
    user = os.getenv('SMTP_USER')
    password = os.getenv('SMTP_PASSWORD')

    if not all([host, user, password]):
        print(f"\n[DEV] Verification code for {email}: {code}\n")
        return False

    msg = EmailMessage()
    msg['Subject'] = 'Your Homystocky verification code'
    msg['From'] = os.getenv('SMTP_FROM', user)
    msg['To'] = email
    msg.set_content(
        f'Your Homystocky verification code is {code}. '
        'It expires in 10 minutes.'
    )

    try:
        port = int(os.getenv('SMTP_PORT', '465'))
        ctx = ssl.create_default_context()

        with smtplib.SMTP_SSL(host, port, context=ctx, timeout=20) as server:
            server.login(user, password)
            server.send_message(msg)

        return True

    except Exception as e:
        print("SMTP ERROR:", repr(e))
        print(f"\n[DEV] Verification code for {email}: {code}\n")
        return False


def login_required():
    return 'user_id' in session


# ---------------------------------------------------------
# PAGE ROUTES
# ---------------------------------------------------------

@app.route('/')
def login_page():
    if login_required():
        return redirect(url_for('dashboard'))

    return render_template('login.html')


@app.route('/signup_page')
def signup_page():
    if login_required():
        return redirect(url_for('dashboard'))

    return render_template('signup.html')


@app.route('/dashboard')
def dashboard():
    if not login_required():
        return redirect(url_for('login_page'))

    return render_template(
        'dashboard.html',
        email=session.get('email'),
        show_dashboard=True
    )


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))


# ---------------------------------------------------------
# SIGNUP AND EMAIL VERIFICATION
# ---------------------------------------------------------

@app.post('/api/signup/send-code')
def signup_send_code():
    data = request.get_json(silent=True) or request.form

    email = (data.get('email') or '').strip().lower()

    if not email or '@' not in email:
        return jsonify(error='Enter a valid email address.'), 400

    if User.query.filter_by(email=email).first():
        return jsonify(error='That email is already registered.'), 409

    code = f'{secrets.randbelow(100000):05d}'

    digest = hashlib.sha256(
        (code + app.config['SECRET_KEY']).encode()
    ).hexdigest()

    VerificationCode.query.filter_by(email=email).delete()

    verification = VerificationCode(
        email=email,
        code_hash=digest,
        expires_at=datetime.utcnow() + timedelta(minutes=10)
    )

    db.session.add(verification)
    db.session.commit()

    if not send_code(email, code):
        return jsonify(
            message='Email is not configured. Check the VS Code terminal for your code.'
        ), 200

    return jsonify(
        message='A five-digit verification code has been sent to your email address.'
    )


@app.post('/signup')
def signup():
    data = request.get_json(silent=True) or request.form

    email = (data.get('email') or '').strip().lower()
    code = (data.get('code') or '').strip()
    password = data.get('password') or ''

    if len(password) < 8:
        return jsonify(
            error='Use a password with at least 8 characters.'
        ), 400

    record = VerificationCode.query.filter_by(
        email=email
    ).order_by(
        VerificationCode.created_at.desc()
    ).first()

    if not record:
        return jsonify(error='Request a verification code first.'), 400

    if record.expires_at < datetime.utcnow():
        return jsonify(error='That code has expired.'), 400

    digest = hashlib.sha256(
        (code + app.config['SECRET_KEY']).encode()
    ).hexdigest()

    if not secrets.compare_digest(record.code_hash, digest):
        return jsonify(error='The verification code is incorrect.'), 400

    user = User(
        email=email,
        password_hash=generate_password_hash(password),
        verified=True
    )

    db.session.add(user)
    db.session.delete(record)
    db.session.commit()

    session.clear()
    session['user_id'] = user.id
    session['email'] = user.email

    return jsonify(
        message='Account created.',
        redirect=url_for('dashboard')
    )


# ---------------------------------------------------------
# LOGIN
# ---------------------------------------------------------

@app.post('/login')
def login():
    data = request.get_json(silent=True) or request.form

    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify(
            error='No account found. Please sign up.'
        ), 404

    if not user.verified or not check_password_hash(
        user.password_hash,
        password
    ):
        return jsonify(
            error='Incorrect email or password.'
        ), 401

    session.clear()
    session['user_id'] = user.id
    session['email'] = user.email

    return jsonify(
        message='Logged in.',
        redirect=url_for('dashboard')
    )


# ---------------------------------------------------------
# HOUSEHOLD ITEMS API
# ---------------------------------------------------------

@app.route('/api/items', methods=['GET', 'POST'])
def api_items():
    if not login_required():
        return jsonify(error='Please log in.'), 401

    uid = session['user_id']

    # GET: Load this user's saved items from the database.
    if request.method == 'GET':
        saved_items = Item.query.filter_by(
            user_id=uid
        ).order_by(
            Item.id.asc()
        ).all()

        return jsonify([
            {
                'id': item.id,
                'name': item.name,
                'description': item.description,
                'quantity': item.quantity,
                'available': item.available,
                'category': item.category
            }
            for item in saved_items
        ])

    # POST: Save the complete list submitted by the browser.
    data = request.get_json(silent=True)

    if not isinstance(data, list):
        return jsonify(error='Expected a list of items.'), 400

    try:
        retained_ids = set()

        for x in data:
            if not isinstance(x, dict):
                continue

            name = (x.get('name') or '').strip()

            # Ignore rows that have no product name.
            if not name:
                continue

            description = (x.get('description') or '').strip()
            category = (x.get('category') or 'Groceries').strip()

            try:
                quantity = int(x.get('quantity') or 1)
            except (TypeError, ValueError):
                quantity = 1

            quantity = max(1, min(999, quantity))
            available = bool(x.get('available', True))

            item_id = x.get('id')
            item = None

            # Update only if this item belongs to the logged-in user.
            if isinstance(item_id, int) and not isinstance(item_id, bool):
                item = Item.query.filter_by(
                    id=item_id,
                    user_id=uid
                ).first()

            if item:
                item.name = name[:160]
                item.description = description[:255]
                item.quantity = quantity
                item.available = available
                item.category = category[:80]

            else:
                # New rows (including temporary browser IDs) are inserted.
                item = Item(
                    user_id=uid,
                    name=name[:160],
                    description=description[:255],
                    quantity=quantity,
                    available=available,
                    category=category[:80]
                )
                db.session.add(item)

            # Get the real database ID for the new or updated row.
            db.session.flush()
            retained_ids.add(item.id)

        # Remove database rows deleted by the user in the browser.
        user_items_query = Item.query.filter_by(user_id=uid)

        if retained_ids:
            user_items_query.filter(
                ~Item.id.in_(retained_ids)
            ).delete(synchronize_session=False)
        else:
            user_items_query.delete(synchronize_session=False)

        db.session.commit()

        return jsonify(
            status='success',
            message='Your household list has been saved successfully!'
        )

    except Exception:
        db.session.rollback()
        traceback.print_exc()

        return jsonify(
            error='Something went wrong while saving your household list.'
        ), 500


# ---------------------------------------------------------
# START APPLICATION
# ---------------------------------------------------------

if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int(os.getenv('PORT', '5000')),
        debug=os.getenv('FLASK_DEBUG', '1') == '1'
    )
