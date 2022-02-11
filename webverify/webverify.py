import logging 
import time
import base64
from binascii import Error as BinAsciiError
import hmac
import hashlib
import uuid

from flask import Flask
from flask import request, g, current_app
from flask import render_template, redirect, url_for

import requests
from requests.exceptions import Timeout as RequestsTimeout

import psycopg2

IS_UWSGI = False
try:
    import uwsgi
    IS_UWSGI = True
except:
    pass

app = application = Flask(__name__)
cfg = app.config
cfg.from_pyfile('../webverify.cfg')

app.logger.setLevel(logging.INFO)

if 'MOUNT_POINT' in cfg and cfg['MOUNT_POINT'] != '/' and cfg['MOUNT_POINT'][0] == '/':
    from werkzeug.middleware.dispatcher import DispatcherMiddleware
    from werkzeug.wrappers import Response

    default_app = Response('Not Found', status=404)
    mounts = {cfg['MOUNT_POINT']: app.wsgi_app}

    app.wsgi_app = DispatcherMiddleware(default_app, mounts)

class WebverifyException(Exception):
    pass

class DbException(WebverifyException):
    pass

class DbRetryDelayException(WebverifyException):
    pass

class TokenException(WebverifyException):
    pass

class CaptchaException(WebverifyException):
    pass

from werkzeug.exceptions import InternalServerError, HTTPException

@app.errorhandler(HTTPException)
def unhandled_exception(e):
    error_id = uuid.uuid4()
    app.logger.error("unhandled exception error_id=%s, path=%s", error_id, request.path)
    return render_template("error_exception.html", error_id=error_id), 500

@app.before_first_request
def before_first_request():
    current_app.last_failed_db_conn = None
    try:
        current_app.conn = db_connect()
    except DbException:
        current_app.conn = DummyConn()

@app.before_request
def before_request():
    conn = current_app.conn

    if conn.closed != 0:
        try:
            conn = db_connect()
        except DbException as e:
            error_id = uuid.uuid4()
            app.logger.error("database exception error_id=%s: %s", error_id, str(e))
            return render_template("error_db.html", error_id=error_id), 503
        current_app.conn = conn

    g.conn = conn

class DummyConn:
    def __init__(self):
        self.closed = 1

def db_connect():
    try:
        if current_app.last_failed_db_conn:
            if time.time() - current_app.last_failed_db_conn <= cfg['PG_RECONN_DELAY']:
                raise DbRetryDelayException('retry-delay')
            else:
                current_app.last_failed_db_conn = None

        conn = psycopg2.connect(
            host=cfg['PG_HOST'], port=cfg['PG_PORT'], sslmode=cfg['PG_SSLMODE'],
            database=cfg['PG_DATABASE'], user=cfg['PG_USER'], password=cfg['PG_PASSWORD'],
            connect_timeout=cfg['PG_TIMEOUT'], application_name='webverify',
            keepalives=1, keepalives_idle=30, keepalives_interval=10, keepalives_count=5,
            target_session_attrs='read-write',
        )
    except (psycopg2.OperationalError, DbRetryDelayException) as e:
        if current_app.last_failed_db_conn == None:
            current_app.last_failed_db_conn = time.time()
        raise DbException(e)
    conn.autocommit = True
    return conn

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/<token>', methods=['GET', 'POST'])
def verify(token=None):
    try:
        key = cfg['TOKEN_HMAC_KEY']

        if cfg['HASH_TOKEN_HMAC_KEY_BEFORE_USE'] == True:
            key = hashlib.sha1(key).digest()

        nick = validate_token(token, key, cfg['TOKEN_EXPIRE'], int(time.time()))
    except TokenException as e:
        error = str(e)
        error_id = None
        if error == 'token-future':
            error_id = uuid.uuid4()
            app.logger.fatal("token exception error=%s, error_id=%s, token=%s", error, error_id, token)
        return render_template('error_token.html', error=error, error_id=error_id), 400

    try:
        verified = is_nick_verified(nick)
        if verified is None:
            return render_template("error_nonick.html", nick=nick), 404
        elif verified is True:
            return render_template("success_already.html", nick=nick)
        else:
            if request.method == 'GET':
                return get(token, nick)
            elif request.method == 'POST':
                return post(token, nick)
    except DbException as e:
        error_id = uuid.uuid4()
        app.logger.error("database exception error_id=%s: %s", error_id, str(e))
        return render_template("error_db.html", error_id=error_id), 503

def get(token, nick):
    return render_template('form.html',
        hcaptcha_site_key=cfg['HCAPTCHA_SITE_KEY'],
        token=token, nick=nick, auto_submit=cfg['AUTO_SUBMIT'])

def post(token, nick):
    if not 'token' in request.form:
        return render_template('error_token.html', error='token-missing'), 400

    if not 'h-captcha-response' in request.form:
        return redirect(url_for('index'), code=303)

    if not token == request.form['token']:
        return render_template('error_token.html', error='token-mismatch'), 400

    try:
        if validate_hcaptcha(request.form['h-captcha-response']):
            did_set = set_nick_verified(nick)
            if did_set == None:
                app.logger.info("verify no_nick nick='%s' token='%s'", nick, token)
                return render_template("error_nonick.html", nick=nick), 404
            elif did_set == True:
                app.logger.info("verify success nick='%s' token='%s'", nick, token)
                return render_template('success.html', nick=nick)
            else:
                app.logger.warning("verify fail nick='%s' token='%s'", nick, token)
                return render_template('failure.html')
    except CaptchaException as e:
        error = str(e)
        skip_log = [
            'invalid-or-already-seen-response', 'missing-input-response',
            'invalid-input-response', 'captcha-timeout', 'captcha-bad-response'
        ]
        if error not in skip_log:
            error_id = uuid.uuid4()
            app.logger.critical("captcha exception error=%s, error_id=%s", error, error_id)
            return render_template('error_captcha.html', token=token, error=error, error_id=error_id)

        return render_template('error_captcha.html', token=token, error=error)

def validate_token(token, key, expire=3600, now=None):
    if not token:
        raise TokenException('token-invalid')

    if now is None:
        now = int(time.time())

    try:
        [token_nick, token_time, token_hash] = token.split(':')
    except ValueError:
        raise TokenException('token-invalid')

    try:
        nick = base64.b16decode(token_nick, casefold=True).decode()
        token_hash = base64.b16decode(token_hash, casefold=True)
    except BinAsciiError:
        raise TokenException('token-invalid')

    message = nick + ':' + token_time
    hash_computed = hmac.new(key, message.encode(), hashlib.sha1).digest()

    if hmac.compare_digest(hash_computed, token_hash):
        try:
            token_time = int(token_time)
        except ValueError:
            raise TokenException('token-invalid')

        if now < token_time:
            raise TokenException('token-future')
        elif (now - token_time) > expire:
            raise TokenException('token-expired')
        else:
            return nick
    else:
        raise TokenException('token-invalid')

def is_nick_verified(nick):
    """
    Returns True if verified, False if not, and None if nick doesn't
    exist.

    If running in uWSGI, it attempts to use a cached value set in
    `maybe_set_cache`.
    """
    if IS_UWSGI:
        key = hashlib.sha1(nick.encode()).digest()
        val = uwsgi.cache_get(key, 'verified')
        if val == b'1':
            return True
        elif val == b'0':
            return None
        
    is_verified = run_query(r'SELECT webverify_check(%s)', (nick,))
    maybe_set_cache(nick, is_verified)
    return is_verified

def set_nick_verified(nick):
    did_verify = run_query(r'SELECT webverify_verify(%s)', (nick,))
    maybe_set_cache(nick, did_verify)
    return did_verify

def run_query(query, params):
    try:
        with g.conn.cursor() as cur:
            cur.execute(query, params)
            return cur.fetchone()[0]
    except psycopg2.OperationalError as e:
        raise DbException(e)

def maybe_set_cache(nick, verified):
    """
    If running in uWSGI, it sets a key to a value depending on if it verified
    successfully or if the nick no longer exists.

    key is the sha1 hash of the nick, and the value is 1 for successful
    verification and 0 for nonexistent.
    """
    if IS_UWSGI:
        if verified == True:
            key = hashlib.sha1(nick.encode()).digest()
            uwsgi.cache_set(key, b'1', cfg['CACHE_EXPIRE'], 'verified')
        elif verified == None:
            key = hashlib.sha1(nick.encode()).digest()
            uwsgi.cache_set(key, b'0', cfg['CACHE_EXPIRE'], 'verified')

def validate_hcaptcha(response):
    data = { 'response': response, 'secret': cfg['HCAPTCHA_SECRET_KEY'] }

    try:
        r = requests.post('https://hcaptcha.com/siteverify', data=data, timeout=cfg.get('REQUESTS_TIMEOUT', (2, 5)))
    except RequestsTimeout:
        raise CaptchaException('captcha-timeout')

    if not (r.status_code == 200 and r.headers['Content-Type'] == 'application/json'):
        raise CaptchaException('captcha-bad-response')

    try:
        resp = r.json()
    except ValueError:
        raise CaptchaException('captcha-bad-response')

    if 'success' in resp and resp['success'] == True:
        return True
    else:
        if not 'error-codes' in resp:
            raise CaptchaException('captcha-bad-response')

        errors = resp['error-codes']

        if len(errors) == 1:
            raise CaptchaException(errors[0])
        else:
            raise CaptchaException('captcha-multiple-errors', errors)
