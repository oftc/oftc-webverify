# OFTC Webverify

Human verification of OFTC Services accounts with the help of hCaptcha.

Implemented in `Python` as a `Flask` app intended to run on `uWSGI`.
Makes use of `requests` and `psycopg2`.

Known to work on Python 3.5 and 3.7.

## Application Configuration
The application expects `webverify.cfg` to exist in the root directory. `webverify.example.cfg` is included as a template. All parameters are required.

## Setup
### Prerequisites
The following build prerequisites need to be met:

  * A C compiler and related tools
  * python3-dev
  * libpq-dev

Which on `Debian` can be satisfied with `apt-get install build-essential python3-dev libpq-dev`

### Virtual Env
Set up the virtual env:
`python3 -m venv venv`

and activate it:
`. venv/bin/activate`

### Python Dependencies

  * Flask
  * requests
  * psycopg2
  * uWSGI

Install them with:
 
`pip3 install -r requirements.txt`

or if you like living on the edge:

`pip3 install flask requests psycopg2 uwsgi`


## Running
Ensure that the virtual env has been activated with `. venv/bin/activate`

### Production
`uWSGI` can be configured in `webverify.uwsgi.ini.` `webverify.uwsgi.example.ini` is included as a template.

Two settings that are important to consider are `http-socket` that sets the address and port to bind on, and `processes` that sets the number of workers that will be spawned to handle requests. Each worker will establish its own connection to the database.

Additionally, if running on `uWSGI`, a `uWSGI` cache named `verified` is expected to exist with `blocksize=1` and `keysize=20`, set up as:

`cache2 = name=verified,items=1000,blocksize=1,keysize=20`

The included `webverify.uwsgi.example.ini` watches two files to perform reloading and to reopen the log. The latter can for instance be used as a `postrotate` command in `logrotate`.

Reload: `touch run/webverify.uwsgi.touch-reload`

Reopen log: `touch run/webverify.uwsgi.touch-logreopen`

#### Standalone
`uwsgi webverify.uwsgi.ini`

#### Systemd Service
A systemd service file suitable to be used as a user service is provided in `webverify.service` as an example.

It expects `oftc-webverify` to be installed in `/opt/oftc-webverify`.

Install `webverify.service` in `~/.config/systemd/user/webverify.service`

Run `systemctl --user start webverify` to start it

Run `systemctl --user enable webverify` to have it start automatically on boot.

#### Logrotate
A suitable logrotate example configuration is provided in `webverify.logrotate`.

It can, for instance, be installed as `/etc/logrotate.d/webverify` on some distributions.

It expects `oftc-webverify` to be installed in `/opt/oftc-webverify` and to be running as the user `oftc-webverify`

### Development
For development you can use the Flask built-in server that provides some debugging help:

`FLASK_ENV=development FLASK_APP=webverify/webverify flask run`

## Verification Token
The token format is 
`base16(nick):epoch:sha1hmac(nick+':'+epoch)`

The nick is base16-encoded due to IRC supporting characters in nicks that are not URL-safe, and because base16 encoding is already available and used in Services.

Currently, Services SHA1-hash the secret to produce the key used in the HMAC.

### Example Token Generation
```python
import time, base64, hmac, hashlib

secret = b'secret'
hash_key = True
nick = 'MyAwesomeNick'
epoch = str(int(time.time()))
message = 'nick' + ':' + epoch

if hash_key:
  key = hashlib.sha1(secret).digest()
else:
  key = secret

msg = (nick + ':' + epoch).encode()
auth = hmac.new(key, message.encode(), hashlib.sha1).hexdigest()

b16nick = base64.b16encode(nick.encode()).decode() 
token = b16nick + ':' + epoch + ':' + auth
print(token)
```

## License
OFTC Webverify is released under Apache License 2.0
