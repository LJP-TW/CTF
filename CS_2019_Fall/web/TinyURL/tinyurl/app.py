import sys
import sqlite3
import string
import random
import urllib.request
from flask import Flask, g, request, redirect, render_template, session, abort
from flask_session import Session
from contextlib import closing
from redis import Redis


app = Flask(__name__)
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = Redis(
    host='redis',
    port=6379
)
Session(app)

DATABASE = './data/database.db'
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.70 Safari/537.36'

def connect_db():
    return sqlite3.connect(DATABASE)

def id_generator(size=7, chars=string.ascii_letters + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def get_title(url):
    req = urllib.request.Request(
        url, 
        data=None, 
        headers={
            'User-Agent': USER_AGENT
        }
    )
    webpage = urllib.request.urlopen(req).read()
    title = webpage.decode().split('<title>')[1].split('</title>')[0]
    return title

@app.before_request
def before_request():
    g.db = connect_db()

@app.teardown_request
def teardown_request(exception):
    if hasattr(g, 'db'):
        g.db.close()

@app.route("/ignore/<url_id>", methods=['GET'])
def ignore_warning(url_id):
    cursor = g.db.cursor()
    cursor.execute('SELECT url FROM urls WHERE id = ?', (url_id,))
    row = cursor.fetchone()
    if not row:
        abort(404)
    url = row[0]
    if request.args.get('ignore') == 'yes':
        ignore_warning = session.get('ignore_warning', None)
        if not ignore_warning:
            ignore_warning = []
            session['ignore_warning'] = ignore_warning
        ignore_warning.append(url_id)
    return redirect(url, code=302)

@app.route("/<url_id>", methods=['GET'])
def preview(url_id):
    cursor = g.db.cursor()
    cursor.execute('SELECT url FROM urls WHERE id = ?', (url_id,))
    row = cursor.fetchone()
    if not row:
        abort(404)
    url = row[0]
    ignore_warning = session.get('ignore_warning', [])
    if url_id in ignore_warning:
        return redirect(url, code=302)
    else:
        return render_template('preview.html',
                                url=url,
                                url_id=url_id,
                                title=get_title(url))

@app.route("/", methods=['POST'])
def shorten_url():
    url = request.form.get('url')
    if not url.startswith('http://') and not url.startswith('https://'):
        abort(400)
    
    url_id = id_generator()
    cursor = g.db.cursor()
    cursor.execute('INSERT INTO urls (id, url) VALUES (?, ?)', (url_id, url))
    g.db.commit()
    return request.url_root + url_id

@app.route("/", methods=['GET'])
def index():
    return render_template('index.html')

def init_db():
    with closing(connect_db()) as db:
        with app.open_resource('schema.sql') as f:
            db.cursor().executescript(f.read().decode())
        db.commit()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print()
        print('Usage: python app.py run/init')
        print()

    if sys.argv[1] == 'init':
        init_db()
    elif sys.argv[1] == 'run':
        app.run(host='0.0.0.0', port=5000, ssl_context='adhoc', threaded=True)


