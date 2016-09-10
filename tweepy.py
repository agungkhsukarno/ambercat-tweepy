# -*- coding: utf-8 -*-

import sqlite3
import time
from flask import Flask, request, session, g, redirect, url_for, \
  abort, render_template, flash, _app_ctx_stack
from contextlib import closing
from werkzeug import check_password_hash, generate_password_hash

# konfigurasi umum
DATABASE = '/tmp/tweepy.db'
DEBUG = True
SECRET_KEY = 'abcdefghijklmnopqrstuvwxyz0123456789'
PER_PAGE = 30

# create application
app = Flask(__name__)
app.config.from_object(__name__)

# fungsi koneksi database
def connect_db():
  db = sqlite3.connect(app.config['DATABASE'])
  db.row_factory = sqlite3.Row
  return db

# fungsi inisialisasi tabel pada database
def init_db():
  with closing(connect_db()) as db:
    with app.open_resource('schema.sql', mode='r') as f:
      db.cursor().executescript(f.read())
    db.commit()

# fungsi untuk melakukan query
def query_db(query, args=(), one=False):
  db = connect_db()
  cur = db.execute(query, args)
  rv = cur.fetchall()
  db.close()
  return (rv[0] if rv else None) if one else rv

def get_user_id(username):
  rv = query_db('select id from users where username = ?',
                [username], one=True)
  return rv[0] if rv else None

def get_user_data(username):
  rv = query_db('select * from users where username = ?',
                [username], one=True)
  return rv if rv else None

def is_followed(user_id, follower_id):
  rv = query_db('select * from followers where user_id = ? and follower_id = ?',
                [user_id, follower_id], one=True)
  return True if rv else False

# routing
@app.route('/')
def home():
	if 'user_id' in session:
		return redirect(url_for('timeline'))
	return render_template('home.html')

@app.route('/timeline/')
def timeline():
  if 'user_id' not in session:
    return redirect(url_for('public_timeline'))

  return render_template('timeline.html', tweets=query_db('''
    select tweets.*, users.* from users
    inner join tweets on (tweets.user_id=users.id)
    where users.id in (select user_id from followers where follower_id=?)
    order by tweets.pub_date desc limit ?''',
    [session['user_id'], app.config['PER_PAGE']]), test=query_db('''
    select * from users where username = 'ambercat'
    '''))

@app.route('/public_timeline')
def public_timeline():
  return render_template('timeline.html', tweets=query_db('''
    select tweets.*, users.* from tweets, users
    where tweets.user_id = users.id order by tweets.pub_date desc limit ?''',
    [app.config['PER_PAGE']]))

@app.route('/add_tweet', methods=['POST'])
def add_tweet():
  if 'user_id' not in session:
    abort(401)
  if request.form['tweet']:
    db = connect_db()
    db.execute('''insert into tweets (user_id, tweet, pub_date)
      values (?, ?, ?)''', (session['user_id'], request.form['tweet'],
                            int(time.time())))
    db.commit()
    db.close()
    flash('Your tweet has been added')
  return redirect(url_for('timeline'))

@app.route('/login', methods=['GET', 'POST'])
def login():
  if 'user_id' in session:
    return redirect(url_for('timeline'))
  error = None
  if request.method == 'POST':
    user = query_db('''select * from users where username = ?''',
      [request.form['username']], one=True)
    if user is None:
      error = 'Invalid username'
    elif not check_password_hash(user[3], request.form['password']):
      error = 'Invalid password'
    else :
      flash('You were successfully logged in')
      session['user_id'] = user[0]
      session['username'] = user[1]
      return redirect(url_for('timeline'))
  return render_template('login.html', error=error)

@app.route('/register', methods=['POST'])
def register():
  if 'user_id' in session:
    return redirect(url_for('timeline'))
  error = None
  if request.method == 'POST':
    if not request.form['username']:
      error = 'Please enter your username'
    elif not request.form['fullname']:
      error = 'Please enter your fullname'
    elif not request.form['password']:
      error = 'Please enter your password'
    elif request.form['password'] != request.form['password2']:
      error = 'The two password that you entered didn\'t match'
    elif get_user_id(request.form['username']) is not None:
      error = 'The username is already taken'
    else:
      db = connect_db()
      db.execute('''insert into users (
        username, fullname, password) values (?, ?, ?)''',
        (request.form['username'], request.form['fullname'],
         generate_password_hash(request.form['password'])))
      db.commit()
      user_id = get_user_id(request.form['username'])
      db.execute('insert into followers (user_id, follower_id) values (?, ?)',
        (user_id, user_id))
      db.commit()
      db.close()
      flash('You were successfully registered')
      return redirect(url_for('login'))

@app.route('/logout')
def logout():
  session.pop('user_id', None)
  flash('You were successfully logged out')
  return redirect(url_for('public_timeline'))

@app.route('/profile/<username>')
def profile(username):
  if 'user_id' not in session:
    return redirect(url_for('public_timeline'))
  return render_template('timeline.html', tweets=query_db('''
    select * from users inner join tweets on (users.id = tweets.user_id)
    where users.username = ?''',
    [username]), user_data=get_user_data(username),
    followed=is_followed(get_user_id(username), session['user_id']))

@app.route('/follow/<username>')
def follow(username):
  if 'user_id' not in session:
    abort(401)
  db = connect_db()
  db.execute('''insert into followers (user_id, follower_id)
    values (?, ?)''', (get_user_id(username), session['user_id']))
  db.commit()
  db.close()
  flash('You have successfully followed @%s', username)
  return redirect(url_for('profile', username=username))

@app.route('/unfollow/<username>')
def unfollow(username):
  if 'user_id' not in session:
    abort(401)
  db = connect_db()
  db.execute('''delete from followers where user_id = ? and follower_id = ?''',
    (get_user_id(username), session['user_id']))
  db.commit()
  db.close()
  flash('You have successfully unfollowed @%s', username)
  return redirect(url_for('profile', username=username))

@app.route('/search', methods=['GET'])
def search():
  if 'user_id' not in session:
    return redirect(url_for('public_timeline'))
  else:
    return render_template('search.html',
                           results=query_db("select * from users where username like ?",
                                            ['%' + request.args.get('q') + '%'])
    )

if __name__ == '__main__':
  app.run()
