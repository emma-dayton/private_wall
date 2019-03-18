from flask import Flask, render_template, request, redirect, session, flash
import re
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = '8babef50fb315b06e2b627dca25c28b3'
email_regex = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
pw_regex = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$")

@app.route('/')
def login_register():
    if 'user' in session:
        return redirect('/wall')
    session['title'] = 'Login or Register'
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def registration():
    is_valid = True
    db = connectToMySQL('private_wall')
    session['fn'] = request.form['fn']
    session['ln'] = request.form['ln']
    session['email'] =request.form['email']
    if 'email2' in session: # gets rid of email from login session data
        session.pop('email2')
    if len(request.form['fn']) < 1:
        flash('Must enter a first name to register', 'fn')
        is_valid = False
    if len(request.form['ln']) < 1:
        flash('Must enter a last name to register', 'ln')
        is_valid = False
    if not email_regex.match(request.form['email']):
        flash('Invalid email address!', 'email')
        is_valid = False
    if not pw_regex.match(request.form['pw']):
        flash('''Password must be at least 8 characters long, have at least
        one uppercase and one lowercase letter, at least one number,
        and on special character (@#$%^&+=)''', 'pw')
        is_valid = False
    if request.form['pwconfirm'] != request.form['pw']:
        flash('Must match above password', 'pwconfirm')
        is_valid = False
    if is_valid:
        data = {
            'fn': request.form['fn'],
            'ln': request.form['ln'],
            'email': request.form['email'],
            }
        pw_hash = bcrypt.generate_password_hash(request.form['pw'])
        data['pw'] = pw_hash
        query = """INSERT INTO users(first_name, last_name, email, pw_hash,
                created_at, updated_at) VALUES(%(fn)s, %(ln)s, %(email)s,
                %(pw)s, now(), now())"""
        db.query_db(query, data)
        db = connectToMySQL('private_wall')
        query = "SELECT id, first_name FROM users WHERE email = %(email)s"
        user = db.query_db(query, data)
        session['user'] = user[0] # probably keeping too much info from user in session, also id could be guessed
        return redirect('/wall')
    else:
        return redirect('/')

@app.route('/login', methods=['POST'])
def login():
    data = {'email': request.form['email2']}
    query = 'SELECT pw_hash FROM users WHERE email=%(email)s'
    db = connectToMySQL('private_wall')
    check = db.query_db(query, data)
    session['email2'] = request.form['email2']
    try: # does this block if database query works
        if bcrypt.check_password_hash(check[0]['pw_hash'], request.form['pw']):
            db = connectToMySQL('private_wall')
            query = "SELECT first_name, id FROM users WHERE email = %(email)s"
            user = db.query_db(query, data)
            session['user'] = user[0] # too much info in session, not secure enough?
            return redirect('/wall')
    except: # handling for failure to run database query
        return redirect('/')
    return redirect('/') # goes here if query worked but pw_hash mismatch


@app.route('/wall')
def wall():
    if 'user' not in session: # if someone tries to go directly to wall sends to registration/login page
        return redirect('/')
    if 'fn' in session: # clears first name from session from registration
        session.pop('fn')
    if 'ln' in session: # clears last name from session from registration
        session.pop('ln')
    if 'email' in session: # clears email from session from registration
        session.pop('email')
    if 'email2' in session: # get rid of the session from login
        session.pop('email2')
    session['title'] = 'Wall'
    db = connectToMySQL('private_wall')
    query = "SELECT first_name, last_name, id FROM users WHERE NOT id = %(id)s;"
    users = db.query_db(query, session['user'])
    db = connectToMySQL('private_wall')
    query = "SELECT * FROM messages WHERE receive_user_id=%(id)s;" # only needs user id for query
    rec_mess = db.query_db(query, session['user'])
    db = connectToMySQL('private_wall')
    query = "SELECT * FROM messages WHERE send_user_id=%(id)s;" # only needs user id for query
    sent_mess = db.query_db(query, session['user'])
    return render_template('wall.html', users=users, rec_mess=rec_mess, sent_mess=sent_mess)

@app.route('/logout')
def logout():
    session_keys = []
    for key in session.keys():
        session_keys.append(key)
    for key in session_keys:
        session.pop(key)
    return redirect('/')

@app.route('/send', methods=['POST'])
def send():
    db = connectToMySQL('private_wall')
    query = """INSERT INTO messages (content, created_at, updated_at, send_user_id,
    receive_user_id) VALUES(%(content)s, now(), now(), %(send_id)s, %(rec_id)s)"""
    data = {
    'content': request.form['message'],
    'rec_id':request.form['select_friend'],
    'send_id':session['user']['id']
    }
    db.query_db(query, data)
    return redirect('/wall')




if __name__ == "__main__":
    app.run(debug=True)
