from flask import Flask, render_template, request, redirect, session, flash
import re
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = '8babef50fb315b06e2b627dca25c28b3'
email_regex = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

@app.route('/')
def login_register():
    session['title'] = 'Login or Register'
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def registration():
    is_valid = True
    db = connectToMySQL('private_wall')
    if len(request.form['fn']) < 1:
        flash('Must enter a first name to register', 'fn')
        is_valid = False
    if len(request.form['ln']) < 1:
        flash('Must enter a last name to register', 'ln')
        is_valid = False
    if not email_regex.match(request.form['email']):
        flash('Invalid email address!', 'email')
        is_valid = False
    if not re.match(r'[A-Za-z0-9@#$%^&+=]{8,}', request.form['pw']):
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
        print(data, '&&&&&&&&&&&&&&&&&&&&&&&')
        query = """INSERT INTO users(first_name, last_name, email, pw_hash,
                created_at, updated_at) VALUES(%(fn)s, %(ln)s, %(email)s,
                %(pw)s, now(), now())"""
        db.query_db(query, data)
        return redirect('/wall')
    else:
        print("didn't work &&&&&&&&&&&&&&&&&&&&&")
        return redirect('/')

@app.route('/login', methods=['POST'])
def login():
    data = {'email': request.form['email']}
    query = 'SELECT pw_hash FROM users WHERE email=%(email)s'
    db = connectToMySQL('private_wall')
    check = db.query_db(query, data)
    try: # does this block if database query works
        if bcrypt.check_password_hash(check[0]['pw_hash'], request.form['pw']):
            db = connectToMySQL('private_wall')
            query = "SELECT * FROM users WHERE email = %(email)s"
            user = db.query_db(query, data)
            session['user'] = user[0]
            session['header_message'] = 'You have successfully logged in!'
            return redirect('/wall')
    except: # handling for failure to run database query
        print('went here *&*&*&*&*&*&*&*&*&*&*&')
        return redirect('/')
    print('this is where we went this time *&*&*&*&*&*&*&*&*&')
    return redirect('/') # goes here if query worked but pw_hash mismatch


@app.route('/wall')
def wall():
    session['title'] = 'Wall'
    db = connectToMySQL('private_wall')
    return render_template('wall.html')




if __name__ == "__main__":
    app.run(debug=True)
