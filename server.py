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
    return render_template('index.html')




if __name__ == "__main__":
    app.run(debug=True)
