from flask import Blueprint

auth= Blueprint('auth',__name__)

@auth.route('/login')
def login():
    return"<p>login</p>"

@auth.route('/logout')
def logout():
    return"<p>logout</p>"

@auth.route('/sign-up')
def sign_up():
    return"<p>Sign up</p>"

@auth.route('/user')
def user():
    return"<p>User</p>"

@auth.route('/admin')
def admin():
    return"<p>Admin</p>"


