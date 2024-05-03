from flask import Blueprint, render_template

views= Blueprint('views',__name__)



@views.route('/')
def role():
    return render_template("role.html")

@views.route('/home')
def home():
    return render_template("home.html")