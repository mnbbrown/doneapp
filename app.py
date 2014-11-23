from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager, UserMixin
from flask import Flask, redirect, url_for, render_template, current_app, request, g, abort
import logging
import requests
import jwt
import urllib
import uuid
import datetime
import json

from flask import flash, session
from flask import flash, redirect, url_for, session, render_template

from wtforms import Form, BooleanField, TextField, PasswordField, validators
from flask import Flask,session, request, flash, url_for, redirect, render_template, abort, g

from flask.ext.login import login_user , logout_user , current_user , login_required



# @app.route("/me/calendars")
# def get_user_calendars(token="ya29.xwBSmkuEITLDuZISlv8eRqmk70HgF-Yfg4DlnsO4qBry2CYebTtDuFuu_tF08Y8vxM6AXJhh-YqF5Q"):
#     url = app.config.get('GOOGLE_CALENDAR_LIST')
#     headers = {"Authorization": "Bearer {0}".format(token)}
#     calendars = requests.get(url, headers=headers)
#     c = []
#     for calendar in calendars.json().get('items'):
#         c.append((calendar.get('id'), calendar.get('summary')))

#     i, name = c[0]
#     if create_calendar_channel(token, i):
#         return render_template('calendars.html', calendars=c)
#     return render_template('calendars.html', calendars=c)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/auth/authorize/<provider>')
def oauth_authorize(provider):
    oauth = OAuthAuthenticator.get_provider(provider)
    return oauth.authorize()


@app.route('/auth/callback/<provider>')
def oauth_callback(provider):
    oauth = OAuthAuthenticator.get_provider(provider)
    response = oauth.callback()
    if "access_token" in response:
        print g.user.id
        dbtoken = User.query.filter_by(id=g.user.id).first()
        if provider == 'google':
            dbtoken.google_token = response.get('access_token')
            #Connected with google
            
        elif provider == 'uber':
            dbtoken.uber_token = response.get('access_token')
        db.session.commit()            
    return redirect(url_for('preferences'))


@app.route("/auth/register")
def register():
    if request.method == 'GET':
        return render_template('register.html')
    user = User(request.form['name'] , request.form['password'], request.form['email'])
    db.session.add(user)
    db.session.commit()
    flash('User successfully registered')
    return redirect(url_for('login'))


@app.route("/time")
def time():
    return str(time_trip("287 Wickham Terrace, Spring Hill", "2 George St, Brisbane"))