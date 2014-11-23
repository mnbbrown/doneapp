import logging
import datetime
import json

from flask import Flask, g, render_template, request, redirect, flash, url_for
from flask.ext.debugtoolbar import DebugToolbarExtension
from flask.ext.login import LoginManager, login_user, logout_user, current_user, login_required
from logentries import LogentriesHandler

from .config import Config
from .oauth import OAuthAuthenticator
from .db import db, User, Calendar, Event, CalenderChannel
from .forms import RegistrationForm, LoginForm

__all__ = ['app','db']


lm = LoginManager()
log = logging.getLogger('logentries')
log.setLevel(logging.INFO)

app = Flask(__name__, static_path='/static')

app.config.from_object(Config)

print app.config.get('SQLALCHEMY_DATABASE_URI')

db.init_app(app)
lm.init_app(app)
lm.login_view = 'login'

log.addHandler(LogentriesHandler(app.config.get('LOGENTRIES_TOKEN')))

if 'DEBUG_TOOLBAR' in app.config and app.config['DEBUG_TOOLBAR']:
    toolbar = DebugToolbarExtension(app)

@lm.user_loader
def user_loader(id):
    return User.query.get(int(id))


@app.before_request
def before_request():
    g.user = current_user


@app.route('/')
def index():
    return render_template('index.html')

# ------ AUTHENTICATION + OAUTH ------

@app.route('/auth/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        user = User(form.name.data, form.email.data, form.password.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)
 


@app.route('/auth/login',methods=['GET','POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        registered_user = User.query.filter_by(email=form.email.data,password=form.password.data).first()
        if registered_user is None:
            print "Username is invalid", registered_user
            return redirect(url_for('login'))
        login_user(registered_user)
        flash('Logged in successfully')
        return redirect(request.args.get('next') or url_for('preferences'))
    return render_template('login.html', form=form)

@app.route('/auth/logout', methods=['GET'])
def logout():
    logout_user()
    return redirect(url_for('index'))

@login_required
@app.route('/auth/authorize/<provider>')
def oauth_authorize(provider):
    oauth = OAuthAuthenticator.get_provider(provider)
    return oauth.authorize()

@login_required
@app.route('/auth/callback/<provider>')
def oauth_callback(provider):
    oauth = OAuthAuthenticator.get_provider(provider)
    response = oauth.callback()
    if "access_token" in response:
        dbtoken = User.query.filter_by(id=g.user.id).first()
        if provider == 'google':
            dbtoken.google_token = response.get('access_token')
        elif provider == 'uber':
            dbtoken.uber_token = response.get('access_token')
        db.session.commit()            
    return redirect(url_for('preferences'))


# ------ AJAX ------

@login_required
@app.route("/me/calendars", methods=["POST"])
def add_calendar():
    calendar_id = request.form.get('calendar_id')
    calendar_name = request.form.get('calendar_name')

    calendar = Calendar(calendar_id, calendar_name)
    db.session.add(calendar)

    headers = {"Authorization": "Bearer {0}".format(token)}
    params = {
        'timeMin' : iso_format(datetime.datetime.now() - datetime.timedelta(days=2))
    }
    url = "https://www.googleapis.com/calendar/v3/calendars/{0}/events".formpat(calendar_id)
    events = requests.get(url, headers=headers, params=params)


    if "items" not in events.json():
        return json.dumps(events.json())
        abort(500)

    for event in events.json()["items"]:
        e = Event(event.get('id'), calendar_id, event.get('summary'), event.get('location'), parse_iso(event.get('start').get('dateTime')), parse_iso(event.get('end').get('dateTime')))
        db.session.add(e)
    
    db.session.commit()
    return "OK"


# ------ APPLICATION! ------

@login_required
@app.route("/calendar")
def calendar():    
    return render_template('calendar.html')

@login_required
@app.route("/me/calendars")
def get_user_calendars():
    token = current_user.google_token
    url = app.config.get('GOOGLE_CALENDAR_LIST')
    headers = {"Authorization": "Bearer {0}".format(token)}
    calendars = requests.get(url, headers=headers)
    c = []
    for calendar in calendars.json().get('items'):
        c.append((calendar.get('id'), calendar.get('summary')))

    i, name = c[0]
    if create_calendar_channel(token, i):
        return render_template('calendars.html', calendars=c)
    return render_template('calendars.html', calendars=c)


@app.route("/preferences")
def preferences():    
    return render_template('preferences.html')


# ------ HOOKS! ------

@app.route("/hooks/channel")
def handle_channel():
    print request
    return "Thanks"