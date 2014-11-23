from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager, UserMixin
from rauth import OAuth2Service
from flask import Flask, redirect, url_for, render_template, current_app, request, g, abort
from logentries import LogentriesHandler
import logging
import requests
import jwt
import urllib
import uuid
import json


app = Flask(__name__)
app.config['BASE_URL'] = 'http://app.doneapp.co/'
app.config['SECRET_KEY'] = 'top_secret_sc@'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['OAUTH_CREDENTIALS'] = {
    'uber': {
        'id' : 'GZ3wKftPBoFNOIbO1-h1WQVhXxUFvvR1',
        'secret' : 'xAXRltk1ISZX3pfZQ0b6EqC3ZvVOkiyjuAfor3zB',
    },
    'google': {
        'id' : '454349647873-isg01li57er0lvokrdnhvtp3jp945s0c.apps.googleusercontent.com',
        'secret' : 'Fwmt1tqLAV9wBI2P9nZy8xmS'
    }
}
app.config['GOOGLE_API_KEY'] = 'AIzaSyDZ0Phgpt9_CXw29f3Ui2NNkYTj14eckUY'
app.config['GOOGLE_DISTANCE_MATRIX_URI'] = 'https://maps.googleapis.com/maps/api/distancematrix/json'
app.config['GOOGLE_CALENDAR_LIST'] = 'https://www.googleapis.com/calendar/v3/users/me/calendarList'
app.config['LOGENTRIES_TOKEN'] = '0d48654e-4ee6-4c64-b5b8-c898d64cf643'

db = SQLAlchemy(app)
lm = LoginManager(app)

log = logging.getLogger('logentries')
log.setLevel(logging.INFO)
log.addHandler(LogentriesHandler(app.config.get('LOGENTRIES_TOKEN')))

class User(db.Model):

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    email = db.Column(db.String(120), index=True, unique=True)
    password = db.Column(db.String(120))
    uber_token = db.Column(db.String)
    uber_token_expiry = db.Column(db.String)
    uber_token_refresh = db.Column(db.String)
    google_token = db.Column(db.String)
    google_token_expiry = db.Column(db.String)
    google_token_refresh = db.Column(db.String)
    dt_created = db.Column(db.DateTime)

    calendars = db.relationship('Calendar', backref='user', lazy='dynamic')

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        try:
            return unicode(self.id)  # python 2
        except NameError:
            return str(self.id)  # python 3

    def __repr__(self):
        return '<User %r>' % (self.nickname)

    def __init__(self , name ,password , email):
        self.name = name
        self.password = password
        self.email = email
        self.registered_on = datetime.utcnow()


class Calendar(db.Model):

    __tablename__ = 'user_calendars'

    id = db.Column(db.String, primary_key=True)
    name = db.Column(db.String)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    events = db.relationship('Event', backref='calendar', lazy='dynamic')

    def __init__(self, id, name):
        self.id = id
        self.name = name

class Event(db.Model):

    __tablename__ = 'calendar_events'

    id = db.Column(db.String, primary_key=True)
    calendar_id = db.Column(db.String, db.ForeignKey('user_calendars.id'))
    summary = db.Column(db.String)
    location = db.Column(db.String)
    start_time = db.Column(db.DateTime(timezone=True))
    end_time = db.Column(db.DateTime(timezone=True))

    def __init__(self, id, calendar_id, summary, location, start_time, end_time):
        self.id = id
        self.calendar_id = calendar_id
        self.summary = summary
        self.location = location
        self.start_time = start_time
        self.end_time = end_time


class CalenderChannel(db.Model):

    __tablename__ = 'calendar_channels'

    id = db.Column(db.String, primary_key=True)
    calendar_id = db.Column(db.String, db.ForeignKey('user_calendars.id'), unique=True)

    def __init__(self, calendar_id):
        self.calendar_id = calendar_id
        self.id = str(uuid.uuid4())

    def json(self):
        return json.dumps({
            'id': self.id,
            'type': 'web_hook',
            'address': url_for('handle_channel', _external=True)
            })



def create_calendar_channel(token, calendar_id):
    ch = CalenderChannel(calendar_id)
    url = 'https://www.googleapis.com/calendar/v3/calendars/{0}/events/watch'.format(calendar_id)
    headers = {"Authorization": "Bearer {0}".format(token)}
    data = ch.json()
    req = requests.post(url, headers=headers, data=data)
    if req.status_code != 200:
        return None
    db.session.save(ch)
    db.session.commit()
    return ch


@app.route("/hooks/channel")
def handle_channel():
    print request
    return "Thanks"

import datetime

def iso_format(dt):
    try:
        utc = dt + dt.utcoffset()
    except TypeError as e:
        utc = dt
    isostring = datetime.datetime.strftime(utc, '%Y-%m-%dT%H:%M:%S.{0}Z')
    return isostring.format(int(round(utc.microsecond/1000.0)))

def parse_iso(string):
    return datetime.datetime.strptime(string, '%Y-%m-%dT%H:%M:%SZ')


@app.route("/me/calendars", methods=["POST"])
def add_calendar():
    calendar_id = request.form.get('calendar_id')
    calendar_name = request.form.get('calendar_name')

    print calendar_name, calendar_id
    calendar = Calendar(calendar_id, calendar_name)
    db.session.add(calendar)

    token="ya29.xwCTgwwFjvSH4lO11fY3Aqwge8x7e8toIzX5p9mYFJIcFTbYa75_GM9GjWEEkVC9h9jVp7rdnR3BSg"
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


@lm.user_loader
def user_loader(id):
    return User.query.get(int(id))

class OAuthAuthenticator(object):

    providers = None

    def __init__(self, provider_name):
        self.provider_name = provider_name
        credentials = current_app.config['OAUTH_CREDENTIALS'][provider_name]
        self.consumer_id = credentials['id']
        self.consumer_secret = credentials['secret']
    
    def init_app(self, app):
        self.app = app

    def authorize(self):
        pass

    def callback(self):
        pass

    def get_callback_url(self):
        return url_for('oauth_callback', provider=self.provider_name, _external=True)

    @classmethod
    def get_provider(self, provider_name):
        if self.providers is None:
            self.providers = {}
            for provider_class in self.__subclasses__():
                provider = provider_class()
                self.providers[provider.provider_name] = provider
        return self.providers[provider_name]

class UberSignIn(OAuthAuthenticator):
    
    def __init__(self):
        super(UberSignIn, self).__init__('uber')
        self.service = OAuth2Service(
            name = 'DoneApp',
            client_id = self.consumer_id,
            client_secret=self.consumer_secret,
            authorize_url='https://login.uber.com/oauth/authorize',
            access_token_url='https://login.uber.com/oauth/token',
            base_url='https://api.uber.com/v1/'
            )

    def authorize(self):
        return redirect(self.service.get_authorize_url(
            scope='profile',
            response_type='code',
            redirect_uri=self.get_callback_url())
        )

    def callback(self):
        if 'code' not in request.args:
            return None
        parameters = {
            'redirect_uri': self.get_callback_url(),
            'code': request.args.get('code'),
            'grant_type': 'authorization_code',
            'client_id' : self.consumer_id,
            'client_secret' : self.consumer_secret
        }
        response = requests.post(self.service.access_token_url,
            data=parameters,
        )
        return str(response.json())


class GoogleSignIn(OAuthAuthenticator):

    def __init__(self):
        super(GoogleSignIn, self).__init__('google')
        self.service = OAuth2Service(
            name = 'DoneApp',
            client_id = self.consumer_id,
            client_secret=self.consumer_secret,
            authorize_url='https://accounts.google.com/o/oauth2/auth',
            access_token_url='https://accounts.google.com/o/oauth2/token',
            base_url='https://www.googleapis.com/oauth2/v1/'
            )

    def authorize(self):
        params = {
            'scope': 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/calendar',
            'response_type': 'code',
            'redirect_uri': self.get_callback_url(),
            'access_type': 'offline'
        }
        return redirect(self.service.get_authorize_url(**params))

    def callback(self):
        if 'code' not in request.args:
            return None
        parameters = {
            'redirect_uri': self.get_callback_url(),
            'code': request.args.get('code'),
            'grant_type': 'authorization_code',
            'client_id' : self.consumer_id,
            'client_secret' : self.consumer_secret
        }
        response = requests.post(self.service.access_token_url,
            data=parameters,
        )

        access_token = response.json()['access_token']
        return str(response.json())


def time_trip(origin, destination):
    url = app.config['GOOGLE_DISTANCE_MATRIX_URI']
    params = {
        'origins' : origin.replace(' ', '+'),
        'destinations': destination.replace(' ', '+'),
        'departure_time' : int(time.time()),
        'mode' : 'driving',
        'sensor' : 'false', 
        'language' : 'en'
    }

    return requests.get(url, params=params)

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
    return oauth.callback()

@app.route("/socialconnect")
def socialconnect():    
    g = {
        "user":{"jared"}
    }    
    return render_template('socialconnect.html')

        # return redirect(request.args.get("next") or url_for("index"))
    # return render_template("login.html", form=form)

@app.route("/signin")
def signin():    
    return render_template('signin.html')

@app.route("/calendar")
def calendar():    
    return render_template('calendar.html')

@app.route("/preferences")
def preferences():    
    return render_template('preferences.html')



@app.route("/auth/register")
def register():
    if request.method == 'POST' and form.validate():
        user = User(request.form['name'] , request.form['password'], request.form['email']) 
        db.session.add(user)
        db.session.commit()
        flash('User successfully registered')
        return redirect(url_for('confirm_register'))
    return render_template('register.html', form=form)


@app.route("/auth/register/confirm")
def confirm_register():
    render_template('confirm-register.html')

@app.route("/time")
def time():
    return str(time_trip("287 Wickham Terrace, Spring Hill", "2 George St, Brisbane"))


@app.route("/today")
def list_todays_events():
    pass



if __name__ == '__main__':
    app.run(debug=True)