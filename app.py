from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager, UserMixin
from rauth import OAuth2Service
from flask import Flask, redirect, url_for, render_template, current_app, request, g
from logentries import LogentriesHandler
import logging
import requests
import jwt
import urllib
import uuid
import datetime
import json

from flask import flash, session
from flask.ext.login import login_user, logout_user, current_user, login_required


from flask.ext.wtf import Form, validators
from wtforms.fields import TextField, BooleanField
from wtforms.validators import Required
from flask import flash, redirect, url_for, session, render_template

from wtforms import Form, BooleanField, TextField, PasswordField, validators
from flask import Flask,session, request, flash, url_for, redirect, render_template, abort ,g

from flask.ext.login import login_user , logout_user , current_user , login_required

app = Flask(__name__)
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
lm.init_app(app)
lm.login_view = 'login'

log = logging.getLogger('logentries')
log.setLevel(logging.INFO)
log.addHandler(LogentriesHandler(app.config.get('LOGENTRIES_TOKEN')))


class RegistrationForm(Form):
    username = TextField('Username', [validators.Length(min=4, max=25)])
    email = TextField('Email Address', [validators.Length(min=6, max=35)])
    password = PasswordField('New Password', [
        validators.Required(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')
    accept_tos = BooleanField('I accept the TOS', [validators.Required()])


class LoginForm(Form):
    username = TextField('Username', [validators.Required()])
    password = PasswordField('Password', [validators.Required()])

    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)
        self.user = None

    def validate(self):
        rv = Form.validate(self)
        if not rv:
            return False

        user = User.query.filter_by(
            username=self.username.data).first()
        if user is None:
            self.username.errors.append('Unknown username')
            return False

        if not user.check_password(self.password.data):
            self.password.errors.append('Invalid password')
            return False

        self.user = user
        return True

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
        self.registered_on = datetime.datetime.utcnow()


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


@app.route("/me/calendars")
def get_user_calendars(token="ya29.xgBWfp_SErFKtnwjB2BdFxJWhlm1jkDUseZF2gPfInhKeXUdSoMFiP4d0wA2kGSoIf2BKAyfnzqIEg"):
    url = app.config.get('GOOGLE_CALENDAR_LIST')
    headers = {"Authorization": "Bearer {0}".format(token)}
    calendars = requests.get(url, headers=headers)
    c = []
    for calendar in calendars.json().get('items'):
        c.append((calendar.get('id'), calendar.get('summary')))

    i, name = c[0]
    events = requests.get('https://www.googleapis.com/calendar/v3/calendars/{0}/events'.format(i), headers=headers)
    e = []
    for event in events.json().get('items'):
        e.append((event['id'], event['summary'],event['location']))
    print e
    return render_template('calendars.html', calendars=c)


@lm.user_loader
def user_loader(id):
    return User.query.get(int(id))


@app.before_request
def before_request():
    g.user = current_user

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

        return response.json()


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



@app.route('/auth/register' , methods=['GET','POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    user = User(request.form['username'] , request.form['password'],request.form['email'])
    db.session.add(user)
    db.session.commit()
    flash('User successfully registered')
    return redirect(url_for('login'))
 
@app.route('/auth/login',methods=['GET','POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    username = request.form['username']
    password = request.form['password']
    registered_user = User.query.filter_by(name=username,password=password).first()
    if registered_user is None:
        flash('Username or Password is invalid' , 'error')
        return redirect(url_for('login'))
    login_user(registered_user)
    flash('Logged in successfully')
    return redirect(request.args.get('next') or url_for('preferences'))

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index')) 

# @app.route("/auth/login", methods=["GET", "POST"])
# def login():   

#     form = LoginForm()
#     if form.validate_on_submit():
#         flash(u'Successfully logged in as %s' % form.user.username)
#         session['user_id'] = form.user.id
#         return redirect(url_for('index'))
#     return render_template('login.html', form=form)
    # form = LoginForm()
    # if form.validate_on_submit():
    #     # login and validate the user...
    #     login_user(user)
    #     flash("Logged in successfully.")
    #     return redirect(request.args.get("next") or url_for("index"))
    # return render_template("login.html", form=form)

    # if g.user is not None and g.user.is_authenticated():s
    #     return redirect(url_for('index'))
    # form = LoginForm()
    # return ""

# @app.route("/auth/register")

# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     form = RegistrationForm(request.form)
#     if request.method == 'POST' and form.validate():
#         user = User(form.username.data, form.email.data,
#                     form.password.data)
#         db_session.add(user)
#         flash('Thanks for registering')
#         return redirect(url_for('login'))
#     return render_template('register.html', form=form)

# def register():
#     if request.method == 'GET':
#         return render_template('register.html')
#     user = User(request.form['name'] , request.form['password'], request.form['email'])
#     db.session.add(user)
#     db.session.commit()
#     flash('User successfully registered')
#     return redirect(url_for('login'))

@app.route("/socialconnect")
def socialconnect():    
    g = {
        "user":{"jared"}
    }    
    return render_template('socialconnect.html')

        # return redirect(request.args.get("next") or url_for("index"))
    # return render_template("login.html", form=form)


@app.route("/calendar")
def calendar():    
    return render_template('calendar.html')

@app.route("/preferences")
def preferences():    
    return render_template('preferences.html')

@app.route("/time")
def time():
    return str(time_trip("287 Wickham Terrace, Spring Hill", "2 George St, Brisbane"))


@app.route("/today")
def list_todays_events():
    pass



if __name__ == '__main__':
    app.run(debug=True)