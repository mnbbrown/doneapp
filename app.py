from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager, UserMixin
from rauth import OAuth2Service
from flask import Flask, redirect, url_for, render_template, current_app, request, g
from logentries import LogentriesHandler
import logging
import requests
import jwt, simplejson, urllib, time

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
app.config['LOGENTRIES_TOKEN'] = '0d48654e-4ee6-4c64-b5b8-c898d64cf643'

db = SQLAlchemy(app)
lm = LoginManager(app)

log = logging.getLogger('logentries')
log.setLevel(logging.INFO)
log.addHandler(LogentriesHandler(app.config.get('LOGENTRIES_TOKEN')))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    email = db.Column(db.String(120), index=True, unique=True)
    password = db.Column(db.String(120))
    dt_created = db.Column(db.DateTime)

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
        return redirect(self.service.get_authorize_url(
            scope='https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/calendar',
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
    token = oauth.callback()['access_token']
    return oauth.callback()    


@app.route("/auth/login")
def login():
    if g.user is not None and g.user.is_authenticated():
        return redirect(url_for('index'))
    form = LoginForm()
    return ""

        # return redirect(request.args.get("next") or url_for("index"))
    # return render_template("login.html", form=form)


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


@app.route("/today")
def list_todays_events():
    pass



if __name__ == '__main__':
    app.run(debug=True)