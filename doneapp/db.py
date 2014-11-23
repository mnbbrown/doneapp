import json
import datetime
import uuid
from flask import url_for
from flask.ext.sqlalchemy import SQLAlchemy

db = SQLAlchemy()

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

    def check_password(self, password):
        print self.password, password
        return self.password == password

    def __repr__(self):
        return '<User %r %s %s>' % (self.name, self.email, self.password)

    def __init__(self, name, email, password):
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