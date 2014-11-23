from .db import db, CalenderChannel
import requests, time, datetime
from flask import current_app

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

def time_trip(origin, destination):
    url = current_app.config['GOOGLE_DISTANCE_MATRIX_URI']
    params = {
        'origins' : origin.replace(' ', '+'),
        'destinations': destination.replace(' ', '+'),
        'departure_time' : int(time.time()),
        'mode' : 'driving',
        'sensor' : 'false', 
        'language' : 'en'
    }

    return requests.get(url, params=params)

def iso_format(dt):
    try:
        utc = dt + dt.utcoffset()
    except TypeError as e:
        utc = dt
    isostring = datetime.datetime.strftime(utc, '%Y-%m-%dT%H:%M:%S.{0}Z')
    return isostring.format(int(round(utc.microsecond/1000.0)))

def parse_iso(string):
    return datetime.datetime.strptime(string, '%Y-%m-%dT%H:%M:%SZ')