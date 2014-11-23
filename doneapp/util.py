from .db import db, CalenderChannel
import requests, time, datetime
from flask import current_app
from uber import UberClient, geolocate, ClientStatus, UberException
from uber.model_base import Model, StringField

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


def nearbyUber(client,address_str):
    
    """
    shows you what taxis are close to you.
    Usage: ping <address>
    """
    if not address_str:
        print
 
    results = geolocate(address_str)
    if not results:
        print 'address not found :('
        return

    geodecoded_address = results[0]

    print 'pinging: ' + geodecoded_address['formatted_address']
    app_state = client.ping(geodecoded_address)
    city = app_state.city
    vehicle_views = city.vehicle_views
    for key in city.vehicle_views_order:
        nearby_info = app_state.nearby_vehicles.get(key)
        view = vehicle_views[key]
        count = len(nearby_info.vehicle_paths)

        if count:
            additional_info = ''
            if view.surge:
                additional_info = 'Warning - x{multiplier} surge pricing is active!'.format(multiplier=view.surge.multiplier)

            print '{name} has {count} cars near by (eta {eta}). {additional_info}'.format(
                name=view.description,
                count=len(nearby_info.vehicle_paths),
                eta=nearby_info.eta_string,
                additional_info=additional_info
                )
        else:
            print '{name} has no vehicles nearby :('.format(name=view.description)
    return 'What'

def canceluber(client):    
    print 'cancelling ride...'
    client.cancel_pickup()
    print 'ride cancelled.'
    return True

def bookuber(address):
     #Login to obtain token
    token = UberClient.login('uber@jaredpage.net','123uberdone')
    # token = 'cLqir9JuchqHqOtxncYSEmMC6BiQfN'
    #Set up client
    client = UberClient('uber@jaredpage.net', token)
    #show nearby ubers
    ubers = nearbyUber(client,address)
    address = 'Citizen Space, 425 2nd St , San Francisco, CA'
    #geolocate
    results = geolocate(address)
    if not results:
        print 'address not found :('
        return
    geo_address = results[0]
    print 'booking UberX for {}...'.format(geo_address['formatted_address'])



def iso_format(dt):
    try:
        utc = dt + dt.utcoffset()
    except TypeError as e:
        utc = dt
    isostring = datetime.datetime.strftime(utc, '%Y-%m-%dT%H:%M:%S.{0}Z')
    return isostring.format(int(round(utc.microsecond/1000.0)))

def parse_iso(string):
    return datetime.datetime.strptime(string, '%Y-%m-%dT%H:%M:%SZ')