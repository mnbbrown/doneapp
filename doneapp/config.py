import os
basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
	DEBUG = True
	RELOAD = True
	SECRET_KEY = 'mysecretkeyvalue'
	SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')

	OAUTH_CREDENTIALS = {
	    'uber': {
	        'id' : 'GZ3wKftPBoFNOIbO1-h1WQVhXxUFvvR1',
	        'secret' : 'xAXRltk1ISZX3pfZQ0b6EqC3ZvVOkiyjuAfor3zB',
	    },
	    'google': {
	        'id' : '454349647873-isg01li57er0lvokrdnhvtp3jp945s0c.apps.googleusercontent.com',
	        'secret' : 'Fwmt1tqLAV9wBI2P9nZy8xmS'
	    }
	}

	GOOGLE_API_KEY = 'AIzaSyDZ0Phgpt9_CXw29f3Ui2NNkYTj14eckUY'
	GOOGLE_DISTANCE_MATRIX_URI = 'https://maps.googleapis.com/maps/api/distancematrix/json'
	GOOGLE_CALENDAR_LIST = 'https://www.googleapis.com/calendar/v3/users/me/calendarList'
	LOGENTRIES_TOKEN = '0d48654e-4ee6-4c64-b5b8-c898d64cf643'