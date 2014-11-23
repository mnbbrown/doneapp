from flask import current_app, url_for, redirect, request
import requests
from rauth import OAuth2Service


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
        return response.json()


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