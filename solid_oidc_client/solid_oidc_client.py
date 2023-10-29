from typing import Optional, List
import base64
import hashlib
import jwcrypto
import jwcrypto.jwk
import jwcrypto.jws
import jwcrypto.jwt
from oic.oic import Client as OicClient
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.oauth2.message import ASConfigurationResponse
import requests
import urllib.parse
from uuid import uuid4

from .dpop_utils import create_dpop_token
from .solid_auth_session import SolidAuthSession
from .storage import KeyValueStore

class SolidOidcClient:
    """Client to handle Solid-OIDC authentication. Create one per identity provider"""
    def __init__(self, storage: KeyValueStore) -> None:
        self.client = OicClient(client_authn_method=CLIENT_AUTHN_METHOD)
        # set base_url to have valid urls for the request_uris preregistration
        # however, as request_uri does not seem to be used later on, we can set it to anything
        self.client.base_url = "https://example.org/"
        self.storage = storage
        self.provider_info: Optional[ASConfigurationResponse] = None 
        self.client_id: Optional[str] = None
        self.client_secret: Optional[str] = None

    def register_client(self, issuer: str, redirect_uris: List[str]):
        """Register this client for a specific identity provider"""
        self.provider_info = self.client.provider_config(issuer)
        registration_response = self.client.register(
                self.provider_info['registration_endpoint'],
                redirect_uris=redirect_uris)
        self.client_id = registration_response['client_id']
        self.client_secret = registration_response['client_secret']

    def create_login_uri(self, application_redirect_uri: str, callback_uri: str) -> str:
        """Initializes internal parameters and configures an uri which should be visited by the user"""
        authorization_endpoint = self.provider_info['authorization_endpoint']
        code_verifier, code_challenge = create_verifier_challenge()
        state = str(uuid4())
        self.storage.set(f'{state}_code_verifier', code_verifier)
        self.storage.set(f'{state}_redirect_url', application_redirect_uri)
        args = {
            "code_challenge": code_challenge,
            "state": state,
            "response_type": "code",
            "redirect_uri": callback_uri,
            "code_challenge_method": "S256",
            "client_id": self.client_id,
            # TODO: should this be an option?
            # offline_access: also asks for refresh token
            "scope": "openid offline_access",
        }
        return f'{authorization_endpoint}?{urllib.parse.urlencode(args)}'

    def finish_login(self, code: str, state: str, callback_uri: str) -> str:
        """Creates a authentication session with the parameters from the redirect"""
        key = jwcrypto.jwk.JWK.generate(kty='EC', crv='P-256')

        access_token = self._get_access_token(callback_uri, code, state, key)

        return SolidAuthSession(access_token, key)
    
    def _get_access_token(self, redirect_uri: str, code: str, state: str, key: jwcrypto.jwk.JWK) -> str:
        token_endpoint = self.provider_info['token_endpoint']
        code_verifier = self.storage.get(f'{state}_code_verifier')

        res = requests.post(token_endpoint,
            auth=(self.client_id, self.client_secret),
            data={
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "redirect_uri": redirect_uri,
                "code": code,
                "code_verifier": code_verifier,
            },
            headers={
                'DPoP': create_dpop_token(key, token_endpoint, 'POST'),
            },
            allow_redirects=False)

        assert res.ok, f'Could not get access token: {res}'
        access_token = res.json()['access_token']
        self.storage.remove(f'{state}_code_verifier')

        return access_token

    def get_application_redirect_uri(self, state: str) -> str:
        """Returns the uri the application should load after authentication was successful"""
        url = self.storage.get(f'{state}_redirect_url')
        self.storage.remove(f'{state}_redirect_url')
        return url


def create_verifier_challenge():
    # code_verifier must be between 43 and 128 chars long
    code_verifier = str(uuid4()) + str(uuid4())

    code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
    code_challenge = code_challenge.replace('=', '')

    return code_verifier, code_challenge