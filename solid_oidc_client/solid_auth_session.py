import json
from jwcrypto import jwk, jwt

from .dpop_utils import create_dpop_token

# TODO: handle token expiration + refreshing
class SolidAuthSession:
    """Authentication session to provide authentication headers"""
    def __init__(self, access_token: str, key: jwk.JWK) -> None:
        self.access_token = access_token
        self.key = key

    def get_web_id(self) -> str:
        decoded_token = jwt.JWT(jwt=self.access_token)
        payload = json.loads(decoded_token.token.objects['payload'])
        return payload['webid']

    def get_auth_headers(self, url: str, method: str) -> dict:
        """returns a dict of authentication headers for a target url and http method"""
        return {
            'Authorization': ('DPoP ' + self.access_token),
            'DPoP': create_dpop_token(self.key, url, method)
        }
    
    def serialize(self) -> str:
        """return a string representation of this session"""
        return json.dumps({
            'access_token': self.access_token,
            'key': self.key.export(),
        })
    
    @staticmethod
    def deserialize(serialization: str):
        obj = json.loads(serialization)
        access_token = obj['access_token']
        key = jwk.JWK.from_json(obj['key'])
        return SolidAuthSession(access_token, key)