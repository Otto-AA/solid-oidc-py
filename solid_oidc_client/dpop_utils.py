import datetime
from jwcrypto import jwt
from uuid import uuid4

def create_dpop_token(keypair, uri, method):
    token = jwt.JWT(header={
        "typ":
        "dpop+jwt",
        "alg":
        "ES256",
        "jwk":
        keypair.export(private_key=False, as_dict=True)
    },
                           claims={
                               "jti": str(uuid4()),
                               "htm": method,
                               "htu": uri,
                               "iat": int(datetime.datetime.now().timestamp())
                           })
    token.make_signed_token(keypair)
    return token.serialize()
