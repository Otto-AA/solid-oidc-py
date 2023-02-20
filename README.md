# Solid OIDC Client

A client to use Solid-OIDC authentication.

## Status

This is in beta: use with care. Expect bugs and breaking changes even with minor version updates.

Currently following features are missing:
- refreshing expired tokens
- persistent client id and client secret

## Contributing

Contributions are welcome. These could be additional features, bug fixes, automated testing, better documentation or any other contribution.

## Example app

Here is a simple example that authenticates users with this library and makes authenticated requests in the python backend: https://github.com/Otto-AA/solid-flask

## Installation

```bash
pip install solid_oidc_client
```

## Usage

Following code guides you through the authentication process:

```python
from solid_oidc_client import SolidOidcClient, SolidAuthSession, MemStore

# create a client instance
solid_oidc_client = SolidOidcClient(storage=MemStore())
OAUTH_CALLBACK_URI = '/oauth/callback'

# register this application with the issuer (client_id and client_secret are currently only stored in memory, regardless of the previous storage)
# the redirect url in this case is /oauth/callback
solid_oidc_client.register_client('https://login.inrupt.com/', [OAUTH_CALLBACK_URI])

# initiate a login by redirecting the user to this url
# store the path you want to redirect the user after the login ('/')
login_url = solid_oidc_client.create_login_uri('/', OAUTH_CALLBACK_URI)

# wait for the user to login with their identity provider
# listen on /oauth/callback
# then get code and state from the query params
code = flask.request.args['code']
state = flask.request.args['state']

# and use them to get an authentication session
# internally this will store an access token and key for dpop
session = solid_oidc_client.finish_login(
    code=code,
    state=state,
    callback_uri=OAUTH_CALLBACK_URI,
)

# use this session to make authenticated requests
private_url = 'https://pod.example.org/private/secret.txt'
auth_headers = session.get_auth_headers(private_url, 'GET')
res = requests.get(url=tested_url, headers=auth_headers)
print(res.text)


# optionally serialize and deserialize the sessions to store them as a string client/server side
flask.session['auth'] = session.serialize()
session = SolidAuthSession.deserialize(flask.session['auth'])
```

## Acknowledgments

This is based on [solid-flask](https://gitlab.com/agentydragon/solid-flask/) by Rai.
