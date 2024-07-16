import os
import json
import flask
from flask import request, redirect, session, url_for
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import google.auth.transport.requests
import requests

# Configure the OAuth 2.0 flow using client secrets file
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # For testing only, disable in production
CLIENT_SECRETS_FILE = "client_secret.json"

SCOPES = ['https://www.googleapis.com/auth/business.manage']
REDIRECT_URI = 'http://localhost:8080/oauth2callback'

app = flask.Flask(__name__)
app.secret_key = os.urandom(24)

@app.route('/')
def index():
    return '''
        <h1>Welcome to the OAuth 2.0 Demo!</h1>
        <a href="/authorize">Authorize</a><br><br>
        <a href="/get_accounts">Get My Business Accounts</a><br><br>
        <a href="/refresh">Refresh Token</a>
    '''

@app.route('/authorize')
def authorize():
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = REDIRECT_URI

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true')

    session['state'] = state
    print(f"State stored in session: {state}")
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    if 'state' not in session:
        print("State not found in session")
        return 'State not found in session. Authorization failed.', 400

    state = session['state']
    print(f"State retrieved from session: {state}")
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = REDIRECT_URI

    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)

    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)
    print(f"Credentials stored in session: {session['credentials']}")

    return 'Authorization successful!'

@app.route('/get_accounts')
def get_accounts():
    if 'credentials' not in session:
        print("No credentials in session, redirecting to authorize")
        return redirect('authorize')

    credentials = google.oauth2.credentials.Credentials(
        **session['credentials'])

    if credentials.expired or credentials.token is None:
        print("Token is expired or None, refreshing token")
        request = google.auth.transport.requests.Request()
        try:
            credentials.refresh(request)
            session['credentials'] = credentials_to_dict(credentials)
            print("Token refreshed successfully")
        except Exception as e:
            print(f"Error refreshing token: {e}")
            return 'Error refreshing token. Please re-authorize.', 400

    access_token = credentials.token
    print(f"Using access token: {access_token}")

    headers = {
        'Authorization': f'Bearer {access_token}',
    }

    response = requests.get('https://mybusinessaccountmanagement.googleapis.com/v1/accounts', headers=headers)

    if response.status_code == 200:
        accounts = response.json()
        return f'<h1>Accounts:</h1><pre>{json.dumps(accounts, indent=2)}</pre>'
    else:
        print(f"Error fetching accounts: {response.status_code} - {response.text}")
        return f'Error: {response.status_code} - {response.text}'

@app.route('/refresh')
def refresh():
    if 'credentials' not in session:
        print("No credentials in session, redirecting to authorize")
        return redirect('authorize')

    credentials = google.oauth2.credentials.Credentials(
        **session['credentials'])

    if credentials.expired or credentials.token is None:
        print("Token is expired or None, refreshing token")
        request = google.auth.transport.requests.Request()
        try:
            credentials.refresh(request)
            session['credentials'] = credentials_to_dict(credentials)
            print("Token refreshed successfully")
            return 'Token refreshed successfully!'
        except Exception as e:
            print(f"Error refreshing token: {e}")
            return 'Error refreshing token. Please re-authorize.', 400
    else:
        print("Token is still valid")
        return 'Token is still valid. No need to refresh.'

def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}

if __name__ == '__main__':
    app.run('localhost', 8080, debug=True)