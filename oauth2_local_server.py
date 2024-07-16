import os
import json
import flask
from flask import request, redirect, session, url_for
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import google.auth.transport.requests
import requests


os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
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

def refresh_access_token():
    refresh_token = session['credentials']['refresh_token']
    client_id = session['credentials']['client_id']
    client_secret = session['credentials']['client_secret']
    token_uri = session['credentials']['token_uri']

    payload = {
        'client_id': client_id,
        'client_secret': client_secret,
        'refresh_token': refresh_token,
        'grant_type': 'refresh_token',
    }

    token_response = requests.post(token_uri, data=payload)

    if token_response.status_code == 200:
        new_tokens = token_response.json()
        session['credentials']['token'] = new_tokens['access_token']
        print("Token refreshed successfully")
        return True
    else:
        print(f"Error refreshing token: {token_response.status_code} - {token_response.text}")
        return False

@app.route('/get_accounts')
def get_accounts():
    if 'credentials' not in session:
        print("No credentials in session, redirecting to authorize")
        return redirect('authorize')

    credentials = google.oauth2.credentials.Credentials(
        **session['credentials'])

    access_token = credentials.token
    headers = {
        'Authorization': f'Bearer {access_token}',
    }

    response = requests.get('https://mybusinessaccountmanagement.googleapis.com/v1/accounts', headers=headers)
    response_json = response.json()

    if response.status_code == 200 and 'error' not in response_json:
        accounts = response_json
        return f'<h1>Accounts:</h1><pre>{json.dumps(accounts, indent=2)}</pre>'
    elif response.status_code == 401 or ('error' in response_json and response_json['error']['code'] == 401):
        print("Access token expired, attempting to refresh token")

        if 'refresh_token' not in session['credentials']:
            print("No refresh token available, redirecting to authorize")
            return redirect('authorize')

        if refresh_access_token():
            access_token = session['credentials']['token']
            headers['Authorization'] = f'Bearer {access_token}'
            response = requests.get('https://mybusinessaccountmanagement.googleapis.com/v1/accounts', headers=headers)
            response_json = response.json()

            if response.status_code == 200 and 'error' not in response_json:
                accounts = response_json
                return f'<h1>Accounts:</h1><pre>{json.dumps(accounts, indent=2)}</pre>'
            else:
                print(f"Error fetching accounts after refresh: {response.status_code} - {response.text}")
                return f'Error: {response.status_code} - {response.text}'
        else:
            return 'Error refreshing token. Please re-authorize.', 400
    else:
        print(f"Error fetching accounts: {response.status_code} - {response.text}")
        return f'Error: {response.status_code} - {response.text}'

@app.route('/refresh')
def refresh():
    if 'credentials' not in session:
        print("No credentials in session, redirecting to authorize")
        return redirect('authorize')

    if refresh_access_token():
        return 'Token refreshed successfully!'
    else:
        return 'Error refreshing token. Please re-authorize.', 400

def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}

if __name__ == '__main__':
    app.run('localhost', 8080, debug=True)