# encoding: utf-8

import click
import msal
import requests
import uuid
import ckan.plugins.toolkit as tk
from ckanext.azure_auth.auth_backend import AdfsAuthBackend
from ckanext.azure_auth.auth_config import (
    ADFS_CREATE_USER,
    ADFS_SESSION_PREFIX,
    ATTR_ADSF_AUDIENCE,
    ATTR_CLIENT_ID,
    ATTR_CLIENT_SECRET,
    ATTR_TENANT_ID,
    ATTR_REDIRECT_URL,
    AUTH_SERVICE,
    TIMEOUT,
    ProviderConfig,
)
from ckan.logic import NotFound

def get_commands():
    return [azure_auth]

@click.group()
def azure_auth():
    pass

@azure_auth.command(short_help=u"Update relations between users and organizations.")
def update_users():
    provider_config = ProviderConfig()
    auth_backend = AdfsAuthBackend(provider_config=provider_config)

    app = msal.ConfidentialClientApplication(
        tk.config[ATTR_CLIENT_ID],
        authority="https://login.microsoftonline.com/%s" % tk.config[ATTR_TENANT_ID],
        client_credential=tk.config[ATTR_CLIENT_SECRET]
        )

    scope = 'https://graph.microsoft.com/.default'

    token_result = app.acquire_token_for_client(scopes=[scope])

    users_data = requests.get(
        "https://graph.microsoft.com/v1.0/users",
        headers={'Authorization': 'Bearer ' + token_result['access_token']},).json()

    for user_data in users_data["value"]:

        user_id = user_data["id"]
        email = user_data["userPrincipalName"]
        ckan_id = f'{AUTH_SERVICE}-{user_id}'
        username = auth_backend.sanitize_username(user_data.get('displayName', ckan_id))

        if not username:
            username = auth_backend.sanitize_username(email.split('@')[0])


        fullname = f'{user_data["givenName"]} {user_data["surname"]}'
        
        try:
          user = tk.get_action('user_show')(
              context={'ignore_auth': True},
              data_dict={'id': ckan_id}
          )
        except NotFound:
          user = tk.get_action('user_create')(
              context={'ignore_auth': True, 'user': username},
              data_dict={
                  'id': ckan_id,
                  'name': username,
                  'fullname': fullname,
                  'password': str(uuid.uuid4()),
                  'email': email,
                  'plugin_extras': {
                      'azure_auth':  user_id,
                  }
              },
          )

        auth_backend.update_organizations_for_user(user)


          



