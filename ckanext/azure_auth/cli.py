# encoding: utf-8

import click
import msal
import requests
import uuid
import ckan.plugins.toolkit as tk
import re
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

    auth_backend.update_users_for_organization()



