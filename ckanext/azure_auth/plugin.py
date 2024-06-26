import logging
import requests

from ckan.logic import get_action, NotAuthorized
from ckan.common import g, session, config as ckan_config
from ckan.exceptions import CkanConfigurationException
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
from typing import Any
import jwt
from .aadtoken import get_public_key
from ckanext.azure_auth.cli import get_commands
from ckanext.azure_auth.auth_backend import AdfsAuthBackend

from ckanext.azure_auth.auth_config import (
    AUTH_SERVICE,
    ADFS_CREATE_USER,
    ADFS_SESSION_PREFIX,
    ATTR_ADSF_AUDIENCE,
    ATTR_AD_SERVER,
    ATTR_AUTH_CALLBACK_PATH,
    ATTR_CLIENT_ID,
    ATTR_CLIENT_SECRET,
    ATTR_DISABLE_SSO,
    ATTR_FORCE_MFA,
    ATTR_HELP_TEXT,
    ATTR_METADATA_URL,
    ATTR_REDIRECT_URL,
    ATTR_TENANT_ID,
    ATTR_WT_REALM,
    AZURE_AD_SERVER_URL,
    ATTR_LOGIN_LABEL, ATTR_LOGIN_BUTTON,
    ProviderConfig,
    RENDERABLE_ATTRS,
)

from ckanext.azure_auth.blueprint import azure_auth_blueprint, azure_admin_blueprint

log = logging.getLogger(__name__)
requests.packages.urllib3.add_stderr_logger()


class AzureAuthPlugin(plugins.SingletonPlugin):
    '''
    Microsoft Azure auth service connector
    '''

    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.ITemplateHelpers)
    plugins.implements(plugins.IAuthenticator)
    plugins.implements(plugins.IApiToken, inherit=True)
    plugins.implements(plugins.IClick)

    def update_config(self, config):
        '''
        Add our templates to CKAN's search path
        '''
        toolkit.add_template_directory(config, 'templates')
        toolkit.add_public_directory(config, 'public')

        toolkit.add_ckan_admin_tab(config, 'azure_admin.azure_auth_config', 'ADFS', icon='windows')

        if ATTR_TENANT_ID in config:
            # If a tenant ID was set, switch to Azure AD mode
            if ATTR_AD_SERVER in config:
                msg = f'The {ATTR_AD_SERVER} should not be set when {ATTR_TENANT_ID} is set.'
                raise CkanConfigurationException(msg)
            config[ATTR_AD_SERVER] = AZURE_AD_SERVER_URL

        # Validate required settings
        if ATTR_TENANT_ID not in config and ATTR_AD_SERVER not in config:
            msg = f'Exactly one of the settings {ATTR_TENANT_ID} or {ATTR_AD_SERVER} must be set'
            raise CkanConfigurationException(msg)
        elif ATTR_TENANT_ID not in config:
            # For on premises ADFS, the tenant ID is set to adfs
            # On AzureAD the adfs part in the URL happens to be replace by the tenant ID.
            config[ATTR_TENANT_ID] = 'adfs'

        # Set plugin defaults
        azure_auth_plugin_defaults = (
            (ATTR_METADATA_URL, 'https://login.microsoftonline.com/'),
            (ATTR_AUTH_CALLBACK_PATH, '/oauth2/callback'),
            (ATTR_REDIRECT_URL, config['ckan.site_url'] + config[ATTR_AUTH_CALLBACK_PATH]),
            (ATTR_FORCE_MFA, False),
            (ATTR_DISABLE_SSO, False),
            ('ckanext.azure_auth.config_reload_interval', 24),  # in hours
            ('ckanext.azure_auth.ca_bundle', True),
            ('ckanext.azure_auth.retry', 5),
            ('ckanext.azure_auth.jwt_leeway', 0),
        )
        for k, d in azure_auth_plugin_defaults:
            config.setdefault(k, d)

    def update_config_schema(self, schema):
        # not_empty = toolkit.get_validator('not_empty')
        unicode_safe = toolkit.get_validator('unicode_safe')
        ignore_missing = toolkit.get_validator('ignore_missing')
        # boolean_validator = toolkit.get_validator('boolean_validator')

        # schema.update(
        #     {
        #         ATTR_WT_REALM: [not_empty, unicode_safe],
        #         ATTR_METADATA_URL: [not_empty, unicode_safe],
        #         ATTR_HELP_TEXT: [ignore_missing, unicode_safe],
        #         ATTR_REDIRECT_URL: [not_empty, unicode_safe],
        #         ATTR_TENANT_ID: [not_empty, unicode_safe],
        #         ATTR_CLIENT_ID: [not_empty, unicode_safe],
        #         ATTR_CLIENT_SECRET: [not_empty, unicode_safe],
        #         ATTR_FORCE_MFA: [ignore_missing, boolean_validator],
        #         ATTR_DISABLE_SSO: [ignore_missing, boolean_validator],
        #         ATTR_AD_SERVER: [ignore_missing, unicode_safe],
        #         ADFS_CREATE_USER: [not_empty, boolean_validator],
        #         ATTR_ADSF_AUDIENCE: [not_empty, unicode_safe],
        #     }
        # )

        schema.update(
            {
                ATTR_LOGIN_LABEL: [ignore_missing, unicode_safe],
                ATTR_LOGIN_BUTTON: [ignore_missing, unicode_safe],
            }
        )

        return schema

    def get_helpers(self):

        def is_adfs_user(user_id: str):
            user = toolkit.get_action('user_show')(data_dict={'id': user_id})
            return user['id'].startswith(AUTH_SERVICE)

        def get_attrib(key):
            if key not in RENDERABLE_ATTRS:
                raise NotAuthorized('Attribute is not accessible')
            return get_action('config_option_show')({'ignore_auth': True}, {'key': key})

        try:
            provider_config = ProviderConfig()
            adfs_authentication_endpoint_error = ''
            adfs_authentication_endpoint = (
                provider_config.build_authorization_endpoint()
            )
        except RuntimeError as err:
            log.critical(err)
            adfs_authentication_endpoint = False
            adfs_authentication_endpoint_error = str(err)

        return {
            'is_adfs_user': is_adfs_user,
            'adfs_authentication_endpoint': adfs_authentication_endpoint,
            'adfs_authentication_endpoint_error': adfs_authentication_endpoint_error,
            'adfs_get_attrib': get_attrib,
        }

    def get_blueprint(self):
        '''Return a Flask Blueprint object to be registered by the app.'''
        return [
            azure_auth_blueprint,
            azure_admin_blueprint
        ]

    # IAuthenticator
    def identify(self):
        user = session.get(f'{ADFS_SESSION_PREFIX}user')
        if user:
            g.user = user

    def login(self):
        pass

    def logout(self):
        if f'{ADFS_SESSION_PREFIX}tokens' in session:
            del session[f'{ADFS_SESSION_PREFIX}tokens']

        keys_to_delete = [
            key for key in session if key.startswith(ADFS_SESSION_PREFIX)
        ]
        if keys_to_delete:
            for key in keys_to_delete:
                del session[key]
            session.save()

    def abort(self, status_code, detail, headers, comment):
        return status_code, detail, headers, comment

    # IApiToken
    def decode_api_token(
        self, encoded: str, **kwargs: Any) -> Any:
    
        provider_config = ProviderConfig()
        provider_config.load_config()
        auth_backend = AdfsAuthBackend(provider_config=provider_config)

        return auth_backend.validate_access_token(encoded, api=True)


    # IClick
    def get_commands(self):
        return get_commands()
