import logging
import uuid
import re

import jwt

from ckan.common import _, config, session
from ckan.lib.munge import substitute_ascii_equivalents
from ckan.logic import NotFound
from ckan.plugins import toolkit
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
from ckanext.azure_auth.exceptions import (
    AzureReloginRequiredException,
    CreateUserException,
    MFARequiredException,
    RuntimeIssueException,
)

log = logging.getLogger(__name__)

import msal
import re
import json
import requests
import ckan.model as model
import pandas as pd


class AdfsAuthBackend(object):
    provider_config: ProviderConfig

    def __init__(self, provider_config):
        self.provider_config = provider_config

    def exchange_auth_code(self, authorization_code):
        log.debug('Received authorization code: %s', authorization_code)
        data = {
            'grant_type': 'authorization_code',
            'client_id': config[ATTR_CLIENT_ID],
            'redirect_uri': config[ATTR_REDIRECT_URL],
            'code': authorization_code,
        }
        if config[ATTR_CLIENT_SECRET]:
            data['client_secret'] = config[ATTR_CLIENT_SECRET]

        log.debug(
            'Getting access token at: %s', self.provider_config.token_endpoint
        )
        response = self.provider_config.session.post(
            self.provider_config.token_endpoint, data, timeout=TIMEOUT
        )

        # 200 = valid token received
        # 400 = 'something' is wrong in our request
        if response.status_code == 400:
            error_description = response.json().get('error_description', '')
            if error_description.startswith('AADSTS50076'):
                raise MFARequiredException

            # AADSTS54005 - expired  (TODO: an issue)
            # AADSTS70008 - already provided. Needs relogin
            if error_description.startswith('AADSTS54005') or \
                    error_description.startswith('AADSTS70008'):
                raise AzureReloginRequiredException(
                    _('Please re-sign in on the Microsoft Azure side')
                )
            log.error(f'ADFS server returned an error: {error_description}')
            raise RuntimeIssueException(error_description)

        if response.status_code != 200:
            log.error(
                'Unexpected ADFS response: %s', response.content.decode()
            )
            raise PermissionError

        adfs_response = response.json()
        session[f'{ADFS_SESSION_PREFIX}tokens'] = adfs_response
        session.save()
        return adfs_response

    def validate_access_token(self, access_token):
        for idx, key in enumerate(self.provider_config.signing_keys):
            try:
                # Explicitly define the verification option.
                # The list below is the default the jwt module uses.
                # Explicit is better then implicit and it protects against
                # changes in the defaults the jwt module uses.
                options = {
                    'verify_signature': True,
                    'verify_exp': True,
                    'verify_nbf': True,
                    'verify_iat': True,
                    'verify_aud': True,
                    'verify_iss': True,
                    'require_exp': False,
                    'require_iat': False,
                    'require_nbf': False,
                }
                # Validate token and return claims
                return jwt.decode(
                    access_token,
                    key=key,
                    algorithms=['RS256', 'RS384', 'RS512'],
                    audience=config[ATTR_ADSF_AUDIENCE],
                    issuer=self.provider_config.issuer,
                    options=options,
                    leeway=config['ckanext.azure_auth.jwt_leeway'],
                )
            except jwt.ExpiredSignatureError as error:
                log.info(f'Signature has expired: {error}')
                raise PermissionError
            except jwt.DecodeError as error:
                # If it's not the last certificate in the list, skip to the
                # next one
                if idx < len(self.provider_config.signing_keys) - 1:
                    continue
                else:
                    log.info(f'Error decoding signature: {error}')
                    raise PermissionError
            except jwt.InvalidTokenError as error:
                log.info(str(error))
                raise PermissionError

    def process_access_token(self, access_token, adfs_response=None):
        if not access_token:
            raise PermissionError

        log.debug(f'Received access token: {access_token}')
        claims = self.validate_access_token(adfs_response['id_token'])
        if not claims:
            raise PermissionError

        log.debug(f'Decoded claims: {claims}')
        return self.get_or_create_user(claims)

    def get_or_create_user(self, claims):
        '''
        Create the user if it doesn't exist yet

        Args:
            claims (dict): claims from the access token

        Returns:
            django.contrib.auth.models.User: A Django user
        '''
        user_id = claims.get("oid")
        if not user_id:
            log.error(f"User claim's doesn't have the claim 'oid' in his claims: {claims}")
            raise PermissionError

        email = claims.get('unique_name')
        ckan_id = f'{AUTH_SERVICE}-{user_id}'
        username = self.sanitize_username(claims.get('name', ckan_id))
        if not username:
            username = self.sanitize_username(email.split('@')[0])

        fullname = f'{claims["given_name"]} {claims["family_name"]}'


        try:
            user = toolkit.get_action('user_show')(
                context={'ignore_auth': True},
                data_dict={'id': ckan_id}
            )
            log.debug(f"User found --> {user}")
            dirty = False
            if user['name'] != username:
                # in ckan we cannot update the username, a warning will suffice
                log.warning(f"Username not aligned:  CKAN:[{user['name']}]  ADFS:[{username}]")
            if user['fullname'] != fullname:
                log.info(f"Resetting fullname from [{user['fullname']}] to [{fullname}]")
                user['fullname'] = fullname
                dirty = True
            if dirty:
                # set some fields required when saving
                user['email'] = email
                toolkit.get_action('user_update')(
                    context={'ignore_auth': True},
                    data_dict=user)
        except NotFound:
            if config[ADFS_CREATE_USER]:
                user = toolkit.get_action('user_create')(
                    context={'ignore_auth': True},
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
                log.debug(f"User created --> {user}")
            else:
                msg = (
                    f"User with email '{email}' doesn't exist and creating"
                    f' users is disabled.'
                )
                log.debug(msg)
                raise CreateUserException(msg)
        return user

    @staticmethod
    def sanitize_username(tag: str):
        tag = substitute_ascii_equivalents(tag)
        tag = tag.lower().strip()
        tag = re.sub(r'[^a-zA-Z0-9\- ]', '', tag).replace(' ', '-')
        return tag

    def authenticate_with_code(self, authorization_code=None, **kwargs):
        '''
        Authentication backend to allow authenticating users against a
        Microsoft ADFS server with an authorization code.

        :param authorization_code:
        :param kwargs:
        :return:
        '''
        self.provider_config.load_config()

        # If there's no token or code, we pass control to the next
        # authentication backend
        if not bool(authorization_code):
            log.debug('No authorization code was received')
            return

        adfs_response = self.exchange_auth_code(authorization_code)
        access_token = adfs_response['access_token']
        user = self.process_access_token(access_token, adfs_response)
        return user

    def authenticate_with_token(self, access_token=None, **kwargs):
        '''
        Authentication backend to allow authenticating users against a
        Microsoft ADFS server with an access token retrieved by the client.
        :param access_token:
        :param kwargs:
        :return:
        '''
        self.provider_config.load_config()

        # If there's no token or code, we pass control to the next
        # authentication backend
        if not bool(access_token):
            log.debug('No authorization code was received')
            return

        access_token = access_token.decode()
        user = self.process_access_token(access_token)
        return user

    def update_organizations_for_user(self, user, groups_data=None):
        # sysadminの場合は何もしない
        if user.get("sysadmin"):
            return

        result = None
        app = msal.ConfidentialClientApplication(
            config[ATTR_CLIENT_ID],
            authority="https://login.microsoftonline.com/%s" % config[ATTR_TENANT_ID],
            client_credential=config[ATTR_CLIENT_SECRET]
            )

        scope = 'https://graph.microsoft.com/.default'
        result = app.acquire_token_silent(scopes=[scope], account=None)
        if not result:
            result = app.acquire_token_for_client(scopes=[scope])

        if "access_token" not in result:
            log.error("There's no access_token in the response from Azure AD")
            return

        try:
            orgs_df = pd.read_excel("/etc/ckan/organizations.xlsx")
        except Exception as e:
            log.error(e)
            return

        user_id = user.get("id")
        user_id_re = re.compile(r'^adfs-')
        if user_id_re.match(user_id):
            aad_user_id = user_id_re.sub('', user_id)
        else:
            return

        # Calling graph using the access token
        if not groups_data:
            groups_data = requests.get(
                "https://graph.microsoft.com/v1.0/users/%s/memberof" % aad_user_id,
                headers={'Authorization': 'Bearer ' + result['access_token']},).json()

        # ユーザに紐付けるCKAN組織名のリストを取得する
        organization_titles = []
        aad_group_re = re.compile(r'^DT-')
        for group_data in groups_data["value"]:
            if group_data.get("@odata.type", "") != "#microsoft.graph.group":
                continue

            aad_group_name = group_data.get("displayName")

            # DT-で始まらないグループの場合はcontinueする
            if not aad_group_re.match(aad_group_name):
                continue

            # ここでDT-をグループ名から取る処理をする
            organization_titles.append(aad_group_re.sub("", aad_group_name))

        # CKANの組織との紐付け状況を取得
        existing_members = model.Session.query(model.Member, model.Group) \
            .join(model.Group, model.Group.id == model.Member.group_id) \
            .filter(model.Member.table_name == "user") \
            .filter(model.Member.table_id == user_id).all()

        # 紐付け済みの組織のtitleのリスト
        existing_member_org_titles = []

        # 既存のCKAN組織との紐付から、organization_titlesに組織名がないものを削除する。
        for existing_member in existing_members:
            if existing_member.Group.title in organization_titles:
                # アクティブでなければアクティブにする
                if existing_member.Group.state != 'active':
                    existing_member.Group.state = 'active'
                    model.repo.commit()
                if existing_member.Member.state != 'active':
                    existing_member.Member.state = 'active'
                    model.repo.commit()
                existing_member_org_titles.append(existing_member.Group.title)
            else:
                model.Session.delete(existing_member.Member)
                model.repo.commit()

        # ユーザとCKAN組織の紐付け
        for ot in organization_titles:
            if ot in existing_member_org_titles:
                continue

            # 組織情報のexcelからorganization名を取得する
            orgs = orgs_df[orgs_df["組織名"] == ot]

            if len(orgs) == 0:
                continue

            organization_name = orgs.iloc[0]["DBスキーマ"]

            #  organizationの存在チェック
            group = model.Session.query(model.Group) \
                .filter(model.Group.is_organization == True) \
                .filter(model.Group.type == 'organization') \
                .filter(model.Group.name == organization_name) \
                .filter(model.Group.title == ot) \
                .first()

            if group is None:
                group = model.Group(
                    is_organization = True,
                    type = 'organization',
                    name = organization_name,
                    title = ot,
                )
                model.Session.add(group)
                model.repo.commit()

            # アクティブでなければアクティブにする
            if group.state != 'active':
                group.state = 'active'
                model.repo.commit()
            
            member = model.Member(table_name='user',
                    table_id=user_id,
                    group=group,
                    capacity='member')

            model.Session.add(member)
            model.repo.commit()


    def update_users_for_organization(self):
        aad_group_re = re.compile(r'^DT-')

        app = msal.ConfidentialClientApplication(
            config[ATTR_CLIENT_ID],
            authority="https://login.microsoftonline.com/%s" % config[ATTR_TENANT_ID],
            client_credential=config[ATTR_CLIENT_SECRET]
            )

        scope = 'https://graph.microsoft.com/.default'
        token_result = app.acquire_token_for_client(scopes=[scope])
        if not token_result:
            token_result = app.acquire_token_for_client(scopes=[scope])

        if "access_token" not in token_result:
            log.error("There's no access_token in the response from Azure AD")
            return

        try:
            orgs_df = pd.read_excel("/etc/ckan/organizations.xlsx")
        except Exception as e:
            log.error(e)
            return
        
        next_groups_url="https://graph.microsoft.com/v1.0/groups?$filter=startswith(displayName,'DT-')"

        while next_groups_url:
            groups_data = requests.get(
                next_groups_url,
                headers={'Authorization': 'Bearer ' + token_result['access_token']},).json()
            
            for group_data in groups_data["value"]:

                aad_group_name = group_data.get("displayName")
                organization_title = aad_group_re.sub("", aad_group_name)
                orgs = orgs_df[orgs_df["組織名"] == organization_title]

                if len(orgs) == 0:
                    continue

                organization_name = orgs.iloc[0]["DBスキーマ"]

                # グループのメンバーを取得
                next_members_url="https://graph.microsoft.com/v1.0/groups/%s/members" % group_data["id"]

                members_data = []                
                while next_members_url:
                    md = requests.get(
                        next_members_url,
                        headers={'Authorization': 'Bearer ' + token_result['access_token']}
                    ).json()

                    members_data.extend(md["value"])

                    next_members_url=md.get("@odata.nextLink")

                # メンバーがいないセキュリティグループは無視する
                if len(members_data) == 0:
                    continue

                #  organizationの存在チェック
                group = model.Session.query(model.Group) \
                    .filter(model.Group.is_organization == True) \
                    .filter(model.Group.type == 'organization') \
                    .filter(model.Group.name == organization_name) \
                    .filter(model.Group.title == organization_title) \
                    .first()

                if group is None:
                    group = model.Group(
                        is_organization = True,
                        type = 'organization',
                        name = organization_name,
                        title = organization_title,
                    )
                    model.Session.add(group)
                    model.repo.commit()

                # アクティブでなければアクティブにする
                if group.state != 'active':
                    group.state = 'active'
                    model.repo.commit()


                # CKAN組織に所属すべきユーザIDのリスト
                member_ckan_ids = [f'{AUTH_SERVICE}-{x["id"]}' for x in members_data]

                # 既存のCKAN組織のユーザを取得
                existing_members = model.Session.query(model.Member, model.Group) \
                    .join(model.Group, model.Group.id == model.Member.group_id) \
                    .filter(model.Member.table_name == "user") \
                    .filter(model.Group.id == group.id).all()
                
                # 組織に紐付け済みのユーザのidのリスト
                existing_member_user_ids = []

                # 既存のCKAN組織のユーザから、members_dataにないものを削除する。
                for existing_member in existing_members:
                    if existing_member.Member.table_id in member_ckan_ids:
                        if existing_member.Member.state != 'active':
                            existing_member.Member.state = 'active'
                            model.repo.commit()
                        existing_member_user_ids.append(existing_member.Member.table_id)
                    else:
                        model.Session.delete(existing_member.Member)
                        model.repo.commit()

                
                # CKAN組織へのユーザの紐付け
                for member_data in members_data:
                    ckan_id = f'{AUTH_SERVICE}-{member_data["id"]}'
                    email = member_data["userPrincipalName"]
                    username = self.sanitize_username(member_data.get('displayName', ckan_id))

                    if not username:
                        username = self.sanitize_username(email.split('@')[0])


                    fullname = f'{member_data["givenName"]} {member_data["surname"]}'


                    if ckan_id in existing_member_user_ids:
                        continue


                    try:
                        user = toolkit.get_action('user_show')(
                            context={'ignore_auth': True},
                            data_dict={'id': ckan_id}
                        )
                    except NotFound:
                        user = toolkit.get_action('user_create')(
                            context={'ignore_auth': True, 'user': username},
                            data_dict={
                                'id': ckan_id,
                                'name': username,
                                'fullname': fullname,
                                'password': str(uuid.uuid4()),
                                'email': email,
                                'plugin_extras': {
                                    'azure_auth':  member_data["id"],
                                }
                            },
                        )

                    member = model.Member(table_name='user',
                            table_id=user.get('id'),
                            group=group,
                            capacity='member')

                    model.Session.add(member)
                    model.repo.commit()
                                
            next_groups_url = groups_data.get("@odata.nextLink")