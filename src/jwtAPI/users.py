# -*- coding: utf-8 -*-

import json

from cromlech.jwt.components import TokenException
from dolmen.api_engine.responder import reply
from dolmen.api_engine.validation import allowed, validate, cors_aware
from zope.interface import Interface
from zope.schema import ASCIILine, List, TextLine

from . import USERS
from .cors import options, allow


def protected(app):
    def jwt_protection(environ, start_response, overhead):
        header = environ.get('HTTP_AUTHORIZATION')
        if header is not None and header.startswith('Bearer '):
            token = header[7:]
            try:
                payload = overhead.service.authenticate(token)
                if payload is not None:
                    overhead.auth = payload
                    return app(environ, start_response, overhead)
            except TokenException:
                pass
        return reply(403)
    return jwt_protection


class IUserAction(Interface):
    username = ASCIILine(
        title="User identifier",
        required=True,
    )


class IUsersListing(Interface):
    departments = List(
        title=u"Department identifiers, for an OR request",
        required=False,
        value_type=ASCIILine(),
    )


class IRegistration(Interface):

    username = ASCIILine(
        title="User identifier",
        required=True,
    )

    password = TextLine(
        title="User password",
        required=True,
    )

    departments = List(
        title=u"Department identifiers, for an OR request",
        required=False,
        value_type=ASCIILine(),
    )

    
@cors_aware(options, allow)
@allowed('GET')
@validate(IUserAction, 'GET')
def UserDetails(action_request, overhead):
    user_details = USERS.get(action_request.username)
    if user_details is not None:
        return reply(
            200, text=json.dumps(user_details['payload']),
            content_type="application/json")
    return reply(404, text="User not found.")


@cors_aware(options, allow)
@protected
@allowed('GET')
@validate(Interface, 'GET')
def PersonalDetails(action_request, overhead):
    user_details = USERS.get(overhead.auth['user'])
    if user_details is not None:
        return reply(
            200, text=json.dumps(user_details),
            content_type="application/json")
    return reply(500)  # this should not happen


@cors_aware(options, allow)
@allowed('POST')
@validate(IRegistration, 'JSON')
def SignUp(action_request, overhead):
    if action_request.username in USERS:
        reply(409, text="User already exists")

    user_details = {
        'password': action_request.password,
        'payload': {
            'departments': [d.strip() for d in action_request.departments],
            },
        }

    USERS[action_request.username] = user_details
    return reply(201)


@cors_aware(options, allow)
@allowed('GET')
@validate(IUsersListing, 'GET')
def UsersListing(action_request, overhead):
    listing = []
    departments = frozenset((d.strip() for d in action_request.departments if d))
    for username, details in USERS.items():
        payload = details['payload'] 
        if not departments:
            listing.append({username: payload})
        elif departments & set(payload['departments']):
            listing.append({username: payload})

    if departments and not listing:
        return reply(404, text="No matching users found.")
    return reply(200, text=json.dumps(listing),
                 content_type="application/json")


module = {
    '/details': UserDetails,
    '/list': UsersListing,
    '/personal': PersonalDetails,
    '/signup': SignUp,
}
