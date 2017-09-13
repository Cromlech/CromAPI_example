# -*- coding: utf-8 -*-

import json
from zope.schema import ASCIILine, TextLine
from zope.interface import Interface
from dolmen.api_engine.validation import allowed, validate, cors_aware
from dolmen.api_engine.responder import reply
from . import USERS
from .cors import options, allow


class ILogin(Interface):

    username = ASCIILine(
        title="User identifier",
        required=True,
    )

    password = TextLine(
        title="User password",
        required=True,
    )


@cors_aware(options, allow)
@allowed('POST')
@validate(ILogin, 'JSON')
def Login(action_request, overhead):
    user = USERS.get(action_request.username)
    if user is not None:
        if user['password'] == action_request.password:
            payload = {'user': action_request.username}
            jwt = overhead.service.generate(payload)
            token = json.dumps({'token': jwt})
            return reply(200, text=token, content_type="application/json")
    return reply(401)


module = {
    '/login': Login,
}
