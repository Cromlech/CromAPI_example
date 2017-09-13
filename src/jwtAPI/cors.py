# -*- coding: utf-8 -*-

from dolmen.api_engine.responder import reply


def options(environ):
    response = reply(200)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "POST"
    response.headers["Access-Control-Allow-Headers"] = (
        "Authorization, Content-Type")
    return response


def allow(response):
    if response.status[0] == '2':  # 2XX Response, OK !
        response.headers["Access-Control-Allow-Origin"] = "*"
    return response
