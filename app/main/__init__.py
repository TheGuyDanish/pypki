""" Main features of servervault. Devices, customers, credentials, etc. """

from flask import Blueprint

bp = Blueprint('main', __name__)

from app.main import routes
