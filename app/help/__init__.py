""" Help features of servervault """

from flask import Blueprint

bp = Blueprint('help', __name__)

from app.help import routes
