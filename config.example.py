""" The main configuration file for the application """
import os

class Config(object):
    """ Configuration items for the application """
    # App related settings
    TITLE = 'pypki'
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'

    # Database settings
    DB_HOST = os.environ.get('DB_HOST') or \
         'hostname'
    DB_USER = os.environ.get('DB_USER') or \
         'username'
    DB_PASS = os.environ.get('DB_PASS') or \
         'password'
    DB_NAME = os.environ.get('DB_NAME') or \
         'database_name'
    DB_PORT = os.environ.get('DB_PORT') or \
         3306
    SQLALCHEMY_TRACK_MODIFICATIONS = True

    # Mail settings
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 25)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS') is not None
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    ADMINS = ['<your email here>']

    # DO NOT EDIT BELOW THIS LINE
    SQLALCHEMY_DATABASE_URI = f'mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}'
    APP_VERSION = "INTERNAL_DEV_VERSION"
    ASN1_TIME_FORMAT = '%Y%m%d%H%M%S%z'
