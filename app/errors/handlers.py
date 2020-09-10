""" This blueprint contians all the error pages used in pypki """

from flask import render_template
from app import db
from app.errors import bp

@bp.app_errorhandler(404)
def not_found_error(error):
    """ Simple 404 page """
    return render_template('errors/404.html', error=error), 404

@bp.app_errorhandler(500)
def internal_error(error):
    """ Default 500 error page. Rolls back any DB transaction and presents the page """
    db.session.rollback()
    return render_template('errors/500.html', error=error), 500
