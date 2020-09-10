from flask import render_template, flash, redirect, url_for, request, current_app
from app.help import bp

@bp.context_processor
def inject_version():
    return dict(version=current_app.config['APP_VERSION'])
