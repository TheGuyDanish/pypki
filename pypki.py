""" Main executable for pypki """

from app import create_app, db
from app.models import User, RootCertificate, IntermediateCertificate, Certificate

app = create_app()

@app.shell_context_processor
def make_shell_context():
    """ Make a shell context for when 'flask shell' is run """
    return {'db': db, 'User': User, 'RootCertificate': RootCertificate,
            'IntermediateCertificate': IntermediateCertificate, 'Certificate': Certificate}
