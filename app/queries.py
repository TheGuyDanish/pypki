from app.models import RootCertificate, IntermediateCertificate

def root_choice_query():
    return RootCertificate.query

def intermediate_choice_query():
    return IntermediateCertificate.query