""" The main logic and routes for servervault """
from datetime import datetime
from random import randint
from cryptography.fernet import Fernet
from flask import render_template, flash, redirect, url_for, request, current_app, session, Response
from flask_login import current_user, login_required
from OpenSSL import crypto
from app import db
from app.certgen import createKeyPair, createCertRequest, TYPE_RSA
from app.main import bp
from app.main.forms import EditProfileForm, NewRootCertForm, NewIntermediateCertForm, NewCertForm,\
                           NewCSRFulfillmentForm
from app.models import RootCertificate, IntermediateCertificate, Certificate
from app.utility import has_extension

#region Jinja Filters
@bp.context_processor
def inject_version():
    """ Provide a version variable that can be used in templates for the footer. """
    return dict(version=current_app.config['APP_VERSION'])

@bp.app_template_filter('asn1_to_datetime')
def asn1_to_datetime(timestamp):
    """ Convert the ASN1 time format to a regular timestamp with datetime. """
    if isinstance(timestamp, bytes):
        timestamp = timestamp.decode("UTF-8")
    else:
        timestamp = str(timestamp)

    time_object = datetime.strptime(timestamp, current_app.config['ASN1_TIME_FORMAT'])
    return time_object.isoformat()

@bp.app_template_filter('decode')
def decode_bytes(input_bytes):
    """ Converts bytes to UTF-8 for display purposes. """
    string = input_bytes.decode("UTF-8")
    return string

@bp.app_template_filter('c_to_human')
def c_to_human(string):
    """ Convert 2-character component names to human-readable elements. """
    if string == "C":
        return 'Country'
    elif string == "ST":
        return 'State or Province'
    elif string == "L":
        return "Locality"
    elif string == "O":
        return "Organization Name"
    elif string == "OU":
        return "Organizational Unit"
    elif string == "CN":
        return "Common Name"
    elif string == "emailAddress":
        return "Email Address"

#endregion

#region Routes
@bp.route('/')
@bp.route('/index')
@login_required
def index():
    """ Render the index page """
    return render_template('index.html')

#region User and Profile features
@bp.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """ Allow the user to change some basic information about their account. """
    form = EditProfileForm(current_user.email)
    if form.validate_on_submit():
        current_user.email = form.email.data
        current_user.title = form.title.data
        current_user.country = form.country.data
        current_user.state = form.state.data
        current_user.locality = form.locality.data
        current_user.org_name = form.org_name.data
        current_user.ou_name = form.ou_name.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('main.user', username=current_user.username))
    elif request.method == 'GET':
        form.email.data = current_user.email
        form.title.data = current_user.title
        form.country.data = current_user.country
        form.state.data = current_user.state
        form.locality.data = current_user.locality
        form.org_name.data = current_user.org_name
        form.ou_name.data = current_user.ou_name
    return render_template('edit_profile.html', title='Edit Profile',
                           form=form)

@bp.route('/user')
@login_required
def user():
    """ Display information saved about the current user. """
    return render_template('user.html', user=current_user)
#endregion

#region Root Certificates
@bp.route('/root')
@login_required
def root_list():
    """ Gathers and lists all root/CA certificates. """
    certs = RootCertificate.query.all()
    return render_template('root_list.html', certs=certs)

@bp.route('/root/new', methods=['GET', 'POST'])
@login_required
def root_new():
    """
    This form takes input to create a new self-signed CA certificate.
    """
    form = NewRootCertForm()
    if request.method == 'GET':
        form.country.data = current_user.country
        form.state.data = current_user.state
        form.locality.data = current_user.locality
        form.organization.data = current_user.org_name
        form.ou_name.data = current_user.ou_name
    if form.validate_on_submit():
        ca_key = createKeyPair(TYPE_RSA, int(form.key_len.data))
        ca_req = createCertRequest(ca_key, CN=form.common_name.data, ST=form.state.data,
                                   L=form.locality.data, O=form.organization.data,
                                   OU=form.ou_name.data, emailAddress=form.email.data)

        ca_cert = crypto.X509()
        ca_cert.set_serial_number(0)
        ca_cert.set_version(2)
        ca_cert.gmtime_adj_notBefore(0)
        ca_cert.gmtime_adj_notAfter(60*60*24*365*int(form.cert_len.data))
        ca_cert.set_issuer(ca_req.get_subject())
        ca_cert.set_subject(ca_req.get_subject())
        ca_cert.set_pubkey(ca_req.get_pubkey())
        ca_cert.add_extensions([
            crypto.X509Extension(b'keyUsage', True, b'Certificate Sign, CRL Sign'),
            crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE'),
            crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=ca_cert)
        ])
        ca_cert.sign(ca_key, "sha256")

        pubkey = crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert).decode("UTF-8")
        privkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key)

        fernet_key = Fernet.generate_key()
        fernet_session = Fernet(fernet_key)
        encrypted_privkey = fernet_session.encrypt(privkey)

        final_cert = RootCertificate(name=form.common_name.data,
                                     pubkey=pubkey, privkey=encrypted_privkey)
        db.session.add(final_cert)
        db.session.commit()

        session[f'fernet_root_{final_cert.id}'] = fernet_key.decode("UTF-8")
        flash(f"Created new certificate '{form.common_name.data}'")
        return redirect(url_for('main.root_view', cert_id=final_cert.id))
    return render_template('root_new.html', form=form)

@bp.route('/root/<cert_id>')
@login_required
def root_view(cert_id):
    """
    This page displays a saved CA certificate.
    The first time after the CA certificate is generated, it will have a fernet key,
    used to decrypt it from the string in storage. This must be saved by the user
    and is only available to them once.
    """
    if session.get(f'fernet_root_{cert_id}'):
        fernet_key = session[f'fernet_root_{cert_id}']
        session[f'fernet_root_{cert_id}'] = None
    else:
        fernet_key = None

    cert = RootCertificate.query.filter_by(id=cert_id).first_or_404()
    cert_x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert.pubkey)
    return render_template('root_view.html', cert=cert, x509=cert_x509, fernet_key=fernet_key)

@bp.route('/enroll/r/<cert_id>')
def enroll_root(cert_id):
    """
    A public endpoint that provides the public key of an root CA
    without the need for a user to authenticate themselves.
    """
    cert = RootCertificate.query.filter_by(id=cert_id).first_or_404()
    cert_pubkey = cert.pubkey
    resp = Response(cert_pubkey, mimetype='application/pkix-cert')
    resp.headers['Content-Disposition'] = f'attachment;filename={cert.name}.cer'
    return resp

#endregion
#region Intermediate Certificates
@bp.route('/intermediate')
@login_required
def intermediate_list():
    """ Gathers and lists all intermediate certificates. """
    certs = IntermediateCertificate.query.all()
    return render_template('intermediate_list.html', certs=certs)

@bp.route('/intermediate/new', methods=['GET', 'POST'])
@login_required
def intermediate_new():
    """
    This form takes input to create a new certificate with a selected intermediate.
    This also requires the encryption key that was generated when the CA was made.
    """
    form = NewIntermediateCertForm()
    if request.method == 'GET':
        form.country.data = current_user.country
        form.state.data = current_user.state
        form.locality.data = current_user.locality
        form.organization.data = current_user.org_name
        form.ou_name.data = current_user.ou_name
    if form.validate_on_submit():
        ca_record = form.ca_cert.data
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_record.pubkey)
        fernet = Fernet(form.ca_passphrase.data)
        ca_privkey = fernet.decrypt(ca_record.privkey.encode())
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_privkey)
        int_key = createKeyPair(TYPE_RSA, int(form.key_len.data))
        int_req = createCertRequest(int_key, CN=form.common_name.data, ST=form.state.data,
                                    L=form.locality.data, O=form.organization.data,
                                    OU=form.ou_name.data, emailAddress=form.email.data)

        int_cert = crypto.X509()
        int_cert.set_serial_number(randint(50000000, 100000000))
        int_cert.set_version(2)
        int_cert.gmtime_adj_notBefore(0)
        int_cert.gmtime_adj_notAfter(60*60*24*365*int(form.cert_len.data))
        int_cert.set_issuer(ca_cert.get_subject())
        int_cert.set_subject(int_req.get_subject())
        int_cert.set_pubkey(int_req.get_pubkey())
        int_cert.add_extensions([
            crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=int_cert),
        ])
        if has_extension(ca_cert, 'subjectKeyIdentifier'):
            int_cert.add_extensions([
                crypto.X509Extension(b'authorityKeyIdentifier', False, b'keyid:always',
                                     issuer=ca_cert),
            ])
        int_cert.add_extensions([
            crypto.X509Extension(b'keyUsage', True, b'Certificate Sign, CRL Sign'),
            crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE, pathlen:0'),
        ])
        int_cert.sign(ca_key, "sha256")

        pubkey = crypto.dump_certificate(crypto.FILETYPE_PEM, int_cert).decode("UTF-8")
        privkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, int_key)

        fernet_key = Fernet.generate_key()
        fernet_session = Fernet(fernet_key)
        encrypted_privkey = fernet_session.encrypt(privkey)

        final_cert = IntermediateCertificate(name=form.common_name.data,
                                             pubkey=pubkey, privkey=encrypted_privkey,
                                             root=ca_record.id)
        db.session.add(final_cert)
        db.session.commit()
        flash(f"Created new certificate '{form.common_name.data}'")
        session[f'fernet_intermediate_{final_cert.id}'] = fernet_key.decode("UTF-8")
        return redirect(url_for('main.intermediate_view', cert_id=final_cert.id))
    return render_template('intermediate_new.html', form=form)

@bp.route('/intermediate/<cert_id>')
@login_required
def intermediate_view(cert_id):
    """
    This page displays a saved intermediate.
    The first time after the intermediate is generated, it will have a fernet key,
    used to decrypt it from the string in storage. This must be saved by the user
    and is only available to them once.
    """
    if session.get(f'fernet_intermediate_{cert_id}'):
        fernet_key = session[f'fernet_intermediate_{cert_id}']
        session[f'fernet_intermediate_{cert_id}'] = None
    else:
        fernet_key = None

    cert = IntermediateCertificate.query.filter_by(id=cert_id).first_or_404()
    cert_x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert.pubkey)
    return render_template('intermediate_view.html', cert=cert, x509=cert_x509,
                           fernet_key=fernet_key)

@bp.route('/enroll/i/<cert_id>')
def enroll_intermediate(cert_id):
    """
    A public endpoint that provides the public key of an intermediate
    without the need for a user to authenticate themselves.
    """
    cert = IntermediateCertificate.query.filter_by(id=cert_id).first_or_404()
    cert_pubkey = cert.pubkey
    resp = Response(cert_pubkey, mimetype='application/pkix-cert')
    resp.headers['Content-Disposition'] = f'attachment;filename={cert.name}.cer'
    return resp

#endregion

#region End User Certificates
@bp.route('/certificate')
@login_required
def certificate_list():
    """ Gathers and lists all end-user/application certificates. """
    certs = Certificate.query.all()
    return render_template('certificate_list.html', certs=certs)

@bp.route('/certificate/new', methods=['GET', 'POST'])
@login_required
def certificate_new():
    """
    This form takes input to create a new certificate with a selected intermediate.
    This also requires the encryption key that was generated when the intermediate was made.
    """
    form = NewCertForm()
    if request.method == 'GET':
        form.country.data = current_user.country
        form.state.data = current_user.state
        form.locality.data = current_user.locality
        form.organization.data = current_user.org_name
        form.ou_name.data = current_user.ou_name
    if form.validate_on_submit():
        if form.csr.data is not None:
            include_key = False
        else:
            include_key = True
        int_record = form.int_cert.data
        int_cert = crypto.load_certificate(crypto.FILETYPE_PEM, int_record.pubkey)
        fernet = Fernet(form.int_passphrase.data)
        int_privkey = fernet.decrypt(int_record.privkey.encode())
        int_key = crypto.load_privatekey(crypto.FILETYPE_PEM, int_privkey)
        if include_key:
            cert_key = createKeyPair(TYPE_RSA, int(form.key_len.data))
            cert_req = createCertRequest(cert_key, CN=form.common_name.data, ST=form.state.data,
                                         L=form.locality.data, O=form.organization.data,
                                         OU=form.ou_name.data, emailAddress=form.email.data)
        else:
            cert_req = crypto.load_certificate_request(crypto.FILETYPE_PEM, form.csr.data.encode())

        cert = crypto.X509()
        cert.set_serial_number(randint(50000000, 100000000))
        cert.set_version(2)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(60*60*24*365*int(form.cert_len.data))
        cert.set_issuer(int_cert.get_subject())
        cert.set_subject(cert_req.get_subject())
        cert.set_pubkey(cert_req.get_pubkey())
        cert.add_extensions([
            crypto.X509Extension(b'authorityKeyIdentifier', False, b'keyid:always',
                                 issuer=int_cert),
        ])
        cert.add_extensions([
            crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=cert),
        ])
        san_bytes = str.encode(f"DNS:{form.common_name.data}")
        cert.add_extensions([
            crypto.X509Extension(b'subjectAltName', False, san_bytes)
        ])
        cert.sign(int_key, "sha256")

        pubkey = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("UTF-8")
        if include_key:
            privkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, cert_key).decode("UTF-8")
        final_cert = Certificate(name=form.common_name.data,
                                 pubkey=pubkey, intermediate=int_record.id)
        db.session.add(final_cert)
        db.session.commit()
        if include_key:
            session[f'privkey_{final_cert.id}'] = privkey
        flash(f"Created new certificate '{form.common_name.data}'")
        return redirect(url_for('main.certificate_view', cert_id=final_cert.id))
    return render_template('certificate_new.html', form=form)

@bp.route('/certificate/complete', methods=['GET', 'POST'])
@login_required
def certificate_new_csr():
    """ This function accepts a standard X.509 CSR and allows the user to select an intermediate
    to sign it with. """
    form = NewCSRFulfillmentForm()
    if form.validate_on_submit():
        new_form = NewCertForm()
        req = crypto.load_certificate_request(crypto.FILETYPE_PEM, form.csr.data.encode())
        key = req.get_pubkey()
        key_type = 'RSA' if key.type() == crypto.TYPE_RSA else 'DSA'
        subject = req.get_subject()
        components = dict(subject.get_components())
        sanitized_components = {}
        for info in components:
            sanitized_components[decode_bytes(info)] = decode_bytes(components[info])

        if 'CN' in sanitized_components:
            new_form.common_name.data = sanitized_components['CN']
        if 'C' in sanitized_components:
            new_form.country.data = sanitized_components['C']
        if 'ST' in sanitized_components:
            new_form.state.data = sanitized_components['ST']
        if 'L' in sanitized_components:
            new_form.locality.data = sanitized_components['L']
        if 'O' in sanitized_components:
            new_form.organization.data = sanitized_components['O']
        if 'OU' in sanitized_components:
            new_form.ou_name.data = sanitized_components['OU']
        if 'emailAddress' in sanitized_components:
            new_form.email.data = sanitized_components['emailAddress']
        new_form.csr.data = form.csr.data
        return render_template('certificate_new_csr_verify.html', key=key, key_type=key_type,
                               subject=subject, components=components, form=new_form)
    return render_template('certificate_new_csr.html', form=form)

@bp.route('/certificate/<cert_id>')
@login_required
def certificate_view(cert_id):
    """
    This page displays information about a certificate for end-users/applications.
    If a private key for the cert ID is in the session, it will be displayed,
    allowing the user to copy it before it is removed from the session,
    as pypki will not store a private key unencrypted.
    """
    if session.get(f'privkey_{cert_id}'):
        privkey = session[f'privkey_{cert_id}']
        session[f'privkey_{cert_id}'] = None
    else:
        privkey = None

    cert = Certificate.query.filter_by(id=cert_id).first_or_404()
    cert_x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert.pubkey)
    return render_template('certificate_view.html', cert=cert, x509=cert_x509, privkey=privkey)

#endregion

#region Admin tools
@bp.route('/admin/reset')
@login_required
def reset_certs():
    """
    This function will only work in debug mode.
    It removes all certificates currently in the installation, allowing a clean experience.
    """
    if not current_app.debug:
        flash("Cannot do this outside of debug mode.")
        return redirect(url_for('main.index'))
    else:
        for cert in [RootCertificate, IntermediateCertificate, Certificate]:
            certs = cert.query.all()
            for i in certs:
                db.session.delete(i)

        db.session.commit()
        flash("Deleted!")
        return redirect(url_for('main.index'))
#endregion
