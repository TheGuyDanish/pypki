""" The main logic and routes for servervault """
from datetime import datetime
from flask import render_template, flash, redirect, url_for, request, current_app, session
from flask_login import current_user, login_user, logout_user, login_required
from OpenSSL import crypto
from random import randint
from sqlalchemy import desc
from werkzeug.urls import url_parse
from app import db
from app.certgen import createCertificate, createKeyPair, createCertRequest, TYPE_RSA
from app.main import bp
from app.main.forms import EditProfileForm, NewRootCertForm, NewIntermediateCertForm, NewCertForm
from app.models import User, RootCertificate, IntermediateCertificate, Certificate

#region Jinja Filters
@bp.context_processor
def inject_version():
    return dict(version=current_app.config['APP_VERSION'])

@bp.app_template_filter('asn1_to_datetime')
def asn1_to_datetime(timestamp):
    if type(timestamp) == bytes:
        timestamp = timestamp.decode("UTF-8")
    else:
        timestamp = str(timestamp)

    time_object = datetime.strptime(timestamp, '%Y%m%d%H%M%S%z')
    return time_object.isoformat()

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
    form = EditProfileForm(current_user.email)
    if form.validate_on_submit():
        current_user.email = form.email.data
        current_user.title = form.title.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('main.user', username=current_user.username))
    elif request.method == 'GET':
        form.email.data = current_user.email
        form.title.data = current_user.title
    return render_template('edit_profile.html', title='Edit Profile',
                           form=form)

@bp.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('user.html', user=user)
#endregion

#region Root Certificates
@bp.route('/root')
@login_required
def root_list():
    certs = RootCertificate.query.all()
    return render_template('root_list.html', certs=certs)

@bp.route('/root/new', methods=['GET', 'POST'])
@login_required
def root_new():
    form = NewRootCertForm()
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
        privkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key).decode("UTF-8")
        final_cert = RootCertificate(name=form.common_name.data,
                                     pubkey=pubkey, privkey=privkey)
        db.session.add(final_cert)
        db.session.commit()
        flash(f"Created new certificate '{form.common_name.data}'")
        return redirect(url_for('main.root_view', cert_id=final_cert.id))
    return render_template('root_new.html', form=form)

@bp.route('/root/<cert_id>')
@login_required
def root_view(cert_id):
    cert = RootCertificate.query.filter_by(id=cert_id).first_or_404()
    cert_x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert.pubkey)
    return render_template('root_view.html', cert=cert, x509=cert_x509)

#endregion
#region Intermediate Certificates
@bp.route('/intermediate')
@login_required
def intermediate_list():
    certs = IntermediateCertificate.query.all()
    return render_template('intermediate_list.html', certs=certs)

@bp.route('/intermediate/new', methods=['GET', 'POST'])
@login_required
def intermediate_new():
    form = NewIntermediateCertForm()
    if form.validate_on_submit():
        ca_record = form.ca_cert.data
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_record.pubkey)
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_record.privkey)
        int_key = createKeyPair(TYPE_RSA, int(form.key_len.data))
        int_req = createCertRequest(int_key, CN=form.common_name.data, ST=form.state.data,
                                   L=form.locality.data, O=form.organization.data,
                                   OU=form.ou_name.data, emailAddress=form.email.data)

        int_cert = crypto.X509()
        int_cert.set_serial_number(randint(50000000,100000000))
        int_cert.set_version(2)
        int_cert.gmtime_adj_notBefore(0)
        int_cert.gmtime_adj_notAfter(60*60*24*365*int(form.cert_len.data))
        int_cert.set_issuer(ca_cert.get_subject())
        int_cert.set_subject(int_req.get_subject())
        int_cert.set_pubkey(int_req.get_pubkey())
        int_cert.add_extensions([
            crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=int_cert),
        ])
        int_cert.add_extensions([
            crypto.X509Extension(b'authorityKeyIdentifier', False, b'keyid:always', issuer=ca_cert),
        ])
        int_cert.add_extensions([
            crypto.X509Extension(b'keyUsage', True, b'Certificate Sign, CRL Sign'),
            crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE, pathlen:0'),
        ])
        int_cert.sign(ca_key, "sha256")

        pubkey = crypto.dump_certificate(crypto.FILETYPE_PEM, int_cert).decode("UTF-8")
        privkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, int_key).decode("UTF-8")
        final_cert = IntermediateCertificate(name=form.common_name.data,
                                             pubkey=pubkey, privkey=privkey,
                                             root=ca_record.id)
        db.session.add(final_cert)
        db.session.commit()
        flash(f"Created new certificate '{form.common_name.data}'")
        return redirect(url_for('main.intermediate_view', cert_id=final_cert.id))
    return render_template('intermediate_new.html', form=form)

@bp.route('/intermediate/<cert_id>')
@login_required
def intermediate_view(cert_id):
    cert = IntermediateCertificate.query.filter_by(id=cert_id).first_or_404()
    cert_x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert.pubkey)
    return render_template('intermediate_view.html', cert=cert, x509=cert_x509)

#endregion

#region End User Certificates
@bp.route('/certificate')
@login_required
def certificate_list():
    certs = Certificate.query.all()
    return render_template('certificate_list.html', certs=certs)

@bp.route('/certificate/new', methods=['GET', 'POST'])
@login_required
def certificate_new():
    form = NewCertForm()
    if form.validate_on_submit():
        int_record = form.int_cert.data
        int_cert = crypto.load_certificate(crypto.FILETYPE_PEM, int_record.pubkey)
        int_key = crypto.load_privatekey(crypto.FILETYPE_PEM, int_record.privkey)
        cert_key = createKeyPair(TYPE_RSA, int(form.key_len.data))
        cert_req = createCertRequest(cert_key, CN=form.common_name.data, ST=form.state.data,
                                   L=form.locality.data, O=form.organization.data,
                                   OU=form.ou_name.data, emailAddress=form.email.data)

        cert = crypto.X509()
        cert.set_serial_number(randint(50000000,100000000))
        cert.set_version(2)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(60*60*24*365*int(form.cert_len.data))
        cert.set_issuer(int_cert.get_subject())
        cert.set_subject(cert_req.get_subject())
        cert.set_pubkey(cert_req.get_pubkey())
        cert.add_extensions([
            crypto.X509Extension(b'authorityKeyIdentifier', False, b'keyid:always', issuer=int_cert),
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
        privkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, cert_key).decode("UTF-8")
        final_cert = Certificate(name=form.common_name.data,
                                 pubkey=pubkey, privkey=privkey,
                                 intermediate=int_record.id)
        db.session.add(final_cert)
        db.session.commit()
        session[f'privkey_{final_cert.id}'] = privkey
        flash(f"Created new certificate '{form.common_name.data}'")
        return redirect(url_for('main.certificate_view', cert_id=final_cert.id))
    return render_template('certificate_new.html', form=form)

@bp.route('/certificate/<cert_id>')
@login_required
def certificate_view(cert_id, **extra):
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
    if not current_app.debug:
        flash("Cannot do this outside of debug mode.")
        return redirect(url_for('main.index'))
    else:
        for c in [RootCertificate, IntermediateCertificate, Certificate]:
            certs = c.query.all()
            for i in certs:
                db.session.delete(i)

        db.session.commit()
        flash("Deleted!")
        return redirect(url_for('main.index'))
#endregion
