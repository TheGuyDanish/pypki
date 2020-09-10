""" Forms used in adventureguide """

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField, PasswordField
from wtforms.fields.html5 import IntegerField
from wtforms.ext.sqlalchemy.fields import QuerySelectField
from wtforms.validators import DataRequired, ValidationError, Email, NumberRange, Length
from app.models import User
from app.queries import root_choice_query, intermediate_choice_query

class EditProfileForm(FlaskForm):
    """ Form to edit a profile """
    email = StringField('Email', validators=[DataRequired(), Email()])
    title = StringField('Title', validators=[DataRequired()])
    country = StringField('Country')
    state = StringField('State or Province')
    locality = StringField('Locality')
    org_name = StringField('Organization Name')
    ou_name = StringField('Organizational Unit Name')
    submit = SubmitField('Submit')

    def __init__(self, original_email, *args, **kwargs):
        super(EditProfileForm, self).__init__(*args, **kwargs)
        self.original_email = original_email

    def validate_email(self, email):
        """ Ensure email does not already exist """
        if email.data != self.original_email:
            user = User.query.filter_by(email=self.email.data).first()
            if user is not None:
                raise ValidationError('Please use a different email')

class NewRootCertForm(FlaskForm):
    """ Form to create a new Root CA """
    common_name = StringField('Common Name', validators=[DataRequired()])
    country = StringField('Country', validators=[DataRequired(), Length(min=2, max=2)])
    state = StringField('State or Province', validators=[DataRequired()])
    locality = StringField('Locality', validators=[DataRequired()])
    organization = StringField('Organization Name', validators=[DataRequired()])
    ou_name = StringField('Organizational Unit Name', validators=[DataRequired()])
    email = StringField('Email Address', validators=[DataRequired()])
    key_len = SelectField('Private Key Length',
                          choices=[('1024', '1024'), ('2048', '2048'), ('4096', '4096')],
                          validators=[DataRequired()])
    cert_len = IntegerField('Certificate Expiry (years)', validators=[NumberRange(min=1, max=99)])
    submit = SubmitField('Submit')

class NewIntermediateCertForm(FlaskForm):
    """ Form to create a new Intermediate """
    common_name = StringField('Common Name', validators=[DataRequired()])
    country = StringField('Country', validators=[DataRequired(), Length(min=2, max=2)])
    state = StringField('State or Province', validators=[DataRequired()])
    locality = StringField('Locality', validators=[DataRequired()])
    organization = StringField('Organization Name', validators=[DataRequired()])
    ou_name = StringField('Organizational Unit Name', validators=[DataRequired()])
    email = StringField('Email Address', validators=[DataRequired()])
    key_len = SelectField('Private Key Length',
                          choices=[('1024', '1024'), ('2048', '2048'), ('4096', '4096')],
                          validators=[DataRequired()])
    cert_len = IntegerField('Certificate Expiry (years)', validators=[NumberRange(min=1, max=99)])
    ca_cert = QuerySelectField('Root CA',
                               query_factory=root_choice_query, allow_blank=False,
                               get_label='name', validators=[DataRequired()])
    ca_passphrase = PasswordField('CA Encryption Key', validators=[DataRequired()])
    submit = SubmitField('Submit')

class NewCertForm(FlaskForm):
    """ Form to create a new certificate """
    common_name = StringField('Common Name', validators=[DataRequired()])
    country = StringField('Country', validators=[DataRequired(), Length(min=2, max=2)])
    state = StringField('State or Province', validators=[DataRequired()])
    locality = StringField('Locality', validators=[DataRequired()])
    organization = StringField('Organization Name', validators=[DataRequired()])
    ou_name = StringField('Organizational Unit Name', validators=[DataRequired()])
    email = StringField('Email Address', validators=[DataRequired()])
    key_len = SelectField('Private Key Length',
                          choices=[('1024', '1024'), ('2048', '2048'), ('4096', '4096')],
                          validators=[DataRequired()])
    cert_len = IntegerField('Certificate Expiry (years)', validators=[NumberRange(min=1, max=99)])
    int_cert = QuerySelectField('Intermediate Certificate',
                                query_factory=intermediate_choice_query, allow_blank=False,
                                get_label='name', validators=[DataRequired()])
    int_passphrase = PasswordField('Intermediate Encryption Key', validators=[DataRequired()])
    submit = SubmitField('Submit')
