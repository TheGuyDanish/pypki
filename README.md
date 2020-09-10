# pypki
pypki (pronounced pyp-ki) is an open source (MIT license), Python/Flask-based utility to run an internal x.509 Public Key Infrastructure. It allows you to create new root and intermediate certificates to use in order to create (and sign) new end-user certificates to be installed into websites, applications, and the like.

pypki was developed as a hobby project with small labs and networks in mind, this means that certain features may not be secure or enterprise ready. It is not recommended to deploy pypki as your management solution in an enterprise environment unless you are able to read the code, comprehend what it does and you are 100% comfortable with every aspect of it. No support will be provided.

### Features
- Generate and store root and intermediate certificates
- Create and sign new certificates

#### In Progress:
- [View the issue tracker for the most up-to-date progress on new features](https://github.com/TheGuyDanish/pypki/issues?q=is%3Aissue+is%3Aopen)
- Encrypted private keys, unlockable via passphrase for signing operations
- Accept and sign X.509 CSR requests

### Development
pypki is being actively developed on Python 3.7.3. It uses f-strings and is therefore incompatible with Python versions prior to 3.6. Keep this in mind when setting up your dev environment.

To start developing pypki:

1. Clone this repository
```
git clone https://github.com/theguydanish/pypki
```

2. Create a new virtual environment and activate it.
```
cd pypki
python3 -m venv pk_venv
source pk_venv/bin/activate
```
3. Install the required packages.
```
pip3 install -r requirements.txt
```
4. Once the requirements are installed, copy config.example.py to config.py and change the database connection parameters to match your environment (remember that SQLAlchemy supports a wide variety of database servers, not just MySQL.)
5. After changing your database connection parameters, update the database to the latest version.
```
flask db upgrade
```
6. Once this is done, you should be able to launch the application.
```
FLASK_DEBUG=1 flask run
```

### Production Deployment
##### TODO