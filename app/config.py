import os
basedir = os.path.abspath(os.path.dirname(__file__))
print(os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db'))
class Config(object):
    SECRET_KEY = 'what the password'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
