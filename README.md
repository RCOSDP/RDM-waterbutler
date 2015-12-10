<img src=/docs/waterbutler.png?raw=true" width="25%" style="float:left;">
# WaterButler

[![Documentation Status](https://readthedocs.org/projects/waterbutler/badge/?version=latest)](http://waterbutler.readthedocs.org/en/latest/?badge=latest)
[![Code Climate](https://codeclimate.com/github/CenterForOpenScience/waterbutler/badges/gpa.svg)](https://codeclimate.com/github/CenterForOpenScience/waterbutler)

`master` Build Status: [![Build Status](https://travis-ci.org/CenterForOpenScience/waterbutler.svg?branch=master)](https://travis-ci.org/CenterForOpenScience/waterbutler)

`develop` Build Status: [![Build Status](https://travis-ci.org/CenterForOpenScience/waterbutler.svg?branch=develop)](https://travis-ci.org/CenterForOpenScience/waterbutler)

Docs can be found [here](https://waterbutler.readthedocs.org/en/latest/)

### osf startup commands

```bash
invoke server
```


### startup commands

In order to run waterbutler, you must have a virtualenv created for waterbutler running python3.5.  This can be created with the following commands:

```bash
# MacOSX: Install the latest version of python3
brew install python3 
pip install virtualenv 
pip install virtualenvwrapper 
mkvirtualenv --python=python3 waterbutler
pip install -U -r requirements.txt
python setup.py develop
invoke server
```

The above code will get the virtualenv up and running for the first time.  After the initial setup, you can run waterbutler by running:

```bash
workon waterbutler
invoke server
```

### testing configuration (optional)

```bash
vim ~/.cos/waterbutler-test.json
```

waterbutler-test.json, e.g.

```json
{
  "OSFSTORAGE_PROVIDER_CONFIG": {
    "HMAC_SECRET": "changeme"
  },
  "SERVER_CONFIG": {
    "ADDRESS": "localhost",
    "PORT": 7777,
    "DOMAIN": "http://localhost:7777",
    "DEBUG": true,
    "HMAC_SECRET": "changeme"
  },
  "OSF_AUTH_CONFIG": {
      "API_URL": "http://localhost:5000/api/v1/files/auth/"
  }
}
```
