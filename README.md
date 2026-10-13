<img src="/docs/waterbutler.png?raw=true" width="25%" style="float:left;">

# GakuNin RDM WaterButler

### GakuNin RDM WaterButler is developed by forking [CenterForOpenScience/waterbutler](https://github.com/CenterForOpenScience/waterbutler)


[![Documentation Status](https://readthedocs.org/projects/waterbutler/badge/?version=latest)](http://waterbutler.readthedocs.org/en/latest/?badge=latest)
[![Code Climate](https://codeclimate.com/github/CenterForOpenScience/waterbutler/badges/gpa.svg)](https://codeclimate.com/github/CenterForOpenScience/waterbutler)

`master` Build Status: [![Build Status](https://travis-ci.org/RCOSDP/RDM-waterbutler.svg?branch=master)](https://travis-ci.org/RCOSDP/master)

`develop` Build Status: [![Build Status](https://travis-ci.org/RCOSDP/RDM-waterbutler.svg?branch=develop)](https://travis-ci.org/RCOSDP/develop)

`nii-mergework-201802` Build Status: [![Build Status](https://travis-ci.org/RCOSDP/RDM-waterbutler.svg?branch=nii-mergework-201802)](https://travis-ci.org/RCOSDP/RDM-waterbutler)

`master`[![Coverage Status](https://coveralls.io/repos/github/RCOSDP/RDM-waterbutler/badge.svg?branch=master)](https://coveralls.io/github/RCOSDP/RDM-waterbutler?branch=master)

`develop`[![Coverage Status](https://coveralls.io/repos/github/RCOSDP/RDM-waterbutler/badge.svg?branch=develop)](https://coveralls.io/github/RCOSDP/RDM-waterbutler?branch=develop)

`nii-mergework-201802`[![Coverage Status](https://coveralls.io/repos/github/RCOSDP/RDM-waterbutler/badge.svg?branch=nii-mergework-201802)](https://coveralls.io/github/RCOSDP/RDM-waterbutler?branch=nii-mergework-201802)

### Compatibility

WaterButler is compatible with Python 3.13.

### Documentation

Documentation available at https://waterbutler.readthedocs.io/en/latest/

### Setting up

WaterButler uses [Poetry](https://python-poetry.org/) to manage its dependencies. With Python 3.13 and
Poetry installed, run the following in your checkout:

```bash
poetry install
poetry run invoke server
```

Poetry creates and manages a virtual environment for the project. To run commands inside it without
the `poetry run` prefix, use `poetry shell` or activate the environment reported by `poetry env info`.

Some tasks also require a running celery worker.  You will need to install `rabbitmq` and run a server:

```bash
brew install rabbitmq
# on Ubuntu:
# apt-get install rabbitmq-server
rabbitmq-server
```

Then in your WaterButler virtualenv:

```bash
invoke celery
```

### Configuring

WaterButler configuration is done through a JSON file (`waterbutler-test.json`) that lives in the `.cos` directory of your home directory.  If this is your first time setting up WaterButler or its sister project, [MFR](https://github.com/CenterForOpenScience/modular-file-renderer/), you probably do not have this directory and will need to create it:

```bash
mkdir ~/.cos
```

The data in `waterbutler-test.json` is used by the many Django-style `settings.py` files sprinkled about.  Most of these files define a top-level key that its specific configuration should be listed under.  For instance, if you wanted your local WaterButler server to listen on port 8989 instead of the default 7777, you would check the settings file for `waterbutler.server`.  That file looks for `HOST` and `DOMAIN` configuration keys under the `SERVER_CONFIG` top-level key.  Your configuration file would need to be updated to look like this:

```json
{
  "SERVER_CONFIG": {
    "PORT": 8989,
    "DOMAIN": "http://localhost:8989"
  }
}
```

If you then wanted to update the GitHub commit message WaterButler submits when deleting files, you would look in `waterbutler.providers.github.settings`. The `DELETE_FILE_MESSAGE` parameter should come under the `GITHUB_PROVIDER_CONFIG` key:

```json
{
  "SERVER_CONFIG": {
    "PORT": 8989,
    "DOMAIN": "http://localhost:8989"
  },
  "GITHUB_PROVIDER_CONFIG": {
    "DELETE_FILE_MESSAGE": "WaterButler deleted this. You're welcome."
  }
}
```

### Testing

Before running the tests, you will need to install some additional requirements. In your checkout, run:

```bash
poetry install --with dev
poetry run invoke test
```

### License

Copyright 2013-2018 Center for Open Science

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

### COS is hiring!

Want to help save science? Want to get paid to develop free, open source software? [Check out our openings!](https://cos.io/our-communities/jobs/)
