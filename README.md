# About
The **trade_journal** app is a tool that allows a stock/options trader to effectively catalog and track investments
across multiple accounts and/or trading strategies.

# Prerequisites
* Python 3
* (see [requirements.txt]() for dependencies)
##   

# Installation
This app was written for python 3.7
Recommend running in a virtual environment:

```bash
$ python3 -m venv venv
```

Install required packages:
```bash
$ (venv) pip install -r requirements.txt
```

Set up ENV vars (the `flask` command requires this):
```bash
$ FLASK_APP=journal.py
```
or
```powershell
# Windows CMD
C:\> set FLASK_APP="journal.py"

# Windows PowerShell
PS C:\> $env:FLASK_APP="journal.py"
```

Initialize the local sqlite database:

```bash
$ (venv) flask db init
```

Make sure the db schema is up to date:

```bash
$ (venv) flask db upgrade
```

Seed the database with some initial values *(This needs some fixing)*:

```bash
$ (venv) python3 utils/db_bootstrap.py
```

Run the app:
```bash
$ (venv) flask run
```

Open a browser to http://127.0.0.1:5000/ to load the app. Currently, the seeded data will show under the [Journal](http://127.0.0.1:5000/journal) link.