<img align="left" src="https://github.com/0x4D31/honeyku/blob/master/docs/honeyku-sm.png" width="250px">

Heroku-based honey{pot/token}

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

honeyku (a sister project of [honeyλ](https://www.github.com/0x4D31/honeyLambda) is a simple Heroku-based web honeypot that can be used to create and monitor fake HTTP endpoints (i.e. [honeytokens](https://www.symantec.com/connect/articles/honeytokens-other-honeypot)). 
* Slack notifications
* Email and SMS alerts
* Load config from local file or Amazon S3
* Customize the HTTP response for each token
* Designed to be deployed on Heroku Cloud Application Platform
  * Can be also set up on your own server

## Description
Honeyku allows you to create and monitor fake HTTP endpoints automatically. You can then place these URL honeytokens in e.g. your inbox, documents, browser history, or embed them as {hidden} links in your web pages. Depending on how and where you implement honeytokens, you may detect human attackers, malicious insiders, content scrapers, or bad bots.

Honeyku is designed to be deployed on Heroku cloud application platform (PaaS), but as it uses [Flask microframework](http://flask.pocoo.org/) it's not dependent to AWS API Gateway (like [honeyλ](https://www.github.com/0x4D31/honeyLambda)) or any other cloud services. So you can deploy it on your own server as well!

## Setup
* a FREE [Heroku account](https://signup.heroku.com/signup/dc).
* Install Python version 3.*
* Install Pipenv
```$ pip install pipenv``` OR ```$ brew install pipenv``` (on macOS)
* Install [Heroku Cli](https://devcenter.heroku.com/articles/getting-started-with-python#set-up):
* Clone the app source-code
```$ git clone https://github.com/0x4D31/honeyku```
```$ cd honeyku```
* Edit `config.json` and fill in your Slack Webhook URL. Change the trap/token configs as you need.
* You can customize the HTTP response for each token/trap
  * For example you can return a 1x1px beacon image in response and embed the token in your decoy documents or email (tracking pixel!)

## Deploy
* Deploy the app
```$ heroku login```
```$ heroku create```
```$ git push heroku master```
* Ensure the app is running
```$ heroku ps```
```$ heroku open```


Output:

```
$ git push heroku master
Counting objects: 3, done.
Delta compression using up to 12 threads.
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 287 bytes | 287.00 KiB/s, done.
Total 3 (delta 2), reused 0 (delta 0)
remote: Compressing source files... done.
remote: Building source:
remote: 
remote: -----> Python app detected
remote:  !     The latest version of Python 3.6 is python-3.6.6 (you are using python-3.7.0, which is unsupported).
remote:  !     We recommend upgrading by specifying the latest version (python-3.6.6).
remote:        Learn More: https://devcenter.heroku.com/articles/python-runtimes
remote:        Skipping installation, as Pipfile.lock hasn't changed since last deploy.
remote: -----> Discovering process types
remote:        Procfile declares types -> web
remote: 
remote: -----> Compressing...
remote:        Done: 55.4M
remote: -----> Launching...
remote:        Released v18
remote:        https://still-chamber-36399.herokuapp.com/ deployed to Heroku
remote: 
remote: Verifying deploy... done.
To https://git.heroku.com/still-chamber-36399.git
   f1414c4..c02b5e3  master -> master
```

## Usage
![honeyku](https://github.com/0x4D31/honeyku/blob/master/docs/example1.png)

![honeyku](https://github.com/0x4D31/honeyku/blob/master/docs/example2.png)

## Slack Alert
![slack](https://github.com/0x4D31/honeyku/blob/master/docs/slack-alert.png)

## TODO
- [ ] Remote config: load config from Amazon S3
- [ ] Check the source IP address against Threat Intelligence feeds (e.g. Cymon API)
- [ ] SMS alert ([Twilio](https://twilio.com))
- [ ] Logging: Support HTTP endpoint
