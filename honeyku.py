#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2017  Adel "0x4D31" Karimi
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from flask import Flask, request, render_template, send_file
import logging
import sys
import os
import json
import time
import urllib.request
import urllib.error
import smtplib
import base64

__author__ = 'Adel "0x4d31" Karimi'
__version__ = '0.1'

# Log to stdout
# On Heroku, anything written to stdout or stderr is captured into your logs.
# https://devcenter.heroku.com/articles/logging
logger = logging.getLogger(__name__)
out_hdlr = logging.StreamHandler(sys.stdout)
out_hdlr.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
out_hdlr.setLevel(logging.INFO)
logger.addHandler(out_hdlr)
logger.setLevel(logging.INFO)

app = Flask(__name__)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
	# Load the config file
	config=load_config()
	# Honeytoken alerts
	if request.path in config['traps'] and request.path != "/favicon.ico":
		# Preparing the alert message
		alertMessage = alert_msg(request, config)
		# Slack alert
		if config['alert']['slack']['enabled'] == "true":
			WEBHOOK_URL = config['alert']['slack']['webhook-url']
			slack_alerter(alertMessage, WEBHOOK_URL)
		# Email alert
		if config['alert']['email']['enabled'] == "true":
			email_alerter(alertMessage, config)
		# SMS alert
		#TODO: Complete and test the SMS alert
		#if config['alert']['sms']['enabled'] == "true":
		#	sms_alerter(alertMessage, config)
		#TODO: HTTP Endpoint Support
	# Honeypot event logs
	if request.headers.getlist("X-Forwarded-For"):
		source_ip = request.headers.getlist("X-Forwarded-For")[0]
	else:
		source_ip = request.remote_addr
	logger.info('{{"sourceip":"{}","host":"{}","request":"{}","http_method":"{}","body":"{}","user_agent":"{}"}}'.format(
		source_ip, request.url_root, request.full_path, request.method, request.data, request.user_agent.string))
	# Prepare and send the custom HTTP response
	contype, body = generate_http_response(request, config)
	# Customize the response using a template (in case you want to return a dynamic response, etc.)
	# You can comment the next 2 lines if you don't want to use this. /Just an example/
	if body == "custom.html":
		return (render_template(body, browser = request.user_agent.browser, ua = request.user_agent.string))
	return (send_file(body, mimetype=contype) if "image" in contype else render_template(body))


def load_config():
	""" Load the configuration from local file or Amazon S3 """

	# Check the environment variable for config type (local/s3)
	CONFIGFILE = os.environ.get('configFile')
	# Load config from S3
	if CONFIGFILE == "s3":
		BUCKET = os.environ.get('s3Bucket')
		KEY = os.environ.get('s3Key')
		#TODO: Add S3 support
	elif CONFIGFILE == "local":
		# Load config from the local file
		with open('config.json') as config_file:
			conf = json.load(config_file)
			logger.info("Local config file loaded")

	return conf


def generate_http_response(req, conf):
	""" Generate HTTP response """

	args = ["{}={}".format(key, value) for key, value in request.args.items()]
	path = req.path
	con_type = None
	body_path = None
	if path in conf['traps']:
		# Check if the token is defined and has a custom http response
		for token in args:
			if (token in conf['traps'][path]) and ("token-response" in conf['traps'][path][token]):
				con_type = conf['traps'][path][token]['token-response']['content-type']
				body_path = conf['traps'][path][token]['token-response']['body']
		# if the 'body_path' is still empty, use the trap/uri response (if there's any)
		if ("trap-response" in conf['traps'][path]) and body_path is None:
			con_type = conf['traps'][path]['trap-response']['content-type']
			body_path = conf['traps'][path]['trap-response']['body']
	# Load the default HTTP response if the 'body_path' is None
	if body_path is None:
		con_type = conf['default-http-response']['content-type']
		body_path = conf['default-http-response']['body']

	return con_type, body_path


def alert_msg(req, conf):
	""" Prepare alert message dictionary """

	# Message fields
	url_root = req.url_root
	full_path = req.full_path
	path = req.path
	data = req.data
	http_method = req.method
	useragent_str = req.user_agent.string
	browser = req.user_agent.browser
	browser_version = req.user_agent.version
	browser_lang = req.user_agent.language
	platform = req.user_agent.platform
	headers = "{}".format(req.headers)
	args = ["{}={}".format(key, value) for key, value in request.args.items()]
	# X-Forwarded-For: the originating IP address of the client connecting to the Heroku router
	if req.headers.getlist("X-Forwarded-For"):
		source_ip = req.headers.getlist("X-Forwarded-For")[0]
	else:
		source_ip = req.remote_addr

	# Search the config for the token note
	note = None
	if path in conf['traps']:
		# Check if the token is defined and has note
		for token in args:
			if (token in conf['traps'][path]) and ("token-note" in conf['traps'][path][token]):
				note = conf['traps'][path][token]['token-note']
		# If the 'note' is still empty, use the trap/uri note (if there's any)
		if ("trap-note" in conf['traps'][path]) and note is None:
			note = conf['traps'][path]['trap-note']

	#TODO: Threat Intel Lookup (Cymon v2)

	# Message dictionary
	msg = {
		"token-note": note if note else "None",
		"host": url_root,
		"path": full_path if full_path else "None",
		"http-method": http_method,
		"token": args[0] if args else "None", #Only the first arg
		"body": data if data else "None",
		"source-ip": source_ip,
		"user-agent": useragent_str,
		"browser": browser if browser else "None",
		"browser_version": browser_version if browser_version else "None",
		"browser_lang": browser_lang if browser_lang else "None",
		"platform": platform if platform else "None",
		"http-headers": headers
		#"threat-intel": threat_intel
	}

	return msg


def email_alerter(msg, conf):
	""" Send Email alert """

	smtp_server = conf['alert']['email']['smtp_server']
	smtp_port = conf['alert']['email']['smtp_port']
	smtp_user = conf['alert']['email']['smtp_user']
	smtp_password = conf['alert']['email']['smtp_password']
	to_email = conf['alert']['email']['to_email']
	subject = 'Honeyku Alert'
	now = time.strftime('%a, %d %b %Y %H:%M:%S %Z', time.localtime())
	body = ("Honeytoken triggered!\n\n"
			"Time: {}\n"
			"Source IP: {}\n"
			#"Threat Intel Report: {}\n"
			"User-Agent: {}\n"
			"Token Note: {}\n"
			"Token: {}\n"
			"Path: {}\n"
			"Host: {}").format(
		now,
		msg['source-ip'],
		#msg['threat-intel'] if msg['threat-intel'] else "None",
		msg['user-agent'],
		msg['token-note'],
		msg['token'],
		msg['path'],
		msg['host'])
	email_text = "From: {}\nTo: {}\nSubject: {}\n\n{}".format(
		smtp_user,
		", ".join(to_email),
		subject,
		body)

	try:
		server = smtplib.SMTP(smtp_server, smtp_port)
		server.ehlo()
		server.starttls()
		server.login(smtp_user, smtp_password)
		server.sendmail(smtp_user, to_email, email_text)
		server.close()
		logger.info("Email alert is sent")
	except smtplib.SMTPException as err:
		logger.error("Error sending email: {}".format(err))


def sms_alerter(msg, conf):
	""" Send SMS alert """
	#TODO: Complete and test the SMS Alert


def slack_alerter(msg, webhook_url):
	""" Send Slack alert """

	now = time.strftime('%a, %d %b %Y %H:%M:%S %Z', time.localtime())
	# Preparing Slack message
	slack_message = {
		"text": "*Honeytoken triggered!*\nA honeytoken has been triggered by {}".format(msg['source-ip']),
		"username": "honeyku",
		"icon_emoji": ":ghost:",
		"attachments": [
			{
				"color": "danger",
				# "title": "Alert details",
				"text": "Alert details:",
				"footer": "honeyku",
				"footer_icon": "https://raw.githubusercontent.com/0x4D31/honeyLambda/master/docs/slack-footer.png",
				"fields": [
					{
						"title": "Time",
						"value": now,
						"short": "true"
					},
					{
						"title": "Source IP Address",
						"value": msg['source-ip'],
						"short": "true"
					},
					#{
					#	"title": "Threat Intel Report",
					#	"value": msg['threat-intel'] if msg['threat-intel'] else "None",
					#},
					{
						"title": "Token",
						"value": msg['token'],
						"short": "true"
					},
					{
						"title": "Token Note",
						"value": msg['token-note'],
						"short": "true"
					},
					{
						"title": "Host",
						"value": msg['host'],
						"short": "true"
					},
					{
						"title": "Path",
						"value": msg['path'],
						"short": "true"
					},
					{
						"title": "Browser",
						"value": msg['browser'],
						"short": "true"
					},
					{
						"title": "Browser Version",
						"value": msg['browser_version'],
						"short": "true"
					},
					{
						"title": "Platform",
						"value": msg['platform'],
						"short": "true"
					},
					{
						"title": "HTTP Method",
						"value": msg['http-method'],
						"short": "true"
					},
					{
						"title": "User-Agent",
						"value": msg['user-agent']
					}
					#{
					#	"title": "HTTP Headers",
					#	"value": msg['http-headers']
					#}
				]
			}
		]
	}

	# Sending Slack message
	req = urllib.request.Request(webhook_url, data=json.dumps(slack_message).encode('utf8'))

	try:
		resp = urllib.request.urlopen(req)
		logger.info("Slack alert is sent")
	except urllib.error.HTTPError as err:
		logger.error("Request failed: {} {}".format(err.code, err.reason))
	except urllib.error.URLError as err:
		logger.error("Connection failed: {}".format(err.reason))

	return


if __name__ == '__main__':
	app.run(debug=False, use_reloader=True)
