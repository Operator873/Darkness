import requests
import sqlite3
import json
import re
from requests_oauthlib import OAuth1
from sopel import module

DARKNESS_DB = "/home/ubuntu/.sopel/modules/dark.db"

def xmit(site, creds, payload, method):
	# This handles the post/get requests
	AUTH = OAuth1(creds[1], creds[2], creds[3], creds[4])
		
	if method is "post":
		return requests.post(site, data=payload, auth=AUTH).json()
	elif method is "get":
		return requests.get(site, params=payload, auth=AUTH).json()

def getWiki(project):
	# Define dbase connection
	db = sqlite3.connect(DARKNESS_DB)
	c = db.cursor()
	
	site = c.execute('''SELECT apiurl FROM wikis WHERE wiki="%s";''' % project).fetchone()[0]
	
	db.close()
	
	if site is None:
		return None
	else:
		return site

def getCSRF(bot, site, creds, type):
	reqtoken = {
		'action':"query",
		'meta':"tokens",
		'format':"json",
		'type':type
	}
	
	token = xmit(site, creds, reqtoken, "get")
	
	# Check for errors and return csrf
	if 'error' in token:
		bot.say(token['error']['info'])
		return False
	else:
		csrfToken = token['query']['tokens']['%stoken' % type]
		return csrfToken

def doEdit(bot, name, project, edit):
	# Setup dbase connection
	db = sqlite3.connect(DARKNESS_DB)
	c = db.cursor()
	
	# Get user credentials and prepare api url for use
	creds = c.execute('''SELECT * from auth where account="%s";''' % name).fetchall()[0]
			
	db.close()
   
	if len(creds) == 0:
		bot.say(name + ", you are not configured. Contact Operator873.")
		return
   
	site = getWiki(project)
	
	if site is None:
		bot.say("I don't know that wiki.")
		return
	
	csrfToken = getCSRF(bot, site, creds, "csrf")
	
	if csrfToken is False:
		return
	
	reqEdit = {
		'action':"edit",
		'format':"json",
		'title':"User:Operator873/sandbox",
		'section':"new",
		'sectiontitle':"New Test",
		'text':edit,
		'summary':"This is a test edit",
		'minor':"true",
		'redirect':"true",
		'token':csrfToken
	}
	
	# send to xmit
	edit = xmit(site, creds, reqEdit, "post")
	
	# Check for success
	if 'edit' in edit:
		bot.say("Success! Edit was made to " + edit['edit']['title'])
	elif 'error' in edit:
		reason = edit['error']['info']
		if reason == "Invalid CSRF token.":
			bot.say("Received CSRF token error. Try again...")
		else:
			bot.say(reason)
	else:
		bot.say("Unknown error!: " + edit)

def doBlock(bot, name, project, target, until, reason):
	# Setup dbase connection
	db = sqlite3.connect(DARKNESS_DB)
	c = db.cursor()
	
	# Get user credentials and prepare api url for use
	creds = c.execute('''SELECT * from auth where account="%s";''' % name).fetchall()[0]
			
	db.close()
	
	if len(creds) == 0:
		bot.say(name + ", you are not configured. Contact Operator873.")
		return
	
	site = getWiki(project)
	
	if site is None:
		bot.say("I don't know that wiki.")
		return
	
	csrfToken = getCSRF(bot, site, creds, "csrf")
	
	if csrfToken is False:
		return
		
	reqBlock = {
		"action": "block",
		"user": target,
		"expiry": until,
		"reason": reason,
		"token": csrfToken,
		"allowusertalk":"",
		"nocreate":"",
		"autoblock":"",
		"format": "json"
	}
	
	# Send block request
	block = xmit(site, creds, reqBlock, "post")
		
	if 'error' in block:
		reason = block['error']['code']
		if reason == "badtoken":
			bot.say("Received CSRF token error. Try again...")
		elif reason == "alreadyblocked":
			bot.say(target + " is already blocked. Use !reblock to change the current block.")
		elif reason == "permissiondenied":
			bot.say("Received permission denied error. Are you a sysop on " + project + "?")
		elif reason == "invalidexpiry":
			bot.say("The expiration time isn't valid. I understand things like 31hours, 1week, 6months, infinite, indefinite.")
		else:
			info = block['error']['info']
			code = block['error']['code']
			bot.say("Unhandled error: " + code + " " + info)
	elif 'block' in block:
		user = block['block']['user']
		expiry = block['block']['expiry']
		reason = block['block']['reason']
		bot.say(user + " was blocked until " + expiry + " with reason: " + reason)
	else:
		bot.say("Unknown error: " + block)

def doReblock(bot, name, project, target, until, reason):
	# Setup dbase connection
	db = sqlite3.connect(DARKNESS_DB)
	c = db.cursor()
	
	# Get user credentials and prepare api url for use
	creds = c.execute('''SELECT * from auth where account="%s";''' % name).fetchall()[0]
			
	db.close()
	
	if len(creds) == 0:
		bot.say(name + ", you are not configured. Contact Operator873.")
		return
	
	site = getWiki(project)
	
	if site is None:
		bot.say("I don't know that wiki.")
		return
	
	csrfToken = getCSRF(bot, site, creds, "csrf")
	
	if csrfToken is False:
		return
		
	reqBlock = {
		"action": "block",
		"user": target,
		"expiry": until,
		"reason": reason,
		"token": csrfToken,
		"allowusertalk":"",
		"nocreate":"",
		"autoblock":"",
		"reblock":"",
		"autoblock":"",
		"format": "json"
	}
	
	# Send block request
	block = xmit(site, creds, reqBlock, "post")
		
	if 'error' in block:
		reason = block['error']['code']
		if reason == "badtoken":
			bot.say("Received CSRF token error. Try again...")
		elif reason == "alreadyblocked":
			bot.say(target + " is already blocked. Use !reblock to change the current block.")
		elif reason == "permissiondenied":
			bot.say("Received permission denied error. Are you a sysop on " + project + "?")
		else:
			info = block['error']['info']
			bot.say("Unhandled error: " + info)
	elif 'block' in block:
		user = block['block']['user']
		expiry = block['block']['expiry']
		reason = block['block']['reason']
		bot.say(user + " was blocked until " + expiry + " with reason: " + reason)
	else:
		bot.say("Unknown error: " + block)

def doGlobalblock(bot, name, target, until, reason):
	# Setup dbase connection
	db = sqlite3.connect(DARKNESS_DB)
	c = db.cursor()
	
	# Get user credentials and prepare api url for use
	creds = c.execute('''SELECT * from auth where account="%s";''' % name).fetchall()[0]
			
	db.close()
	
	if len(creds) == 0:
		bot.say(name + ", you are not configured. Contact Operator873.")
		return
	
	site = getWiki("metawiki")
	
	if site is None:
		bot.say("I don't know that wiki.")
		return
	
	csrfToken = getCSRF(bot, site, creds, "csrf")
	
	if csrfToken is False:
		return
		
	block = {
			"action": "globalblock",
			"format": "json",
			"target": target,
			"expiry": until,
			"reason": reason,
			"alsolocal": True,
			"token": csrfToken
		}
	
	# Send block request
	gblock = xmit(site, creds, block, "post")
	
	if 'error' in gblock:
		failure = gblock['error']['info']
		bot.say("Block failed! " + failure)
	elif 'block' in gblock or 'globalblock' in gblock:
		user = gblock['globalblock']['user']
		expiry = gblock['globalblock']['expiry']
		bot.say("Block succeeded. " + user + " was blocked until " + expiry)
	else:
		bot.say("Unknown failure... " + gblock)

def doLock(bot, name, target, reason):
	# Setup dbase connection
	db = sqlite3.connect(DARKNESS_DB)
	c = db.cursor()
	
	# Get user credentials and prepare api url for use
	creds = c.execute('''SELECT * from auth where account="%s";''' % name).fetchall()[0]
			
	db.close()
	
	if len(creds) == 0:
		bot.say(name + ", you are not configured. Contact Operator873.")
		return
	
	site = getWiki("metawiki")
	
	if site is None:
		bot.say("I don't know that wiki.")
		return
	
	csrfToken = getCSRF(bot, site, creds, "setglobalaccountstatus")
	
	if csrfToken is False:
		return
		
	lockRequest = {
		"action":"setglobalaccountstatus",
		"format":"json",
		"user":target,
		"locked":"lock",
		"reason":reason,
		"token":csrfToken
	}
	
	# Send block request
	lock = xmit(site, creds, lockRequest, "post")
	
	if 'error' in lock:
		bot.say("lock failed! " + lock['error']['info'])
	else:
		bot.say("Lock succeeded. ")

def dorevokeTPA(bot, name, project, target, until, reason):
	# Setup dbase connection
	db = sqlite3.connect(DARKNESS_DB)
	c = db.cursor()
	
	# Get user credentials and prepare api url for use
	creds = c.execute('''SELECT * from auth where account="%s";''' % name).fetchall()[0]
			
	db.close()
	
	if len(creds) == 0:
		bot.say(name + ", you are not configured. Contact Operator873.")
		return
	
	site = getWiki(project)
	
	if site is None:
		bot.say("I don't know that wiki.")
		return
	
	csrfToken = getCSRF(bot, site, creds, "csrf")
	
	if csrfToken is False:
		return
		
	reqBlock = {
		"action": "block",
		"user": target,
		"expiry": until,
		"reason": reason,
		"token": csrfToken,
		"noemail":"",
		"nocreate":"",
		"reblock":"",
		"autoblock":"",
		"format": "json"
	}
	
	# Send block request
	block = xmit(site, creds, reqBlock, "post")
		
	if 'error' in block:
		reason = block['error']['code']
		if reason == "badtoken":
			bot.say("Received CSRF token error. Try again...")
		elif reason == "alreadyblocked":
			bot.say(target + " is already blocked. Use !reblock to change the current block.")
		elif reason == "permissiondenied":
			bot.say("Received permission denied error. Are you a sysop on " + project + "?")
		else:
			info = block['error']['info']
			bot.say("Unhandled error: " + info)
	elif 'block' in block:
		user = block['block']['user']
		expiry = block['block']['expiry']
		reason = block['block']['reason']
		bot.say(user + " was blocked until " + expiry + " with reason: " + reason)
	else:
		bot.say("Unknown error: " + block)

def doltaBlock(bot, name, project, target):
	# Setup dbase connection
	db = sqlite3.connect(DARKNESS_DB)
	c = db.cursor()
	
	# Get user credentials and prepare api url for use
	creds = c.execute('''SELECT * from auth where account="%s";''' % name).fetchall()[0]
			
	db.close()
	
	if len(creds) == 0:
		bot.say(name + ", you are not configured. Contact Operator873.")
		return
	
	site = getWiki(project)
	
	if site is None:
		bot.say("I don't know that wiki.")
		return
	
	csrfToken = getCSRF(bot, site, creds, "csrf")
	
	if csrfToken is False:
		return
		
	reqBlock = {
		"action": "block",
		"user": target,
		"expiry": "1week",
		"reason": "[[Wikipedia:Blocks and bans#Evasion|Block evasion]]",
		"token": csrfToken,
		"noemail":"",
		"nocreate":"",
		"reblock":"",
		"autoblock":"",
		"format": "json"
	}
	
	# Send block request
	block = xmit(site, creds, reqBlock, "post")
		
	if 'error' in block:
		reason = block['error']['code']
		if reason == "badtoken":
			bot.say("Received CSRF token error. Try again...")
		elif reason == "alreadyblocked":
			bot.say(target + " is already blocked. Use !reblock to change the current block.")
		elif reason == "permissiondenied":
			bot.say("Received permission denied error. Are you a sysop on " + project + "?")
		else:
			info = block['error']['info']
			bot.say("Unhandled error: " + info)
	elif 'block' in block:
		user = block['block']['user']
		expiry = block['block']['expiry']
		reason = block['block']['reason']
		bot.say(user + " was blocked until " + expiry + " with reason: " + reason)
	else:
		bot.say("Unknown error: " + block)

def doSoftblock(bot, name, project, target, until, reason):
	# Setup dbase connection
	db = sqlite3.connect(DARKNESS_DB)
	c = db.cursor()
	
	# Get user credentials and prepare api url for use
	creds = c.execute('''SELECT * from auth where account="%s";''' % name).fetchall()[0]
			
	db.close()
	
	if len(creds) == 0:
		bot.say(name + ", you are not configured. Contact Operator873.")
		return
	
	site = getWiki(project)
	
	if site is None:
		bot.say("I don't know that wiki.")
		return
	
	csrfToken = getCSRF(bot, site, creds, "csrf")
	
	if csrfToken is False:
		return
		
	reqBlock = {
		"action": "block",
		"user": target,
		"expiry": until,
		"reason": reason,
		"token": csrfToken,
		"allowusertalk":"",
		"format": "json"
	}
	
	# Send block request
	block = xmit(site, creds, reqBlock, "post")
		
	if 'error' in block:
		reason = block['error']['code']
		if reason == "badtoken":
			bot.say("Received CSRF token error. Try again...")
		elif reason == "alreadyblocked":
			bot.say(target + " is already blocked. Use !reblock to change the current block.")
		elif reason == "permissiondenied":
			bot.say("Received permission denied error. Are you a sysop on " + project + "?")
		else:
			info = block['error']['info']
			bot.say("Unhandled error: " + info)
	elif 'block' in block:
		user = block['block']['user']
		expiry = block['block']['expiry']
		reason = block['block']['reason']
		bot.say(user + " was blocked until " + expiry + " with reason: " + reason)
	else:
		bot.say("Unknown error: " + block)

def doUnblock(bot, name, project, target, reason):
	# Setup dbase connection
	db = sqlite3.connect(DARKNESS_DB)
	c = db.cursor()
	
	# Get user credentials and prepare api url for use
	creds = c.execute('''SELECT * from auth where account="%s";''' % name).fetchall()[0]
			
	db.close()
	
	if len(creds) == 0:
		bot.say(name + ", you are not configured. Contact Operator873.")
		return
	
	site = getWiki(project)
	
	if site is None:
		bot.say("I don't know that wiki.")
		return
	
	csrfToken = getCSRF(bot, site, creds, "csrf")
	
	if csrfToken is False:
		return
		
	reqBlock = {
		"action": "unblock",
		"user": target,
		"reason": reason,
		"token": csrfToken,
		"format": "json"
	}
	
	# Send block request
	unblock = xmit(site, creds, reqBlock, "post")
	
	if 'error' in unblock:
		reason = unblock['error']['info']
		bot.say(reason)
	elif 'unblock' in unblock:
		user = unblock['unblock']['user']
		reason = unblock['unblock']['reason']
		bot.say(user + " was unblocked with reason: " + reason)
	else:
		bot.say("Unhandled error: " + unblock)

def addUser(bot, name):
	# Setup dbase connection
	db = sqlite3.connect(DARKNESS_DB)
	c = db.cursor()
	
	# Check for user already existing
	check = c.execute('''SELECT * FROM auth WHERE account="%s";''' % name).fetchall()
	
	if len(check) != 0:
		bot.say("User already exists!")
		db.close()
		return
	else:
		# Add new user to database
		c.execute('''INSERT INTO auth VALUES("%s", NULL, NULL, NULL, NULL);''' % name)
		db.commit()
		db.close()
		bot.say("User added.")

def remUser(bot, name):
	# Setup dbase connection
	db = sqlite3.connect(DARKNESS_DB)
	c = db.cursor()
	
	# Check for user already existing
	check = c.execute('''SELECT * FROM auth WHERE account="%s";''' % name).fetchall()
	
	if len(check) == 0:
		bot.say("User does not exist!")
		db.close()
	else:
		c.execute('''DELETE FROM auth WHERE account="%s";''' % name)
		db.commit()
		db.close()
		bot.say("User deleted.")

def addKeys(bot, name, info):
	# Setup dbase connection
	db = sqlite3.connect(DARKNESS_DB)
	c = db.cursor()
	
	try:
		c_token, c_secret, a_token, a_secret = info.split(" ")
	except Exception as e:
		bot.say(str(e))
	
	check = c.execute('''SELECT * FROM auth WHERE account="%s";''' % name).fetchall()
	
	if len(check) == 0:
		bot.say("You are not approved to add tokens. Contact Operator873.")
		db.close()
		return
	else:
		try:
			c.execute('''UPDATE auth SET consumer_token="%s", consumer_secret="%s", access_token="%s", access_secret="%s" WHERE account="%s";''' % (c_token, c_secret, a_token, a_secret, name))
			bot.say("Keys added.")
		except Exception as e:
			bot.say(str(e))
		finally:
			db.commit()
			db.close()

@module.commands('block')
@module.nickname_commands('block')
def commandBlock(bot, trigger):
	# !block Some Nick Here > simplewiki 1week/31hours/6months/indef Some reason here.
	target, info = trigger.group(2).split(">", 1)
	project, until, reason = info.strip().split(" ", 2)
	adjust = re.sub(r"([0-9]+([0-9]+)?)",r" \1 ", until)
	until = re.sub(' +', ' ', adjust).strip()
	doBlock(bot, trigger.nick, project, target.strip(), until, reason)

@module.commands('lta')
@module.nickname_commands('lta')
def commandltablock(bot, trigger):
	# doltaBlock(bot, name, project, target):
	target, project = trigger.group(2).split(">", 1)
	doltaBlock(bot, trigger.nick, project.strip(), target.strip())

@module.commands('tpa')
@module.nickname_commands('tpa')
def commandRevoketpa(bot, trigger):
	# !block Some Nick Here > simplewiki 1week/31hours/6months/indef Some reason here.
	target, info = trigger.group(2).split(">", 1)
	project, until, reason = info.strip().split(" ", 2)
	adjust = re.sub(r"([0-9]+([0-9]+)?)",r" \1 ", until)
	until = re.sub(' +', ' ', adjust).strip()
	dorevokeTPA(bot, trigger.nick, project, target.strip(), until, reason)

@module.commands('reblock')
@module.nickname_commands('reblock')
def commandreBlock(bot, trigger):
	# !block Some Nick Here > simplewiki 1week/31hours/6months/indef Some reason here.
	target, info = trigger.group(2).split(">", 1)
	project, until, reason = info.strip().split(" ", 2)
	adjust = re.sub(r"([0-9]+([0-9]+)?)",r" \1 ", until)
	until = re.sub(' +', ' ', adjust).strip()
	doReblock(bot, trigger.nick, project, target.strip(), until, reason)

@module.commands('proxyblock')
@module.nickname_commands('proxyblock')
def commandproxyBlock(bot, trigger):
	# !proxyblock Some Nick Here > simplewiki 1week/31hours/6months/indef.
	target, info = trigger.group(2).split(">", 1)
	project, until = info.strip().split(" ", 1)
	adjust = re.sub(r"([0-9]+([0-9]+)?)",r" \1 ", until)
	until = re.sub(' +', ' ', adjust).strip()
	reason = "[[m:NOP|Open proxy]]"
	doReblock(bot, trigger.nick, project, target.strip(), until, reason)

@module.commands('gblock')
@module.nickname_commands('gblock')
def commandglobalBlock(bot, trigger):
	# !gblock Some IP Here > 1week/31hours/6months/indef Some reason here.
	target, info = trigger.group(2).split('>')
	until, reason = info.split(' ', 1)
	adjust = re.sub(r"([0-9]+([0-9]+)?)",r" \1 ", until)
	until = re.sub(' +', ' ', adjust).strip()

	if reason == "proxy":
		reason = "[[m:NOP|Open proxy]]"
	elif reason == "LTA" or reason == "lta":
		reason = "Long term abuse"
	elif reason == "spam":
		reason = "Cross wiki spam"
	elif reason == "abuse":
		reason = "Cross wiki abuse"
	else:
		pass
	doGlobalblock(bot, trigger.nick, target.strip(), until, reason)

@module.commands('lock')
@module.nickname_commands('lock')
def commandLock(bot, trigger):
	# !lock Some Account > Some reason here.
	target, reason = trigger.group(2).split(">", 1)
	reason = reason.strip()
	if reason == "proxy":
		reason = "[[m:NOP|Open proxy]]"
	elif reason == "LTA" or reason == "lta":
		reason = "Long term abuse"
	elif reason == "spam":
		reason = "Cross wiki spam"
	elif reason == "abuse":
		reason = "Cross wiki abuse"
	elif reason == "banned" or reason == "banned user":
		reason = "Globally banned user"
	else:
		pass
	doLock(bot, trigger.nick, target.strip(), reason)

@module.commands('softblock')
@module.nickname_commands('softblock')
def commandSoftblock(bot, trigger):
	# !block Some Nick Here > simplewiki 1week/31hours/6months/indef Some reason here.
	target, info = trigger.group(2).split(">", 1)
	project, until, reason = info.strip().split(" ", 2)
	adjust = re.sub(r"([0-9]+([0-9]+)?)",r" \1 ", until)
	until = re.sub(' +', ' ', adjust).strip()
	doSoftblock(bot, trigger.nick, project, target.strip(), until, reason)

@module.commands('unblock')
@module.nickname_commands('unblock')
def commandUnblock(bot, trigger):
	# !unblock Some Nick Here > simplewiki Some reason here.
	target, info = trigger.group(2).split(">", 1)
	project, reason = info.strip().split(" ", 1)
	doUnblock(bot, trigger.nick, project, target.strip(), reason)
	
@module.commands('edit')
@module.nickname_commands('edit')
def commandEdit(bot, trigger):
	# doEdit(bot, name, project, edit)
	bot.say("This command is disabled.")
	
@module.require_owner(message="This function is only available to Operator873.")
@module.commands('addUser')
@module.nickname_commands('addUser')
def commandAdd(bot, trigger):
	addUser(bot, trigger.group(2))

@module.require_owner(message="This function is only available to Operator873.")
@module.commands('remUser')
@module.nickname_commands('remUser')
def commandRem(bot, trigger):
	remUser(bot, trigger.group(2))

@module.require_privmsg(message="This function must be used in PM.")
@module.commands('tokens')
@module.nickname_commands('tokens')
def commandTokens(bot, trigger):
	addKeys(bot, trigger.nick, trigger.group(2))

@module.require_owner(message="This function is only available to Operator873.")
@module.commands('getapi')
def getAPI(bot, trigger):
	# Setup dbase connection
	db = sqlite3.connect(DARKNESS_DB)
	c = db.cursor()
	wiki = str(trigger.group(3))
	check = c.execute('''SELECT apiurl FROM wikis WHERE wiki="%s";''' % wiki).fetchone()[0]
	db.close()
	bot.say(check)
