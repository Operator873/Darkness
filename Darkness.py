import requests
import sqlite3
import json
import re
from requests_oauthlib import OAuth1
from sopel import module

DARKNESS_DB = "/home/ubuntu/.sopel/modules/dark.db"

def addtomemory(user, payload):
    result = {}
    db = sqlite3.connect(DARKNESS_DB)
    c = db.cursor()
    
    check = c.execute('''SELECT * FROM memory WHERE user="%s" AND payload="%s";''' % (user, payload)).fetchall()
    
    if len(check) == 0:
    
        try:
            c.execute('''INSERT INTO memory VALUES("%s", "%s");''' % (user, payload))
            db.commit()
            result['status'] = "Success"
            result['data'] = "'" + payload + "' saved"
        except Exception as e:
            result['status'] = "Failure"
            result['data'] = str(e)
     
    else:
        result['status'] = "Success"
        result['data'] = "'" + payload + "' is already in memory." 
    
    db.close()
    
    return result
    
def getfrommemory(user):
    result = {}
    db = sqlite3.connect(DARKNESS_DB)
    c = db.cursor()
    
    try:
        result['data'] = c.execute('''SELECT payload FROM memory WHERE user="%s";''' % user).fetchall()
        result['status'] = "Success"
    except Exception as e:
        result['status'] = "Failure"
        result['data'] = str(e)
        
    db.close()
    
    return result

def delfrommemory(user, payload):
    result = {}
    db = sqlite3.connect(DARKNESS_DB)
    c = db.cursor()

    check = c.execute('''SELECT * FROM memory WHERE user="%s" AND payload="%s";''' % (user, payload)).fetchall()

    if len(check) > 0:
        c.execute('''DELETE FROM memory WHERE user="%s" AND payload="%s";''' % (user, payload))
        db.commit()
        result['status'] = "Success"
        result['data'] = "'" + payload + "' removed from memory."
    else:
        result['status'] = "Failure"
        result['data'] = "'" + payload + "' is not currently in memory for " + user + "."

    db.close()

    return result

def clearmemory(user):
    result = {}
    db = sqlite3.connect(DARKNESS_DB)
    c = db.cursor()
    
    try:
        c.execute('''DELETE FROM memory WHERE user="%s";''' % user)
        db.commit()
        result['status'] = "Success"
        result['data'] = "Memory Cleared."
    except Exception as e:
        result['status'] = "Failure"
        result['data'] = str(e)
        
    db.close()

    return result

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

def getCreds(name):
    # Setup dbase connection
    db = sqlite3.connect(DARKNESS_DB)
    c = db.cursor()
    
    # Get user credentials and prepare api url for use
    creds = c.execute('''SELECT * from auth where account="%s";''' % name).fetchall()[0]
    db.close()
    
    if creds is not None:
        return creds
    else:
        return None

def doBlock(bot, name, project, target, until, reason):
    creds = getCreds(name)
    
    if creds is None:
        bot.say("You are not configured. Please contact Operator873.")
        return
    
    site = getWiki(project)
    
    if site is None:
        bot.say("I don't know that wiki.")
        return
    
    csrfToken = getCSRF(bot, site, creds, "csrf")
    
    if csrfToken is False:
        return
    
    if until == "indef" or until == "forever":
        until = "never"
    
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
    creds = getCreds(name)
    
    if creds is None:
        bot.say("You are not configured. Please contact Operator873.")
        return
        
    site = getWiki(project)
    
    if site is None:
        bot.say("I don't know that wiki.")
        return
    
    csrfToken = getCSRF(bot, site, creds, "csrf")
    
    if csrfToken is False:
        return
    
    if until == "indef" or until == "forever":
        until = "never"
        
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
    creds = getCreds(name)
    
    if creds is None:
        bot.say("You are not configured. Please contact Operator873.")
        return
        
    site = getWiki("metawiki")
    
    if site is None:
        bot.say("I don't know that wiki.")
        return
    
    csrfToken = getCSRF(bot, site, creds, "csrf")
    
    if csrfToken is False:
        return
    
    if until == "indef" or until == "forever":
        until = "never"
    
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
    creds = getCreds(name)
    
    if creds is None:
        bot.say("You are not configured. Please contact Operator873.")
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
        bot.say(target + " locked.")

def doUnlock(bot, name, target, reason):
    creds = getCreds(name)
    
    if creds is None:
        bot.say("You are not configured. Please contact Operator873.")
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
        "locked":"unlock",
        "reason":reason,
        "token":csrfToken
    }
    
    # Send block request
    lock = xmit(site, creds, lockRequest, "post")
    
    if 'error' in lock:
        bot.say("Unlock failed! " + lock['error']['info'])
    else:
        bot.say("Unlock succeeded. ")

def dorevokeTPA(bot, name, project, target, until, reason):
    creds = getCreds(name)
    
    if creds is None:
        bot.say("You are not configured. Please contact Operator873.")
        return
    
    site = getWiki(project)
    
    if site is None:
        bot.say("I don't know that wiki.")
        return
    
    csrfToken = getCSRF(bot, site, creds, "csrf")
    
    if csrfToken is False:
        return
    
    if until == "indef" or until == "forever":
        until = "never"
        
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
    creds = getCreds(name)
    
    if creds is None:
        bot.say("You are not configured. Please contact Operator873.")
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
    creds = getCreds(name)
    
    if creds is None:
        bot.say("You are not configured. Please contact Operator873.")
        return
    
    site = getWiki(project)
    
    if site is None:
        bot.say("I don't know that wiki.")
        return
    
    csrfToken = getCSRF(bot, site, creds, "csrf")
    
    if csrfToken is False:
        return
    
    if until == "indef" or until == "forever":
        until = "never"
        
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
    creds = getCreds(name)
    
    if creds is None:
        bot.say("You are not configured. Please contact Operator873.")
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
    doBlock(bot, trigger.account, project, target.strip(), until, reason)

@module.commands('lta')
@module.nickname_commands('lta')
def commandltablock(bot, trigger):
    # doltaBlock(bot, name, project, target):
    target, project = trigger.group(2).split(">", 1)
    doltaBlock(bot, trigger.account, project.strip(), target.strip())

@module.commands('tpa')
@module.nickname_commands('tpa')
def commandRevoketpa(bot, trigger):
    # !block Some Nick Here > simplewiki 1week/31hours/6months/indef Some reason here.
    target, info = trigger.group(2).split(">", 1)
    project, until, reason = info.strip().split(" ", 2)
    adjust = re.sub(r"([0-9]+([0-9]+)?)",r" \1 ", until)
    until = re.sub(' +', ' ', adjust).strip()
    dorevokeTPA(bot, trigger.account, project, target.strip(), until, reason)

@module.commands('reblock')
@module.nickname_commands('reblock')
def commandreBlock(bot, trigger):
    # !block Some Nick Here > simplewiki 1week/31hours/6months/indef Some reason here.
    target, info = trigger.group(2).split(">", 1)
    project, until, reason = info.strip().split(" ", 2)
    adjust = re.sub(r"([0-9]+([0-9]+)?)",r" \1 ", until)
    until = re.sub(' +', ' ', adjust).strip()
    doReblock(bot, trigger.account, project, target.strip(), until, reason)

@module.commands('proxyblock')
@module.nickname_commands('proxyblock')
def commandproxyBlock(bot, trigger):
    # !proxyblock Some Nick Here > simplewiki 1week/31hours/6months/indef.
    target, info = trigger.group(2).split(">", 1)
    project, until = info.strip().split(" ", 1)
    adjust = re.sub(r"([0-9]+([0-9]+)?)",r" \1 ", until)
    until = re.sub(' +', ' ', adjust).strip()
    reason = "[[m:NOP|Open proxy]]"
    doReblock(bot, trigger.account, project, target.strip(), until, reason)

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
    doGlobalblock(bot, trigger.account, target.strip(), until, reason)

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
    doLock(bot, trigger.account, target.strip(), reason)

@module.commands('mlock')
@module.nickname_commands('mlock')
def commandmLock(bot, trigger):
    # !lock Some Account > Some reason here.
    targets, reason = trigger.group(2).split(">", 1)
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
    
    for target in targets.split(','):
        doLock(bot, trigger.account, target.strip(), reason)

@module.commands('unlock')
@module.nickname_commands('unlock')
def commandUnlock(bot, trigger):
    # !unlock Some Account
    reason = "Unlock"
    doUnlock(bot, trigger.account, trigger.group(2), reason)

@module.commands('softblock')
@module.nickname_commands('softblock')
def commandSoftblock(bot, trigger):
    # !block Some Nick Here > simplewiki 1week/31hours/6months/indef Some reason here.
    target, info = trigger.group(2).split(">", 1)
    project, until, reason = info.strip().split(" ", 2)
    adjust = re.sub(r"([0-9]+([0-9]+)?)",r" \1 ", until)
    until = re.sub(' +', ' ', adjust).strip()
    doSoftblock(bot, trigger.account, project, target.strip(), until, reason)

@module.commands('unblock')
@module.nickname_commands('unblock')
def commandUnblock(bot, trigger):
    # !unblock Some Nick Here > simplewiki Some reason here.
    target, info = trigger.group(2).split(">", 1)
    project, reason = info.strip().split(" ", 1)
    doUnblock(bot, trigger.account, project, target.strip(), reason)
    
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
    addKeys(bot, trigger.account, trigger.group(2))

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

@module.commands('altnick')
def addAltNick(bot, trigger):
    # !altnick <alt nick> -- must be done from existing nick
    db = sqlite3.connect(DARKNESS_DB)
    c = db.cursor()

    creds = c.execute('''SELECT * from auth where account="%s";''' % trigger.nick).fetchone()
    
    if creds is None:
        bot.say("You're not configured. Are you using your main nick?")
        return
    
    addUser(bot, trigger.group(2))
    
    origaccount, key1, key2, key3, key4 = creds
    
    try:
        c.execute('''UPDATE auth SET consumer_token="%s", consumer_secret="%s", access_token="%s", access_secret="%s" WHERE account="%s";''' % (key1, key2, key3, key4, trigger.group(2)))
        db.commit()
        bot.say("Keys added.")
    except Exception as e:
        bot.say(str(e))
    
    check = c.execute('''SELECT * from auth where account="%s";''' % trigger.group(2)).fetchall()[0]
    
    db.close()
    
    if check != 0:
        bot.say("Alternate nick addded successfully.")
    else:
        bot.say("Something weird happened during confirmation. Ping Operator873")

@module.require_owner(message="This function is only available to Operator873.")
@module.commands('addalt')
def addAlt(bot, trigger):
    # !addalt <orig> <alt>
    db = sqlite3.connect(DARKNESS_DB)
    c = db.cursor()

    creds = c.execute('''SELECT * from auth where account="%s";''' % trigger.group(3)).fetchone()
    
    if creds is None:
        bot.say("You're not configured. Are you using your main nick?")
        return
    
    addUser(bot, trigger.group(4))
    
    origaccount, key1, key2, key3, key4 = creds
    
    try:
        c.execute('''UPDATE auth SET consumer_token="%s", consumer_secret="%s", access_token="%s", access_secret="%s" WHERE account="%s";''' % (key1, key2, key3, key4, trigger.group(4)))
        db.commit()
        bot.say("Keys added.")
    except Exception as e:
        bot.say(str(e))
    
    check = c.execute('''SELECT * from auth where account="%s";''' % trigger.group(4)).fetchone()
    
    db.close()
    
    if check is not None:
        bot.say("Alternate nick addded successfully.")
    else:
        bot.say("Something weird happened during confirmation. Ping Operator873")

@module.commands('whoami')
def whoami(bot, trigger):
    bot.say("You are " + trigger.nick + " using Freenode account: " + trigger.account + ".")

@module.commands('memadd')
def memadd(bot, trigger):
    response = addtomemory(trigger.account, trigger.group(2))
    if response['status'] == "Success":
        bot.say(response['data'])
    else:
        bot.say("Operator873 something blew up! " + response['data'])

@module.commands('memclear')
def memclear(bot, trigger):
    response = clearmemory(trigger.account)
    
    if response['status'] == "Success":
        bot.say(response['data'])
    else:
        bot.say("Operator873 something blew up! " + response['data'])

@module.commands('memdel')
def memdel(bot, trigger):
    response = delfrommemory(trigger.account, trigger.group(2))
    
    if response['status'] == "Success":
        bot.say(response['data'])
    else:
        bot.say("Operator873 something blew up! " + response['data'])

@module.commands('memshow')
def memshow(bot, trigger):
    payload = getfrommemory(trigger.account)
    
    if payload['status'] == "Success":
        if len(payload['data']) > 0:
            response = ""
            for entry in payload['data']:
                if len(response) > 0:
                    response = response + ", " + entry[0]
                else:
                    response = entry[0]
            bot.say("Items currently in memory: " + response)
        else:
            bot.say("It doesn't appear you have anything stored in memory.")
    else:
        bot.say("An error occured fetching memory items. Ping Operator873")
        bot.say(payload['data'])

@module.commands('memory')
def domemory(bot, trigger):
    try:
        action, reason = trigger.group(2).split(" ", 1)
    except:
        bot.say("Missing data. Syntax is !memory <action> <optional args>")
        return
    
    dump = getfrommemory(trigger.account)
    
    if len(dump['data']) > 0:
    
        if action.lower() == "lock":
            # !memory lock <reason>
            if reason.lower() == "proxy":
                reason = "[[m:NOP|Open proxy]]"
            elif reason.lower() == "lta":
                reason = "Long term abuse"
            elif reason.lower() == "spam":
                reason = "Cross wiki spam"
            elif reason.lower() == "abuse":
                reason = "Cross wiki abuse"
            elif reason.lower() == "banned" or reason.lower() == "banned user":
                reason = "Globally banned user"
            else:
                pass
            
            for item in dump['data']:
                doLock(bot, trigger.account, item[0], reason.strip())
            
            devnull = clearmemory(trigger.account)
                
        elif action.lower() == "block":
            # !memory block simplewiki 30days <reason>
            try:
                project, until, reason = reason.split(" ", 2)
            except:
                bot.say("Missing args! Syntax is: !memory block <project> <length> <reason>")
                return
            
            adjust = re.sub(r"([0-9]+([0-9]+)?)",r" \1 ", until)
            until = re.sub(' +', ' ', adjust).strip()
            
            for item in dump['data']:
                doBlock(bot, trigger.account, project.lower(), item[0], until, reason)
            
            devnull = clearmemory(trigger.account)
                
        elif action.lower() == "lta":
            # !memory lta simplewiki
            project = reason
            for item in dump['data']:
                doltaBlock(bot, trigger.account, project, item[0])
            
            devnull = clearmemory(trigger.account)
        
        elif action.lower() == "gblock":
            # !memory gblock 1week/31hours/6months/indef <Some reason here.>
            try:
                until, reason = reason.split(' ', 1)
            except:
                bot.say("Missing args! Syntax is: !memory gblock <length> <reason>")
                return
            
            adjust = re.sub(r"([0-9]+([0-9]+)?)",r" \1 ", until)
            until = re.sub(' +', ' ', adjust).strip()

            if reason.lower() == "proxy":
                reason = "[[m:NOP|Open proxy]]"
            elif reason.lower() == "lta":
                reason = "Long term abuse"
            elif reason.lower() == "spam":
                reason = "Cross wiki spam"
            elif reason.lower() == "abuse":
                reason = "Cross wiki abuse"
            elif reason.lower() == "banned" or reason.lower() == "banned user":
                reason = "Globally banned user"
            else:
                pass
            
            for item in dump['data']:
                doGlobalblock(bot, trigger.account, item[0], until, reason)
            
            devnull = clearmemory(trigger.account)
        
        elif action.lower() == "test":
            try:
                project, until, reason = reason.split(" ", 2)
            except:
                bot.say("Missing args! Syntax is: !memory block <project> <length> <reason>")
                return
            
            adjust = re.sub(r"([0-9]+([0-9]+)?)",r" \1 ", until)
            until = re.sub(' +', ' ', adjust).strip()
            
            for item in dump['data']:
                bot.say(item[0] + " would be blocked on " + project + ". Length: " + until + ". Reason: " + reason)
            
            bot.say("I would clear memory now, but I haven't for testing.")
            
        else:
            bot.say("Error! I currently know lock, block, lta, and gblock. Ping Operator873 if additional command is needed.")
            bot.say("Your stored information has not been altered. Please try again.")
    else:
        bot.say("It doesn't appear I have anything in memory to act on for you.")