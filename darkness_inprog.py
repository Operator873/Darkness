import requests
import sqlite3
from sopel import module
from sopel import tools

# To do list:
#
# 1) //DONE\\ Combine auth and config tables to auth table by adding csrf column. 
# 2) Rewrite any site= to use getWiki(project)
# 3) Rewrite initial command to request project abbreviation like simplewiki, testwiki, enwikisource, etc
#
#
# json example responses
#
# Edit messages
# 1) {'edit': {'result': 'Success', 'pageid': 4020, 'title': 'User:Operator873/sandbox', 'contentmodel': 'wikitext', 'oldrevid': 10560, 'newrevid': 10561, 'newtimestamp': '2020-06-08T23:35:24Z'}}
# 2) {'error': {'code': 'badtoken', 'info': 'Invalid CSRF token.', '*': 'See https://testwiki.wiki/api.php for API usage. Subscribe to the mediawiki-api-announce mailing list at &lt;https://lists.wikimedia.org/mailman/listinfo/mediawiki-api-announce&gt; for notice of API deprecations and breaking changes.'}}
# 3)
#
# Block messages
# {'block': {'user': 'GoodSock873', 'userID': 1287, 'expiry': '2020-06-09T23:41:38Z', 'id': 1120, 'reason': 'Another test block', 'pagerestrictions': None, 'namespacerestrictions': None}}
# {'error': {'code': 'badtoken', 'info': 'Invalid CSRF token.', '*': 'See https://testwiki.wiki/api.php for API usage. Subscribe to the mediawiki-api-announce mailing list at &lt;https://lists.wikimedia.org/mailman/listinfo/mediawiki-api-announce&gt; for notice of API deprecations and breaking changes.'}}
# {'error': {'code': 'alreadyblocked', 'info': '"GoodSock873" is already blocked.', '*': 'See https://testwiki.wiki/api.php for API usage. Subscribe to the mediawiki-api-announce mailing list at &lt;https://lists.wikimedia.org/mailman/listinfo/mediawiki-api-announce&gt; for notice of API deprecations and breaking changes.'}}



# Editing with broken csrf token. Detect, correct, re-send edit

def login(name, project):
    
    # Define the database connection
    db = sqlite3.connect("D:\\Bot873\\dark.db")
    c = db.cursor()
    
    # Check to see if this requesting account is set up for use
    try:
        isUser = c.execute('''SELECT account FROM auth WHERE account="%s";''' % name).fetchall()
    except Exception as e:
        print("Error: 01020 " + str(e))
    # If user not conifgured, report error, stop login process
    if len(isUser) == 0:
        print("Sorry! You're not configured!")
        return
    
    # Fetch existing user data
    try:
        secure = c.execute('''SELECT * from auth where account="%s";''' % name).fetchall()[0]
    except Exception as e:
        print("Error: 01029 " + str(e))

    # Check for stored csrf token, if none exists, get one.
    if secure[1] is None:
        csrf(secure, project)
        print("CSRF updated.")
    else:
        #print("CSRF token already stored.")
        pass
    
    # terminate db connection
    db.close()
    return

def xmit(site, creds, payload, method):
    # This handles the post/get requests
    AUTH = OAuth1(creds[2], creds[3], creds[4], creds[5])
        
    if method is "post":
        return requests.post(site, data=payload, auth=AUTH).json()
    elif method is "get":
        return requests.get(site, params=payload, auth=AUTH).json()

def csrf(creds, project):
    # This configures the request for a csrf token, sends it to xmit, and returns the token
    reqtoken = {
        'action':"query",
        'meta':"tokens",
        'format':"json"
    }
    site = getWiki(project)
    token = xmit(site, creds, reqtoken, "get")['query']['tokens']['csrftoken']
    
    db = sqlite3.connect("D:\\Bot873\\dark.db", check_same_thread=False)
    c = db.cursor()
    
    try:
        c.execute('''update auth set csrf="%s" where account="%s";''' % (token, creds[0]))
    except Exception as e:
        print("Error: 03089 " + str(e))
    
    db.close()

def doEdit(name, project, edit):
    # Setup dbase connection
    db = sqlite3.connect("D:\\Bot873\\dark.db")
    c = db.cursor()
    
    login(name, project)
    
    # Get user credentials and prepare api url for use
    creds = c.execute('''SELECT * from auth where account="%s";''' % name).fetchall()[0]
    site = getWiki(project)
    
    reqEdit = {
        'action':"edit",
        'format':"json",
        'title':"User:Operator873/sandbox",
        'section':"new",
        'sectiontitle':"New Test",
        'text':edit,
        'summary':"This is a bot edit",
        'minor':"true",
        'redirect':"true",
        'token':creds[1]
    }
    
    # send to xmit
    edit = xmit(site, creds, reqEdit, "post")
    
    db.close()
    
    # Check for success
    if 'edit' in edit:
        print("Success! Edit was made to " + edit['edit']['title'])
    elif 'error' in edit:
        reason = edit['error']['info']
        if reason == "Invalid CSRF token.":
            csrf(creds, project)
            doEdit(name, project, edit)
        else:
            print(reason)
    else:
        print("Unknown error!: " + edit)


def doBlock(name, project, target, until, reason):
    # Define database connection
    db = sqlite3.connect("D:\\Bot873\\dark.db")
    c = db.cursor()
    
    # Check for csrf, if none found, get one.
    csrfCheck = c.execute('''SELECT csrf FROM auth WHERE account="%s";''' % name).fetchone()[0]

    if csrfCheck is None:
        login(name, project)
    
    # Get user credentials
    creds = c.execute('''SELECT * from auth where account="%s";''' % name).fetchall()[0]
    site = getWiki(project)
    
    # Configure request
    reqBlock = {
        "action": "block",
        "user": target,
        "expiry": until,
        "reason": reason,
        "token": creds[1],
        "format": "json"
    }
    
    # Send block request
    block = xmit(site, creds, reqBlock, "post")
    print(block)
    
    db.close()

def getWiki(project):
    # Define dbase connection
    db = sqlite3.connect("D:\\Bot873\\wiki.db")
    c = db.cursor()
    
    # Get the api url based on the project's short name like enwiki, simplewiktionary, ptwikibooks
    try:
        site = c.execute('''SELECT apiurl FROM GSwikis WHERE project="%s";''' % project).fetchone()[0]
    except Exception as e:
        site = None
    
    db.close()
    return site

def main():
    command = input("Command> ")
    
    if command == "login":
        name = input("Account name> ")
        project = input("What project? ")
        login(name, project)
    elif command == "edit":
        name = input("Account name> ")
        project = input("Project? ")
        edit = input("What shall I write? ")
        doEdit(name, project, edit)
    elif command == "block":
        name = input("Account name> ")
        target = "GoodSock873"
        project = input("Project? ")
        reason = input("What's the block reason? ")
        until = input("How long? ")
        doBlock(name, project, target, until, reason)
    elif command == ("project"):
        project = input("What project? ")
        print(getWiki(project))
    else:
        print("Command not recognized")
