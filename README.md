# Darkness
Hello Darkness my old friend...

[![GitHub issues](https://img.shields.io/github/issues/Operator873/Darkness)](https://github.com/Operator873/Darkness/issues)
[![GitHub forks](https://img.shields.io/github/forks/Operator873/Darkness)](https://github.com/Operator873/Darkness/network)
[![GitHub stars](https://img.shields.io/github/stars/Operator873/Darkness)](https://github.com/Operator873/Darkness/stargazers)
![GitHub All Releases](https://img.shields.io/github/downloads/Operator873/Darkness/total)
![GitHub contributors](https://img.shields.io/github/contributors/Operator873/Darkness)

This is a Sopel IRC Bot plugin which supports Wikimedia sysops, global sysops, checkusers, and stewards by allowing block and lock actions from IRC. It could be modified quite easily to work with Miraheze or any other Mediawiki install.

I call it Darkness because the ease at which you can apply blocks will make othere wonder if you have dark arts at your disposal.

I take absolutely no responsibility for anything you do on wiki with this plugin. Play stupid games, win stupid prizes... like being desysopped. 

# Dependencies

This plugin requires Python3.x and libraries: requests, sqlite3, json, re, and OAuth1. This plugin also requires darkness.db.

# WYSIWYG

I'm not a professional programmer. At best, I think of myself as a Python hacker. Everything I write is pretty muched a hack job. If you notice something that could be improved or fixed, please either fix it, or open an issue for me to fix it. Thanks.

# Installation

1. Unzip/Untar into /path/to/.sopel/modules
2. Verify Darkness.py and darkness.db now exist in your modules folder.
3. If requred, add "enable = Darkness" in your /path/to/.sopel/YourBot.cfg file
4. Restart your bot

# Configuration

This plugin requires OAuth 1.0a tokens configured on https://meta.wikimedia.org/wiki/Special:OAuthConsumerRegistration/propose.

* Application name --> Anything you want it to be. I suggeste Darkness
* Consumer version --> Anything
* OAuth protocol version --> OAuth 1.0a
* Application description --> Bot plugin to assist with blocks and locks.
* This consumer is for use only by _____ --> ***YOU MUST CHECK THIS BOX***
* OAuth "callback" URL --> Blank
* Allow consumer to specify a callback in requests and use "callback" URL above as a required prefix. --> Unchecked
* Requests authorization for specific permissions
  * High-volume editing
  * Edit existing pages
  * Create, edit, and move pages
  * Block and unblock users
 
* Allowed IP ranges: --> Optional
* Public RSA --> blank
* Check the bottom box and click Propose consumer

**SAVE YOUR TOKENS** You will need them during the ```!tokens``` command below.

# Commands

```!block target > project duration Some reason here```
  - Applies a standard block to the provided target. The target can be either an IP or an account

```!lta target > project```
  - Applies a hard block with no email/talk page access on the provided target for 1 week. Block reason is hard coded to "[[Wikipedia:Blocks and bans#Evasion|Block evasion]]"

```!tpa target > project duration Some reason here```
  - Reblocks with no talk page access and no email access with the provided reason for the provided duration

```!reblock target > project duration Some reason here```
  - Reblocks the target. Useful for when your target is already blocked and you want to change the duration or reason.

```!proxyblock target > project duration```
  - Blocks the target IP with reason "[[m:NOP|Open proxy]]" for the provided duration

```!gblock target > duration Reason```
  - (Steward Action) Globally blocks the target IP and then blocks on metawiki.
  - Supports code words for reason
    - proxy --> [[m:NOP|Open proxy]]
    - LTA or lta --> Long term abuse
    - spam --> cross wiki spam
    - abuse --> cross wiki abuse
    - your typed reason --> your typed reason

```!lock target > Reason```
  - (Steward Action) Locks an account
  - Supports code words for reason
    - proxy --> [[m:NOP|Open proxy]]
    - LTA or lta --> Long term abuse
    - spam --> cross wiki spam
    - abuse --> cross wiki abuse
    - banned or banned user --> Globally banned user
    - your typed reason --> your typed reason

```!softblock target > project duration Some reason here```
  - Soft blocks (autoblock disabled, allow account creation) the provided target for the duration.

```!unblock target > project Some reason here```
  - Unblocks the provided target with the reason.

```!adduser TheirIRCNick```
  - This command tells the bot to add a new OAuth user to the database. See above guide for creating the required tokens. This command should be followed with a PM to the bot from the added user with their tokens.
  
```!remUser TheirIRCnick```
  - Remove the nick and delete their tokens.

```!tokens sad8gaysodiu a892e24hg 20847t2gaidhad 23984735tghad```
  - This command should ONLY be used via PM to the bot.
  - The provided tokens (the gibberish in the above example) are added to the database for the user PM'ing the bot.
  - The tokens are in the following order:
    - consumer token
    - consumer secret
    - access token
    - access secret

```!getapi project```
  - Debug command. Searches the database for the specified project and returns the apiurl

## Memory functions

```!memadd <data>```
  - Add the provided data to memory

```!memdel <data>```
  - Remove the provided data from memory

```!memshow```
  - Show all currently stored data

```!memclear```
  - Clears all data stored

```!memory <action> <optional ags>```
  - Uses the contents of the memory to perform given actions. Once the action is complete, memory is wiped.
  
```!memory block <project> <duration> <reason>```
  - Blocks the accounts in memory on the project provided for the duration provided with the reason.
  
```!memory lock <reason>```
  - Locks the accounts
  
```!memory gblock <duration> <reason>```
  - Globally blocks for the duration with reason
  
```!memory lta <project>```
  - A quick hardblock for 7 days on the provided project
  
```!memory test <project> <duration> <reason>```
  - A test operation for debug purposes. Does not clear memory upon completion.
  
