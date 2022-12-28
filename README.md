# Discord SMTP Relay
This project is a very simple relay from SMTP to a Discord webhook. This allows applications that only support SMTP email notifications to be routed to Discord without an actual email server as a middle-man.

This is currently a work-in-progress. At the moment, it supports a few options for authentication:
 - No authenticaion, no TLS
 - PLAIN or LOGON authentication, without TLS
 - PLAIN or LOGON authentication with TLS

It currently only allows one username/password combination, which are set by environment variables (see below). If you don't need authentication or TLS, simply don't set those variables (SMTP_USERNAME/PASSWORD or TLS_CERT/KEY respectively).

This is designed for use internally only, specifically within a Docker network. I would not recommend exposing this to the internet (or any untrusted network) in its current form, especially if not using TLS.

It uses a discord bot for connecting to discord.  This allows for the bot to talk to multiple channels, rather than via a single web hook.  These instructions were used in the creation of a bot and obtain the DISCORD_TOKEN - https://realpython.com/how-to-make-a-discord-bot-python/  

# Environment variables
| Variable    | Description          | Example                                          |
|-------------|----------------------|--------------------------------------------------|
| DISCORD_TOKEN | Discord bot token  | kj4234234jh2k4242k42434234 |
| SMTP_USERNAME | Accepted username for SMTP | `testuser` |
| SMTP_PASSWORD | Accepted password for SMTP | `testpass` |
| TLS_CERT_CHAIN | File path to full TLS certificate chain | `fullchain.pem` |
| TLS_KEY | File path to private key for certificate | `privkey.pem` |

# Configuration File

The configuration file is used for some configuration information.  SMTP_USERNAME, SMTP_PASSWORD can be otained from configuration or environment variable.   If set in both, the environment variable will take precendence.

## Example configuration

```
[smtp]
#username=
#password=
port=2525

[default]
# Create a discord channels, and copy the channel ID to this default section.
# if this section is missing it will fail to start
# for subsequent sections, is no channel ID is specified it will default to this ID.
channelid=<discord channel id>

[camera]
#emails from an account called camera@any domain
channelid=<discord channel id>
from=camera@.+

[test-machine]
#emails to an account called test@any domain
channelid=<discord channel id>
to=test@.+

[other]
#emails with test in the subject
subject=.+test.?
```

## Configuration Notes

SMTP Port.  To set the port internally use a `port` option in the `[smtp]` section.

`default` section must contain a `channelid` - this channel id is used if any of the filters do not have their own channel id.

All other sections can be named for your own reference, they should contain at least one filter and optionally, a channel id.

The filters a python format regex and can be filtered on the `to` email address, `from` address or the `subject`.  When any of these filters match, they will return the assigned channel id for posting the message.

# Running Command Line
1. Install the requirements:
```
pip install -r requirements.txt
```
2. Set the environment variables as desired

3. Set the configuration file `config.ini` in the directory with `discord_relay.py`

4. Run the server:
```
python discord_relay.py
```

# Running Docker

## Docker Compose

```
version: '3'
# compose file for discord-smtp
services:
  discord-smtp:
    container_name: discord-smtp
    image: registry.internal.andc.nz/discord-smtp
    restart: always
    environment:
      - PYTHONUNBUFFERED=1
      #- SMTP_USERNAME=${SMTP_USERNAME}
      #- SMTP_PASSWORD=${SMTP_PASSWORD}
      - DISCORD_TOKEN=${DISCORD_TOKEN}
    volumes:
      - $PWD/config.ini:/conf/config.ini
    ports:
      - "2525:2525"
```

The above compose file has authentication turned off, left in the env variables to show the format.
The DISCORD_TOKEN is passed in from a .env file where the format is:
DISCORD_TOKEN='token from discord bot'

The config.ini file is being passed in directly as well. 

Having `PYTHONUNBUFFERED` set to 1 will show any console messages when running detached (logging0)