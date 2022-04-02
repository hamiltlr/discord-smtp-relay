# Discord SMTP Relay
This project is a very simple relay from SMTP to a Discord webhook. This allows applications that only support SMTP email notifications to be routed to Discord without an actual email server as a middle-man.

This is currently a work-in-progress. 

# Running
To run:
```
python -m aiosmtpd -n --class discord_relay.DiscordRelayHandler
```
