import os
import io
import ssl
import email
import signal
from email import policy

import requests
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Message
from aiosmtpd.smtp import AuthResult, LoginPassword
from discord.ext import commands, tasks
import discord
from html2text import html2text
from dotenv import load_dotenv


class DiscordRelayHandler(Message):
    def __init__(self, webhook_url, client):
        self.webhook_url = webhook_url
        self.client = client
        
        super().__init__(email.message.EmailMessage)
    #def __init__(self, webhook_url):

    # We need to override this method in order to define the policy on the message_from_xxxx calls. If this isn't done, you get a Compat32 error when attempting to get the email body.
    # It would be nicer if the aiosmtpd Message handler provided an option to specify a policy, but it doesn't as far as I can tell.
    def prepare_message(self, session, envelope):
        super().prepare_message(session, envelope)

        data = envelope.content
        if isinstance(data, bytes):
            message = email.message_from_bytes(data, self.message_class, policy=policy.default)
        else:
            assert isinstance(data, str), (
                'Expected str or bytes, got {}'.format(type(data)))
            message = email.message_from_string(data, self.message_class, policy=policy.default)
        return message
    #def prepare_message(self, session, envelope):

    def handle_message(self, message):
        # Extract the message body as a string
        # It will prefer extracting the HTML if possible, and that will be
        # converted to text via html2text. This preserves some of the
        # formatting and looks nicer in Discord
        msg_body = message.get_body(('html','plain')).get_content()
        msg_body = html2text(msg_body)

        attachments = []
        for attachment in message.iter_attachments():
            if attachment.get_content_disposition() == "attachment":

                file_obj = io.BytesIO()
                file_obj = attachment.get_payload(decode=True)
                filename = attachment.get_filename()

                #create a discord file from the email attachment payload
                discordfile = discord.File(io.BytesIO(file_obj),filename=filename)
                attachments.append(discordfile)
        #for attachment in message.iter_attachments():

        self.notify_discord_bot(message.get('to'),
                            message.get('from'),
                            message.get('subject'),
                            msg_body,
                            attachments)
        
    #def handle_message(self, message):


    def notify_discord_bot(self, to_addr, from_addr, subject, body,attachments = None):
        # Set the properties fo the bot client to values that will be sent to discord.
        self.client.subject = subject
        self.client.embeds = discord.Embed(title=subject,description="desc")
        self.client.embeds.add_field(name="To",value=to_addr,inline=False)
        self.client.embeds.add_field(name="From",value=from_addr)
        self.client.embeds.add_field(name="Subject",value=subject)
        if body is not None:
            self.client.embeds.add_field(name="Body",value=body)
        

        self.client.files = attachments
        self.client.msg_sent = False

    def notify_discord(self, to_addr, from_addr, subject, body):
        webhook_data = { 
            "embeds": [
                {
                    "title": subject,
                    "description": "",
                    "fields": [
                        self.discord_field("To",to_addr),
                        self.discord_field("From",from_addr),
                        self.discord_field("Subject",subject),
                        self.discord_field("Body",body)
                    ]
                }
            ]
        }

        r=requests.post(self.webhook_url,json=webhook_data)
    #def notify_discord(self, to_addr, from_addr, subject, body):

    # This helper function constructs a dictionary in the format of a "field" object
    # in the Discord webhooks API
    def discord_field(self, name, value="", inline=False):
        r = { 
                "name": name,
                "value": value,
                "inline": inline
            }
        return r
    #def discord_field(self, name, value="", inline=False):

    
    

class Authenticator:
    def __init__(self, smtp_username, smtp_password):
        self.smtp_username = smtp_username
        self.smtp_password = smtp_password

    def __call__(self, server, session, envelope, mechanism, auth_data):
        fail_nothandled = AuthResult(success=False, handled=False)
        success = AuthResult(success=True)

        if mechanism not in ("LOGIN", "PLAIN"):
            return fail_nothandled
        if not isinstance(auth_data, LoginPassword):
            return fail_nothandled

        username = auth_data.login.decode()
        password = auth_data.password.decode()

        if (username == self.smtp_username and
            password == self.smtp_password):
            return success
        else:
            print(f"WARNING: Attempted login for user '{username}'. Incorrect password specified.")
            return fail_nothandled

class MyClient(commands.Bot):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.msg_sent = False
        self.subject = "Its 7 am"
        self.embeds = None
        self.files = None

    async def on_ready(self):
        channel = client.get_channel(1048053896754516089)  # replace with channel ID that you want to send to
        print(f'{client.user} has connected to discord')
        await self.timer.start(channel)

    @tasks.loop(seconds=1)
    async def timer(self, channel):
       
        if not self.msg_sent:

            if self.embeds is not None:
                await channel.send(embed=self.embeds,files=self.files)
            else:
                await channel.send(self.subject,files=self.files)
            self.msg_sent = True    

def main():
    # Retrieve the environment variables
    load_dotenv()
    WEBHOOK_URL = os.getenv('WEBHOOK_URL')
    DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
    SMTP_USERNAME = os.getenv('SMTP_USERNAME')
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
    TLS_CERT_CHAIN = os.getenv('TLS_CERT_CHAIN')
    TLS_KEY = os.getenv('TLS_KEY')

    if WEBHOOK_URL is None:
        print(f"Variable 'WEBHOOK_URL' not found")
        exit(1)

    

    handler = DiscordRelayHandler(WEBHOOK_URL,client)

    require_auth_setting = False
    require_tls_setting = False
    context = None
    auth = None

    if (SMTP_USERNAME is not None and
        SMTP_PASSWORD is not None):
        print("SMTP_USERNAME and SMTP_PASSWORD specified, authentication is enabled and required.")
        require_auth_setting = True
        auth = Authenticator(SMTP_USERNAME, SMTP_PASSWORD)
    else:
        print("SMTP_USERNAME or SMTP_PASSWORD not specified, authentication is not enabled.")

    if (TLS_CERT_CHAIN is not None and
        TLS_KEY is not None):
        print("TLS_CERT_CHAIN and TLS_KEY specified, TLS is enabled and required.")
        require_tls_setting = True
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(TLS_CERT_CHAIN, TLS_KEY)
    else:
        print("TLS_CERT_CHAIN or TLS_KEY not specified, TLS is not enabled.")

    cont = Controller(handler,
                      hostname='',
                      port=8025,
                      tls_context=context,
                      auth_require_tls=require_tls_setting,
                      authenticator=auth,
                      auth_required=require_auth_setting)
    cont.start()
    

    client.run(DISCORD_TOKEN)
    # Wait for SIGINT or SIGQUIT to stop the server
    sig = signal.sigwait([signal.SIGINT, signal.SIGQUIT])
    print("Shutting down server...")
    cont.stop()




#@client.event
#async def on_ready():
#    print(f'{client.user} has connected to Discord!')



if __name__ == '__main__':
    client = MyClient(command_prefix='!')
    main()

