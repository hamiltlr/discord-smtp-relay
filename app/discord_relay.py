import os
import io
import datetime
import re
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
try:
    #python 3+
    from configparser import ConfigParser
except:
    # Python 2.7
    from ConfigParser import ConfigParser

class DiscordRelayHandler(Message):
    def __init__(self, client,discordchannels,defaultchannelid):
        self.client = client
        self.discordchannels = discordchannels
        self.defaultchannelid = defaultchannelid
        
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
        print(f'Processing any message attachments')
        for attachment in message.iter_attachments():
            if attachment.get_content_disposition() == "attachment":

                file_obj = io.BytesIO()
                file_obj = attachment.get_payload(decode=True)
                filename = attachment.get_filename()

                #create a discord file from the email attachment payload
                discordfile = discord.File(io.BytesIO(file_obj),filename=filename)
                attachments.append(discordfile)
        #for attachment in message.iter_attachments():

        try:
            channelid = self.get_discord_channel(message.get('to'),
                                message.get('from'),
                                message.get('subject'))
        except Exception as ex:
            print("Error retrieving channel ID using default: " + self.defaultchannelid)

        self.notify_discord_bot(channelid,
                            message.get('to'),
                            message.get('from'),
                            message.get('subject'),
                            msg_body,
                            attachments)
        
    #def handle_message(self, message):


    def notify_discord_bot(self, channelid,to_addr, from_addr, subject, body,attachments = None):
        # Set the properties fo the bot client to values that will be sent to discord.
        print("Generating email at %s" % datetime.datetime.now())
        print(f'Email Subject: "{subject}"')
        self.client.channelid = channelid
        self.client.subject = subject
        self.client.embeds = discord.Embed(title=subject,description="desc")
        self.client.embeds.add_field(name="To",value=to_addr,inline=False)
        print(f'Email To: "{to_addr}"')
        self.client.embeds.add_field(name="From",value=from_addr)
        print(f'Email From: "{from_addr}"')
        self.client.embeds.add_field(name="Subject",value=subject)
        if body is not None:
            chunklength = 1000
            chunks = [body[i:i+chunklength] for i in range(0,len(body),chunklength)]
            print('Email Body length: %s = %s chunks' % (len(body),len(chunks)))
            chunknum = 1
            for chunk in chunks:
                self.client.embeds.add_field(name="Body-%s" %chunknum,value=chunk)
                chunknum += 1
        
        print('Adding Attachments: %s' % len(attachments) )
        self.client.files = attachments
        
        print('Sending email')
        #reset flag
        self.client.msg_sent = False
    #def notify_discord_bot(self, to_addr, from_addr, subject, body,attachments = None):

    def get_discord_channel(self,to_addr, from_addr, subject):
        """
        Gets the discord channel from the message details
        Uses regex on the from, to or subject, depending on what is in the config,
        to determine which channel ID to send a message to.

        """

        print(f'Getting discord channel for to:{to_addr} from:{from_addr} subject:{subject}')

        for discord in self.discordchannels:
            if "to" in self.discordchannels[discord]:
                # look for to regex in to_addr
                if re.match(self.discordchannels[discord].get("to"),to_addr):
                    return int(self.discordchannels[discord].get("channelid"))
            if "from" in self.discordchannels[discord]:
                # look for to regex in to_addr
                if re.match(self.discordchannels[discord].get("from"),from_addr):
                    return int(self.discordchannels[discord].get("channelid"))
            if "subject" in self.discordchannels[discord]:
                # look for to regex in to_addr
                if re.match(self.discordchannels[discord].get("subject"),subject):
                    return int(self.discordchannels[discord].get("channelid"))
        #for discord in self.discordchannels:
        print("Returning default channel id as no rules found")
        return int(self.defaultchannelid)
        

    #def get_discord_channel():

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
        self.subject = "I'm ALIVE"
        self.embeds = None
        self.files = None
        self.channelid = None
        self.channel = None
        self.counter = 1
        
        

    async def on_ready(self):
        self.channel = client.get_channel(self.channelid)  # replace with channel ID that you want to send to
        print(f'{client.user} has connected to discord')
        await self.timer.start()

    @tasks.loop(seconds=1)
    async def timer(self):
        try:
            if not self.msg_sent:
                print("Email content passed to bot for processing.")
                if self.channel is None or self.channel.id != self.channelid:
                    self.channel = client.get_channel(self.channelid)

                print("Sending email: %s" % datetime.datetime.now())
                if self.embeds is not None:
                    await self.channel.send(embed=self.embeds,files=self.files)
                else:
                    await self.channel.send(self.subject,files=self.files)
                self.msg_sent = True 
            #if not self.msg_sent:
            self.counter += 1
            if self.counter % 30 == 0:
                print("Bot Loop %s" % datetime.datetime.now())
                counter = 1
        except Exception as ex:
            print("Error in bot send: " + str(ex))
            pass
    #async def timer(self):

    async def on_message(self,message):
        username = str(message.author).split("#")[0]
        channel = str(message.channel.name)
        user_message = str(message.content)

        print(f'Message {user_message} by {username} on {channel}')

        if message.author == client.user:
            return

        if message.content == "!timer":
            print("timer status: %s " % self.timer.is_running)
            await message.channel.send("timer status: %s " % self.timer.is_running)

    #async def on_message(message):

def main():
    # Retrieve the environment variables
    load_dotenv()
    DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
    TLS_CERT_CHAIN = os.getenv('TLS_CERT_CHAIN')
    TLS_KEY = os.getenv('TLS_KEY')

    if DISCORD_TOKEN is None:
        print(f"Variable 'DISCORD_TOKEN' not found")
        exit(1)

    cp = ConfigParser()
    filename = {"config.ini","/conf/config.ini","/app/config.ini","./config.ini"}
    dataset = cp.read(filename)

    try:
        if len(dataset) == 0:
            raise ValueError( "Failed to open/find all files")

        #smtp section
        smtp_items = dict(cp.items( "smtp" ))
        SMTP_USERNAME = smtp_items.get("username",None)
        SMTP_PASSWORD = smtp_items.get("password",None)
        SMTP_PORT = smtp_items.get("port","8025")
        print("Set smtp username and password from config")

        if os.getenv('SMTP_USERNAME') is not None: 
            SMTP_USERNAME = os.getenv('SMTP_USERNAME')
            print("Override SMTP_USERNAME from env variable")
        if os.getenv('SMTP_PASSWORD') is not None: 
            SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
            print("Override SMTP_PASSWORD from env variable")

        try:
            defaultchannelid = cp.get("default","channelid")
        except:
            print("No Default channelid set in a [default] section.  This is required.")
            exit(1)

        #sets client default channel id
        client.channelid = int(defaultchannelid)

        #emails - discord channel Sections.
        discordchannels = {}
        for section in cp.sections():
            if section != 'smtp':
                sectiondict = dict(cp.items(section))
                print("Section Name: %s" % section)
                print("Section Channel ID: %s" % sectiondict.get("channelid"))
                if "channelid" not in sectiondict:
                    sectiondict["channelid"] = int(defaultchannelid)
                print("Section From: %s" % sectiondict.get("from",None) )
                print("Section To: %s" % sectiondict.get("to",None) )
                print("Section Subject: %s" % sectiondict.get("subject",None) )
                discordchannels[section] = sectiondict
            #if section != 'smtp':  
        #for section in cp.sections(): 

    except Exception as ex:
        print("Error loading config: " + str(ex))
        exit(1)

    handler = DiscordRelayHandler(client,discordchannels, defaultchannelid)

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
                      port=SMTP_PORT,
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




if __name__ == '__main__':
    intents = discord.Intents.default()
    intents.messages = True
    client = MyClient(command_prefix='!',intents=intents)
    main()

