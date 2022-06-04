import asyncio
import os
import ssl
import email
import signal
from email import policy

import requests
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Message
from aiosmtpd.smtp import AuthResult, LoginPassword
from html2text import html2text

class DiscordRelayHandler(Message):
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url
        super().__init__(email.message.EmailMessage)

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

    def handle_message(self, message):
        # Extract the message body as a string
        # It will prefer extracting the HTML if possible, and that will be
        # converted to text via html2text. This preserves some of the
        # formatting and looks nicer in Discord
        msg_body = message.get_body(('html','plain')).get_content()
        msg_body = html2text(msg_body)

        self.notify_discord(message.get('to'),
                            message.get('from'),
                            message.get('subject'),
                            msg_body)

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

    # This helper function constructs a dictionary in the format of a "field" object
    # in the Discord webhooks API
    def discord_field(self, name, value="", inline=False):
        r = { 
                "name": name,
                "value": value,
                "inline": inline
            }
        return r

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
            return fail_nothandled

def main():
    # Retrieve the environment variables
    WEBHOOK_URL = os.getenv('WEBHOOK_URL')
    SMTP_USERNAME = os.getenv('SMTP_USERNAME')
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
    TLS_CERT_CHAIN = os.getenv('TLS_CERT_CHAIN')
    TLS_KEY = os.getenv('TLS_KEY')

    if WEBHOOK_URL is None:
        print(f"Variable 'WEBHOOK_URL' not found")
        exit(1)

    handler = DiscordRelayHandler(WEBHOOK_URL)

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
    # Wait for SIGINT or SIGQUIT to stop the server
    sig = signal.sigwait([signal.SIGINT, signal.SIGQUIT])
    print("Shutting down server...")
    cont.stop()

if __name__ == '__main__':
    main()

