import asyncio
import os
import email
from email import policy

import requests
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Message
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
        print(f"webhook_url = {self.webhook_url}")
        print(f"webhook_data = {webhook_data}")

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

async def amain(loop):
    # Retrieve the environment variables
    WEBHOOK_URL = os.getenv('WEBHOOK_URL')

    handler = DiscordRelayHandler(WEBHOOK_URL)

    cont = Controller(handler,
                      hostname='',
                      port=8025,
                      auth_required=True)
    cont.start()

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.create_task(amain(loop=loop))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        exit(0)
