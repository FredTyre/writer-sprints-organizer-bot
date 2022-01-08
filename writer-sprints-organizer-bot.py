import slack
import os
from pathlib import Path
from dotenv import load_dotenv
from flask import Flask
from slackeventsapi import SlackEventAdapter
import hmac
import hashlib
import time

env_path = Path('.') / '.env'
load_dotenv(dotenv_path = env_path)

app = Flask(__name__)
slack_event_adapter = SlackEventAdapter(os.environ['SIGNING_SECRET'], '/slack/events', app)

client = slack.WebClient(token=os.environ['SLACK_TOKEN'])

client.chat_postMessage(channel='#test', text="Hello!")

BOT_ID = client.api_call("auth.test")['user_id']

def verify_request(request):
    slack_signing_secret_in_bytes = bytes(os.environ['SIGNING_SECRET'], "utf-8")
    request_body = request.get_data().decode()
    slack_request_timestamp = request.headers["X-Slack-Request-Timestamp"]
    slack_signature = request.headers["X-Slack-Signature"]
    # Check that the request is no more than 60 seconds old
    if (int(time.time()) - int(slack_request_timestamp)) > 60:
        print("Verification failed. Request is out of date.")
        return False
    
    # Create a basestring by concatenating the version, the request timestamp, and the request body
    basestring = f"v0:{slack_request_timestamp}:{request_body}".encode("utf-8")
    # Hash the basestring using your signing secret, take the hex digest, and prefix with the version number
    my_signature = (
        "v0=" + hmac.new(os.environ['SIGNING_SECRET'], basestring, hashlib.sha256).hexdigest()
    )
    # Compare the resulting signature with the signature on the request to verify the request
    if hmac.compare_digest(my_signature, slack_signature):
        return True
    else:
        print("Verification failed. Signature invalid.")
        return False

@slack_event_adapter.on('message')
def message(payload):
    print(payload)
    event = payload.get('event', {})
    channel_id = event.get('channel')
    user_id = event.get('user')
    text = event.get('text')

    if BOT_ID != user_id:
        client.chat_postMessage(channel=channel_id, text=text)

if __name__ == "__main__":
    app.run(debug=True)