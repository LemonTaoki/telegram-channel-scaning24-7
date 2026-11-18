"""Ye script apne laptop pe EK BAAR chalao. Phone + OTP maangega,
phir ek lambi string print karegi. Use Render me TG_SESSION env me daalna.
Is string ko kisi ke saath share mat karna (isse tumhara Telegram account access hota hai)."""
import os
from dotenv import load_dotenv
from telethon.sync import TelegramClient
from telethon.sessions import StringSession

load_dotenv()
with TelegramClient(StringSession(), int(os.environ["TG_API_ID"]), os.environ["TG_API_HASH"]) as c:
    print("\nTG_SESSION =\n" + c.session.save())
