from opentele.td import TDesktop
from opentele.tl import TelegramClient
from opentele.api import API, UseCurrentSession
import asyncio
import binascii
import sys
from AndroidTelePorter import AndroidSession

async def main():

    # Load TDesktop client from tdata folder
    #tdataFolder = r"/mnt/MAKOP/image17/Telegram/tdata"
    tdataFolder = sys.argv[1]
    tdesk = TDesktop(tdataFolder)
    
    # Check if we have loaded any accounts
    assert tdesk.isLoaded()
    for account in tdesk.accounts:
        print("=======") 
        print(account.UserId)
        print(account.MainDcId)
        print(binascii.hexlify(account.localKey.key))
        print(binascii.hexlify(account.authKey.key))
        print(account.api)
        print(account.keyFile)

    # Convert TDesktop to Telethon using the current session.
    client = await tdesk.ToTelethon(session="telethon.session", flag=UseCurrentSession)
    # Use this if you are willing to patch manually telethon.session 
    #client = TelegramClient("telethon.session")
    
    # Connect and print all logged-in sessions of this client.
    # Telethon will save the session to telethon.session on creation.
    await client.connect()
    await client.PrintSessions()
     # Iterate through all dialogs (chats, groups, channels)
    # Iterate through all dialogs (chats, groups, channels)
    print("🔹 Your Telegram Contacts & Chats:")
    async for dialog in client.iter_dialogs():
        if dialog.is_user:  # Ensure it's a private contact
            print(f"Name: {dialog.name} | User ID: {dialog.entity.id} | Username: @{dialog.entity.username or 'N/A'}")
            # 🔹 Fetch messages from the user
            async for message in client.iter_messages(dialog.entity.id, limit=100):  # Adjust limit as needed
                print(f"[{message.date}] {message.sender_id}: {message.text}")


    #Use this to write a tgnet.dat file and use pcap scripts (info i haven't suceed here) 
    session = AndroidSession.from_manual(
        auth_key=account.localKey.key,
        dc_id=account.MainDcId,  # datacenter id (from 1 to 5)
        user_id=account.UserId  # telegram user id
    )  # can be used to create any session (tgnet / tdata / telethon) from auth key, dc id and user id
    session.to_tgnet('converted/tgnet')


asyncio.run(main())

