#! /usr/bin/env python
import os
import json
import telethon
import csv
import sys
import time
from telethon import TelegramClient
from telethon.errors import SessionPasswordNeededError
from telethon.tl.functions.channels import GetParticipantsRequest
from telethon.tl.types import ChannelParticipantsSearch
from telethon.errors.rpc_error_list import ChatAdminRequiredError
from harpoon.commands.base import Command
from datetime import date, datetime


def json_serial(obj):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return obj.decode('utf-8', 'ignore')
    raise TypeError("Type %s not serializable" % type(obj))


class CommandTelegram(Command):
    """
    # Telegram

    **Dump information from Telegram**

    * Get an information on an user : harpoon telegram id USER
    * Dump messages of a channel in json : harpoon telegram messages -f json CHANNEL
    * Dump messages of a channel with media : harpoon telegram messages -f json -D media CHANNEL
    * List users in a group : harpoon telegram users CHANNEL
    """
    name = "telegram"
    description = "Request information from Telegram through the API"
    config = {'Telegram': ['id', 'hash', 'phone']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommands')
        parser_a = subparsers.add_parser('id', help='Query information on a phone number or handle')
        parser_a.add_argument('ID', help='Id to be requested')
        parser_a.set_defaults(subcommand='id')
        parser_b = subparsers.add_parser('messages', help='Get messages from a public channel')
        parser_b.add_argument('ID', help='Id to be requested')
        parser_b.add_argument('--limit', '-l', default=25, type=int,
                help="Limit number of messages to get")
        parser_b.add_argument('--format', '-f', default='text', choices=['text', 'csv', 'json'], help="Output format")
        parser_b.add_argument('--dump', '-D', help="Dump media in the given path")
        parser_b.set_defaults(subcommand='messages')
        parser_c = subparsers.add_parser('users', help='Get user list of a group')
        parser_c.add_argument('ID', help='Id to be requested')
        parser_c.add_argument('--limit', '-l', default=25, type=int,
                help="Limit number of messages to get")
        parser_c.add_argument('--format', '-f', default='text', choices=['text', 'csv', 'json'],
                help="Output format")
        parser_c.set_defaults(subcommand='users')
        self.parser = parser

    def run(self, conf, args, plugins):
        session_file = os.path.join(os.path.expanduser("~"), ".config/harpoon/telegram")
        client = TelegramClient(session_file, int(conf['Telegram']['id']), conf['Telegram']['hash'])
        # FIXME : do not connect if it's help
        client.connect()
        if not client.is_user_authorized():
            client.send_code_request(conf['Telegram']['phone'])
            code_ok = False
            while not code_ok:
                code = input("Enter Telegram code:")
                try:
                    code_ok = client.sign_in(conf['Telegram']['phone'], code)
                except SessionPasswordNeededError:
                    # FIXME: getpass is not imported, that would not work
                    password = getpass('Two step verification enabled. Please enter your password: ')
                    code_ok = client.sign_in(password=password)
        if hasattr(args, 'subcommand'):
            if args.subcommand == 'id':
                try:
                    res = client.get_entity(args.ID)
                    print(json.dumps(res.to_dict(), sort_keys=True, indent=4, default=json_serial))
                except ValueError:
                    print('Identifier not found')
            elif args.subcommand == "messages":
                entity = client.get_entity(args.ID)
                messages = client.get_messages(entity, args.limit)
                users = {}
                if args.dump:
                    if not os.path.exists(args.dump):
                         os.makedirs(args.dump)
                if args.format == "text":
                    if len(messages) == 0:
                        print("No messages in this channel")
                    else:
                        print("%i messages downloaded:" % len(messages))
                        for msg in messages:
                            if isinstance(msg, telethon.tl.types.MessageService):
                                if isinstance(msg.action, telethon.tl.types.MessageActionChatEditPhoto):
                                    print("[%s] Channel Photo Changed" % msg.date.isoformat())
                                elif isinstance(msg.action, telethon.tl.types.MessageActionChannelCreate):
                                    print("[%s] Channel Created" % msg.date.isoformat())
                                elif isinstance(msg.action, telethon.tl.types.MessageActionChatAddUser):
                                    print("[%s] Add Users To the Chat - %s" % (
                                            msg.date.isoformat(),
                                            ", ".join([str(a) for a in msg.action.users])
                                        )
                                    )
                                elif isinstance(msg.action, telethon.tl.types.MessageActionChatDeleteUser):
                                    print("[%s] Remove User from the chat - %i" % (
                                            msg.date.isoformat(),
                                            msg.action.user_id
                                        )
                                    )
                                else:
                                    print("[%s] Message Service: %s" % (
                                            msg.date.isoformat(),
                                            msg.action.message
                                        )
                                    )
                            else:
                                if msg.media is None:
                                    if entity.megagroup:
                                        if msg.from_id not in users:
                                            users[msg.from_id] = client.get_entity(msg.from_id)
                                        print("[%s][%i - @%s] %s" % (
                                                msg.date.isoformat(),
                                                msg.from_id,
                                                users[msg.from_id].username,
                                                msg.message
                                            )
                                        )
                                    else:
                                        print("[%s] %s (%i views)" % (
                                                msg.date.isoformat(),
                                                msg.message,
                                                msg.views
                                            )
                                        )
                                else:
                                    if msg.views:
                                        print("[%s] Media (%i views)" % (
                                                msg.date.isoformat(),
                                                msg.views
                                            )
                                        )
                                    else:
                                        print("[%s] Media" % (msg.date.isoformat()))
                                    if args.dump:
                                        if not os.path.exists(os.path.join(args.dump, str(msg.id) + '.jpg')):
                                            client.download_media(msg.media, os.path.join(args.dump, str(msg.id)))
                                            time.sleep(7)
                elif args.format == "json":
                    msg = [m.to_dict() for m in messages]
                    print(json.dumps(msg, sort_keys=True, indent=4, default=json_serial))
                    if args.dump:
                        for msg in messages:
                            if msg.media is None:
                                if not os.path.exists(os.path.join(args.dump, str(msg.id)+ '.jpg')):
                                    client.download_media(msg.media, os.path.join(args.dump, str(msg.id)))
                                    time.sleep(7)
                elif args.format == "csv":
                    if entity.megagroup:
                        # Chat
                        w = csv.writer(sys.stdout, delimiter=';')
                        w.writerow(["Date", "id", "Username", "userid", "Type", "Message"])
                        for m in messages:
                            if m.from_id not in users:
                                users[m.from_id] = client.get_entity(m.from_id)
                            if isinstance(m, telethon.tl.types.MessageService):
                                w.writerow([m.date.isoformat(), m.id, users[m.from_id].username, m.from_id, m.__class__.__name__, m.action.__class__.__name__])
                            else:
                                w.writerow([m.date.isoformat(), m.id, users[m.from_id].username, m.from_id, m.__class__.__name__, m.message])
                    else:
                        w = csv.writer(sys.stdout, delimiter=';')
                        w.writerow(["Date", "id", "Type", "Information", "Media", "Views"])
                        for m in messages:
                            if isinstance(m, telethon.tl.types.MessageService):
                                if isinstance(m.action, telethon.tl.types.MessageActionChatEditPhoto):
                                    w.writerow([m.date.isoformat(), m.id,  m.__class__.__name__, "Channel Photo Changed", "No", ""])
                                elif isinstance(m.action, telethon.tl.types.MessageActionChannelCreate):
                                    w.writerow([m.date.isoformat(), m.id, m.__class__.__name__, "Channel Created", "No", ""])
                                else:
                                    w.writerow([m.date.isoformat(), m.id, m.__class__.__name__, m.action.__class__.__name__, "No", ""])
                            else:
                                if m.media is None:
                                    # message
                                    w.writerow([m.date.isoformat(), m.id, m.__class__.__name__, m.message, "No", m.views])
                                else:
                                    w.writerow([m.date.isoformat(), m.id, m.__class__.__name__, m.message, "Yes", m.views])
                                    if args.dump:
                                        if not os.path.exists(os.path.join(args.dump, str(m.id) + '.jpg')):
                                            client.download_media(m.media, os.path.join(args.dump, str(m.id)))
                                            # Sleep to avoid being banned
                                            time.sleep(7)
                else:
                    print("Not implemented yet, sorry!")
            elif args.subcommand == "users":
                # List users from a group
                try:
                    entity = client.get_entity(args.ID)
                    offset = 0
                    limit = args.limit
                    all_participants = []

                    while True:
                        participants = client.invoke(GetParticipantsRequest(entity, ChannelParticipantsSearch(''), offset, limit, hash=0))
                        if not participants.users:
                            break
                        all_participants.extend(participants.users)
                        offset += len(participants.users)
                        time.sleep(1)  # This line seems to be optional, no guarantees!
                except ChatAdminRequiredError:
                    print("You don't have required access rights to get this list")
                else:
                    if args.format == "text":
                        for p in all_participants:
                            print("[+] User: %s (%s %s)" % (p.username, p.first_name, p.last_name))
                    elif args.format == "json":
                        users = [u.to_dict() for u in all_participants]
                        print(json.dumps(users, sort_keys=True, indent=4, default=json_serial))
                    else:
                        print("Not implemented yet, sorry!")

            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
