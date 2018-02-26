#! /usr/bin/env python
import os
import json
import telethon
from telethon import TelegramClient
from telethon.errors import SessionPasswordNeededError
from telethon.tl.functions.channels import GetParticipantsRequest
from telethon.tl.types import ChannelParticipantsSearch
from telethon.errors.rpc_error_list import ChatAdminRequiredError
from time import sleep
from harpoon.commands.base import Command
from datetime import date, datetime


def json_serial(obj):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return obj.decode('utf-8')
    raise TypeError("Type %s not serializable" % type(obj))


class CommandTelegram(Command):
    """
    # Telegram

    **Dump information from Telegram**
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
        parser_b.add_argument('--format', '-f', default='text', choices=['text', 'csv', 'json'],
                help="Output format")
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
                messages = client.get_message_history(entity, args.limit)
                if args.format == "text":
                    if len(messages) == 0:
                        print("No messages in thie channel")
                    else:
                        print("%i messages downloaded:" % len(messages))
                        for msg in messages:
                            if isinstance(msg, telethon.tl.types.MessageService):
                                print("[%s] Message Service: %s" % (
                                        msg.date.isoformat(),
                                        msg.action.message
                                    )
                                )
                            else:
                                if msg.media is None:
                                    print("[%s] %s (%i views)" % (
                                            msg.date.isoformat(),
                                            msg.message,
                                            msg.views
                                        )
                                    )
                                else:
                                    print("[%s] Media (%i views)" % (
                                            msg.date.isoformat(),
                                            msg.views
                                        )
                                    )
                elif args.format == "json":
                    msg = [m.to_dict() for m in messages]
                    print(json.dumps(msg, sort_keys=True, indent=4, default=json_serial))
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
                        sleep(1)  # This line seems to be optional, no guarantees!
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
