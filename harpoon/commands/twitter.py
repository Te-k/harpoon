#! /usr/bin/env python
import sys
import json
from harpoon.commands.base import Command
from harpoon.lib.bird import Bird

class CommandTwitter(Command):
    name = "twitter"
    description = "Request Twitter information"

    def add_arguments(self, parser):
        parser.add_argument('--user', '-u',
	    	help='Get user infos')
        parser.add_argument('--tweets', '-t',
            help='Download tweets of an user')
        parser.add_argument('--tweet', '-T',
            help='Download tweet with the given id')
        parser.add_argument('--save', '-s',
            help='save all infos about an user and their tweets')

    def run(self, conf, args):
        if 'Twitter' not in conf:
            print('Invalid configuration for Twitter plugin, quitting...')
            sys.exit(1)
        for attr in ['consumer_key', 'consumer_secret', 'access_token', 'access_token_secret']:
            if attr not in conf['Twitter']:
                print('Invalid configuration for Twitter plugin, quitting...')
                sys.exit(1)

        bird = Bird(conf)

        if args.user:
            a = bird.get_profile_information(args.user)
            print(json.dumps(a._json, sort_keys=True, indent=4, separators=(',', ': ')))
        elif args.tweets:
            a = bird.get_user_tweets(args.tweets, limit=1000)
            for page in a:
                # FIXME : improve this
                print(json.dumps(page, sort_keys=True, indent=4, separators=(',', ': ')))
        elif args.tweet:
            a = bird.get_tweet(args.tweet)
            print(json.dumps(a._json, sort_keys=True, indent=4, separators=(',', ': ')))
        elif args.save:
            data = {}
            a = bird.get_profile_information(args.save)
            data["user"] = a._json
            b = bird.get_user_tweets(args.save)
            data["tweets"] = []
            for t in b:
                data["tweets"].append(t._json)
            print(json.dumps(data))
