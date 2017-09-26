import tweepy

class Bird(object):
    def __init__(self, config):
        self.consumer_key = config['consumer_key']
        self.consumer_secret = config['consumer_secret']
        self.access_token = config['access_token']
        self.access_token_secret = config['access_token_secret']
        self.api = None

    def _authenticate(self):
        """
        Authenticate on twitter
        """
        auth = tweepy.OAuthHandler(self.consumer_key, self.consumer_secret)
        auth.set_access_token(self.access_token, self.access_token_secret)
        self.api = tweepy.API(auth)

    def get_profile_information(self, username):
        """
        Get profile information on an account
        """
        if self.api is None:
            self._authenticate()

        return self.api.get_user(screen_name=username)

    def get_user_tweets(self, username, since_id=None):
        """
        Download all tweets for an user
        Max is around 3200 tweets
        """
        if self.api is None:
            self._authenticate()
        tweets = []
        if since_id:
            cursor = tweepy.Cursor(self.api.user_timeline, screen_name=username, since_id=since_id)
        else:
            cursor = tweepy.Cursor(self.api.user_timeline, screen_name=username)

        for item in cursor.items():
            tweets.append(item)

        return tweets

    def get_searched_tweets(self, hashtag, since_id=None):
        """
        Search all tweets for a hashtag
        """
        if self.api is None:
            self._authenticate()

        tweets = []
        if since_id:
            cursor = tweepy.Cursor(self.api.search, q=hashtag, count=100, since_id=since_id)
        else:
            cursor = tweepy.Cursor(self.api.search, q=hashtag, count=100)
        try:
            for item in cursor.items():
                tweets.append(item)
        except tweepy.error.TweepError:
            print("Reached Twitter rate limit")
        return tweets

    def get_tweet(self, tweet_id):
        """
        Return a Tweepy status for this id
        """
        if self.api is None:
            self._authenticate()
        return self.api.get_status(tweet_id)
