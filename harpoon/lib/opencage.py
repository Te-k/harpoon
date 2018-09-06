import requests
import collections
import six
from datetime import datetime
from decimal import Decimal


class OpenCageGeocodeError(Exception):

    """Base class for all errors/exceptions that can happen when geocoding."""

    pass


class InvalidInputError(OpenCageGeocodeError):

    """
    There was a problem with the input you provided.

    :var bad_value: The value that caused the problem
    """

    def __init__(self, bad_value):
        self.bad_value = bad_value

    def __unicode__(self):
        return "Input must be a unicode string, not "+repr(self.bad_value)[:100]

    __str__ = __unicode__


class UnknownError(OpenCageGeocodeError):

    """There was a problem with the OpenCage server."""

    pass

class RateLimitExceededError(OpenCageGeocodeError):

    """
    Exception raised when account has exceeded it's limit.
    :var datetime reset_time: When your account limit will be reset.
    :var int reset_to: What your account will be reset to.
    """

    def __init__(self, reset_time, reset_to):
        """Constructor."""
        self.reset_time = reset_time
        self.reset_to = reset_to

    def __unicode__(self):
        """Convert exception to a string."""
        return "Your rate limit has expired. It will reset to {0} on {1}".format(self.reset_to, self.reset_time.isoformat())

    __str__ = __unicode__


class OpenCageGeocode(object):

    """
    Geocoder object.
    Initialize it with your API key:
        >>> geocoder = OpenCageGeocode('your-key-here')
    Query:
        >>> geocoder.geocode("London")
    Reverse geocode a latitude & longitude into a point:
        >>> geocoder.reverse_geocode(51.5104, -0.1021)
    """

    url = 'http://api.opencagedata.com/geocode/v1/json'
    key = ''

    def __init__(self, key):
        """Constructor."""
        self.key = key

    def geocode(self, query, **kwargs):
        """
        Given a string to search for, return the results from OpenCage's Geocoder.
        :param string query: String to search for
        :returns: Dict results
        :raises InvalidInputError: if the query string is not a unicode string
        :raises RateLimitExceededError: if you have exceeded the number of queries you can make. Exception says when you can try again
        :raises UnknownError: if something goes wrong with the OpenCage API
        """
        if six.PY2:
            # py3 doesn't have unicode() function, and instead we check the text_type later
            try:
                query = unicode(query)
            except UnicodeDecodeError:
                raise InvalidInputError(bad_value=query)

        if not isinstance(query, six.text_type):
            raise InvalidInputError(bad_value=query)

        data = {
            'q': query,
            'key': self.key
        }
        # Add user parameters
        data.update(kwargs)

        url = self.url
        response = requests.get(url, params=data)

        if (response.status_code == 402 or response.status_code == 429):
            # Rate limit exceeded
            reset_time = datetime.utcfromtimestamp(response.json()['rate']['reset'])
            raise RateLimitExceededError(reset_to=int(response.json()['rate']['limit']), reset_time=reset_time)

        elif response.status_code == 500:
            raise UnknownError("500 status code from API")

        try:
            response_json = response.json()
        except ValueError:
            raise UnknownError("Non-JSON result from server")

        if 'results' not in response_json:
            raise UnknownError("JSON from API doesn't have a 'results' key")


        return floatify_latlng(response_json['results'])

    def reverse_geocode(self, lat, lng, **kwargs):
        """
        Given a latitude & longitude, return an address for that point from OpenCage's Geocoder.
        :param lat: Latitude
        :param lng: Longitude
        :return: Results from OpenCageData
        :rtype: dict
        :raises RateLimitExceededError: if you have exceeded the number of queries you can make. Exception says when you can try again
        :raises UnknownError: if something goes wrong with the OpenCage API
        """
        return self.geocode(_query_for_reverse_geocoding(lat, lng), **kwargs)


def _query_for_reverse_geocoding(lat, lng):
    """
    Given a lat & lng, what's the string search query.
    If the API changes, change this function. Only for internal use.
    """
    # have to do some stupid f/Decimal/str stuff to (a) ensure we get as much
    # decimal places as the user already specified and (b) to ensure we don't
    # get e-5 stuff
    return "{0:f},{1:f}".format(Decimal(str(lat)), Decimal(str(lng)))


def float_if_float(float_string):
    try:
        float_val = float(float_string)
        return float_val
    except ValueError:
        return float_string


def floatify_latlng(input_value):
    """
    Work around a JSON dict with string, not float, lat/lngs.
    Given anything (list/dict/etc) it will return that thing again, *but* any
    dict (at any level) that has only 2 elements lat & lng, will be replaced
    with the lat & lng turned into floats.
    If the API returns the lat/lng as strings, and not numbers, then this
    function will 'clean them up' to be floats.
    """
    if isinstance(input_value, collections.Mapping):
        if len(input_value) == 2 and sorted(input_value.keys()) == ['lat', 'lng']:
            # This dict has only 2 keys 'lat' & 'lon'
            return {'lat': float_if_float(input_value["lat"]), 'lng': float_if_float(input_value["lng"])}
        else:
            return dict((key, floatify_latlng(value)) for key, value in input_value.items())
    elif isinstance(input_value, collections.MutableSequence):
        return [floatify_latlng(x) for x in input_value]
    else:
        return input_value
