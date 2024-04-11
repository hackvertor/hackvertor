####
# BIG DISCLAIMER
# I only copied the relevant parts of https://pypi.org/project/pyotp/
# The code there is MIT License (MIT License)
# Unfortunately Hackvertor can't do Python type hinting, sad panda, removed all type hinting
# START OF COPIED CODE
####

import calendar
import datetime
import hashlib
import time
import hmac
import base64
import unicodedata

def strings_equal(s1, s2):
    """
    Timing-attack resistant string comparison.

    Normal comparison using == will short-circuit on the first mismatching
    character. This avoids that by scanning the whole string, though we
    still reveal to a timing attack whether the strings are the same
    length.
    """
    s1 = unicodedata.normalize("NFKC", s1)
    s2 = unicodedata.normalize("NFKC", s2)
    return hmac.compare_digest(s1.encode("utf-8"), s2.encode("utf-8"))


class OTP(object):
    """
    Base class for OTP handlers.
    """

    def __init__(
        self,
        s,
        digits = 6,
        digest = hashlib.sha1,
        name = None,
        issuer = None,
    ):
        self.digits = digits
        if digits > 10:
            raise ValueError("digits must be no greater than 10")
        self.digest = digest
        self.secret = s
        self.name = name or "Secret"
        self.issuer = issuer

    def generate_otp(self, input):
        """
        :param input: the HMAC counter value to use as the OTP input.
            Usually either the counter, or the computed integer based on the Unix timestamp
        """
        if input < 0:
            raise ValueError("input must be positive integer")
        hasher = hmac.new(self.byte_secret(), self.int_to_bytestring(input), self.digest)
        hmac_hash = bytearray(hasher.digest())
        offset = hmac_hash[-1] & 0xF
        code = (
            (hmac_hash[offset] & 0x7F) << 24
            | (hmac_hash[offset + 1] & 0xFF) << 16
            | (hmac_hash[offset + 2] & 0xFF) << 8
            | (hmac_hash[offset + 3] & 0xFF)
        )
        str_code = str(10000000000 + (code % 10**self.digits))
        return str_code[-self.digits :]

    def byte_secret(self):
        secret = self.secret
        missing_padding = len(secret) % 8
        if missing_padding != 0:
            secret += "=" * (8 - missing_padding)
        return base64.b32decode(secret, casefold=True)

    @staticmethod
    def int_to_bytestring(i, padding = 8):
        """
        Turns an integer to the OATH specified
        bytestring, which is fed to the HMAC
        along with the secret
        """
        result = bytearray()
        while i != 0:
            result.append(i & 0xFF)
            i >>= 8
        # It's necessary to convert the final result from bytearray to bytes
        # because the hmac functions in python 2.6 and 3.3 don't work with
        # bytearray
        return bytes(bytearray(reversed(result)).rjust(padding, b"\0"))


class TOTP(OTP):
    """
    Handler for time-based OTP counters.
    """

    def __init__(
        self,
        s,
        digits = 6,
        digest = None,
        name = None,
        issuer = None,
        interval = 30,
    ):
        """
        :param s: secret in base32 format
        :param interval: the time interval in seconds for OTP. This defaults to 30.
        :param digits: number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
        :param digest: digest function to use in the HMAC (expected to be SHA1)
        :param name: account name
        :param issuer: issuer
        """
        if digest is None:
            digest = hashlib.sha1

        self.interval = interval
        super(TOTP, self).__init__(s=s, digits=digits, digest=digest, name=name, issuer=issuer)

    def at(self, for_time, counter_offset = 0):
        """
        Accepts either a Unix timestamp integer or a datetime object.

        To get the time until the next timecode change (seconds until the current OTP expires), use this instead:

        .. code:: python

            totp = pyotp.TOTP(...)
            time_remaining = totp.interval - datetime.datetime.now().timestamp() % totp.interval

        :param for_time: the time to generate an OTP for
        :param counter_offset: the amount of ticks to add to the time counter
        :returns: OTP value
        """
        if not isinstance(for_time, datetime.datetime):
            for_time = datetime.datetime.fromtimestamp(int(for_time))
        return self.generate_otp(self.timecode(for_time) + counter_offset)

    def now(self):
        """
        Generate the current time OTP

        :returns: OTP value
        """
        return self.generate_otp(self.timecode(datetime.datetime.now()))

    def verify(self, otp, for_time = None, valid_window = 0):
        """
        Verifies the OTP passed in against the current time OTP.

        :param otp: the OTP to check against
        :param for_time: Time to check OTP at (defaults to now)
        :param valid_window: extends the validity to this many counter ticks before and after the current one
        :returns: True if verification succeeded, False otherwise
        """
        if for_time is None:
            for_time = datetime.datetime.now()

        if valid_window:
            for i in range(-valid_window, valid_window + 1):
                if strings_equal(str(otp), str(self.at(for_time, i))):
                    return True
            return False

        return strings_equal(str(otp), str(self.at(for_time)))

    def timecode(self, for_time):
        """
        Accepts either a timezone naive (`for_time.tzinfo is None`) or
        a timezone aware datetime as argument and returns the
        corresponding counter value (timecode).

        """
        if for_time.tzinfo:
            return int(calendar.timegm(for_time.utctimetuple()) / self.interval)
        else:
            return int(time.mktime(for_time.timetuple()) / self.interval)

####
# END OF COPIED CODE
# BIG DISCLAIMER
# I only copied the relevant parts of https://pypi.org/project/pyotp/
# The code there is MIT License (MIT License)
####
#TODO: In practice it's always 6 digits, SHA-1, but it would be fairly easy to add some ifs and arguments to the TOTP() call if a TOTP would be different once

# As an input use the secret from:
#% zbarimg ~/Downloads/Authenticator-QR-Code.png 
#QR-Code:otpauth://totp/SomeOrg:something?secret=YESHOOLALALFOOOBARKOOKUCK&issuer=SomeOrg
#scanned 1 barcode symbols from 1 images in 0.05 seconds

totp = TOTP(input)
output = str(totp.now())
#input + strHello + str(intTest)