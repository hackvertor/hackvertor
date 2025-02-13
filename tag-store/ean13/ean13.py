# Takes a number as an input and ignores dots in the input, then calculates EAN13 checksum, see https://en.wikipedia.org/wiki/International_Article_Number
# the "append" parameter can be set to 0 or 1.
# Examples:
# <@_ean13(1,'[...]')>756.9217.0769.8</@_ean13> -> 756.9217.0769.85
# <@_ean13(0,'[...]')>756.9217.0769.8</@_ean13> -> 5
# Was tested with de-facto Swiss Social Security numbers (AHV/AVS numbers)
# see also https://www.pentagrid.ch/en/blog/burp-suite-hackvertor-custom-tags-email-sms-tan-multi-factor-authentication/
z=input
y=z.replace('.','')
checksum=str(10-(sum([3*int(x) for x in y[1:][::-2]])+sum([int(x) for x in y[::-1][1::2]]))%10)[-1]
output = z+checksum if append else checksum
