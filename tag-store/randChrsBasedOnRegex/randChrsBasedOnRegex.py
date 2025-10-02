import re
import random
import string

def randChrsBasedOnRegex(pattern):
    # Match things like [a-z]{4} or [0-5]{10}
    m = re.match(r'(\[[^\]]+\])\{(\d+)\}', pattern)
    if not m:
        raise ValueError("Only patterns of form [chars]{n} are supported")

    char_class, count = m.groups()
    count = int(count)

    # Expand the character class
    # Remove [ and ]
    inner = char_class[1:-1]
    chars = []
    i = 0
    while i < len(inner):
        if i+2 < len(inner) and inner[i+1] == '-':
            start, end = inner[i], inner[i+2]
            chars.extend(chr(c) for c in range(ord(start), ord(end)+1))
            i += 3
        else:
            chars.append(inner[i])
            i += 1

    return ''.join(random.choice(chars) for _ in range(count))

output = randChrsBasedOnRegex(input)