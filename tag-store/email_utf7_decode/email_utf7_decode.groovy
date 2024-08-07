output = input.replaceAll("&[a-zA-Z0-9]+-", { match ->
    return new String(match.replaceAll("[&-]","").decodeBase64())
})