output = input.length() == 0 ? ""
        : "&" + input.replaceAll("(.)","\u0000\$0")
        .bytes.encodeBase64().toString()
        .replaceAll(/=+$/,"") + "-";