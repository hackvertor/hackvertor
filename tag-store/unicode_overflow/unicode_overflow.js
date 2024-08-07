output = input.split('').map(chr =>
	String.fromCodePoint(mask + chr.codePointAt())
).join('');