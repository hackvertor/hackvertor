if(max > 0xffff) {
   throw new Error("Max parameter is too large");
}
output = input.split('').map(chr => {
	let characters = '';
	for(let i=chr.codePointAt()+1;i<=max;i++){
		if(i % 256 === chr.codePointAt()) {
			characters += String.fromCodePoint(i);
		}
	}
	return characters;
}).join('');