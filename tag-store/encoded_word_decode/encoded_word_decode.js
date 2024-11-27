//Ugh regex isn't working in the JS engine I use :(
function isHexChar(char) {
  return (char >= '0' && char <= '9') || (char >= 'A' && char <= 'F') || (char >= 'a' && char <= 'f');
}

let parts = input.replaceAll("_"," ").split('=');
output = parts.slice(1).reduce((str, part) =>
  str + (isHexChar(part[0]) && isHexChar(part[1]) ? String.fromCodePoint(parseInt(part.slice(0, 2), 16)) : part.slice(0, 2)) + part.slice(2),
parts[0]);