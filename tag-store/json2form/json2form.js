/**
 * Hackvertor Tag: json2form
 * Usage: <@json2form>{"name":"John","age":30}<@/json2form>
 */

function json2form(input, options) {
  const opts = Object.assign({
    arrayFormat: 'indices', // 'indices', 'brackets', 'repeat', 'comma'
    delimiter: '&',
    encode: true,
    skipNulls: false,
    allowDots: false,
    addQueryPrefix: false,
    sort: false
  }, options);
  
  // Parse JSON if it's a string
  let data;
  if (typeof input === 'string') {
    try {
      data = JSON.parse(input);
    } catch (e) {
      throw new Error('Invalid JSON string provided');
    }
  } else {
    data = input;
  }
  
  // Convert object to query string and return
  return objectToQueryString(data, opts);
}

function objectToQueryString(obj, options) {
  if (obj === null || typeof obj === 'undefined') {
    return '';
  }
  
  const pairs = [];
  
  // Get keys and optionally sort them
  let keys = Object.keys(obj);
  if (options.sort) {
    keys = keys.sort(typeof options.sort === 'function' ? options.sort : undefined);
  }
  
  // Process each key-value pair
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    const value = obj[key];
    
    if (options.skipNulls && value === null) {
      continue;
    }
    
    const encodedPairs = serializeValue(key, value, options);
    for (let j = 0; j < encodedPairs.length; j++) {
      pairs.push(encodedPairs[j]);
    }
  }
  
  const result = pairs.join(options.delimiter);
  return options.addQueryPrefix && result ? '?' + result : result;
}

function serializeValue(key, value, options, prefix) {
  prefix = prefix || '';
  const fullKey = prefix ? prefix + (options.allowDots ? '.' + key : '[' + key + ']') : key;
  
  if (value === null) {
    if (options.skipNulls) {
      return [];
    }
    return [encodeKeyValue(fullKey, '', options)];
  }
  
  if (typeof value === 'undefined') {
    return [];
  }
  
  if (Array.isArray(value)) {
    return serializeArray(fullKey, value, options);
  }
  
  if (typeof value === 'object' && value !== null) {
    return serializeObject(fullKey, value, options);
  }
  
  // Primitive value
  return [encodeKeyValue(fullKey, value, options)];
}

function serializeArray(key, array, options) {
  if (array.length === 0) {
    return options.allowEmptyArrays ? [encodeKeyValue(key + '[]', '', options)] : [];
  }
  
  const pairs = [];
  
  for (let i = 0; i < array.length; i++) {
    const value = array[i];
    let arrayKey;
    
    switch (options.arrayFormat) {
      case 'indices':
        arrayKey = key + '[' + i + ']';
        break;
      case 'brackets':
        arrayKey = key + '[]';
        break;
      case 'repeat':
        arrayKey = key;
        break;
      case 'comma':
        // For comma format, join all values with comma
        if (i === 0) {
          const values = array.map(v => 
            typeof v === 'object' ? JSON.stringify(v) : String(v)
          ).join(',');
          pairs.push(encodeKeyValue(key, values, options));
        }
        continue;
      default:
        arrayKey = key + '[' + i + ']';
    }
    
    if (typeof value === 'object' && value !== null) {
      if (Array.isArray(value)) {
        const subPairs = serializeArray(arrayKey, value, options);
        pairs.push(...subPairs);
      } else {
        const subPairs = serializeObject(arrayKey, value, options);
        pairs.push(...subPairs);
      }
    } else {
      pairs.push(encodeKeyValue(arrayKey, value, options));
    }
  }
  
  return pairs;
}

function serializeObject(key, obj, options) {
  const pairs = [];
  const keys = Object.keys(obj);
  
  for (let i = 0; i < keys.length; i++) {
    const subKey = keys[i];
    const value = obj[subKey];
    
    if (options.skipNulls && value === null) {
      continue;
    }
    
    const subPairs = serializeValue(subKey, value, options, key);
    pairs.push(...subPairs);
  }
  
  return pairs;
}

function encodeKeyValue(key, value, options) {
  const encodedKey = options.encode ? encodeURIComponent(key) : key;
  const encodedValue = options.encode ? encodeURIComponent(String(value)) : String(value);
  return encodedKey + '=' + encodedValue;
}

output = json2form(input)



