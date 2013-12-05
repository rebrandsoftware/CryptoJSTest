function encode_utf8(s) {
  try {
      s = encodeURIComponent(s);
  } catch(err) {
      
  }
  try {
      s = unescape(s);
  } catch(err) {
      
  }
  return s;
}

function decode_utf8(s) {
  try {
      s = escape(s);
  } catch (err) {
      
  }
  try {
      s = decodeURIComponent(s);
  } catch (err) {
      
  }
  return s;
}
