const crypto = require('crypto');

function calculateHashes(buffer) {
  const md5 = crypto.createHash('md5').update(buffer).digest('hex');
  const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
  return { md5, sha256 };
}

module.exports = { calculateHashes };
