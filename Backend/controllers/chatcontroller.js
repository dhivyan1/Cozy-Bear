const { queryAlienVaultOTX } = require('../services/alienvault');
const { queryVirusTotal } = require('../services/virustotal');
const { callMistral } = require('../services/mistralAI');
const { computeHash } = require('../utils/hash'); // optional: compute file hash

async function handleChat(req, res) {
  try {
    const { message, file } = req.body;

    let ioc = null;

    // Determine if user shared a file or hash
    if (file) {
      // Compute hash if file uploaded
      const hash = await computeHash(file);
      ioc = { type: 'hash', value: hash };
    } else {
      // Try to extract hash or IOC from message
      ioc = extractIOC(message);
    }

    // If a valid IOC (hash/file) is present → check VT and OTX
    if (ioc && (ioc.type === 'hash' || ioc.type === 'file')) {
      const vtResult = await queryVirusTotal(ioc.value);
      if (vtResult.isMalware) return res.json({ remediation: vtResult.details });

      const otxResult = await queryAlienVaultOTX(ioc.value);
      if (otxResult.isThreat) return res.json({ remediation: otxResult.details });

      // If clean, optionally pass to Mistral
      const aiResult = await callMistral(message, ioc);
      return res.json({ remediation: aiResult.analysis });
    }

    // Otherwise → fully use Mistral for general queries
    const aiResult = await callMistral(message);
    res.json({ remediation: aiResult.analysis });

  } catch (err) {
    console.error('Chat API error:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
}

// Simple IOC extraction stub — improve as needed
function extractIOC(message) {
  // Detect hash-like strings or simple file indicators
  const hashMatch = message.match(/\b[a-fA-F0-9]{32,64}\b/); // md5, sha256
  if (hashMatch) return { type: 'hash', value: hashMatch[0] };
  return null;
}

module.exports = { handleChat };
