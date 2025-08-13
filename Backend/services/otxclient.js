const axios = require('axios');

async function queryAlienVaultOTX(ioc) {
  try {
    const typeMap = { ip: 'ip', domain: 'domain', url: 'url', hash: 'file' };
    const type = typeMap[ioc.type];
    if (!type) return null;

    const url = `https://otx.alienvault.com/api/v1/indicators/${type}/${encodeURIComponent(ioc.value)}/general`;
    const response = await axios.get(url);

    return response.data ? response.data.pulse_info : null;
  } catch (err) {
    console.error('AlienVault OTX API error:', err.message);
    return null;
  }
}

module.exports = { queryAlienVaultOTX };
