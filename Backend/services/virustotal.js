const axios = require('axios');

async function queryVirusTotal(ioc) {
  try {
    const urlMap = {
      ip: `https://www.virustotal.com/api/v3/ip_addresses/${ioc.value}`,
      domain: `https://www.virustotal.com/api/v3/domains/${ioc.value}`,
      url: `https://www.virustotal.com/api/v3/urls`,
      hash: `https://www.virustotal.com/api/v3/files/${ioc.value}`,
    };

    const apiKey = process.env.VIRUSTOTAL_API_KEY;

    if (ioc.type === 'url') {
      const urlId = Buffer.from(ioc.value).toString('base64').replace(/=+$/, '');
      const response = await axios.get(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
        headers: { 'x-apikey': apiKey }
      });
      return response.data;
    } else if (urlMap[ioc.type]) {
      const response = await axios.get(urlMap[ioc.type], {
        headers: { 'x-apikey': apiKey }
      });
      return response.data;
    }
    return null;
  } catch (err) {
    console.error('VirusTotal API error:', err.message);
    return null;
  }
}

module.exports = { queryVirusTotal };
