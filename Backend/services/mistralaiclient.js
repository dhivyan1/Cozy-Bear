const axios = require('axios');

async function callMistral(analysis, ioc) {
  try {
    const prompt = `
You are a cybersecurity support assistant.

Analyze this IOC and threat intelligence:

IOC Type: ${ioc.type}
IOC Value: ${ioc.value}
AlienVault OTX Data: ${JSON.stringify(analysis.alienVaultOTX, null, 2)}
VirusTotal Data: ${JSON.stringify(analysis.virusTotal, null, 2)}

Provide simple, step-by-step remediation instructions for a non-technical user.
`;

    const response = await axios.post(process.env.MISTRAL_API_URL, {
      model: 'mistral-7b-v0.1',
      prompt,
      max_tokens: 250,
      temperature: 0.7
    }, {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.MISTRAL_API_KEY}`
      }
    });

    if (response.data && response.data.choices && response.data.choices.length > 0) {
      return response.data.choices[0].text.trim();
    }
    return 'No response from Mistral AI.';
  } catch (error) {
    console.error('Mistral AI API error:', error.response?.data || error.message);
    return 'Error calling Mistral AI.';
  }
}

module.exports = { callMistral };
