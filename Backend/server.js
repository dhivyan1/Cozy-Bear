const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const axios = require('axios');
const path = require('path');

const app = express();
const upload = multer({ dest: 'uploads/' });

app.use(bodyParser.json());
app.use(express.static('public'));

let conversationState = {};

// --- Chat endpoint ---
app.post('/api/chat', async (req, res)=>{
  const { userId, message } = req.body;
  if(!userId || !message) return res.status(400).json({error:'Missing userId or message'});

  if(!conversationState[userId]) conversationState[userId] = { stage:'initial', ioc:null };
  const state = conversationState[userId];

  try{
    // If user mentions "suspicious" or "file", Mistral prompts file upload
    if(/suspicious|file|malware|download/i.test(message)){
      return res.json({reply:"If you have a suspicious file or hash, please use the upload button to scan it."});
    }

    // Normal Mistral response for general queries
    const response = await axios.post('http://localhost:11434/v1/completions',{
      model:'mistral',
      prompt:`You are a cybersecurity assistant. Answer user query in simple language:\n${message}`,
      max_tokens:500,
      temperature:0.3
    });

    const reply = response.data?.completion || response.data?.choices?.[0]?.text || "No response from AI assistant.";
    res.json({reply});

  }catch(err){
    console.error(err);
    res.json({reply:'Error contacting Cozy Bear AI'});
  }
});

// --- File upload endpoint ---
app.post('/api/upload', upload.single('file'), async (req,res)=>{
  const file = req.file;
  if(!file) return res.status(400).json({error:'No file uploaded'});

  try{
    const fs = require('fs');
    const crypto = require('crypto');

    const fileBuffer = fs.readFileSync(file.path);
    const sha256 = crypto.createHash('sha256').update(fileBuffer).digest('hex');

    // --- VirusTotal ---
    let vtResult = 'Error fetching VirusTotal';
    try{
      const vtResp = await axios.get(`https://www.virustotal.com/api/v3/files/${sha256}`,{
        headers:{ "x-apikey": process.env.VIRUSTOTAL_API_KEY }
      });
      vtResult = vtResp.data.data.attributes.last_analysis_stats;
    }catch(e){ console.error('VT error:', e.message); }

    // --- AlienVault OTX ---
    let otxResult = 'Error fetching OTX';
    try{
      const otxResp = await axios.get(`https://otx.alienvault.com/api/v1/indicators/file/${sha256}/general`,{
        headers:{ "X-OTX-API-KEY": process.env.OTX_API_KEY }
      });
      const pulse = otxResp.data.pulse_info?.pulses?.[0];
      otxResult = pulse ? `OTX threat found: ${pulse.name}` : "No OTX threat detected";
    }catch(e){ console.error('OTX error:', e.message); }

    // --- Mistral analysis ---
    const mistralResp = await axios.post('http://localhost:11434/v1/completions',{
      model:'mistral',
      prompt:`You are a cybersecurity assistant. Analyze this file hash (SHA256: ${sha256}) with VirusTotal: ${JSON.stringify(vtResult)} and OTX: ${otxResult}. Provide simple, step-by-step remediation.`,
      max_tokens:500,
      temperature:0.3
    });

    const reply = mistralResp.data?.completion || mistralResp.data?.choices?.[0]?.text || 'No reply from AI';
    res.json({reply});

  }catch(err){
    console.error(err);
    res.json({reply:'Error processing uploaded file'});
  }
});

const PORT = process.env.PORT||5000;
app.listen(PORT,()=>console.log(`Cozy Bear server running on port ${PORT}`));
