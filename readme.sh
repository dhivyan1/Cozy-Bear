**Cozy Bear** is an AI-powered cybersecurity assistant designed to help non-technical users identify and respond to suspicious files, URLs, domains, IPs, or hashes. It integrates threat intelligence from VirusTotal and AlienVault OTX while leveraging a local Mistral LLM for contextual guidance and remediation instructions.

---

## **Key Features**
- Chat interface for general cybersecurity queries.
- File upload and hash scanning via VirusTotal and AlienVault OTX.
- Context-aware AI prompts users to upload suspicious files when necessary.
- Provides step-by-step remediation instructions for non-technical users.
- Responsive web frontend built with HTML, CSS, and JavaScript.
- In-memory conversation state to track user queries and context.

---

## **Tech Stack**
- **Backend:** Node.js, Express, Axios, Multer  
- **Frontend:** HTML, CSS, JavaScript  
- **APIs & Services:** VirusTotal, AlienVault OTX, Mistral LLM (self-hosted)
