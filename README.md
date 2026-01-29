# See-SURF

Security scanner (now powered with AI 🤖) to find potential Server Side Request Forgery (SSRF) parameters in your web application. See-SURF not only helps you detect potential SSRF parameters but also helps you validate it, protecting your application with system and user data compromise.

![alt text](https://github.com/In3tinct/See-SURF/blob/master/See-SURF.png?raw=true)

## 🎓 Citation
Please cite, If you use this software in your Research papers, articles etc.

```
@software{Agrawal_See-SURF_Detect_SSRF_2019,
author = {Agrawal, Vaibhav},
month = jul,
title = {{See-SURF: Detect SSRF security vulnerability}},
url = {https://github.com/In3tinct/See-SURF},
version = {2.0.0},
year = {2019}
}
```

## 🚀 Key Features

- Automated Reconnaissance: Multi-threaded crawler that gathers and parses data to identify potential SSRF parameters using strong regex matching (e.g., matching keywords like url, website, or IP addresses). Supports cookie-based authentication to scan endpoints behind login pages.

- Burp Suite Integration: Seamlessly parses Burp Suite sitemaps (.xml) to discover a wider range of parameters before crawling.

- Validation & Exploitation: The new AI integration features AI-powered detection through providers like Google Gemini and OpenAI by analyzing response headers and generating custom payloads, a smart pivot mechanism for targeting internal services like AWS Metadata, and automated vulnerability validation to confirm the leakage of sensitive data (for Reflected/Non-blind SSRF).
 
- For Blind SSRF Detection, Integrated Out-of-Band (OOB) detection using Webhook.site to identify vulnerabilities where the server does not return a direct response.

![alt text](https://github.com/In3tinct/See-SURF/blob/master/SSRF%20in%20action.png?raw=true)

## ⚙️ Installation
```bash
git clone https://github.com/In3tinct/See-SURF.git
cd See-SURF/
pip3 install -r requirements.txt
```

## 💻 How to use?

#### Basic Command
 ```bash
python3 see-surf.py -H https://www.target.com
```
#### AI-Enhanced Scanning (New & Recommended)
```bash
# Using Google Gemini
python3 see-surf.py -H http://vulnerable-site.com -p google -m gemini-1.5-flash --api-key YOUR_KEY

# Using OpenAI GPT-4
python3 see-surf.py -H http://vulnerable-site.com -p openai -m gpt-4 -a YOUR_KEY

# Using local Ollama
python3 see-surf.py -H http://vulnerable-site.com -p ollama -m llama3
```

#### Authenticated Scan

 ```bash
python3 see-surf.py -H https://www.target.com -c "cookie_name1=value1 cookie_name2=value2"
```

#### Authenticated with Using Burp Suite Sitemap

```bash
 python3 see-surf.py -H https://www.google.com -c cookie_name1=value1 cookie_name2=value2 -b burp_file.xml
```

`-H` Host name/Ip address to scan<br/>
`-c` Cookies for authenticated scanning, seperated by space (Some websites use multiple cookies for session tracking<br/>
`-p` AI Provider: [ollama](https://github.com/ollama/ollama) (for local inference), [gemini](https://ai.google.dev/), OpenAI [chatgpt](https://platform.openai.com/settings/organization/api-keys), Anthropic [claude](https://console.anthropic.com/settings/keys) <br/>
`-m` Specific model name (e.g., gemini-1.5-flash, gpt-4o, llama3). <br/>
`-a` API Key for the selected provider (can also be set as API_KEY env var). <br/>
`-e` For testing Blind-SSRF OOBE request with your custom external domain in the format http://google.com, else webhook.site will be used by default. <br/>
`-b` (Optional but recommended) - Spider the request using burpsuite site map, export the site map file and give it to see-surf as input (check detailed features on how to do it). <br/>
`-v` (Optional) By default, normal mode is On, with a verbose switch you would see the same vulnerable param in different endpoints. The same parameter may not be sanitized at all places. But verbose mode generates a lot of noise. <br/>

### Detailed Features

[-] <b>-b switch</b> Burp's site map shows the information that Burp collects as you explore your target application like URLs collected etc. Provide burp sitemap files for a better discovery of potential SSRF parameters. The script would first parse the burp file and try to identify potential params and then run the built in crawler on it <br/><br/>
Browser the target with your burpsuite running at the background, make some GET/POST requests, the more the better. Then go to target, right click-> "Save selected Items" and save it. Provide to the script as follows. <br/>

</br>![alt text](https://user-images.githubusercontent.com/18059590/61342249-6a644a00-a7fe-11e9-87e8-3b26305cd8b5.png))

## 🤔 How it Works
1. **Discovery**: The script crawls the target for \<a\> links and \<form\> inputs, or parses a Burp sitemap file.

2. **Parameter Matching**: It looks for keywords in parameter names (e.g., url, redirect, dest) or URL patterns in values.

3. **Canary Probing (Non-Blind)**: It first attempts to fetch http://example.com. If the "Example Domain" signature is found in the response, it raises a potential Reflected/Non-Blind SSRF.

4. **AI Fingerprinting & Exploitation (Non-Blind)**: If AI is enabled, it analyzes server headers & tech stack and generates specific internal payloads (AWS, etc.).

5. **Validation (Non-Blind)**: The AI reviews the result of the attack response to verify if the data returned is actually sensitive or internal information, reducing any false positives.

6. **OOBE Probing (Blind)**: For every potential parameter, it generates a unique Webhook.site payload. It then polls the Webhook API to confirm if the target server made an external request.

## 🤝 Contribute
- Report bugs.
- Suggestions for improvement.
- Suggestions for future extensions.

## 🔮 Future Extensions
- ✅ AI integration for context-aware payload generation and Reflected SSRF.
- ✅ Probing for Blind SSRF.
- Exploitation for Blind SSRF.

## ⚠️ Disclaimer
Use See-SURF for scanning targets with prior mutual consent. It is the end user's responsibility and the developer assumes no liability and is not responsible for any misuse or damage caused by this program. Only use this tool for educational purposes or on domains you have explicit permission to test. Use it at your own risk.

## 📜 License
GNUV3 © [In3tinct]
