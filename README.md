# See-SURF

Security scanner (now powered with AI 🤖) to find potential Server Side Request Forgery (SSRF) parameters in a web application. See-SURF helps you detect potential SSRF parameters and validates the finding it by making a DNS/HTTP request back to your server. It can be added to your arsenal of recon while doing bug hunting/web security testing.

![alt text](https://github.com/In3tinct/See-SURF/blob/master/See-SURF.png?raw=true)

## 🚀 Key Features

- Automated Reconnaissance: Multi-threaded crawler that gathers and parses data to identify potential SSRF parameters using strong regex matching (e.g., matching keywords like url, website, or IP addresses).

- Burp Suite Integration: Seamlessly parses Burp Suite sitemaps (.xml) to discover a wider range of parameters before crawling.

- Authenticated Scanning: Supports cookie-based authentication to scan endpoints behind login pages.

- Verbose Reporting: Optional verbose mode to track parameter sanitization across different endpoints.

- Validation & Exploitation: The new AI integration features AI-powered detection through providers like Google Gemini and OpenAI to analyze response headers, a smart pivot mechanism for targeting internal services like AWS Metadata, and automated vulnerability validation to confirm the leakage of sensitive data.

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

` -H` - Host name/Ip address fo the target<br/>
` -c` - Cookies for authenticated scanning, seperated by space (Some websites use multiple cookies for session tracking<br/>
` -b` (Optional but recommended) - Spider the request using burpsuite site map, export the site map file and give it to see-surf as input (check detailed features on how to do it)<br/>
` -p` (Optional but recommended) - Your own web server/burp collaborator, the script will try to connect back for validation of SSRF params<br/>
` -v` (Optional) By default, normal mode is On, with a verbose switch you would see the same vulnerable param in different endpoints. The same parameter may not be sanitized at all places. But verbose mode generates a lot of noise.
`-p` --provider	AI Provider: google, openai, anthropic, or ollama. [gemini](https://ai.google.dev/), OpenAI [chatgpt](https://platform.openai.com/settings/organization/api-keys), Anthropic [claude](https://console.anthropic.com/settings/keys)
`-m` --model	Specific model name (e.g., gemini-1.5-flash, gpt-4o, llama3).
`-a` --api-key	API Key for the selected provider (can also be set as API_KEY env var).

### Detailed Features

[-] <b>-b switch</b> Burp's site map shows the information that Burp collects as you explore your target application like URLs collected etc. Provide burp sitemap files for a better discovery of potential SSRF parameters. The script would first parse the burp file and try to identify potential params and then run the built in crawler on it <br/><br/>
Browser the target with your burpsuite running at the background, make some GET/POST requests, the more the better. Then go to target, right click-> "Save selected Items" and save it. Provide to the script as follows. <br/>

</br>![alt text](https://user-images.githubusercontent.com/18059590/61342249-6a644a00-a7fe-11e9-87e8-3b26305cd8b5.png))

## 🤔 How it Works
1. **Discovery**: The script crawls the target for \<a\> links and \<form\> inputs, or parses a Burp sitemap file.

2. **Parameter Matching**: It looks for keywords in parameter names (e.g., url, redirect, dest) or URL patterns in values.

3. **Canary Probing**: It first attempts to fetch http://example.com. If the "Example Domain" signature is found in the response, it raises a potential Non-Blind SSRF.

4. **AI Fingerprinting**: If AI is enabled, it sends the response headers to the LLM to identify the server stack (e.g., AWS, PHP, Tomcat).

5. **Exploitation**: The AI generates specific internal payloads (like 169.254.169.254 for AWS or file:///etc/passwd for Linux).

6. **Validation**: The AI reviews the result of the attack response to verify if the data returned is actually sensitive or internal information.

## 🤝 Contribute
- Report bugs.
- Suggestions for improvement.
- Suggestions for future extensions.

## 🔮 Future Extensions
- Integration for Blind SSRF.

## 📜 License
GNUV3 © [In3tinct]
