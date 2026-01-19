# See-SURF

Security scanner to find potential Server Side Request Forgery (SSRF) parameters in a web application. See-SURF helps you detect potential SSRF parameters and validates the finding it by making a DNS/HTTP request back to your server. It can be added to your arsenal of recon while doing bug hunting/web security testing.

![alt text](https://github.com/In3tinct/See-SURF/blob/master/See-SURF.png?raw=true)

## 🚀 Key Features

- Automated Reconnaissance: Multi-threaded crawler that gathers and parses data to identify potential SSRF parameters using strong regex matching (e.g., matching keywords like url, website, or IP addresses).

- Burp Suite Integration: Seamlessly parses Burp Suite sitemaps (.xml) to discover a wider range of parameters before crawling.

- Authenticated Scanning: Supports cookie-based authentication to scan endpoints behind login pages.

- Validation & Exploitation: Automatically attempts to make external requests to your listener (e.g., Burp Collaborator or a custom server) to confirm vulnerabilities.

- Verbose Reporting: Optional verbose mode to track parameter sanitization across different endpoints.

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
git clone https://github.com/In3tinct/See-SURF.git<br/>
cd See-SURF/<br/>
pip3 install -r requirements.txt<br/>
```

## 💻 How to use?

#### Basic Command
 ```bash
python3 see-surf.py -H https://www.target.com -p http://your-listener-ip:8000
```
#### Authenticated Scan

 ```bash
python3 see-surf.py -H https://www.target.com -c "cookie_name1=value1 cookie_name2=value2" -p http://your-listener-ip:8000
```

#### Authenticated with Using Burp Suite Sitemap (Recommendeded)

```bash
 python3 see-surf.py -H https://www.google.com -c cookie_name1=value1 cookie_name2=value2 -b burp_file.xml -p http://72.72.72.72:8000
```

` -H` - Host name/Ip address fo the target<br/>
` -c` - Cookies for authenticated scanning, seperated by space (Some websites use multiple cookies for session tracking<br/>
` -b` (Optional but recommended) - Spider the request using burpsuite site map, export the site map file and give it to see-surf as input (check detailed features on how to do it)<br/>
` -p` (Optional but recommended) - Your own web server/burp collaborator, the script will try to connect back for validation of SSRF params<br/>
` -v` (Optional) By default, normal mode is On, with a verbose switch you would see the same vulnerable param in different endpoints. The same parameter may not be sanitized at all places. But verbose mode generates a lot of noise.

### Detailed Features

[-] <b>-b switch</b> Burp's site map shows the information that Burp collects as you explore your target application like URLs collected etc. Provide burp sitemap files for a better discovery of potential SSRF parameters. The script would first parse the burp file and try to identify potential params and then run the built in crawler on it <br/><br/>
Browser the target with your burpsuite running at the background, make some GET/POST requests, the more the better. Then go to target, right click-> "Save selected Items" and save it. Provide to the script as follows. <br/>

</br>![alt text](https://user-images.githubusercontent.com/18059590/61342249-6a644a00-a7fe-11e9-87e8-3b26305cd8b5.png))

[-] <b>-p switch</b> Fire up burpsuite collaborator and pass the host with -p parameter Or start a simple python http server and wait for the 
vulnerable param to execute your request. <b>(Highly Recommended)</b><br/>
(This basically helps in exploiting GET requests, for POST you would need to try to exploit it manually)<br/>
Payload will get executed with the param at the end of the string so its easy to identify which one is vulnerable.
For example: http://72.72.72.72:8000/vulnerableparam <br/>

![alt text](https://user-images.githubusercontent.com/18059590/61342277-849e2800-a7fe-11e9-832b-7de37cb027ff.png)

## 🤝 Contribute
- Report bugs.
- Suggestions for improvement.
- Suggestions for future extensions.

## 🔮 Future Extensions
- Include more places to look for potential params like Javascript files.
- Exploitation, send internal/localhost URLs and check responses, instead of external server.
- Finding potential params during redirection.
- Hidden parameters.

## 📜 License
GNUV3 © [In3tinct]
