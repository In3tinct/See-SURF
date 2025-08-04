# See-SURF

A Python based scanner to find potential SSRF parameters in a web application. See-SURF helps you detect potential SSRF parameters and validates the finding it by making a DNS/HTTP request back to your server. It can be added to your arsenal of recon while doing bug hunting/web security testing.

![alt text](https://user-images.githubusercontent.com/18059590/61342276-849e2800-a7fe-11e9-9f2a-7ba3835903a8.png)

## Citation
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

## Tech/framework used
<b>Built with</b>
- `Python3`

## Installation
`git clone https://github.com/In3tinct/See-SURF.git`<br/>
`cd See-SURF/`<br/>
`pip3 install BeautifulSoup4`<br/>
`pip3 install requests`

## How to use?
 <b>Complete Command would look like this </b> <br/>
 
 <b>`python3 see-surf.py -H https://www.google.com -c cookie_name1=value1 cookie_name2=value2 -b burp_file.xml -p http://72.72.72.72:8000` </b><br/>
 
` -H - Host name/Ip address fo the target`<br/>
` -c - Cookies for authenticated scanning, seperated by space (Some websites use multiple cookies for session tracking`<br/>
` -b (Optional but recommended) - Spider the request using burp, export the site map file and give it to see-surf as input (check detailed features on how to do it)`<br/>
` -p (Optional but recommended) - Your own web server/burp collaborator, the script will try to connect back for validation of SSRF params`<br/><br/>

## Features
1) Multi-threaded In-built crawler to run and gather as much data as possible to parse and identify potentially vulnerable SSRF parameters with a strong regex matches in GET/POST URL parameters containing, potentially vulnerable keywords like URL/website etc. Also, checks the parameter values for any URL or IP address passed.

For Example, Matches would look like -

For GET request  - `google.com/url=https://yahoo.com` <br/>
`google.com/q=https://yahoo.com` <br/>
For POST/FORMS - `<input type="text" name="url" value="https://google.com" placeholder="https://msn.com">`
<br/><br/>
2) Takes burp's sitemap as input. Check detailed features for more details.
<br/><br/>
3) Supply cookies for an authenticated scanning.<br/>
`python3 see-surf.py -H https://www.google.com -c cookie_name1=value1 cookie_name2=value2`
<br/><br/>
4) By default, normal mode is On, with a verbose switch you would see the same vulnerable param in different endpoints. The same parameter may not be sanitized at all places. But verbose mode generates a lot of noise. <br/>
`python3 see-surf.py -H https://www.google.com -c cookie_name1=value1 cookie_name2=value2 -t 20 -v` <br/>
Example:<br/>
https://google.com/path/1/urlToConnect=https://yahoo.com <br/>
https://google.com/differentpath/urlToConnect=https://yahoo.com
<br/><br/>
5) Exploitation - Makes an external request to burp collaborator or any other http server with the vulnerable parameter to confirm the possibility of SSRF. (An external redirect vulnerability can potentially be vulnerable to SSRF)
<br/><br/>

### Detailed Features

[-] <b>-b switch</b> Burp's site map shows the information that Burp collects as you explore your target application like URLs collected etc. Provide burp sitemap files for a better discovery of potential SSRF parameters. The script would first parse the burp file and try to identify potential params and then run the built in crawler on it <br/><br/>
Browser the target with your burpsuite running at the background, make some GET/POST requests, the more the better. Then go to target, right click-> "Save selected Items" and save it. Provide to the script as follows. <br/>
`python3 see-surf.py -H https://www.google.com -c cookie_name1=value1 cookie_name2=value2 -b burp_file.xml`

</br>![alt text](https://user-images.githubusercontent.com/18059590/61342249-6a644a00-a7fe-11e9-87e8-3b26305cd8b5.png))


[-] <b>-p switch</b> Fire up burpsuite collaborator and pass the host with -p parameter Or start a simple python http server and wait for the 
vulnerable param to execute your request. <b>(Highly Recommended)</b><br/>
(This basically helps in exploiting GET requests, for POST you would need to try to exploit it manually)<br/>
Payload will get executed with the param at the end of the string so its easy to identify which one is vulnerable.
For example: http://72.72.72.72:8000/vulnerableparam <br/>

`python3 see-surf.py -H https://www.google.com -c cookie_name1=value1 cookie_name2=value2 -p http://72.72.72.72:8000`

![alt text](https://user-images.githubusercontent.com/18059590/61342277-849e2800-a7fe-11e9-832b-7de37cb027ff.png)

## Contribute
- Report bugs.
- Suggestions for improvement.
- Suggestions for future extensions.

## Future Extensions
- Include more places to look for potential params like Javascript files.
- Exploitation, send internal/localhost URLs and check responses, instead of external server.
- Finding potential params during redirection.
- Hidden parameters.

## License
GNUV3 © [In3tinct]
