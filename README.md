# See-SURF

A Python based scanner to find potential SSRF parameters in a web application.

## Motivation
SSRF being one of the critical vulnerabilities out there in web, i see there was no tool which would automate finding potential
vulnerable parameters. See-SURF can be added to your arsenal for recon while doing bug hunting/web security testing.

 
## Screenshots
![alt text](https://user-images.githubusercontent.com/18059590/61342276-849e2800-a7fe-11e9-9f2a-7ba3835903a8.png)

## Tech/framework used
<b>Built with</b>
- `Python3`

## Features
1) Matches any GET URL Parameters containing keyword web/url (MORE TO BE ADDED). <br/>
Example `google.com/url=https://yahoo.com `
<br/>Also, <br/>
checks the parameter values for any URL or IP address passed. <br/>
Example: `google.com/q=https://yahoo.com`

2) Matches any POST request INPUT params with "Name" attribute containing keyword web/url(MORE TO BE ADDED)
<br/>Also,<br/>
matches Values and Placeholder attribute containing a URL pattern. <br/>
Example: <br/>
`<input type="text" name="url" value="https://google.com" placeholder="https://msn.com">`

3) Multiple conditions to cut down false positives, as crawling pulls up a lot of stuff. Only same domain is crawled for now.

4) By Default, normal mode is On, with verbose switch you would see the same vulnerable param in different endpoints. 
Same parameter may not be sanitized at all places. But verbose mode generates a lot of noise.
<br/>Example: <br/>
`https://google.com/abc/1/urlToConnect=https://yahoo.com> `<br/>
`https://google.com/123/urlToConnect=https://yahoo.com`

5) Supply cookies for an authenticated scanning.

6) Comments on almost every logic so people who would like to contribute can understand easily.

7) Makes external request with the vulnerable parameter to confirm the possibility of SSRF

## How to use?
[-] This would run with default threads=10, no cookies/session and NO verbose mode <br/>
`python3 see-surf.py -H https://www.google.com`


[-] Space separate Cookies can be supplied for an authenticated session crawling <br/>
`python3 see-surf.py -H https://www.google.com -c cookie_name1=value1 cookie_name2=value2`

<b>Recently added feature </b><br/>

[-] Fire up burpsuite collaborator and pass the host with -p parameter Or start a simple python http server and wait for the 
vulnerable param to execute your request. <b>(Highly Recommended)</b><br/>
(This basically helps in exploiting GET requests, for POST you would need to try to exploit it manually)<br/>
Payload will get executed with the param at the end of the string so its easy to identify which one is vulnerable.
For example: http://72.72.72.72:8000/vulnerableparam <br/>

`python3 see-surf.py -H https://www.google.com -c cookie_name1=value1 cookie_name2=value2 -p http://72.72.72.72:8000`

![alt text](https://user-images.githubusercontent.com/18059590/61342277-849e2800-a7fe-11e9-832b-7de37cb027ff.png)


[-] Supplying no. of threads and verbose mode (VERBOSE MODE IS NOT RECOMMENDED IF YOU DON'T WANT TO SPEND LONGER TIME BUT THE 
POSSIBILITY OF BUG FINDING INCREASES)<br/>
`python3 see-surf.py -H https://www.google.com -c cookie_name1=value1 cookie_name2=value2 -t 20 -v`

By Default, normal mode is On, with verbose switch you would see the same potential vulnerable param in different endpoints. 
(Same parameter may not be sanitized at all places. But verbose mode generates a lot of noise.)
<br/>Example: <br/>
https://google.com/abc/1/urlToConnect=https://yahoo.com <br/>
https://google.com/123/urlToConnect=https://yahoo.com

## Version-2 (Best Recommended)
Provide burp sitemap files for a better discovery of potential SSRF parameters. The script would first parse the burp file and try to identify potential params and then run the built in crawler on it <br/><br/>
Browser the target with your burpsuite running at the background, make some GET/POST requests, the more the better. Then go to target, right click-> "Save selected Items" and save it. Provide to the script as follows. <br/>
`python3 see-surf.py -H https://www.google.com -c cookie_name1=value1 cookie_name2=value2 -b burp_file.xml -p http://72.72.72.72:8000`

</br>![alt text](https://user-images.githubusercontent.com/18059590/61342249-6a644a00-a7fe-11e9-87e8-3b26305cd8b5.png))

## Installation
`git clone https://github.com/In3tinct/See-SURF.git`<br/>
`cd See-SURF/`<br/>
`pip3 install BeautifulSoup4`<br/>
`pip3 install requests`

## Tests
A basic framework has been created. 
More tested would be added to reduce any false positives.


## Contribute
- Report bugs.
- Suggestions for improvement.
- Suggestions for future extensions.

## Credits
Template - https://gist.github.com/akashnimare/7b065c12d9750578de8e705fb4771d2f <br/>
Some regexes from https://www.regextester.com/97040 <br/>
Stackoverflow and Entire Internet. 

## Future Extensions
- Include more places to look for potential params like Javascript files
- Finding potential params during redirection.
- More conditions to avoid false positives.
- Exploitation. (Hitting Bulls eye)


## License
GNUV3 © [In3tinct]

Twitter - https://twitter.com/_In3tinct
