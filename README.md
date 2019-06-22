# See-SURF (UNDER CONSTRUCTION)


## Project title
Python based scanner to find potential SSRF parameters in a web application.

## Motivation
SSRF being one of the critical vulnerabilities out there, i see there was not a tool which would automate finding potential
vulnerale parameters, reducing the manual work in the age of automation. See-SURF can be added to your arsenal for recon while doing bug hunting/web application testing.

 
## Screenshots
![alt text](https://github.com/In3tinct/See-SURF/blob/master/See-SURF.png)

## Tech/framework used
<b>Built with</b>
- Python3

## Features
1) Matches any GET URL Parameters containing keyword web/url (MORE TO BE ADDED). Example google.com/url=https://yahoo.com 
Also, 
checks the parameter values for any URL or IP address passed. Example google.com/q=https://yahoo.com

2) Matches any POST request INPUT params with "Name" attribute containing keyword web/url(MORE TO BE ADDED)
Also,
matches Values and Placeholder attribute containing a URL pattern. 
Example: <input type="text" name="url" value="https://google.com"

3) Multiple conditions to cut down false positives, as crawling pulls up a lot of stuff. Only same domain is crawled for now.

4) By Default, normal mode is On, with verbose switch you would see the same vulnerable param in different endpoints. 
Same parameter may not be sanitized at all places. But verbose mode generates a lot of noise.
For example: 
https://google.com/abc/1/urlToConnect=https://yahoo.com
https://google.com/123/urlToConnect=https://yahoo.com

5) Supply cookies for an authenticated scanning.

## How to use?
This would run with default threads=10, no cookies/session and NO verbose mode 
python3 see-surf.py -H https://www.google.com

Space seperate Cookies can be supplied for an authenticated session crawling (Highly Recommended)
python3 see-surf.py -H https://www.google.com -c cookie_name1=value1 cookie_name2=value2

Supplying no. of threads and verbose mode (VERBOSE MODE IS NOT RECOMMENDED IF YOU DON'T WANT TO SPEND LONGER TIME BUT THE 
POSSIBILITY OF BUG FINDING INCREASES)
python3 see-surf.py -H https://www.google.com -c cookie_name1=value1 cookie_name2=value2 -t 20 -v

By Default, normal mode is On, with verbose switch you would see the same potential vulnerable param in different endpoints. 
(Same parameter may not be sanitized at all places. But verbose mode generates a lot of noise.)
For example: 
https://google.com/abc/1/urlToConnect=https://yahoo.com
https://google.com/123/urlToConnect=https://yahoo.com


## Installation
Provide step by step series of examples and explanations about how to get a development env running.

## Tests
A basic framework has been created. 
More tested would be added to reduce false positives.


## Contribute

Let people know how they can contribute into your project. A [contributing guideline](https://github.com/zulip/zulip-electron/blob/master/CONTRIBUTING.md) will be a big plus.

## Credits
Template - https://gist.github.com/akashnimare/7b065c12d9750578de8e705fb4771d2f
Stackoverflow and Entire Internet. 

#### Future Extensions
- More conditions to avoid false positives.
- Transitioning from potential parameter to trying an exploit. (Hitting Bulls eye).

## License
GNUV3 © [In3tinct]
