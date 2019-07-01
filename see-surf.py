#!/usr/bin/env python3

import queue
from threading import Thread
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import sys
import re
from argparse import ArgumentParser
import requests

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
parser.add_argument("-c","--cookies", dest="cookies", nargs='+', metavar="COOKIES")
parser.add_argument("-v","--verbose", dest="verbose", action='store_true')
parser.add_argument("-p","--payload", dest="payload")

args = parser.parse_args()

validateHost_regex="^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$"
validateHostIpWithPort_regex="^https?:\/\/(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])?:?[0-9]+$"

#Validating Host name
if not re.match(validateHost_regex,args.host):
	print ("Terminating... Please enter Host in the format http://google.com or https://google.com")
	sys.exit()

if args.payload and not re.match(validateHost_regex,args.payload) and not re.match(validateHostIpWithPort_regex,args.payload):
        print ("Terminating... Please enter Host in the format http://google.com or http://192.168.1.1:80")
        sys.exit()

#Keeps a record of links which are already saved and are present just once in the queue
linksVisited=set()
ssrfVul=set()

#Throw away list just used for ignoring unnecessary crawling and generating noisy output
throwAwayListForRest=set()
throwAwayGetReqs={}

#Ignore the path which we couldn't be crawled
ignoreList=["pdf","mailto","javascript"]

#List containing keywords to look for in post param name attributes and in get parameters
matchList="(url|web)"

#Cookies to send along with each requests
cookiesDict={}
if args.cookies:
	for cook in args.cookies:
                cookiesDict[cook[:cook.find("=")]]=cook[cook.find("=")+1:]
		#cookiesDict[cook.split("=")[0]]=cook.split("=")[1]

print (cookiesDict)
#Making an external request to a hostname through the potential vulnerable parameter to validate SSRF
def makingExternalRequests(paramName, url):
	regexToReplace=paramName+"=(.*?)(?:&|$)"
	parameterValuetoReplace=re.search(regexToReplace,url).group(1)

	#Adding paramname 'args.payload+"/"+paramName,' at the end of burp collaborator url to differentiate which param succeeded to make external request.
	formingPayloadURL=re.sub(parameterValuetoReplace,args.payload+"/"+paramName,url)
	print ("\033[91m[+] Making external request with the potential vulnerable url:"+formingPayloadURL)
	requests.get(formingPayloadURL)

#This checks against URL keywords in param NAME
def matchURLKeywordsInName(getOrForm,paramName,url):
	if args.verbose:
		temp=url+":paramname:"+paramName
	else:
		temp=paramName
	if temp not in ssrfVul and re.search(matchList,paramName,re.I):
		print ("\033[92m[-] Potential vulnerable '{}' parameter {} '{}' at '{}'".format(getOrForm,"Name",paramName,url))
		ssrfVul.add(temp)
		#Trying to make an external request to validate potential SSRF (Only for GET parameter for now) 	
		if getOrForm == "GET":
			makingExternalRequests(paramName,url)

#This checks URL pattern in param VALUE and also if an IP is passed somewhere in the values
def matchURLPatternInValue(getOrForm, paramName,paramValues,url):
        #Since param name was same and param values were different there was some duplication, decided to avoid duplication with paramname here
        if args.verbose:
                temp=url+":paramname:"+paramValues if paramName=="" else paramName
        else:
                temp=paramValues if paramName=="" else paramName
                
        if temp not in ssrfVul and (re.match("^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$",paramValues) or re.match("((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}",paramValues)):
                print ("\033[92m[-] Potential vulnerable '{}' parameter {} '{}' at '{}'".format(getOrForm, "Value" if paramName=="" else "Name",paramValues if paramName=="" else paramName,url))
                ssrfVul.add(temp)
                if getOrForm == "GET":
                        makingExternalRequests(paramName,url)


def checkForGetRequest(url):
	#print ("Checking for ssrf:"+url)
	#Regex to find parameters in a url
	checking_params_for_url= re.findall("(\?|\&)([^=]+)\=([^&]+)",url)

	#Checking if there is a paramater in the URL (This would filter rest APIs in the format /test/1 /test/2)
	if not len(checking_params_for_url)==0:
		#Getting the param values params[2] and param name params[1] and matching against regex
		for params in checking_params_for_url:
			matchURLKeywordsInName("GET",params[1],url)
			matchURLPatternInValue("GET",params[1],params[2],url)
			

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

def do_stuff(q):
	while True:
		url = q.get()
		try:
			if args.cookies:
				r = requests.get(url, cookies=cookiesDict)
			else:
				r = requests.get(url)
			siteContent=r.text	
			
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
						checking_params_for_url= re.findall("(\?|\&)([^=]+)\=([^&]+)",linkUrl)
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
						linksVisited.add(linkUrl)
						q.put(linkUrl)
						checkForGetRequest(linkUrl)
						checkFormParameters(siteContent,linkUrl)
			
			q.task_done()
			#print ("queue size after"+ str(q.qsize()))
							
		except Exception as e: 
			print(e)
			q.task_done()
			continue


parsed=urlparse(args.host)
baseURL=parsed.scheme+"://"+parsed.netloc
print ("Target URL - " + baseURL)

q = queue.Queue()
q.put(baseURL)

#Since we do not want to visit the root url again we add it into the visited list 
linksVisited.add(baseURL+"/")
linksVisited.add(baseURL)

if args.threads:
	num_threads = int(args.threads)
else:
	num_threads=10

print ("Here we go!!!")
for i in range(num_threads):
  worker = Thread(target=do_stuff, args=(q,))
  worker.setDaemon(True)
  worker.start()

#Since the threads were clearing the queues before new queue was added, the program was exiting, so running and infinite loop now
q.join()

print (ssrfVul)
