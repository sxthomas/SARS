'''
SARS (Static Analysis Report on Sessions)
Version 1.2 - Updated June 11, 2016
Created by Stephen Thomas

Usage Note:
Different web frameworks have very different requests and responses so this tool may not work 100% with every web technology.  It is always best to verify all results.
The file export does its best to carve out files.  Depending on the web technology used and how the requests are formatted, results may vary.

Due to the need to clean ascii control characters from the xml file, parsing the burp xml will take a long time for large files.  If you are using SARS with a burp output created by spidering, make sure you are not downloading unneeded items such as pdf or other files during the spider.

Feel free to use, change and add to the code as you see fit.

change log
v1.2 - 6/11/16
now uses stringIO to read in xml file
removes ascii control characters that were breaking ET
added module for hidden form data
added module for listing directories in appendix
added module for HTTP header best practices
fixed clickjacking test for sameorigin
added export time to html file
added burp version to html file
added comment feature
added host-date-time to html file name

v1.1
fixed cookie message
fixed clickjack regex
uniq requets in clickjack table

'''

import sys
import os
import re
import string
from time import strftime
import xml.etree.ElementTree as ET
import getopt
import base64
from StringIO import StringIO

def main():
	version = '1.2'
	print "SARS - Static Analysis Report on Sessions"
	print "Version", version
	# setup variables 
	global requestDict
	requestDict = {}
	customRegexPresent = False
	regexListMatches = [] # used as empty list if no regex is used
	customRegex = ''
	userComment = ''
	export = False
	inputGiven = False
	# command line options
	try:
		options, args = getopt.getopt(sys.argv[1:], 'hi:r:ec:')
	except getopt.GetoptError as err:
		print str(err)
		print 'Try -h for help'
		sys.exit(2)

	for option, value in options:
		if option == '-i':
			inputFile = value
			inputGiven = True
		elif option == '-r':
			customRegexPresent = True
			customRegex = value
		elif option == '-h':
			print "Usage: sars.py -i <input_file.xml> -r <seach_term> -c \"comment\"\n"
			print "-c   comment to be added to the html file"
			print "-e   export all files by file type"
			print "-h   help file"
			print "-i   input xml file from Burp"
			print "-r   regex search term"
			sys.exit(2)
		elif option == '-e':
			export = True
		elif option == '-c':
			userComment = value
		else:
			print 'command not recognized!'
			sys.exit(2)
	if inputGiven == False:
		print "Please provide and input file with the -i option \n"
		print "use -h for more help\n"
		sys.exit(2)

	# read input file into stringio to remove bad chars before sending to et
	print "\n[+] Inspecting/Cleaning Input File"
	xml = ''
	count = 0
	with open(inputFile, 'rb') as f:
		for line in f:
			newLine = re.sub(r'[\x00-\x09\x0b-\x0c\x0e-\x1f]+','', line)
			xml += newLine
	
	print '[+] Parsing XML'
	tree = ET.parse(StringIO(xml))
	root = tree.getroot()

	requestIndex = 0

	# check if requests and responses are base64 encoded.
	if (root[0].find("request").attrib['base64']) == "true":
		print "[!] SARS has detected base64 encoded requests/responses"
		print "    Please make sure to disable base64 when exporting from Burp"
		sys.exit(2)

	# get burp version and expor time 
	burpVer = root.attrib['burpVersion']
	exportTime = root.attrib['exportTime']

	for item in root.findall("item"):
		
		# setup cookies lists in case no cookies are found
		setCookiesList = []
		cookies = []
		# content list will reset for each item in list
		contentList = []
		# save each attribute to a variable
		url = item.find("url").text
		port = item.find("port").text
		method = item.find("method").text
		request = item.find("request").text
		status = item.find("status").text
		response = item.find("response").text
		extension = item.find("extension").text
		mimetype = item.find("mimetype").text
		host = item.find("host").text.replace("/","").replace("\\","").replace("www.","")

		# regex out cookie information
		if "Set-Cookie" in response:
			# save each response cookie as a list item
			for line in response.splitlines():
				try:
					setCookies = re.search(r'Set-Cookie:\s(.*)', line)
					setCookies = setCookies.group(1)
					setCookies = setCookies.replace(" ","")
					setCookies = setCookies.split(";")
					setCookiesList.append(setCookies)

				# error parsing out the response cookies
				except:
					pass

		if "Cookie" in request:
			# try to save each cookie as a list item
			try:
				cookies = re.search(r'Cookie:\s(.*)', request)
				cookies = cookies.group(1)
				cookies = cookies.replace(" ","")
				cookies = cookies.split(";")
			# error parsing out the cookies
			except:
				print "Error parsing known cookies for", url

		# add attributes to list
		contentList.append(url)
		contentList.append(port)
		contentList.append(method)
		contentList.append(request)
		contentList.append(status)
		contentList.append(response)
		contentList.append(cookies)
		contentList.append(setCookiesList)
		contentList.append(extension)
		contentList.append(mimetype)
		contentList.append(host)

		# add list to dictionary
		requestDict[requestIndex] = contentList
		requestIndex += 1

	print "[+] Number of requests in session:", requestIndex

	# === Security Checks ===
	clickJackingMisses = test_clickJacking()
	searchResultsList = test_stringMatch()
	uniqueCookieList, decodedCookieList = cookieAnalysis()
	missingHTTPList, missingSecureList, setCookieTotalCount = setCookieAnalysis()
	robotsText = test_robots()
	listNon200 = test_non200()
	if export == True:
		exportFiles()
	if customRegexPresent == True:
		regexListMatches = test_regex(customRegex)
	postList = test_posts()
	hiddenFormList = test_hiddenForms()
	dirList = test_dirList()
	allRequestsLists = test_allRequests()
	headerInfoList = test_headerCheck()

	# output function to print findings to html file
	outputFunction(regexListMatches,customRegex,clickJackingMisses,searchResultsList,missingHTTPList,missingSecureList,uniqueCookieList,setCookieTotalCount,decodedCookieList,robotsText,listNon200,export,postList,hiddenFormList,dirList,allRequestsLists,headerInfoList,burpVer,exportTime,userComment)

	# --- Functions for each test/module ---
	# check for clickjacking protection. looks for javascript and also http header.
def test_clickJacking():
	clickJackProtectionFound = False
	clickJackingMisses = []
	for index in requestDict:
		clickJackProtectionFound = False
		for line in requestDict[index][5].splitlines():
			# search for possible clickjacking protections. This may have false positive if developers use other methods
			if (re.search('^top.*self', line, re.IGNORECASE)) or (re.search('X-FRAME-OPTIONS: DENY', line, re.IGNORECASE)) or (re.search('X-FRAME-OPTIONS: SAMEORIGIN', line, re.IGNORECASE)):
				# protection found
				clickJackProtectionFound = True

		if clickJackProtectionFound == False:
			clickJackingMisses.append(requestDict[index][0])

	return clickJackingMisses

def test_regex(customRegex):
	customRegex = '^(.)*' + customRegex + '(.)*$'
	regexListMatches = []
	try:
		for index in requestDict:
			for line in requestDict[index][5].splitlines():
				if re.match(customRegex, line):
					line = line.replace("<","&lt;").replace(">","&gt;").replace("&","&amp;")
					regexListMatches.append([requestDict[index][0],line,customRegex])
				else:
					pass
	except:
		print "[!]Error with search term"
	return regexListMatches

# match a list of strings that could be suspicious.  Add strings to the list below.
def test_stringMatch():

	searchTermList = ['password','vulnerability','authentication']
	searchResultsList = []
	for index in requestDict:
		for term in searchTermList:
			if term in requestDict[index][5]:
				searchTerm = '^(.)*' + term + '(.)*$'
				for line in requestDict[index][5].splitlines():
					if re.match(searchTerm, line):
						searchResultsList.append([requestDict[index][0],line[:100],term])
		
	return searchResultsList

def cookieAnalysis():
	cookieList = []
	uniqueCookieList = []
	decodedCookieList = []
	cookieValueList = []
	uniqueCookieValueList = []
	for index in requestDict:
		for cookie in requestDict[index][6]:
			cookieList.append(cookie)
			cookieValue = cookie.partition("=")
			cookieValueList.append(cookieValue[2])

	# get unique cookies
	cookieSet = set(cookieList)
	for cookie in cookieSet:
		uniqueCookieList.append(cookie)

	# get unique cookie values
	cookieValueSet = set(cookieValueList)
	for cookieValue in cookieValueSet:
		uniqueCookieValueList.append(cookieValue)

	# base 64 check
	for cookie in uniqueCookieValueList:
		if re.search('^[A-Za-z0-9+/]*=*$',cookie):
			try:
				decodedCookie = cookie.decode('base64')
				decodedCookieList.append([cookie,decodedCookie])
			except:
					pass

	return uniqueCookieList,decodedCookieList

def setCookieAnalysis():
	setCookieRequestCount = 0
	setCookieInRequestCount = 0
	setCookieTotalCount = 0
	httpOnlyCount = 0
	secureCount = 0
	missingHTTPList = []
	missingSecureList = []

	totalRequestCount = len(requestDict)
	for index in requestDict:
		if requestDict[index][7]:
			setCookieInRequestCount += 1
			for cookie in requestDict[index][7]:
				setCookieRequestCount += 1

				# search for HttpOnly in set-cookies
				if "httponly" in cookie or "HttpOnly" in cookie or "HTTPONLY" in cookie:
					httpOnlyCount += 1
				else:
					missingHTTPList.append([requestDict[index][0],cookie, 'Missing HttpOnly Flag'])
				# search for Security flag in set-cookies
				if "secure" in cookie or "Secure" in cookie or "SECURE" in cookie:
					secureCount += 1
				else:
					missingSecureList.append([requestDict[index][0],cookie, 'Missing Secure Flag'])

		for cookieList in requestDict[index][7]:
			setCookieTotalCount += 1

	if setCookieTotalCount > 0:
		totalSetCookiePercentage = (float(setCookieInRequestCount) / len(requestDict)) *100
		#print "%.0f percent of responses have set-cookies" %totalSetCookiePercentage
		httpOnlyPercentage = (float(httpOnlyCount) / setCookieRequestCount) *100
		#print "%.0f percent of set-cookies have HttpOnly" %httpOnlyPercentage


	return missingHTTPList, missingSecureList, setCookieTotalCount

	# check for robots.txt file.
def test_robots():
	robotsText = ''
	for index in requestDict:
		if "robots.txt" in requestDict[index][0]:
			try:
				robotsText = requestDict[index][5].partition("\n\n")[2].replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')
			except:
				robotsText = "Error parsing robots.txt file"
		else:
			pass
			#robotsText = "No robots.txt file was observed in this session"
	return robotsText

def test_non200():
	listNon200 = []
	for index in requestDict:
		if requestDict[index][4] != "200":
			try:
				msgNon200 = (str(requestDict[index][5]).split("\n\n")[1])
			except:
				msgNon200 = "Error parsing 404 request"
			listNon200.append([requestDict[index][0],requestDict[index][4],msgNon200])

	return listNon200

	# export files based on file type
def exportFiles():
	fileList = []
	#create directory for results

	directory = requestDict[0][10].replace("\\","").replace("/","") + "\\"
	if os.path.isdir(directory):
		#directory is already there
		pass
	else:
		# creating directory
		os.makedirs(directory)

	print "[+] Exporting files to: " + os.getcwd() + "\\" + directory

	#loop through dict and make a list of filenames and file data parsed out of response
	for index in requestDict:
		if requestDict[index][4] == '200':
			# file extension
			if requestDict[index][8] == 'null':
				fileExtension = requestDict[index][9]

			else:
				fileExtension = requestDict[index][8]

			fileExtension = str(fileExtension)
			fileExtension = fileExtension.replace("?","")
			fileExtension = fileExtension.replace("/","")
			fileExtension = fileExtension.replace("\\","")

			# file name
			if requestDict[index][0][-1] == '/':
				fileName = requestDict[index][0].split("/")[-2]
			else:
				fileName = requestDict[index][0].split("/")[-1]
			fileName = str(fileName)
			fileName = fileName.replace("?","")
			fileName = fileName.replace("/","")
			fileName = fileName.replace("\\","")
			fullFileName = str(fileName) + "." + str(fileExtension)

			# file data
			fileData = requestDict[index][5].partition("\n\n")[2]
			
		else:
			fullFileName = ''
			fileExtension = ''
			fileData = ''
			
		fileList.append([fullFileName,fileExtension,fileData])

	# create directory for each file type and save file		
	for index in fileList:
		try:
			if index[1] != "None":
				if index[2]:
					subDirectory = directory + str(index[1])
					if os.path.isdir(subDirectory):
						# directory already there
						pass
					else:
						# creating directory
						os.makedirs(subDirectory)

					fullPath = subDirectory+"\\"+index[0]
					# write file
					with open(fullPath, 'w') as export_file:
						export_file.write(index[2])
		except:
			# error saving file
			pass

# save list of all post request and post data			
def test_posts():
	postList = []
	for index in requestDict:
		if requestDict[index][2] == 'POST':
			postData = requestDict[index][3].partition("\n\n")[2]

			postList.append([requestDict[index][0],postData])

	return postList

# save list of hidden form data
def test_hiddenForms():
	count = 0
	hiddenFormsList = []
	hiddenFormsHold = [] # list used for removing duplicates
	for index in requestDict:
		for line in requestDict[index][5].splitlines():
			count += 1
			try:
				# search for hidden form fields in responses
				hiddenForms = re.findall(r'<input type="hidden"[^>]*name="([\s:\.\w-]*)"[^>]*value="([\s:\.\w-]*)"', line)
				# check for duplicates
				if len(hiddenForms) > 0:
					for match in hiddenForms:
						if match not in hiddenFormsHold:
							fullHiddenData = (requestDict[index][0], match[0], match[1])
							# add form data to list
							hiddenFormsList.append(fullHiddenData)
							hiddenFormsHold.append(match)						
			except:
				pass
	return hiddenFormsList

# get all directories observed
def test_dirList():
	dirList = []
	for index in requestDict:
		url = requestDict[index][0]
		# split urls by / and remove protocol and domain
		splitUrl = url.split('/')
		if 'http' in splitUrl[0]:
			splitUrl = splitUrl[3:]
		# make each dir end with a /
		if splitUrl[-1] != '':
			splitUrl.pop(-1)
			splitUrl.append('')
		# get each combo of dir for multi level directories
		for count in xrange(1,len(splitUrl)):
			newUrl = splitUrl[0:(count+1)]
			newUrl = '/'.join(newUrl)
			# add unique directories to dirList
			if newUrl[-1] == '/':
				if newUrl not in dirList:
					dirList.append(newUrl)
	return dirList

# get all requests observed (uniq)
def test_allRequests():
	allRequestsLists = []
	for index in requestDict:
		url = requestDict[index][0]
		allRequestsLists.append(url)
	allRequestsLists = list(set(allRequestsLists))
	return allRequestsLists

# check all response headers for best practice header options
def test_headerCheck():
	# setup lists for best practices
	headerInfoList = []
	xssProtectionList = []
	contentTypeList = []
	xFrameList = []
	strictTransportList = []
	cacheList = []
	poweredByList = []

	for index in requestDict:
		response = requestDict[index][5]
		headers = response.split('\n\n')
		headers = headers[0]

		# missing xss
		if not (re.search('X-XSS-Protection', headers, re.IGNORECASE)):
			xssProtectionList.append(requestDict[index][0])

		# missing content type
		if not (re.search('X-Content-Type-Options: nosniff', headers, re.IGNORECASE)):
			contentTypeList.append(requestDict[index][0])

		# missing x-frame-options
		if not (re.search('X-FRAME-OPTIONS: DENY', headers, re.IGNORECASE)) and not (re.search('X-FRAME-OPTIONS: SAMEORIGIN', headers, re.IGNORECASE)):
			xFrameList.append(requestDict[index][0])

		# missing strict-transport
		if not (re.search('Strict-Transport-Security', headers, re.IGNORECASE)):
			strictTransportList.append(requestDict[index][0])

		# missing cache control
		if not (re.search('cache-control: no-store', headers, re.IGNORECASE)) and not (re.search('pragma: no-cache', headers, re.IGNORECASE)):
			cacheList.append(requestDict[index][0])

		# information disclosure
		if (re.search('x-powered-by:', headers, re.IGNORECASE)):
			poweredByList.append(requestDict[index][0])

	# add all lists to master list for returning
	headerInfoList.append(xssProtectionList)
	headerInfoList.append(contentTypeList)	
	headerInfoList.append(xFrameList)
	headerInfoList.append(strictTransportList)
	headerInfoList.append(cacheList)
	headerInfoList.append(poweredByList)
		
	return headerInfoList

# functino to output the results in an html file
def outputFunction(regexListMatches,customRegex,clickJackingMisses,searchResultsList,missingHTTPList, missingSecureList,uniqueCookieList,setCookieTotalCount,decodedCookieList,robotsText,listNon200,export,postList,hiddenFormList,dirList,allRequestsLists,headerInfoList,burpVer,exportTime,userComment):

	totalRequestCount = str(len(requestDict))
	fileName = "SARS-" + requestDict[0][10] + "-" + strftime("%Y-%m-%d_%H-%M") + ".html"
	print 'Output file: ', fileName
	with open(fileName, 'w') as output_file:
		output_file.write("<html><head>")
		output_file.write("<style>table{text-align:left;margin:0 0 0px;width:100%;border-left:1pxsolid#ddd;border-right:1pxsolid#ddd;border-collapse:collapse;}html,body,div,span,applet,object,iframe,h1,h2,h3,h4,h5,h6,p,blockquote,pre,a,cite,del,dfn,em,font,q,s,samp,strike,strong,ol,ul,li,fieldset,form,label,legend,tbody,tfoot,thead,tr{border:0;font-family:inherit;font-size:100%;font-style:inherit;font-weight:inherit;margin:0;outline:0;padding:5;vertical-align:baseline;}body,button,input,select,textarea{color:#000;font-family:Helvetica,Arial,sans-serif;font-size:16px;line-height:1.7;word-wrap:break-word;}ul,ol{margin:0 0 0px 20px;}</style>")
		output_file.write("</head><body>")
		output_file.write("<h1 style='font-size:300%'>SARS Report</h1>")
		output_file.write("Static Analysis Report on Sessions v1.2<br>")
		output_file.write("Host: ")
		output_file.write((requestDict[0][10]).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;'))
		output_file.write("<br>Comment: ")
		output_file.write(userComment.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;'))
		output_file.write("<br>Export Time: ")
		output_file.write(exportTime)
		output_file.write("<br>Burp Version: ")
		output_file.write(burpVer)

		# -------Summary
		output_file.write("<br><br><table border='1' style='width:100%'' bgcolor='#819FF7''><tr><td>Summary</td></tr></table>")
		# add num of unique cookies and also number of set cookies
		output_file.write("<ul><li>")
		output_file.write(totalRequestCount)
		output_file.write(" requests were detected in this session</li><li>")
		output_file.write(str(setCookieTotalCount))
		output_file.write(" set-cookies were detected in this session</li><li>")
		output_file.write(str(len(uniqueCookieList)))
		output_file.write(" unique cookies were detected in this session</li><li>")
		if robotsText:
			output_file.write(" Robots.txt file was observed</li><li>")
		else:
			output_file.write(" No Robots.txt file was observed</li><li>")
		if export == True:
			output_file.write("Observed files were exported</li><li>")
		else:
			output_file.write(" Observed files were not exported</li><li>")
		output_file.write(str(len(listNon200)))
		output_file.write(" Non-200 status pages in this session</li></ul>")

		# -----Regex searches
		output_file.write("<br><table border='1' style='width:100%' bgcolor='#819FF7'><tr><td>Regex Searches</td></tr></table>")
		if regexListMatches:
			output_file.write("<br><table border='1' style='width:100%'><tr bgcolor='#E6E6E6'><td>Request URL</td><td>Search Match</td></tr>")
			output_file.write("The term <i>")
			output_file.write(customRegex)
			output_file.write(" </i>was found in the following lines:<br>")
			for index in regexListMatches:
				output_file.write("<tr><td>")
				output_file.write((str(index[0][:100]).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')))
				output_file.write("</td><td>")
				output_file.write((str(index[1][:100]).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')))
				output_file.write("</td></tr>")
			output_file.write("</table>")
		else:
			if customRegex:
				output_file.write("<br>No matches for <i>")
				output_file.write(customRegex)
				output_file.write(" </i>were found in all ")
				output_file.write(totalRequestCount)
				output_file.write(" requests and responses<br>")
			else:
				output_file.write("<br>No regex search was provided at the command line<br>")

		# -------Suspicious text searches
		output_file.write("<br><table border='1' style='width:100%' bgcolor='#819FF7'><tr><td>Suspicious Text</td></tr></table>")
		if searchResultsList:
			output_file.write("<br>Suspicious terms were found in the following lines:")
			output_file.write("<br><table border='1' style='width:100%'><tr bgcolor='#E6E6E6'><td>Request URL</td><td>Request/Response Line</td><td>Search Term</td></tr>")
			for index in searchResultsList:
				output_file.write("<tr><td>")
				output_file.write((str(index[0][:100]).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')))
				output_file.write("</td><td>")
				output_file.write((str(index[1][:100]).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')))
				output_file.write("</td><td>")
				output_file.write((str(index[2][:100]).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')))
				output_file.write("</td></tr>")
			output_file.write("</table>")
		else:
			output_file.write("<br>No suspicious terms were found in all ")
			output_file.write(totalRequestCount)
			output_file.write(" requests and responses<br>")

		# -----------Set-Cookie Analysis
		output_file.write("<br><table border='1' style='width:100%' bgcolor='#819FF7'><tr><td>Set-Cookie Analysis</td></tr></table>")
		# missingHTTPList, missingSecureList
		if setCookieTotalCount > 0:
			if missingHTTPList:
				output_file.write("<br>Set-Cookies that are missing the <i>HTTPOnly</i> flag:")
				output_file.write("<br><table border='1' style='width:100%'><tr bgcolor='#E6E6E6'><td>Response URL</td><td>Cookie</td><td>Note</td></tr>")
				for index in missingHTTPList:
					output_file.write("<tr><td>")
					output_file.write((str(index[0][:100]).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')))
					output_file.write("</td><td>")
					output_file.write((str(index[1][:100]).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')))
					output_file.write("</td><td>")
					output_file.write((str(index[2][:100]).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')))
					output_file.write("</td></tr>")
				output_file.write("</table>")
			else:
				output_file.write("<br>All Set-Cookies appear to have the <i>HTTPOnly</i> flag set<br>")

			if missingSecureList:
				output_file.write("<br>Set-Cookies that are missing the <i>Secure</i> flag:")
				output_file.write("<br><table border='1' style='width:100%'><tr bgcolor='#E6E6E6'><td>Response URL</td><td>Set-Cookie</td><td>Note</td></tr>")
				for index in missingSecureList:
					output_file.write("<tr><td>")
					output_file.write((str(index[0][:100]).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')))
					output_file.write("</td><td>")
					output_file.write((str(index[1][:100]).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')))
					output_file.write("</td><td>")
					output_file.write((str(index[2][:100]).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')))
					output_file.write("</td></tr>")
				output_file.write("</table>")
			else:
				output_file.write("<br>All Set-Cookies appear to have the <i>Secure</i> flag set<br>")
		else:
			output_file.write("<br>No Set-Cookies were observed in this session<br>")

		# -----------request cookie analysis
		output_file.write("<br><table border='1' style='width:100%' bgcolor='#819FF7'><tr><td>Request Cookie Analysis</td></tr></table>")
		# uniqueCookieList,decodedCookieList
		if uniqueCookieList:
			output_file.write("<br>List of unique cookies:")
			output_file.write("<br><table border='1' style='width:100%'><tr bgcolor='#E6E6E6'><td>Cookie</td></tr>")
			for index in uniqueCookieList:
				output_file.write("<tr><td>")
				output_file.write((str(index[:100]).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')))
				output_file.write("</td></tr>")
			output_file.write("</table>")
		else:
			output_file.write("No cookies found")

		if decodedCookieList:
			output_file.write("<br>Possible base64 encoded cookies:")
			output_file.write("<table border='1' style='width:100%'><tr bgcolor='#E6E6E6'><td>Cookie</td><td>Decoded Cookie</td></tr>")
			for index in decodedCookieList:
				output_file.write("<tr><td>")
				output_file.write((str(index[0][:100]).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')))
				output_file.write("</td><td>")
				output_file.write((str(index[1][:100]).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')))
				output_file.write("</td></tr>")
			output_file.write("</table>")
		else:
			output_file.write("<br>No base64 decodable cookies found")

		# -----------Robots.txt
		output_file.write("<br><table border='1' style='width:100%' bgcolor='#819FF7'><tr><td>Robots.txt</td></tr></table><br>")
		if robotsText:
			output_file.write(robotsText)
		else:
			output_file.write("No robots.txt file was observed in this session")
		output_file.write("<br>")

		# -----------non 200s pages
		output_file.write("<br><table border='1' style='width:100%' bgcolor='#819FF7'><tr><td>Non-200 Status Pages</td></tr></table><br>")
		if listNon200:
			for index in listNon200:
				output_file.write((index[1]).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;'))
				output_file.write(" - ")
				output_file.write((index[0]).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;'))
				output_file.write("<br>")
		else:
			output_file.write("No non-200 status pages were observed in this session<br>")
		# -----------Hidden Form Data
		output_file.write("<br><table border='1' style='width:100%' bgcolor='#819FF7'><tr><td>Hidden Form Data</td></tr></table><br>")
		if hiddenFormList:
			output_file.write("<table border='1' style='width:100%'><tr bgcolor='#E6E6E6'><td>URL</td><td>Hidden Form Name</td><td>HIdden Form Value</td></tr>")
			for index in hiddenFormList:
				output_file.write("<tr><td>")
				output_file.write((str(index[0].replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;'))))
				output_file.write("</td><td>")
				output_file.write((str(index[1][:20]).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')))
				output_file.write("</td><td>")
				output_file.write((str(index[2][:40]).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')))
				output_file.write("</td></tr>")
			output_file.write("</table>")
		else:
			output_file.write("No hidden form fields were observed<br>")
		# -----------HTTP Header Best Practices
		output_file.write("<br><table border='1' style='width:100%' bgcolor='#819FF7'><tr><td>HTTP Header Best Practices</td></tr></table><br>")
		output_file.write("<table border='1' style='width:100%'><tr bgcolor='#E6E6E6'><td>Finding</td><td>Recommendation</td><td>Percentage of Requests Affected</td></tr>")

		if headerInfoList[0]:
			output_file.write("<tr><td>")
			output_file.write("Missing X-XSS-Protection")
			output_file.write("</td><td>")
			output_file.write("Add 'X-XSS-Protection: 1; mode=block' header")
			output_file.write("</td><td>")
			output_file.write(str((float(len(headerInfoList[0])) / len(requestDict)) *100)[0:5])
			output_file.write("</td></tr>")

		if headerInfoList[1]:
			output_file.write("<tr><td>")
			output_file.write("Missing X-Content-Type-Options")
			output_file.write("</td><td>")
			output_file.write("Add 'X-Content-Type-Options: nosniff' header")
			output_file.write("</td><td>")
			output_file.write(str((float(len(headerInfoList[1])) / len(requestDict)) *100)[0:5])
			output_file.write("</td></tr>")

		if headerInfoList[2]:
			output_file.write("<tr><td>")
			output_file.write("Missing X-Frame-Options")
			output_file.write("</td><td>")
			output_file.write("Add 'X-Frame-Options: DENY|SAMEORIGIN' header")
			output_file.write("</td><td>")
			output_file.write(str((float(len(headerInfoList[2])) / len(requestDict)) *100)[0:5])
			output_file.write("</td></tr>")

		if headerInfoList[3]:
			output_file.write("<tr><td>")
			output_file.write("Missing Strict-Transport-Security")
			output_file.write("</td><td>")
			output_file.write("Add 'Strict-Transport-Security: max-age=<exp time>; includeSubDomains' header")
			output_file.write("</td><td>")
			output_file.write(str((float(len(headerInfoList[3])) / len(requestDict)) *100)[0:5])
			output_file.write("</td></tr>")

		if headerInfoList[4]:
			output_file.write("<tr><td>")
			output_file.write("Missing Cache-Control")
			output_file.write("</td><td>")
			output_file.write("Add 'Cache-Control: no-store' or 'pragma: no-cache' header")
			output_file.write("</td><td>")
			output_file.write(str((float(len(headerInfoList[4])) / len(requestDict)) *100)[0:5])
			output_file.write("</td></tr>")

		if headerInfoList[5]:
			output_file.write("<tr><td>")
			output_file.write("Information Disclosure - X-Powered-By")
			output_file.write("</td><td>")
			output_file.write("Remove unneeded headers")
			output_file.write("</td><td>")
			output_file.write(str((float(len(headerInfoList[5])) / len(requestDict)) *100)[0:5])
			output_file.write("</td></tr>")

		output_file.write("</table>")

		# -------Click Jacking
		output_file.write("<br><table border='1' style='width:100%' bgcolor='#819FF7'><tr><td>ClickJacking</td></tr></table>")
		# percent of missing click jacking protection
		percentMissingClickJack = '{0:,.2f}'.format((float(len(clickJackingMisses))/len(requestDict))*100)
		output_file.write("<ul><li>")
		if percentMissingClickJack == 100:
			output_file.write("100")
		else:
			output_file.write(str(percentMissingClickJack))
		output_file.write(" percent of all requests are missing ClickJacking protection</li></ul>")
		if len(clickJackingMisses) != 0:
			output_file.write("Responses possibly missing ClickJack protection:")
		if len(clickJackingMisses) > 10:
			output_file.write(" (displaying first 10 requests)")
		if clickJackingMisses:
			output_file.write("<br><table border='1' style='width:100%'><tr bgcolor='#E6E6E6'><td>Response URL</td></tr>")
			uniqClickJackingMisses = list(set(clickJackingMisses))
			for index in uniqClickJackingMisses[:10]:
				output_file.write("<tr><td>")
				output_file.write((str(index[:100]).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')))
				output_file.write("</td></tr>")
			output_file.write("</table>")

		else:
			output_file.write("Possible ClickJacking protection was detected for all ")
			output_file.write(totalRequestCount)
			output_file.write(" responses<br>")

		# -----------Post requests
		output_file.write("<br><table border='1' style='width:100%' bgcolor='#819FF7'><tr><td>POST Requests</td></tr></table><br>")
		if postList:
			output_file.write("<table border='1' style='width:100%'><tr bgcolor='#E6E6E6'><td>Request</td><td>POST Data</td></tr>")
			for index in postList:
				output_file.write("<tr><td>")
				output_file.write((str(index[0].replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;'))))
				output_file.write("</td><td>")
				output_file.write((str(index[1][:100]).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')))
				output_file.write("</td></tr>")
			output_file.write("</table>")
		else:
			output_file.write("No POST requests were observed<br>")

		# -----------Appendix
		output_file.write("<br><table border='1' style='width:100%' bgcolor='#819FF7'><tr><td>Appendix</td></tr></table><br>")
		output_file.write("<b>Directories</b><br>")
		for index in dirList:
			output_file.write(index)
			output_file.write('<br>')
		output_file.write('<br>')
		output_file.write("<b>Requests</b><br>")
		for index in allRequestsLists:
			output_file.write((index).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;'))
			output_file.write('<br>')

		output_file.write('</body></html>')

if __name__ == "__main__":
	main()
