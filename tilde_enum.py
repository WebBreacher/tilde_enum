#!/usr/bin/env python -tt

'''
-------------------------------------------------------------------------------
Name:		tilde_enum.py
Purpose:	Expands the file names found from the tilde enumeration vuln
Authors:	Ryan Tierney (nu11by73) and Micah Hoffman (@WebBreacher)
-------------------------------------------------------------------------------
'''

import os, sys, re, argparse, random, string
from urllib2 import Request, urlopen, URLError
from urlparse import urlparse

#=================================================
# Constants and Variables
#=================================================

# In the 'headers' below, change the data that you want sent to the remote server
# This is an IE10 user agent
headers = { 'User-Agent' : 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)' }

# Targets is the list of files from the scanner output
targets = []

# Findings is the list of URLs that may be good on the web site
findings = []

# Location of the extension brute force word list
exts = 'exts'

# Response codes - user and error
response_code = {}

#=================================================
# Functions & Classes
#=================================================

def check_os():
	# Check operating system for colorization
    if os.name == "nt":
        operating_system = "windows"
    if os.name == "posix":
        operating_system = "posix"
    return operating_system


def getWebServerResponse(url):
	# This function takes in a URL and outputs the HTTP response code and content length (or error)
	try:
		req = Request(url, None, headers)
		response = urlopen(req)
		return response
	except URLError as e:
		return e
	except HTTPError as e:
		return e
	except Exception as e:
		return 0


def initialCheckUrl(url):
	# This function checks to see if the web server is running and what kind of response codes
	# come back from bad requests (this will be important later)

	# Need to split url into protocol://host|IP and then the path
	u = urlparse(url)

	# Make a string that we can use to ensure we know what a "not found" response looks like
	not_there_string = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for x in range(10))
	print bcolors.GREEN + '[-]  Testing with dummy file request %s://%s/%s.htm' % (u.scheme, u.netloc, not_there_string) + bcolors.ENDC
	not_there_url = u.scheme + '://' + u.netloc + '/' + not_there_string + '.htm'

	# Make the dummy request to the remote server
	not_there_response = getWebServerResponse(not_there_url)
	if not_there_response.getcode():
		print '[-]	URLNotThere -> HTTP Code: %s, Response Length: %s' % (not_there_response.getcode(), not_there_response.headers['content-length'])
		response_code['dummy_code'], response_code['dummy_length'] = not_there_response.getcode(), not_there_response.headers['content-length']
	else:
		print '[+]	URLNotThere -> HTTP Code: %s, Error Code: %s' % (not_there_response.code, not_there_response.reason)
		response_code['dummy_code'], response_code['dummy_reason'] = not_there_response.code

	# Check if we didn't get a 404. This would indicate custom error messages or some redirection
	# and will cause issues later.
	if response_code['dummy_code'] != 404:
		print bcolors.RED + '[!]  FALSE POSITIVE ALERT: We may have a problem determining real responses since we did not get a 404 back.' + bcolors.ENDC

	# Now that we have the "definitely not there" page, check for one that should be there
	print bcolors.GREEN + '[-]  Testing with user-submitted %s' % (url) + bcolors.ENDC
	url_response = getWebServerResponse(url)
	if url_response.getcode():
		print '[-]	URLUser -> HTTP Code: %s, Response Length: %s' % (url_response.getcode(), url_response.headers['content-length'])
		response_code['user_code'], response_code['user_length'] = url_response.getcode(), url_response.headers['content-length']
	else:
		print '[+]	URLUser -> HTTP Code: %s, Error Code: %s' % (url_response.code, url_response.reason)
		response_code['user_code'], response_code['user_reason'] = url_response.code, url_response.reason

	# Check if we got an HTTP response code of 200.
	if response_code['user_code'] != 200:
		print bcolors.RED + '[!]  ERROR: We did not receive an HTTP response code 200 back. Please check URL.' + bcolors.ENDC
		sys.exit()
	else:
		return response_code


def readScanFile(file_name):
	# Open the tilde output scan_file (or try to)
	try:
		scan_file = open(file_name,'r').readlines()
	except (IOError) :
		print bcolors.RED + '[!]  [Error] Can\'t read the scanner file you entered.' + bcolors.ENDC
		sys.exit()

	# Need to parse through the scanner output file for the target files and URL
	for line in scan_file:
		# One line should have the Target URL used for the scanner
		url = re.match('Target = (.+)', line)
		if url: targets.append(url.group(1))

		# Matching the "File:" and then pulling the name and ext
		# This strips out the ~[0-9] and just makes the result ABCDEF.EXT
		found = re.match('File: (.+)~[0-9](\..+)', line)
		if found:
			targets.append(found.group(1) + found.group(2))

	# Finally, return a sorted list of files. Sorting is important as it puts the lowercase
	# http... of the URL at the bottom
	return sorted(targets)


def searchFileForString(string, file):
	# Open the wordlist file (or try to)
	try:
		wordlist = open(file,'r').readlines()
	except (IOError) :
		print bcolors.RED + '[!]  [Error] Can\'t read the wordlist file you entered.' + bcolors.ENDC
		sys.exit()

	matches = []
	for line in wordlist:
		if line.startswith(string.lower()):
			matches.append(line.rstrip())
	return matches


def main():
	# Read the scanner output file into a list
	# They will be in ABCDEF.EXT format (no tilde and number)
	targets = readScanFile(args.scan_file_to_parse.name)
	if not targets:
		print bcolors.RED + '[!]  Error: No FILE entries found in scanner output' + bcolors.ENDC
		sys.exit()

	# The last item in the targets list is the URL. Remove it and assign it to url variable
	url = targets.pop()
	print bcolors.YELLOW + '[+]  Found URL: %s' % url + bcolors.ENDC

	if args.v:
		for file in targets:
			print bcolors.PURPLE + '[+]  Found file: %s' % file + bcolors.ENDC

	# URL to check. Extracted from the scanner output file. The HTTP response codes and lengths are returned.
	response_code = initialCheckUrl(url)
	if args.v: print bcolors.PURPLE + '[+]  HTTP Response Codes: %s' % response_code + bcolors.ENDC

	filename_matches = []

	# Start the URL requests to the server
	print bcolors.GREEN + '[-]  Now starting the web calls' + bcolors.ENDC

	# So the URL is live and gives 200s back (otherwise script would have exit'd)
    # Find matches to the filename in our word list
	for file in targets:

		# Break apart the file into filename and extension
		filename, ext_temp = os.path.splitext(file)
		ext = ext_temp.lstrip('.')

		# Go search the user's word list file for matches for the file
		if args.v: print bcolors.PURPLE + '[+]  Searching for %s in word list' % filename + bcolors.ENDC
		filename_matches = searchFileForString(filename, args.wordlist)
		# If nothing came back from the search, just try use the original string
		if not filename_matches:
			filename_matches.append(filename.lower())
		# debug if args.v: print bcolors.PURPLE + '[+]  File name matches for %s are: %s' % (filename, filename_matches) + bcolors.ENDC

		# Go search the extension word list file for matches for the extension
		if len(ext) < 3:
			print bcolors.RED + '[!]  Extension (%s) too short to look up in word list. We will use it to bruteforce.' % ext + bcolors.ENDC
			ext_matches.append(ext.lower())
		else:
			if args.v: print bcolors.PURPLE + '[+]  Searching for %s in extension word list' % ext + bcolors.ENDC
			ext_matches = searchFileForString(ext, exts)
		# debug if args.v: print bcolors.PURPLE + '[+]  Extension matches for %s are: %s' % (ext, ext_matches) + bcolors.ENDC

		# Now do the real hard work of cycling through each filename_matches and adding the ext_matches,
		# do the look up and examine the response codes to see if we found a file.
		for line in filename_matches:
			for e in ext_matches:
				url_to_try = url + line + '.' + e
				url_response = getWebServerResponse(url_to_try)

				# Pull out just the HTTP response code number
				if hasattr(url_response, 'code'):
					test_response_code = url_response.code
					test_response_length = url_response.headers['Content-Length']
				elif hasattr(url_response, 'getcode'):
					test_response_code = url_response.getcode()
					test_response_length = len(url_response.reason())
				else:
					test_response_code = 0

				if args.v: print bcolors.PURPLE + '[+]  URL: %s  -> RESPONSE: %s' % (url_to_try, test_response_code) + bcolors.ENDC

				# Here is where we figure out if we found something or just found something odd
				if test_response_code == response_code['user_code']:
					print bcolors.YELLOW + '[*]  Found one! (Size %s) %s' % (test_response_length, url_to_try) + bcolors.ENDC
					findings.append(url_to_try + '  (Size ' + test_response_length + ')')
				elif test_response_code != 404:
					print bcolors.YELLOW + '[?]  URL: (Size %s) %s with Response: %s ' % (test_response_length,url_to_try, url_response) + bcolors.ENDC
					findings.append('Response Code ' + test_response_code + ' - ' + url_to_try + '  (Size ' + test_response_length + ')')

	# Output findings
	if findings:
		print '\n----------------------------------------'
		print '[*]  We found files for you to look at'
		for out in sorted(findings):
			print bcolors.YELLOW + '[*]  %s' % out + bcolors.ENDC
	else:
		print '[ ]  No valid files were discovered. Sorry dude.'


#=================================================
# START
#=================================================

# Command Line Arguments
parser = argparse.ArgumentParser(description='Expands the file names found from the tilde enumeration vuln')
parser.add_argument('-b', action='store_true', default=False, help='brute force backup extension, extensions')
parser.add_argument('scan_file_to_parse', type=file, help='the java scanner file that you want parsed')
parser.add_argument('-v', action='store_true', default=False, help='verbose output')
parser.add_argument('wordlist', help='the wordlist file')
args = parser.parse_args()

# COLORIZATION OF OUTPUT
# The entire bcolors class was taken verbatim from the Social Engineer's Toolkit (ty @SET)
if check_os() == "posix":
	class bcolors:
		PURPLE = '\033[95m'    # Verbose
		CYAN = '\033[96m'
		DARKCYAN = '\033[36m'
		BLUE = '\033[94m'
		GREEN = '\033[92m'     # Normal
		YELLOW = '\033[93m'    # Findings
		RED = '\033[91m'       # Errors
		ENDC = '\033[0m'

		def disable(self):
			self.PURPLE = ''
			self.CYAN = ''
			self.BLUE = ''
			self.GREEN = ''
			self.YELLOW = ''
			self.RED = ''
			self.ENDC = ''
			self.DARKCYAN = ''

# If we are running on Windows or something like that then define colors as nothing
else:
	class bcolors:
		PURPLE = ''
		CYAN = ''
		DARKCYAN = ''
		BLUE = ''
		GREEN = ''
		YELLOW = ''
		RED = ''
		ENDC = ''

		def disable(self):
			self.PURPLE = ''
			self.CYAN = ''
			self.BLUE = ''
			self.GREEN = ''
			self.YELLOW = ''
			self.RED = ''
			self.ENDC = ''
			self.DARKCYAN = ''

if args.v:
	print bcolors.PURPLE + '[-]  Entering "Verbose Mode"....brace yourself for additional information.' + bcolors.ENDC

if __name__ == "__main__": main()


