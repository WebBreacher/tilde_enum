tilde_enum
==========

Takes a URL and then exploits the IIS tilde 8.3 enumeration vuln and tries to get you full file names.

You feed this script URL and also a word list of potential file names. The script will look up the file roots in your word list and then try them with appropriate extensions.

The [fuzzdb](https://code.google.com/p/fuzzdb/) word lists are pretty good. We sometimes use the https://code.google.com/p/fuzzdb/source/browse/trunk/discovery/PredictableRes/raft-small-words-lowercase.txt (or large or medium) for this work.

There are known bugs that we are working to resolve in this version (it is 93+% good). Looking for feedback and suggestions.


Help
====
<pre>$  ./tilde_enum.py -h
usage: tilde_enum.py [-h] [-b] [-f] [-u URL] [-v] wordlist

Expands the file names found from the tilde enumeration vuln

positional arguments:
  wordlist    the wordlist file

optional arguments:
  -h, --help  show this help message and exit
  -b          brute force backup extension, extensions
  -f          force testing of the server even if the headers do not report it
              as an IIS system
  -u URL      URL to scan
  -v          verbose output
</pre>


Sample Output
======
<pre>
$  ./tilde_enum.py -u http://iis /pentest/fuzzdb/discovery/PredictableRes/raft-small-words-lowercase.txt
[-]  Testing with dummy file request http://iis/BgLWKLNKUm.htm
[-]	URLNotThere -> HTTP Code: 404, Response Length: 1635
[-]  Testing with user-submitted http://iis
[-]	URLUser -> HTTP Code: 200, Response Length: 1433
[+]  The server is reporting that it is IIS (Microsoft-IIS/6.0).
[+]  The server is vulnerable to the tilde enumeration vulnerability.
[+]  Found a new directory: aspnet
[+]  Found a new directory: copyof
[+]  Found file:  dqa5e5 . htm
[+]  Found file:  eee . htm
[+]  Found a new directory: javasc
[+]  Found file:  parame . xml
[+]  Found file:  passwo . x
[+]  Found a new directory: php_so
[+]  Found file:  postin . htm
[+]  Found file:  server . ht
[+]  Found file:  2ac185 . htm
[+]  Found file:  321 . xls
[+]  Found file:  4321 . htm
[+]  Found file:  654321 . old
[+]  Found file:  765432 . htm
[+]  Found file:  876543 . jpg
[+]  Found file:  987654 . abc
[+]  Found file:  _vti_i . htm
[+]  Found a new directory: _vti_s
[-]  Finished doing the 8.3 enumeration for http://iis.
[-]  Now starting the word guessing using word list calls
[+]  Searching for dqa5e5 in word list
[+]  Searching for htm in extension word list
[-]  File name (eee) too  to look up in word list. We will use it to bruteforce.
[+]  Searching for htm in extension word list
[*]  Found one! (Size 8) http://iis/eee.html
[+]  Searching for parame in word list
[+]  Searching for xml in extension word list
[*]  Found one! (Size 1307) http://iis/parameters.xml
[*]  Found one! (Size 1307) http://iis/parameter.xml
[+]  Searching for passwo in word list
[-]  Extension (x) too short to look up in word list. We will use it to bruteforce.
[*]  Found one! (Size 198) http://iis/passwords.x
[+]  Searching for postin in word list
[+]  Searching for htm in extension word list
[*]  Found one! (Size 2449) http://iis/postinfo.html
[+]  Searching for server in word list
[-]  Extension (ht) too short to look up in word list. We will use it to bruteforce.
[+]  Searching for 2ac185 in word list
[+]  Searching for htm in extension word list
[-]  File name (321) too  to look up in word list. We will use it to bruteforce.
[+]  Searching for xls in extension word list
[*]  Found one! (Size 227) http://iis/321.xlsx
[-]  File name (4321) too  to look up in word list. We will use it to bruteforce.
[+]  Searching for htm in extension word list
[*]  Found one! (Size 227) http://iis/4321.html
[+]  Searching for 654321 in word list
[+]  Searching for old in extension word list
[+]  Searching for 765432 in word list
[+]  Searching for htm in extension word list
[+]  Searching for 876543 in word list
[+]  Searching for jpg in extension word list
[+]  Searching for 987654 in word list
[+]  Searching for abc in extension word list
[+]  Searching for _vti_i in word list
[+]  Searching for htm in extension word list
[*]  Found one! (Size 1754) http://iis/_vti_inf.html
[-]  Trying to find directory matches now.
[?]  URL: (Size 218) http://iis/aspnet_client/ with Response: HTTP Error 403: Forbidden 
[?]  URL: (Size 218) http://iis/javascript/ with Response: HTTP Error 403: Forbidden 

---------- FINAL OUTPUT ------------------------------
[*]  We found files for you to look at
[*]      http://iis/321.xlsx  - Size 227
[*]      http://iis/4321.html  - Size 227
[*]      http://iis/_vti_inf.html  - Size 1754
[*]      http://iis/eee.html  - Size 8
[*]      http://iis/parameter.xml  - Size 1307
[*]      http://iis/parameters.xml  - Size 1307
[*]      http://iis/passwords.x  - Size 198
[*]      http://iis/postinfo.html  - Size 2449

[*]  Here are all the 8.3 names we found.
[*]  If any of these are 6 chars and look like they should work,
        try the file name with the first or second instead of all of them.
[*]      http://iis/2ac185~1.htm
[*]      http://iis/321~1.xls
[*]      http://iis/4321~1.htm
[*]      http://iis/654321~1.old
[*]      http://iis/765432~1.htm
[*]      http://iis/876543~1.jpg
[*]      http://iis/987654~1.abc
[*]      http://iis/_vti_i~1.htm
[*]      http://iis/dqa5e5~1.htm
[*]      http://iis/eee~1.htm
[*]      http://iis/parame~1.xml
[*]      http://iis/passwo~1.x
[*]      http://iis/postin~1.htm
[*]      http://iis/server~1.ht

[*]  Here are all the directory names we found. You may wish to try to guess them yourself too.
[*]      http://iis/_vti_s/
[*]      http://iis/aspnet/
[*]      http://iis/copyof/
[*]      http://iis/javasc/
[*]      http://iis/php_so/

[*]  We found directory URLs you should check out. They were not HTTP response code 200s.
[?]      HTTP Resp 403 - http://iis/aspnet_client/  - Size 218
[?]      HTTP Resp 403 - http://iis/javascript/  - Size 218
</pre>
