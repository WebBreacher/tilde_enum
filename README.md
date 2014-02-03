tilde_enum
==========

Takes the output of a java scanner that exploits the IIS tilde 8.3 enumeration vuln and tries to get you full file names

You feed this script the output from the https://code.google.com/p/iis-shortname-scanner-poc/ scanner and also a word list of potential file names. The script will look up the file roots in your word list and then try them with appropriate extensions.

The [fuzzdb](https://code.google.com/p/fuzzdb/) word lists are pretty good. We sometimes use the https://code.google.com/p/fuzzdb/source/browse/trunk/discovery/PredictableRes/raft-small-words-lowercase.txt (or large or medium) for this work.

There are known bugs that we are working to resolve in this version (it is 75+% good). Looking for feedback and suggestions.


Help
====
<pre>$  ./tilde_enum.py -h
usage: tilde_enum.py [-h] [-b] [-v] scan_file_to_parse wordlist

Expands the file names found from the tilde enumeration vuln

positional arguments:
  scan_file_to_parse  the java scanner file that you want parsed
  wordlist            the wordlist file

optional arguments:
  -h, --help          show this help message and exit
  -b                  brute force backup extension, extensions
  -v                  verbose output
</pre>


Output
======
<pre>
$  ./tilde_enum.py scanner_out.txt /fuzzdb/discovery/PredictableRes/raft-small-words-lowercase.txt 
[+]  Found URL: https://vulnwebsite.example.com/
[-]  Testing with dummy file request https://vulnwebsite.example.com/Vv4c9T3sfc.htm
[-]	   URLNotThere -> HTTP Code: 404, Response Length: 1635
[-]  Testing with user-submitted https://vulnwebsite.example.com/
[-]	   URLUser -> HTTP Code: 200, Response Length: 1588
[-]  Now starting the web calls
[?]  URL: (Size TBD) https://vulnwebsite.example.com/global.asax with Response: HTTP Error 403: Forbidden 
[?]  URL: (Size TBD) https://vulnwebsite.example.com/mvc.sitemap with Response: HTTP Error 403: Forbidden 
[?]  URL: (Size TBD) https://vulnwebsite.example.com/packages.config with Response: HTTP Error 403: Forbidden 
[***]  Found one! (Size 1588) https://vulnwebsite.example.com/parameters.xml
[***]  Found one! (Size 1588) https://vulnwebsite.example.com/systeminfo.xml
</pre>
