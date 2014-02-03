tilde_enum
==========

Takes the output of a java scanner that exploits the IIS tilde 8.3 enumeration vuln and tries to get you full file names

You feed this script the output from the https://code.google.com/p/iis-shortname-scanner-poc/ scanner and also a word list of potential file names. The script will look up the file roots in your word list and then try them with appropriate extensions.

There are bugs in this version (it is 75+% good). Looking for fedback and suggestions.


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
