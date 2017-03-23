===========
1. Terminal
===========

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1.1 String manipulation (cut,perl,sed,awk)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

AWK 
---
-if, print, match pattern/no action columns,delete words ending with g,gsub,delimiter,remove bom

	::
	
		less codetable.independit.nl.country.xml | awk '{if ($0 ~ "CodeID") {print "-->"$0} else {print $0}}'
		awk '{gsub("bar", "");print}' <<< "This is a bar test"
		awk '{gsub("[a-zA-Z0-9]*[g|G]$", "");print}' input
		awk '{sub(/:/, "", $3); print $3$4}'
		awk 'BEGIN{memo=0} {memo=$1+memo} END{print memo}'
		awk -F"*" '{print $1 " | " $2}'
		awk '{if(NR==1)sub(/^\xef\xbb\xbf/,"");print}' INFILE > OUTFILE
		...| awk '{print $5"\t\t" $3"\t"$4}'|column -t
		awk '/httpd/' processes
		awk '{ print }' processes
		awk '$11 ~ /sendmail/'  processes
		awk '$11 ~ /^c/'  processes
		awk '{arr[NR]=arr[NR-1]+$1} END {print arr[NR]}' text
		less codetable.independit.nl.country.xml | awk '{if ($0 ~ "CodeID") {print "-->"$0} else {print $0}}'

PASTE
-----
	::
	
		paste -d", " fileone filetwo (-d the delimiter, columnwise)
		paste -s fileone filetwo (space as default delimiter, -s linewise)

REMOVE BOM
----------
- awk,tail,head

	::
	
		awk '{if(NR==1)sub(/^\xef\xbb\xbf/,"");print}' INFILE > OUTFILE
		tail -c +4 UTF8 > UTF8.nobom
		hd -n 3 UTF8

AVERGA PROCESSING TIME 
----------------------
- grep, perl, awk

	::
	
		cat wiacek.log.2013-04-* | grep "time=" | grep -v royaltystat | grep -v monitor | grep -v otys | perl -ne '/.*time=(\d+)\.0ms.*/ && print "$1\n"' | awk 'BEGIN{totaltime=0;total=0}{totaltime=$1+totaltime;total=total+1; print totaltime/total; print "TOTAL="total}END{print totaltime/total}'


SED
---
- replace, delimitors, tokenize, replace in file+backup, delete all words ending with a letter 'g' in each line

	::
	
		sed 's/tutorial/example/' file.txt
		sed -i 's/tutorial/example/' file.txt
		sed -i_bkp 's/example/tutorial/' file.txt
		sed -e 's/\<regex-for-word\>//g' input > output
		sed -e 's/\<[a-zA-Z0-9]*[g|G]\>//g' input
		echo "Hallo" | sed 's/\(.\)/\1 /g (tokenize characters)
		echo "     This is a test" | sed -e 's/^[ \t]*//' (Delelte all leading blank spaces)
		sed -e '2d' /etc/services | head 	(delete 2nd line)


TR
--
- decapitalize, delete satzzeichen, replace repetitive occureences

tr '[A-Z]' '[a-z]'	# decapitalize
tr -d ';:)\.,'		# delete satzzeichen
tr -s ' ' '\n'		# replace repetitive occureences
cat file7 | tr '[A-Z]' '[a-z]' > file8
cat file7 | tr [:upper:] [:lower:] > file8
tr -s ' ' ' ' < file9 > file10 (which replaces each instance of a sequence)
cat file11 | tr -d 'soft' > file12


PERL
----
- match and print each line, apply on files, print output, while, change encoding, show librairs
	-n	This option places a loop around your script. It will automatically read a line from the diamond operator and then execute the script. It is most often used with the -e option. See "Examples: Using the -n and -p Options" for more information.
	-e	This option lets you specify a single line of code on the command line. This line of code will be executed in lieu of a script file. You can use multiple -e options to create a multiple line program - although given the probability of a typing mistake, I'd create a script file instead. Semi-colons must be used to end Perl statements just like a normal script.


cat blah.txt | perl -ne '/filename=(.*?)\s\S+=/ and print "$1\n"' | sort | uniq 
perl -pi -e 's/cp1252/UTF-8/' file
perl -ne '/.*time=(\d+)\.0ms.*/ && print "$1\n"'
perl -e '"A" =~ /(?i:a|b|c)/ && print "$1\n"'
perl -e '$code; $description; while(<>) {$code=$1 if /<CodeID>(..)<\/CodeID>/; /<CodeDescription>([^<]+)<\/CodeDescription>/ and print "$code $1\n";}' Countrycode.xml
less Italy1.txt | perl -ne 'tr/[0-9.]/*/s and print' | awk -F"*" '{print $2}' | sed 's/^ //g' > Italy1.csv
less codetable.monster.nl-en-fr.languages.xml |perl -e '$counter=0; while(<>) { if(/<CodeID>(.*)<\/CodeIr++;print "     <CodeID>$counter</CodeID>\n"} else {print}}'
cat MLDemoXmltable/Phraserules/xmltable.phrs |perl -MEncode=from_to -pe 'from_to($_,"utf8","latin1");'
perl -MFile::Find=find -MFile::Spec::Functions -lwe 'find { wanted => sub { print canonpath $_ if /\.pm\z/ }, no_chdir => 1 }, @INC' (show librairs)
perl -pi -e 's/TKHOME.*/TKHOME = \/projects\/Wiacek\/Wiacek\/Wiacek.0/' /etc/wiacek.cfg 
perl -MEncode=from_to -pi -e 'from_to($_,"utf8","latin1");' lugera-latin1.phrs 


- check syntax
perl -wc script.pl
perl -Mstrict -cw [PHRASERULEFILE]

- find all cfg files that contains verbosity
grep config /etc/wiacek.cfg | awk '{print $3}' | perl -ne 'chomp; system "grep -H verbosity $_ ";'

- perl comvert from utf8 to latin1
cat MLDemoXmltable/Phraserules/xmltable.phrs |perl -MEncode=from_to -pe 'from_to($_,"utf8","latin1");'

- Applies changes directly to the file
perl -pi -e 's/TKHOME.*/TKHOME = \/projects\/Wiacek\/Wiacek\/wiacek.0/' /etc/wiacek.cfg 
perl -MEncode=from_to -pi -e 'from_to($_,"utf8","latin1");' lugera-latin1.phrs 

- Transform XML into entities
perl -p -e 'BEGIN { use CGI qw(escapeHTML); } $_ = escapeHTML($_);'  FILENAME

- Show perl libraries
perl -MFile::Find=find -MFile::Spec::Functions -lwe 'find { wanted => sub { print canonpath $_ if /\.pm\z/ }, no_chdir => 1 }, @INC'



CUT
---
- show field, set delimitor, show first/till characters

cut -d: -f 1 names.txt
cut -d: -f 1,3 names.txt
cut -c 1-8 names.txt
cut -f1, 3 -d" " (shows 1 and 3 field, space is deleimiter)
cut -c16 (shown 16th character and not field)
# ls -l | cut -c16-24 (charcters 16-24)
# ls -l | cut -c55- (charcters 55 till the end)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1.2 Files/dirs (grep, locate, find, sort, wc, tail, join, head, rename,dif,for,hexdump, okteta, truncate)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

HEXDATA 
-------
- show bytes, hexeditor, remove 2 last bytes

hexdump -b 
okteta
truncate -s-2 filename.
tail -c +4 UTF8 > UTF8.nobom


DIFF
---- 
- specify width, output, in color

diff -y -W200 file1 file2 | less
diff -y -W160 countries-used.txt countries-all.txt|less
diff -u file1 file2 | colordiff | less -R
alias diff=colordiff


RENAME
------
- rename all xml~ to .xml

rename .xml~ .xml *.xml~

HEAD
----
-first 5 lines, all but 5 last, print bytes

head -n 5 flavours.txt
head -4 flavours.txt
head -n -5 flavours.txt
head -c 5 flavours.txt

JOIN
----
- files by fields, choose field to print, specify delimiter, ignore case,Print non pairable lines

join -1 2 -2 1 emp.txt dept.txt
join -o 1.1 2.2 -1 2 -2 1 emp.txt dept.txt
join -t: -1 2 -2 1 emp.txt dept.txt
join -t, -i -1 2 -2 1 emp.txt dept.txt
join -a 1 -a 2 P.txt Q.txt

TAIL
----
- 5 last lines, print appended, terminate when pid dies, keep trying on error, print

tail -n 5 flavours.txt
tail -f /var/log/messages
tail -f /tmp/debug.log --pid=2575
tail -f /tmp/debug.log --retry
tail -c +4 UTF8 > UTF8.nobom

WC
--
- line count, length of lingest line, byte count, new line count, wordcount

wc -l demofile.txt
wc -L demofile.txt
wc -c testfile1
wc -l testfile1
wc -w testfile1

SORT
----
- at column, reverse, numeric, columns in files, positions
sort -k4 test.txt
sort -k7 -r test.txt
sort -r -n -k5
dir | \cygwin\bin\sort.exe -k 1.4,1.5n -k 1.40,1.60r
sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n /etc/hosts
sort -t: -k 3n /etc/passwd | more

SORT
----
- Sort the passwd file by the 3rd field (numeric userid)
sort -t: -k 3n /etc/passwd | more

SORT
----
- Sort /etc/hosts file by ip-address
sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n /etc/hosts

SORT
----
- Sort a colon delimited text file on 2nd field (employee_id)
sort -t: -k 2 names.txt

TRUNCATE
--------
- remove/add bytes from file
truncate -s-2 filename.
truncate -s 10 /tmp/foo
truncate -s 345M /tmp/foo

FIND
---- 
-find files/dirs based on patterns, recursively, execute remove, copy all to one location

find . -iname "*#" -exec rm \{} \;
find . -name "grzegorz*" -print
find Voorbeeld\ CVs/ -name "*.*" -exec cp {} all/ \;
find . -name '*[+{;"\\=?~()<>&*|$ ]*' -maxdepth 0 -exec rm -f '{}' \;
find ~/mail -type f | xargs grep "Linux"
find / -type f -print0 | xargs -0 grep -liwZ GUI | xargs -0 rm -f
find $UPLOAD_DIR/CVs -type f -exec rm -f {} \;

GREP 
----
-grep in files, regex, highlight in color, negative match, display context, recursively, display files and matches, count, 

grep -l this demo_*
grep -o "is.*line" demo_file
grep -c "go" demo_text
grep -Ei "http://res.carerix.net/cgi-bin/WebObjects/PublicTest.woa/wa/getExtractorTable\?table=Land" carerix.log.2008-10-*
grep ".*name=\"ResumeAdditionalItem" *
grep -v "go" demo_text
export GREP_OPTIONS='--color=auto' GREP_COLOR='100;8'
grep -C 2 "Example" demo_text
grep -A 3 -i "example" demo_text
echo 1 | grep -P '\d' #grep for digit using gnu-grep (enables \d)
echo 1 | grep '[[:digit:]]' #grep for digit using 	POSIX
 
MAGIC
-----
- Grep all lines from CFG file,filter pattern with perl, copy with while+do and copy to other location
less bruinsNormalization.cfg | perl -ne '/\sdata\s+(\S+)/ and print "$1\n"' | while read file; do echo cp $file another_directory; done

MAGIC
-----Use for loop, create variable and write timetamp, write that to files as input
for i in *xml; do timestamp="07-03-2011 14:00"; echo $timestamp > `basename $i .xml`.date; done

MAGIC
-----
- Carerix The Command: replace XML encoding in all files
grep -R cp1252 */*xml | cut -d":" -f1 | xargs -n 1 -t -I file perl -pi -e 's/cp1252/UTF-8/' file

MAGIC
-----
- Remove bom/BOM with AWK
awk '{if(NR==1)sub(/^\xef\xbb\xbf/,"");print}' INFILE > OUTFILE
tail -c +4 UTF8 > UTF8.nobom
hd -n 3 UTF8

MAGIC
-----
- Grep all CFG files that use gender and create a wiki format
grep -r -l -i "gendernamedisambig" */*.cfg | xargs -n 1 -I {} echo '|' {} '| | | |' | tr '/' '*' | awk -F"*" '{print $1 " | " $2}'

MAGIC
-----
- replace all occurances of cp1525->utf-8 in XML files recursively:
grep -R cp1252 */*xml | cut -d":" -f1 | xargs -n 1 -t -I file perl -pi -e 's/cp1252/UTF-8/' file

MAGIC
-----
- Grep all lines from CFG and copy to other location
less bruinsNormalization.cfg | perl -ne '/\sdata\s+(\S+)/ and print "$1\n"' | while read file; do echo cp $file another_directory; done

MAGIC
-----
- Write content to all files
for i in *.date; do echo 09-04-2010 20:00 > $i; done
for i in *xml; do timestamp="07-03-2011 14:00"; echo $timestamp > `basename $i .xml`.date; done

MAGIC
-----
- Diff all files in fields.original vs fields.ported
for i in fields.original/*; do echo `basename $i`; diff -y -W160 $i fields.ported/`basename $i`; echo; done | less

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1.3 Process (tcpdump,netstat, lsof, traceroute, ps, ping, top, curl, sniff, nmap, route, dns, strace, nc)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

NC
--
- check port on host, use udp,scan for listening deamons, start server/client, send/receive file
- arbitrary TCP and UDP connections and listens
- Netcat or nc is a networking utility for debugging and investigating the network.
- This utility can be used for creating TCP/UDP connections and investigating them. The biggest use of this utility is in the scripts where we need to deal with TCP/UDP sockets.

nc -vzu monitor.wiacek.local 514
-v verbose
-z scan for listening deamons, without sending data
-u use UDP

nc -z vip-1.vsnl.nixcraft.in 1-1023 ( to scan Linux / UNIX / Windows server port, with -z flag)
nc -l 3333 (start server)
nc 192.168.0.1 3333 (start client)
cat backup.iso | nc -l 3333 (transfer file)
 nc 192.168.0.1 3333 > backup.iso (receive file)
 nc -k -l 2389 (stay alive)

STRACE
------
- trace executable/specific system calls/running linux process, statistics, save to file 
- Strace monitors the system calls and signals of a specific program. It is helpful when you do not have the source code and would like to debug the execution of a program. strace provides you the execution sequence of a binary from start to end.

strace ls (Trace the Execution of an Executable)
strace -e open ls (Specific System Calls in an Executable Using Option -e)
strace -e trace=open,read ls /home
strace -o output.txt ls (save to file)
sudo strace -p 1725 -o firefox_trace.txt (Running Linux Process Using Option -p)
strace -t -e open ls /home (Print Timestamp for Each Trace Output Line Using Option -t)
strace -c ls /home (Generate Statistics Report of System Calls Using Option -c)

ROUTE
-----
- routing for all ips, add a (custom)route, delete default, set gateway

route -n (Shows routing table for all IPs bound to the server.)
route add -net 192.56.76.0 netmask 255.255.255.0 dev eth0 (adds a route to the network 192.56.76.x via "eth0".)
route delete default
route add default gw 192.168.0.227
route add -host 82.94.180.72 gw 192.168.0.3 (custom route for 82.94.180.72 via 192.168.0.3)

SNIFF
-----
- find all hosts in your network (for+ping+echo and nmap)

for ip in $(seq 1 254); do ping -c 1 192.168.1.$ip>/dev/null; [ $? -eq 0 ] && echo "192.168.1.$ip UP" || : ; done
nmap -sP 192.168.1.1/24
-s: ip protocol scan

NMAP
----
- for open ports, host enumeration, tcp scan, choose host at random, ip protocol scan

nmap -sP 192.168.1.1/24
nmap -v scanme.nmap.org (scan host for open ports)
nmap -sV -p 22,53,110,143,4564 198.116.0-255.1-127 (Launches host enumeration and a TCP scan at the first half of each of the 255 possible eight-bit subnets in the 198.116 class B address space. This tests whether the systems run SSH, DNS, POP3, or IMAP on their standard ports, or anything on port 4564. For any of these ports found open, version detection is used to determine what application is running.)
nmap -v -iR 100000 -Pn -p 80 (Asks Nmap to choose 100,000 hosts at random and scan them for web servers (port 80). Host enumeration is disabled with -Pn since first sending a couple probes to determine whether a host is up is wasteful when you are only probing one port on each target host anyway.)
nmap -Pn -p80 -oX logs/pb-port80scan.xml -oG logs/pb-port80scan.gnmap 216.163.128.20/20 (This scans 4096 IPs for any web servers (without pinging them) and saves the output in grepable and XML formats.)


CURL
----
- http authentification
curl -u yacitus:xxxx http://api.tr.im/api/trim_url.json?url=http://www.google.co.uk



UPTIME
------
- output
 16:42:50 up 10 days, 19:58,  9 users,  load average: 1.05, 1.04, 1.04

PING 
----
- of echos, socket-level debugging, #bytes, flood-ping,interval,diagnos data-depended network problems)

ping  -c 5 canopus ( to host canopus and specify the number of echo requests to send)
ping  -d lear (host lear and start socket-level debugging)
ping  -s 2000 opus (host opus and specify the number of data bytes to be sent)
ping  -f stlopnor (the flood-ping option to host stlopnor)
ping  -i5 opus (interval 5 seconds)
ping  -l 10 opus (To send the number of packets specified by the Preload variable as fast as possible before falling into normal mode of behavior to host opus)
ping  -p ff opus (To diagnose data-dependent problems in a network)
ping  -q bach (To specify quiet output)


PS
--
- processes, all, listening,for user, on pids, forest, command which executed, what values to output,memory leak
ps -ef
e to display all the processes.
-f to display full format listing.
ps -f -u wwwrun,postfix (process that are owned by user wwwrun, or postfix)
ps -f --ppid 9576
$ ps -f  -p 25009,7258,2426
ps -e -o pid,args --forest (forest)
ps -C java -L -o pid,tid,pcpu,state,nlwp,args (all threads for a particular process )
-C This selects the processes whose executable name is given in cmdlist.
ps -fe --cols 1000 | grep wiacek | grep dyna

- for memory
ps -e -orss=,args= | sort -b -k1,1n | pr -TW$COLUMNS ( List processes by mem usage )
ps -e -orss=,args= | sort -b -k1,1n | awk 'BEGIN{memo=0} {memo=$1+memo} END{print memo}' (This sums it up:)


PS
--
Memory leak
ps aux --sort pmem
$ ps ev --pid=27645
PID TTY STAT TIME MAJFL TRS DRS RSS %MEM COMMAND
27645 ? S 3:01 0 25 1231262 1183976 14.4 /TaskServer/bin/./wrapper-linux-x86-32
Note: In the above output, if RSS (resident set size, in KB) increases over time (so would %MEM), it may indicate a memory leak in the application.

TRACEROUTE
----------
1) ping the end machine (how long does it take? does it reach the destination?)
2) traceroute (see any thing takeing a bit longer then the rest of the results?)
3) netstat (you can use it to do a bunch of stuff like see how much traffic is flowing)

traceroute computerhope.com

LSOF
----
- process opened file, process with name, user (kill),process, port, protocol 
It is a command line utility which is used to list the information about the files that are opened by various processes. In unix, everything is a file, ( pipes, sockets, directories, devices, etc.). So by using lsof, you can get the information about any opened files.
Network connections are also files. So we can find information about them by using lsof.

lsof /var/log/syslog (which process opened file)
lsof +D /var/log/ (opened file under dir)
lsof -c ssh -c init (List opened files based on process names starting with)
lsof -u lakshmanan (files opened by user)
lsof -u ^lakshmanan
lsof -p 1753 (files opened on port)
kill -9 `lsof -t -u lakshmanan` (kill process belong to a user)
lsof -u lakshmanan -c init -a -r5 (repeat mode)
lsof -i (network connections)
lsof -i -a -c ssh (list the network files opened by the processes starting with ssh.)
lsof -i :25 (process listening on port)
lsof -i tcp; lsof -i udp; (protocols)


NETSTAT
-------
- ntpl,ports,listening,protocol,pid,stats,routing,on what port program running,what running on port
Netstat command displays various network related information such as network connections, routing tables, interface statistics, masquerade connections, multicast memberships etc.,
N - show numerical addresses instead host
T - --tcp
P - program,pid
L-listening
netstat -n 
netstat -ntpl
netstat -a
netstat -an
less /etc/services 
netsta t-tulpn
lsof -Pnl +M -i4
netstat -a | more (all ports)
netstat -at (all tcp ports)
netstat -au (udp)
netstat -l (only listening)
netstat -lu (only listening udp)
netstat -s (show stats)
netstat -pt (pid and program)
netstat -c (continously)
netstat -r (kernel routing info)
netstat -ap | grep ssh (on which port programkm running?)
netstat -an | grep ':80' (which proccess listenig on port?)
netstat -ie (extened network interface)


NETSTAT
-------
- Port 8005 is taken, find the process which is taking this port
netstat -ntpl | grep ":8005" (gives pid)
ps -ef | grep 21756 (find process)

TCPDUMP
-------
- catch traffic from certain IP, caputure (with ip, timestamp, n-)-packets on port from a particular eth,verbose,write/read into file,on protocol (arp),betweem host, filter other
tcpdump -nnAltqSs 0 -i eth0 host \(95.211.66.22 or 95.211.66.46\) >hostlog 2>hostlog.err &
tcpdump -nn -i eth0 port 5000 (on port)
tcpdump -i eth1 (on ethernet)
tcpdump -c 2 -i eth0 (n-packets)
tcpdump -A -i eth0 (in ascii)
tcpdump -w 08232010.pcap -i eth0 (write to file)
tcpdump -tttt -r data.pcap (read from file)
tcpdump -n -i eth0 
tcpdump -n -tttt -i eth0 (timestamp)
tcpdump -i eth0 arp (protocol)
tcpdump -w xpackets.pcap -i eth0 dst 10.181.140.216 and port 22 (for destination)
tcpdump -w comm.pcap -i eth0 dst 16.181.170.246 and port 22 (between two hosts)
tcpdump -i eth0 not arp and not rarp (filter other then)
tcpdump -nn -i eth0 port 5000 (See incoming packagies on port)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1.3 Networking (DNC, DHCP, dig,nslookup, ifcfg files, nsupdate)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

DNS RECORDS
-----------
SOA: start of zone authority
NS: an authoritative name server
A: a host address
CNAME: the canonical name for an alias
MX: mail exchanger
PTR: a domain name pointer (used in reverse DNS)

NSUPDATE
--------
- start with key, enter zone
- delete reverse lookup, commit, quit
- add/delete A, add/delete CNAME

nsupdate -v -k /etc/rndc.key
> zone wiacek.local.
> update delete tk55.wiacek.local. 86400 CNAME tk55.wiacek.local.
> show
> update add carerix.wiacek.local. 86400 CNAME tk55.wiacek.local.
> send
> quit
> update add newhost.example.com 86400 A 172.16.1.1
> update delete PTR 164.0.168.192.in-addr.arpa (delete reverse lookup,watch the reverse IP address)
> update delete oldhost.example.com A (delete)
> update add newhost.example.com 86400 A 172.16.1.1 (add new=>A)

NSLOOKUP
--------
- query ns/soa/available records, reverse, use specific dns-server
- nslookup is a network administration tool for querying the Domain Name System (DNS) to obtain domain name or IP address mapping or any other specific DNS record.

nslookup -type=ns redhat.com (Query the NS Record)
nslookup -type=soa redhat.com (Query the SOA Record)
nslookup -type=any google.com (available DNS records)
nslookup 209.132.183.181 (Reverse)
nslookup redhat.com ns1.redhat.com (Specific DNS server)
nslookup -debug redhat.com (debug)

REVERSE_LOOKUP
--------------
- perform reverse lookup (x3), explain binding, delete from dns

nslookup 209.132.183.181 (Reverse)
dig +noall +answer -x 199.232.41.10
host 75.126.43.235

* reverse lookup is created automatically for all leases
* is deleted automatically for full dhcp leases
* is not deleted automatically for static leases
* how to delete (watch the reverse IP address)
update delete PTR 164.0.168.192.in-addr.arpa


HOST_RESOLVING
--------------

- Lookup order
/etc/nsswitch.conf (hosts: files dns nis)

- File hosts
/etc/hosts
192.168.0.179   tkpgsql1

- DNS Configuration (nameservers)
/etc/resolv.conf (dns configuration)
; generated by /sbin/dhclient-script
search wiacek.local.
nameserver 192.168.0.31
nameserver 192.168.0.129
nameserver 192.168.0.227

- Lookup only via DNS (disregarding nsswitch.conf)
host carerix
host carerix ns1.xs4all.nl

LOCAL_HOSTNAME
--------------
- change own hostname (terminal, network)

/etc/hosts
variable $HOSTNAME in /etc/sysconfig/network(for term)
hostname {newnanme}
hostname -f 
relogin
$DHCP_HOSTNAME /etc/sysconfig/network-scripts/ifcfg-eth.
/etc/dhcpd.conf
/etc/dhcpd.d/leases.conf

DIG
---
- query DNS name servers for your DNS lookup related tasks
- query answer section, mx/ns/all/any dns records, short, from file 

dig redhat.com

-  Display Only the ANSWER SECTION 
dig redhat.com +nocomments +noquestion +noauthority +noadditional +nostats
dig redhat.com +noall +answer

- Query MX Records Using dig -t MX
dig redhat.com  MX +noall +answer
dig -t MX redhat.com +noall +answer

- Query NS Records Using dig -t NS
dig redhat.com NS +noall +answer
dig -t NS redhat.com +noall +answer

- View ALL DNS Records Types Using dig -t ANY
dig redhat.com ANY +noall +answer
dig -t ANY redhat.com  +noall +answer

- View Short Output Using dig +short
dig redhat.com +short
dig redhat.com ns +short

- Use a Specific DNS server Using dig @dnsserver
dig @ns1.redhat.com redhat.com

-  Bulk DNS Query Using dig -f (and command line)
dig -f names.txt +noall +answer
dig -f names.txt MX +noall +answer

- Reverse lookup
dig -x 74.125.45.100
dig +noall +answer -x 199.232.41.10

DHCP
----
- where config, leases, matches

port 68
/etc/init.d/dhcpd
/etc/dhcpd.conf
/etc/dhcpd.d/leases.conf
mac address case-sensitive

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1.4 Compression (tar,zip/unzip)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ZIP
--- 
- individual files, all matches, directory, check if ok, extract one file, extract into /tmp, list

zip mydata.zip mydata.doc
zip data.zip *.doc
zip zipped-up-filename.zip file1.txt file2.txt file3.log file4.inc
zip -r zipped-up-filename.zip folder-to-be-zipped/
zip -r zipped-up-filename.zip .
unzip -tq pics.zip (check if ok)
unzip pics.zip  cv.doc (extract file)
unzip pics.zip  -d /tmp (To extract all files into the /tmp directory:)
unzip -l pics.zip (list)


- ZIP commands - exclude from zipping -x
zip -r CV-Common.zip CV-Common/* -x \*.log \*.pid
zip -r monsterNormalization-1_7.zip MonsterNormalization/* -x \*.log \*.pid \*light* \*previous*

TAR
---
- create archive no_comoression/gzip/bzip, extract all/file/dir, add, estimate size
tar cvf archive_name.tar dirname/ (no compression)
	c – create a new archive
	v – verbosely list files which are processed.
	f – following is the archive file name
tar cvzf archive_name.tar.gz dirname/ (with compression)
	z – filter the archive through gzip
	.tgz is same as .tar.gz
tar cvfj archive_name.tar.bz2 dirname/ (create bzip)
	j – filter the archive through bzip2
	gzip vs bzip2: bzip2 takes more time to compress and decompress than gzip. bzip2 archival size is less than gzip.
tar xvf archive_name.tar (Extract a tar file using option x as shown below:)
	x – extract files from archive
tar xvfz archive_name.tar.gz (Use the option z for uncompressing a gzip tar archive.)
tar xvfj archive_name.tar.bz2 (Use the option j for uncompressing a bzip2 tar archive.)

tar tvf archive_name.tar (list)
tar tvfz archive_name.tar.gz
tar tvfj archive_name.tar.bz2

tar xvf archive_file.tar /path/to/file (Extract a single file from tar, tar.gz, tar.bz2 file)
$ tar xvfz archive_file.tar.gz /path/to/file
$ tar xvfj archive_file.tar.bz2 /path/to/file

tar xvf archive_file.tar /path/to/dir1/ /path/to/dir2/ (Extract a single directory)
$ tar xvfz archive_file.tar.gz /path/to/dir/
$ tar xvfj archive_file.tar.bz2 /path/to/dir/

tar rvf archive_name.tar newfile (add to archive)
 	- Note: You cannot add file or directory to a compressed archive. If you try to do so, you will get “tar:
	
tar -cf - /directory/to/archive/ | wc -c (estimate size before creating)
	
- Tar whole directory
tar czfv /Wiacek/paqckage/Wiacek.05.14_linux.tgz Wiacek-3.05.14/
tar -cf - list_of_file_names | gzip > output_file.tar.gz	

- tar files and split in 100MiB parts
tar zcf - Wiacek | split -d -b 100MiB - Wiacek/Wiacek.tar.bz2__

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1.5 XML (xmlint, prett print, xpath)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

XMLLINT
-------
- with schema, no outpout, validation, relaxng,dtd

xmllint --noout --schema ~isaac/data/hr-xml/Candidate.xsd ~/hrxml_example.xml
xmllint --noout --schema Resume.xsd test.hrxml 
xmllint --noout ~/Documents/angela.tk54-11400-norm.xml
xmllint --noout --dtdvalid URL file.xml
xmllint --noout --relaxng airport.rng sfo.xml
xmllint --valid --noout file.xml
xmllint --format myXmlFile.xml > myPrettyPrintedFile.xml 

PRETTYPRINT XML 
---------------
- tidy, xmllint,xml_pp (with backups named, preserve spaces in pre and code tags)

tidy -i -xml -asxml ~/Download/Wiacek.xml | less
xmllint --format myXmlFile.xml > myPrettyPrintedFile.xml 
xml_pp foo.xml > foo_pp.xml           # pretty print foo.xml
xml_pp < foo.xml > foo_pp.xml         # pretty print from standard input
xml_pp -v -i.bak *.xml                # pretty print .xml files, with backups
xml_pp -v -i'orig_*' *.xml            # backups are named orig_<filename>
xml_pp -i -p pre foo.xhtml            # preserve spaces in pre tags
xml_pp -i.bak -p 'pre code' foo.xml   # preserve spaces in pre and code tags

XPATH
-----
//ItemGroup[@key='ansi_linked_dateofbirth']//Field[@key='ansi_linked_dateofbirth']
//ItemGroup[@key='educationitem']/Item[./Field[@key='ishighestitem']//text()='true']/Field[@key='institutionclasscode@description']
//ItemGroup[@key='contracttype' and //Field[@key='contracttype@type']='Rate']//Field[@key='contracttype@rate']


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1.6 Misc (svn, git, crontab, iptables,rsync,swap,chkconfig)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

CHKCONFIG
---------
sudo chkconfig collectd on
chkconfig --list
chkconfig postgresql on
chkconfig --list | grep 3:on
chkconfig --add iptables
chkconfig --del ip6tables
chkconfig --level 5 nfsserver off
chkconfig --level 35 nfsserver off


SWAP
----
-remove swap, add swap 512MB, change from 32->16

- Remove swap file
swapoff /var/swapfile
/var/swapfile swap swap defaults 0 0 (remove entry from /etc/fstab)
remove /var/swapfile

- Change swap from 32 to 16:
dd if=/dev/zero of=/var/swapfile 1 bs=1024 count=16777216 (16777216 = 1024 * 1024 * 16)
swapoff /var/swapfile
mkswap /var/swapfile
swapon /var/swapfile

- Add create 512MB swap file (1024 * 512MB = 524288 block size):
dd if=/dev/zero of=/swapfile1 bs=1024 count=524288
mkswap /swapfile1 (set up a Linux swap area in a file)
chown root:root /swapfile1 (only root user can read/write to the file)
chmod 0600 /swapfile1
swapon /swapfile1 (activate)
/swapfile1 swap swap defaults 0 0 (add entry to /etc/fstab file)

RSYNC
-----
$ rsync options source destination
start deamon with rsync --deamon 
rsync -cva --inplace --exclude=*pg_xlog* /data/pgsql/9.0/data/ /data/pgsql/9.2/data/
rsync  -avzR --numeric-ids --delete --link-dest=/backup/$SERVER/$SERVER-$ldate rsync://tkpgsql2:/system/var/lib/pgsql/9.0/data /backup/$SERVER/$SERVER-$date
nohup rsync -avzr --delete --exclude=*pg_xlog* --partial rsync://beta:/projects/pgsql/9.0/data /data/pgsql/9.0/ >lo 2>&1 &

	-z is to enable compression
	-v verbose
	-r indicates recursive
	-a indicates archive mode

- To sync two directories in a local computer, use the following rsync -zvr command.
rsync -zvr /var/opt/installation/inventory/ /root/temp

-a indicates archive mode (preserves timestamps)
rsync -azv /var/opt/installation/inventory/ /root/temp/
 	
- rsync allows you to synchronize files/directories between the local and remote system.
rsync -avz /root/temp/ thegeekstuff@192.168.200.10:/home/thegeekstuff/temp/
rsync -avz thegeekstuff@192.168.200.10:/var/lib/rpm /root/temp

-  View the rsync Progress during Transfer
rsync -avz --progress thegeekstuff@192.168.200.10:/var/lib/rpm/ /root/temp/

- Delete the Files Created at the Target
rsync -avz --delete thegeekstuff@192.168.200.10:/var/lib/rpm/ .

- Do not Create New File at the Target
rsync -avz --existing root@192.168.1.2:/var/lib/rpm/ .

- displays this difference. -i option displays the item changes.
rsync -avzi thegeekstuff@192.168.200.10:/var/lib/rpm/ /root/temp/

-  Include and Exclude Pattern during File Transfer
rsync -avz --include 'P*' --exclude '*' thegeekstuff@192.168.200.10:/var/lib/rpm/ /root/temp/

IPTABLES
--------
- block IP, block tcp, from outgoiing, block port, to destination,allow ssh on specifc network
- allow incoming HTTP and HTTPS, Allow Ping from Outside to Inside, Allow outbound DNS, Prevent DoS Attack
- to allow syslog-ng port probing add a line like this (complete config)


less /etc/sysconfig/iptables
/etc/init.d/iptables {start|stop|restart|condrestart|status|panic|save}


iptables -A INPUT -s "$BLOCK_THIS_IP" -j DROP (block IP)
iptables -A INPUT -i eth0 -s "$BLOCK_THIS_IP" -j DROP
iptables -A INPUT -i eth0 -p tcp -s "$BLOCK_THIS_IP" -j DROP (block tcp)

- The following rule will block ip address 202.54.1.22 from making any outgoing connection:
iptables -A OUTPUT -d 202.54.1.22 -j DROP

- It is also possible to block specific port numbers. For example, you can block tcp port # 5050 as follows:
iptables -A OUTPUT -p tcp –dport 5050 -j DROP

- To block tcp port # 5050 for an IP address 192.168.1.2 only, enter: 
iptables -A OUTPUT -p tcp -d 192.168.1.2 –dport 5050 -j DROP

- allow ssh
iptables -A INPUT -i eth0 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT (allow ssh1)
iptables -A OUTPUT -o eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT (allow ssh2)

- allow ssh on specific network 
iptables -A INPUT -i eth0 -p tcp -s 192.168.100.0/24 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

- Allow Incoming HTTP and HTTPS
iptables -A INPUT -i eth0 -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

- Allow Ping from Outside to Inside
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT

-  Allow Ping from Inside to Outside
iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT

- Allow Internal Network to External network.
In this example, eth1 is connected to external network (internet), and eth0 is connected to internal network (For example: 192.168.1.x).
iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT

-  Allow outbound DNS
iptables -A OUTPUT -p udp -o eth0 --dport 53 -j ACCEPT
iptables -A INPUT -p udp -i eth0 --sport 53 -j ACCEPT

- Allow Rsync From a Specific Network
iptables -A INPUT -i eth0 -p tcp -s 192.168.101.0/24 --dport 873 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --sport 873 -m state --state ESTABLISHED -j ACCEPT

- Prevent DoS Attack
iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j

- Displaying the Status of Your Firewall
iptables -L -n -v

- to allow syslog-ng port probing add a line like this (complete config)
cat /etc/sysconfig/iptables
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 9200 -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 9300:9302 -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 9292 -j ACCEPT
-A INPUT -m state --state NEW -m udp -p udp --dport 514 -j ACCEPT
-A INPUT -m state --state NEW -m udp -p udp -s 224.2.2.4 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited
-A FORWARD -j REJECT --reject-with icmp-host-prohibited
COMMIT

- allow only http+https (full config)
# Firewall configuration written by system-config-firewall
# Manual customization of this file is not recommended.
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
#state related and established accept allre3ady defined here
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
#MW: added two next rules to allow HTTP traffic and https on eth1 the public interface
-A INPUT -i eth1 -p tcp --dport 80 -m state --state NEW -j ACCEPT
-A INPUT -i eth1 -p tcp --dport 443 -m state --state NEW  -j ACCEPT
#MW: added rules to accept 8080 traffic for our network, not necessary all traffic is allowed from our network
#-A INPUT -i eth1 -p tcp -s 192.168.0.0/22 --dport 8080 -m state --state NEW,ESTABLISHED -j ACCEPT
#block all other traffic on the public interface, eth1
#the private interface ,eth0 ,is not blocked alltogether
-A INPUT -i eth1 -j REJECT --reject-with icmp-host-prohibited
#no forwarding allowed
-A FORWARD -j REJECT --reject-with icmp-host-prohibited
COMMIT

CRONTAB
-------
- format, 10th June 08:30 AM., 11:00 and 16:00 on every day,working hours 9 a.m – 6 p.m, 
- every minute,10 minutes, every year, month, list, edit

MIN	Minute field	0 to 59
HOUR	Hour field	0 to 23
DOM	Day of Month	1-31
MON	Month field	1-12
DOW	Day Of Week	0-6
CMD	Command	Any command to be executed

0 0 6 6 9 ? 2010
| | | | | |   |
| | | | | |   +- 2010 only.
| | | | | +----- any day of the week. (? allowed)
| | | | +------- 9th month (September).
| | | +--------- 6th day of the month. (? allowed)
| | +----------- 6th hour of the day.
| +------------- Top of the hour (minutes = 0).
+--------------- Top of the minute (seconds = 0).

30 08 10 06 * /home/ramesh/full-backup (10th June 08:30 AM.)
00 11,16 * * * /home/ramesh/bin/incremental-backup (11:00 and 16:00 on every day)
00 09-18 * * * /home/ramesh/bin/check-db-status (working hours 9 a.m – 6 p.m)
crontab -l
crontab -e
* * * * * CMD (every minute)
*/10 * * * * /home/ramesh/check-disk-space ( every 10 minutes)
@yearly /home/ramesh/red-hat/bin/annual-maintenance (00:00 on Jan 1st for every year)
@monthly /home/ramesh/suse/bin/tape-backup (00:00 on 1st of every month)
"0 0/5 * * * ?" (every five minutes)
10 0/5 * * * ? (every 5 minutes, at 10 seconds after the minute)
"0 30 10-13 ? * WED,FRI" (10:30, 11:30, 12:30, and 13:30 , on every Wednesday and Friday)

- every half hour between the hours of 8 am and 10 am on the 5th and 20th of every month. Note that the trigger will NOT fire at 10:00 am, , just at 8:00, 8:30, 9:00 and 9:30
"0 0/30 8-9 5,20 * ?" 

SVN 
---
checkout,update,revert,diff,commit message,add,delete,remove,copy revision

svn checkout http://svn.greenstone.org/main/trunk/greenstone3 gs3-svn (checkout)
svn checkout svn://somepath@1234 working-directory
svn update <filename1> <filename2> ... <filenameN> (update)
svn revert <filename1> ... <filenameN> (go back to the version of the file in the repository)
svn diff util.pm
> svn diff <filename> <filename2> <filenameN>
> svn update <filename> <filename2> <filenameN>
> svn diff <filename> <filename2> <filenameN>
> svn commit - m "message" <filename> <filename2> <filenameN>
svn add <filename1> <filename2> <filenameN>
svn commit -m "These new files work together to add some extra functionality" <filename1> <filename2> <filenameN>
svn remove -m "I deleted this file for a reason" http://svn.greenstone.org/....../thefile.ext
svn status
svn mkdir -m "Making a new dir." http://svn.red-bean.com/repos/newdir
svn delete http://www.yourrepository.com/svn/folder --message "Deleting"
svn copy https://secure.wiacek.local/repos/Test@75705 https://secure.wiacek.local/repos/trunk/
svn export -r {2009-02-17} (from date)
svn export -r{2009-12-20} svn://project/path/trunk export_directory

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1.7 Execution (xargs, execute, watch)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

WATCH
-----
- run command 1 sec, every 1/10 sec, display changes highlighted
watch <some arguments> | awk '{print $5}'
watch -n 5 "ls -lh club_prod.sql | awk '{print \$5}'"
watch du -s /tmp/CentOS-6.2-i386-bin-DVD1.iso
watch -n 1 ls -l (Run ls command for every 1 second)
watch -n 0.1 free (Run free command for every 1/10 second)
watch -d -n 1 free (Display changes in output of a command with -d option of watch)
watch -n 10 -d ls -l /var/adm/messages

XARGS
-----

- kill process by name, grep and delete files
ps ax | grep "$PROCESS_NAME" | awk '{print $1}' | xargs -i kill {} 2&>/dev/null
find / -type f -print0 | xargs -0 grep -liwZ GUI | xargs -0 rm -f
find <directory> -print0 |xargs -0 -n 1 setfattr -h -x security.selinux
find -name "*.cfg" | perl -pe 's/(\S+)/$1.bak $1/' | xargs -n 2 cp
find . -name '*~' -print0 | xargs -0 -l -i -t  rm {}
echo a b c d e f | xargs -n 2 echo | xargs -l2 echo

- Cleans current directory from all subversion directories recursively.
find . -type d -name ".svn" -print | xargs rm -fr

- Unzip 4 zip files with CV-Models
echo /tmp/*.zip | sudo xargs -n 1 unzip  

- Delete all ~ files
find . -name '*~' -print0 | xargs -0 -l -i -t  rm {}

- replace all occurances of cp1525->utf-8 in XML files recursively:
grep -R cp1252 */*xml | cut -d":" -f1 | xargs -n 1 -t -I file perl -pi -e 's/cp1252/UTF-8/' file

- to remove the selinux acl's (presented by a dot after the permissions)
find <directory> -print0 |xargs -0 -n 1 setfattr -h -x security.selinux
<directory> is e.g. /usr or / or . (current directory) etc.

EXEC
----

- talk to TCP Wiacek on port via file
exec 3<>/dev/tcp/localhost/8888
echo -en "LIST-SERVICES\n" >&3
cat <&3
{"services":[{"status":"on","name":"CV-EN","port":"50200"},{"status":"on","name":"CV-NL","port":"50100"},{"status":"on","name":"CV-PL","port":"51200"},{"status":"on","name":"CV-IT","port":"50500"},{"status":"on","name":"CV-ES","port":"50600"}]}[root@extern ~]# 

- talk to www.google.com
exec 3<>/dev/tcp/www.google.com/80 (opens file descriptor 3 for reading and writing on the specified TCP/IP socket)
echo -e "GET / HTTP/1.1\r\nhost: http://www.google.com\r\nConnection: close\r\n\r\n" >&3 (send request)
cat <&3 (read response)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1.8 Remote (ssh, rdesktop, cssh, multiple terminals)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

TERMINAL
--------
TTY=$(basename $(tty))
HOSTNAME=$(hostname)
export PS1="\n$HOSTNAME - $LOGNAME ($TTY) [$SHLVL] - \$PWD\n> "
export PS1="[$LOGNAME@$HOSTNAME \$PWD/]$ "

RDESKTOP
--------
- full script, bits, names, password, user, visuals, mount dir, client name
rdesktop2 -f -a24 -0 -T tk29 tk29 -u Administrator
rdesktop2 -f -a24 -0 -T tk18 tk18 -u Administrator 
rdesktop2 -f -a 24 -T s1459.nxs.nl -f -u Unisys -p  MXwysCJd s1459.nxs.nl -0 &
rdesktop2 -f -a 24 -T s1211.nxs.nl -f -u Unisys -p  MXwysCJd s1211.nxs.nl -0
XLIB_SKIP_ARGB_VISUALS=1 rdesktop -f -a24 -0 -T "YER S2" -d YERADAM 212.78.179.142 -u txtkernel -p 2006@Y3R -r disk:client=/home/isaac/data/YER -r clientname=tk113 -xb &

-a24 -- bit depth
-0   -- Terminal
-T tk29 Title screen

MULTIPLE SSH
------------
- You can also try Cluster SSH (cssh)
- Rundeck

SSH
---

- No password required
mkdir -p $HOME/.ssh
chmod 0700 $HOME/.ssh
ssh-keygen -t dsa -f $HOME/.ssh/id_dsa -P '' (generates private and public key):
ssh-keygen -t rsa
copy Copy $HOME/.ssh/id_dsa.pub to the server.
cat id_dsa.pub >> $HOME/.ssh/authorized_keys
chmod 0600 $HOME/.ssh/authorized_keys
ssh -i /home/wiacek/.ssh/id_dsa wiacek@home.wiacek.local 'find /projects/configuration/search/conf -name "*.env.conf"'

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1.9 Profile (alias, path etc)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ALIAS:
alias lsof='sudo /usr/sbin/lsof'
unalias cp

- Edit the .profile file , add the entry
aliase alias_name='command'

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1.10 users/groups (chmod, chown, id, usermod)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

USERS/GROUPS
------------

    useradd: Create a new user or update default new user information
    usermod: Modify a user account
    userdel: Delete a user account and related files
    chage: change user password expiry information
    pwconv: convert to and from shadow pass- words and groups.
    pwunconv: convert to and from shadow pass- words and groups.
    grpconv: creates gshadow from group and an optionally existing gshadow
    grpunconv: creates group from group and gshadow and then removes gshadow
    accton: turns process accounting on or off (Red Hat/Fedora/CentOS)
    ac: Prints stats about users connect time (Red Hat/Fedora/CentOS)

- list groups, add new user to group, create user
- check if group exists,create group,check new user
- change group of user, check if user exists, 


- Add new user to a group
useradd -G {group-name} username
useradd -G developers vivek

- Create users
useradd txtor3
passwd txtor3

- Check if group exists
grep developers /etc/group

- Create/delete group
groupadd apache -g 9090 (id)
groupdel
chgrp

- Check if user exists
egrep "^$USERNAME" /etc/passwd >/dev/null
if [ $? -eq 0 ]; then
    echo "$USERNAME exists!"


- Check new user
id vivek

- Change group/dir for user:
usermod -g www tony
usermod -d /path/to/new/homedir/ username

- Check if group/user exists
grep <username> /etc/passwd
id <username>
grep apache /etc/group
less /etc/group

- Create user with password one line
pass=$(perl -e 'print crypt($ARGV[0], "password")' $PASSWORD)
SCRIPTDIR="$(cd $(dirname "$0");pwd)"
useradd -m -d $HOME_DIR -p $pass $USERNAME

ACCES_RIGHTS
------------

- read read/write access, all members user/group/other/everyone
- deny read/write access

- Grant read access (r) to a file to all members of your group (g):
chmod g+r file-name

- Grant read access to a directory to all members your group:
chmod g+rx directory-name

- Grant read permissions to everyone on the system to a file which you own so that everyone may read it: (u)ser, (g)roup and (o)ther.
chmod ugo+r file-name

- Grant read permissions on a directory to everyone on the system:
chmod ugo+rx directory-name

- Grant modify or delete permissions to a file which you own for everyone in the group:
chmod ugo+rw file-name

- Deny read access to a file by everyone except yourself:
chmod go-r file-name

- Allow everyone in your group to be able to modify the file:
chmod 660 file-name 


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1.11 Disk (du, df, nfs/mount)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

NFS
---
/etc/init.d/nfs (start nfs on tk64)

- add an entry to the /etc/exports file on tk64)
/opt/vdhoven    192.168.0.0/24(rw,no_root_squash,sync

exportfd -rv (on tk6400)

- add an entry on your own machine to /etc/fstab to map the drive
192.168.0.64:/opt/vdhoven /tk64    nfs    lock,exec,dev,suid,rw,hard,intr,noauto    0 0

- make the directory entry on your machine if it doesn't exist
mkdir /tk64

- run (as root) on your machine 
mount /tk64 

DU
--
Linux du command is used for summarizing the disk usage in terms of file size. It can be used with folders to get the total disk usage. 

du -ah (human readable)
du -ahc (grand total -c)
du -sh (total count only -s)
du -achb (in bytes using -b)
du -cbha --exclude="*.txt" (exculde)
du -cbha --time --time-style=iso (display style)
du -h --max-depth=1 data/

DF
--
df command in Linux provides disk space usage information of your file systems

df -ah (human readable)
df -h --total (grandtotal)
df -T ( File System Type)
df -t ext2 (inlude file system type)
df -x ext2 (exclude file system type)

- partition sizes:
#!/bin/sh
DISC=$1
PARTITION=`df -h |grep $DISC |awk ‘{print $1}’`
SIZE=`df -h|grep $DISC|awk ‘{print $2}’`
USED=`df -h|grep $DISC|awk ‘{print $3}’`
FREE=`df -h|grep $DISC|awk ‘{print $4}’`
echo “Partition: $PARTITION”
echo “Total size: $SIZE”
echo “Used space: $USED”
echo “Free space: $FREE”

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1.12 Java (heap, params, collection, memory)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


MEMORY
------
- min and max heap, max thread stack size, large heap for young gen, different GC, permsize

-XX:+UseParallelGC 
-XX:+UseConcMarkSweepGC 
-Xms1303m 
-Xmx2048m 
-XX:PermSize=256m 
-XX:MaxPermSize=512m 
-XX:+UseParallelGC 
-XX:+UseParallelOldGC 
-XX:+HeapDumpOnOutOfMemoryError
-XX:-UseGCOverheadLimit 

export CATALINA_OPTS="$CATALINA_OPTS -Djava.library.path=/projects/tomcat/apache-tomcat-6.0.32/bin/tomcat-native-1.1.20-src/jni/native/.libs"

#memory settings and tuning
#-Xmx3800m -Xms3800m: Configures a large Java heap to take advantage of the large memory system.
#-Xmn2g: Configures a large heap for the young generation (which can be collected in parallel), again taking advantage of the large memory system. It helps prevent short lived objects from being prematurely promoted to the old generation, where garbage collection is more expensive.
#-Xss128k: Reduces the default maximum thread stack size, which allows more of the process' virtual memory address space to be used by the Java heap.
#-XX:+UseParallelGC: Selects the parallel garbage collector for the new generation of the Java heap  
#-XX:+UseParallelOldGC: Use the parallel old generation collector. Certain phases of an old generation collection can be performed in parallel, speeding up a old generation collection. 
#export CATALINA_OPTS="$CATALINA_OPTS -server -XX:MaxPermSize=250m -Xmx5120m -Xms3072m -Xss128k -Xmn2g -XX:+UseParallelGC -XX:+UseParallelOldGC -XX:+UseCompressedOops"
export CATALINA_OPTS="$CATALINA_OPTS -server -XX:MaxPermSize=250m -Xmx5120m -Xms3072m -Xss256k"

#http://stackoverflow.com/questions/541832/know-of-any-java-garbage-collection-log-analysis-tools
export CATALINA_OPTS="$CATALINA_OPTS -XX:-HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=$CATALINA_HOME/dumps -Xloggc:$CATALINA_HOME/logs/gc.log -XX:+PrintGCDetails -XX:+PrintGCTimeStamps"

export CATALINA_OPTS="$CATALINA_OPTS -Dcom.sun.management.jmxremote -Dcom.sun.management.jmxremote.port=28999 -Dcom.sun.management.jmxremote.ssl=false -Dcom.sun.management.jmxremote.authenticate=true -Djava.rmi.server.hostname=tk54 -Dcom.sun.management.jmxremote.password.file=$CATALINA_HOME/conf/jmxremote.password -Dcom.sun.management.jmxremote.access.file=$CATALINA_HOME/conf/jmxremote.access";

KEYSTORE
--------
- delete with alias, add new key, generate self-signed cert
- generate java keystore and key pair, cert signing request for existing keystore
- import root/intermed. CA cert to an keystore, Import a signed primary cert
- generate keystore and selfsigned cert
- check certificate, all certs, using alias, 
- delete cert, change password, export a cert, list trusted CA, import new into trusted

- delete previous keystore with alias:
keytool -delete -alias tomcat -keystore c:/apps/jdk/jre/lib/security/cacerts -storepass changeit

- add new one
$JAVA_HOME/bin/keytool -v -genkey -alias tomcat6 -keyalg RSA -keysize 2048 -sigalg SHA1withRSA -keypass changeit -keystore /home/tomcat/tomcat-keystore

- Generate a Self Signed Certificate using Java Keytool
keytool -genkey -keyalg RSA -alias selfsigned -keystore keystore.jks -storepass password -validity 360 -keysize 2048

- Generate a Java keystore and key pair
keytool -genkey -alias mydomain -keyalg RSA -keystore keystore.jks -keysize 2048

- Generate a certificate signing request (CSR) for an existing Java keystore
keytool -certreq -alias mydomain -keystore keystore.jks -file mydomain.csr

- Import a root or intermediate CA certificate to an existing Java keystore
keytool -import -trustcacerts -alias root -file Thawte.crt -keystore keystore.jks

- Import a signed primary certificate to an existing Java keystore
keytool -import -trustcacerts -alias mydomain -file mydomain.crt -keystore keystore.jks

- Generate a keystore and self-signed certificate (see How to Create a Self Signed Certificate using Java Keytool for more info)
keytool -genkey -keyalg RSA -alias selfsigned -keystore keystore.jks -storepass password -validity 360 -keysize 2048

- Check a stand-alone certificate
keytool -printcert -v -file mydomain.crt

- Check which certificates are in a Java keystore
keytool -list -v -keystore keystore.jks

- Check a particular keystore entry using an alias
keytool -list -v -keystore keystore.jks -alias mydomain

- Delete a certificate from a Java Keytool keystore
keytool -delete -alias mydomain -keystore keystore.jks

- Change a Java keystore password
keytool -storepasswd -new new_storepass -keystore keystore.jks

- Export a certificate from a keystore
keytool -export -alias mydomain -file mydomain.crt -keystore keystore.jks

- List Trusted CA Certs
keytool -list -v -keystore $JAVA_HOME/jre/lib/security/cacerts

- Import New CA into Trusted Certs
keytool -import -trustcacerts -file /path/to/ca/ca.pem -alias CA_ALIAS -keystore $JAVA_HOME/jre/lib/security/cacerts

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1.14 System distro/resource information (uname,dmesg,dmidecode)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

sudo dmidecode --t memory
cat /proc/meminfo 
sudo dmidecode --type 17
cat /proc/version
cat /etc/issue (on a RHEL machine shows)
uname -r
uname -mrs
lsb_release -a
cat /etc/*-release
less /proc/cpuinfo
less /proc/meminfo 
dmidecode --t memory
uname -a
uname -i
dmesg | grep "Linux version"
cat /proc/cpuinfo 
grep flags /proc/cpuinfo
dmidecode --t memory
/etc/redhat-release
/etc/debian_version
/etc/gentoo-release

#get machine architecture
uname -m
uname -a
getconf LONG_BIT
lscpu

~~~~~~~~~~~~~~~~~~~
1.15 Pipping (2>&1)
~~~~~~~~~~~~~~~~~~~

# Redirect standard out and standard error separately
% cmd >stdout-redirect 2>stderr-redirect

# Redirect standard error and out together
% cmd >stdout-redirect 2>&1

# Merge standard error with standard out and pipe
% cmd 2>&1 |cmd2

java -version 1>/tmp/stdout 2>/tmp/stderr

ls -l > ls-l.txt#stdout 2 file
grep da * 2> grep-errors.txt#stderr 2 file
grep da * 1>&2#stdout 2 stderr
grep * 2>&1#stderr 2 stdout
rm -f $(find / -name core) &> /dev/null #stderr and stdout 2 file

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1.16 Packaging (yum, rpm, wget)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

RPM/YUM
-------

- list repos, groups, install groups, epel, 
- whats in the package, which repo delivers package,
- disable package from repos, enable repos, 

yum list available
yum grouplist
rpm -qpl <package>
yum provides httpd
yum whatprovides libstdc++.so.6
yum info httpd
yum list httpd*
yum deplist package-name
What command can show a list of scripts that will be installed by a package?: rpm --scripts <package>?
repoquery -i cherokee

- install all belongs to group mysql
yum grouplist | grep -i mysql
yum groupinstall "MySQL Database server

- exclude postgres from existing repose
cd /etc/yum.repos.d (fedora.repo, Centos.repo)
Add exclude=postgresql* to the bottom of the section

- install epel
Extra Packages for Enterprise Linux (or EPEL) is a Fedora Special Interest Group that creates, maintains, and manages a high quality set of additional packages for Enterprise Linux, including, but not limited to, Red Hat Enterprise Linux (RHEL),CentOS and Scientific Linux (SL).
wget http://ftp.astral.ro/mirrors/fedora/pub/epel/6/i386/epel-release-6-8.noarch.rpm
rpm -ivh epel-release-6-8.noarch.rpm
yum -y install collectd

- install epel, install package from specific repo, enable repo 
wget http://ftp.astral.ro/mirrors/fedora/pub/epel/6/i386/epel-release-6-8.noarch.rpm
rpm -Uvh epel-release-6-8.noarch.rpm
yum -y install --enablerepo=epel syslog-ng
yum-config-manager --enable repository…name
yum-config-manager --add-repo http://www.example.com/example.repo

- list repositories
yum repolist 

- check what package owns a utility
rpm -qf $(type -p certutil)

- RPM List files owned by an RPM
rpm -qlp /TK-VCS/SVN/rpms/Wiacek/rpm-build/Wiacek-3.3.11-1.el6.noarch.rpm

- delete repo
rm epel.repo epel-testing.repo
rm /etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL (delete GPG keys)
yum clean all

- epel repo entry
/etc/yum.repos.d/epel.repo
[epel]
name=epel
baseurl=http://192.168.3.187/cobbler/repo_mirror/epel
enabled=1
priority=99
gpgcheck=0

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1.17 Windows (compmgmt.misc, net, msconnfig, taskkill)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

compmgmt.msc -- User Add ++
net user postgres /delete -- Delete user
runas /user:postgres cmd.exe 

- add user
net user postgres secret /fullname:"postgres" /add

-- assign to group
net localgroup "Power User" postgres /add

-- change permission
cacls e:\Wiacek\deployment\PostgreSQL /e /p postgres:f

-- postgres installation problem
http://forums.holdemmanager.com/general-support/150771-solved-postgresql-database-cluster-initialisation-failed.html
http://forums.enterprisedb.com/posts/list/1891.page

-- determine windows version
ver
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

-- System admin tools
msconfig.msc
secpol.msc
msinfo32.exe

-- kill process
netstat -a -no (with pids and states)
netstat | findstr "8080"	 
taskkill /PID 4456 /F (for force)	

The administator user gains most of its priviledges through being in the administrators group. The only exception (i.e. inherant to administrator) is running always elevated under UAC. 

-- show services
net start
sc

~~~~~~~~~~~~~~~~
1.18 File limits
~~~~~~~~~~~~~~~~

- display maximum number of open file descriptors
cat /proc/sys/fs/file-max (75000 files normal user can have open in single login session)

- concurrently open file descriptors throughout the system
/proc/sys/fs/file-max -> sysctl -w fs.file-max=100000
/etc/sysctl.conf -> fs.file-max = 100000 (fpr reboot)
sysctl fs.file-max

- User Level FD Limits
vi /etc/security/limits.conf
httpd soft nofile 4096
httpd hard nofile 10240
ulimit -Hn
ulimit -Sn

- java
bin/elasticsearch -f -Des.max-open-files=true

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1.19 Ports (ssh,http,dns,dhcp,rsync)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- ftp, ssh, telnet, smtp, dns, bootp, dhcp, http, pop3
- ntp, ldap, https, syslogd, ldaps, rsync, openvpn
- pop3s, nfs, cvs, mysql, svn, postgres, x11

20 – FTP Data (For transferring FTP data)
21 – FTP Control (For starting FTP connection)
22 – SSH(For secure remote administration which uses SSL to encrypt the transmission)
23 – Telnet (For insecure remote administration
25 – SMTP(Mail Transfer Agent for e-mail server such as SEND mail)
53 – DNS(Special service which uses both TCP and UDP)
67 – Bootp
68 – DHCP
80 – HTTP/WWW(apache)
110 – POP3(Mail delivery Agent)
123 – NTP(Network time protocol used for time syncing uses UDP protocol)
389 – LDAP(For centralized administration)
443 – HTTPS(HTTP+SSL for secure web access)
514 – Syslogd(udp port)
636 – ldaps(both tcp and udp)
873 – rsync
1194 – openVPN
995 – POP3s
2049 – NFS(nfsd, rpc.nfsd, rpc, portmap)
2401 – CVS server
3306 – MySql
3690 – SVN
5432 - Postgres
6000-6063-X11

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1.19 SSL (handshake, openssl, java keys, certificates)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

SSL
---
- generate the self-signing key 
openssl genrsa -des3 -out staging.wiacek.nl.key 1024
(remember the password you give in here)

- generate the certificate signing request (csr):
certificate signing request is a message sent from an applicant to a certificate authority in order to apply for a digital identity certificate.
openssl req -new -key staging.wiacek.nl.key -out staging.wiacek.nl.csr

- remove the passwrod from the key (to be able to let httpd startup without being prompted for the password)
cp staging.wiacek.nl.key staging.wiacek.nl.key.org
openssl rsa -in staging.wiacek.nl.key.org -out staging.wiacek.nl.key

- generate the self-signed cert :
openssl x509 -req -days 3650 -in staging.wiacek.nl.csr -signkey staging.wiacek.nl.key -out staging.wiacek.nl.crt




===============
2. Python
===============

~~~~~~~~~
2.1 Files
~~~~~~~~~

- open file read/write/append/delete/move, close file
- read lines, split on chars and loop
- define encoding

#readline() will only return one line (signifed by a new line break) 
#readlines() returns a list of the lines within the file. 
#The read function will read an entire file.

counts_file_string = open(counts_file_name, 'r').read()
counts_line = counts_file_string.splitlines()
for count_line in counts_line:
	tokens  = count_line.split()

with open(training_file_name,'r') as file:
	training_file = file.readlines()
	file_lines = file.read().splitlines()
	for line in lines:
		tag = line.split()[4]
	file_lines.append("")

file.close()

new_file = open(replaced_file_name,'w')
new_file.write("".join(words_replaced))
new_file.close()  

fo = open("foo.txt", "rw+")
print "Name of the file: ", fo.name
line = fo.readline()
print "Read Line: %s" % (line)
fo.seek(0, 0)# Again set the pointer to the beginning
line = fo.readline()
print "Read Line: %s" % (line)

openfile.seek(45,0) #would move the cursor to 45 bytes/letters after the beginning of the file.
openfile.seek(10,1) #would move the cursor to 10 bytes/letters after the current cursor position.
openfile.seek(-77,2) #would move the cursor to 77 bytes/letters before the end of the file (notice the - before the 77)
openfile.tell() #returns where the cursor is in the file

~~~~~~~~~~~~~~~
2.2 Directories
~~~~~~~~~~~~~~~
- open dirs, list files/attributes
- check if dir a dir, check if file exists

#mix
os.path.exists('/tmp/dirname/filename.etc')
os.path.isdir('/tmp/dirname/filename.etc')
d = os.path.dirname(f)

#traverse all dirs and files
import os

def listdir_fullpath(d):
    return [os.path.join(d, f) for f in os.listdir(d)]

print listdir_fullpath("/home/wiacek") 
print os.listdir("/home/wiacek")

for dirname, dirnames, filenames in os.walk("/home/wiacek"):
    #print dirname
    for subdirname in dirnames:
        print os.path.join(dirname,subdirname)
    for filename in filenames:
        print os.path.join(dirname,filename)
    if '.git' in dirnames:
        dirnames.remove('.git')
        
#make delete dir/file (empty, recursively)
if not os.path.exists(directory):
    os.makedirs(directory)
    
def make_sure_path_exists(path):
    try:
        os.makedirs(path)
    except OSError as exception:
        if exception.errno != errno.EEXIST:
            raise



os.remove() #will remove a file.
os.rmdir() #will remove an empty directory.

import shutil
shutil.rmtree() #will delete a directory and all its contents.

# Make a new file.
# Simply opening a file in write mode will create it, if it doesn't exist. (If
# the file does exist, the act of opening it in write mode will completely
# overwrite its contents.)
try:
    f = open("file.txt", "w")
except IOError:
    pass
 
# Remove a file.
try:
    os.remove(temp)
except os.error:
    pass
 
# Make a new directory.
os.mkdir('dirname')
 
# Recursive directory creation: creates dir_c and if necessary dir_b and dir_a.
os.makedirs('dir_a/dir_b/dir_c')
 
# Remove an empty directory.
os.rmdir('dirname')
os.rmdir('dir_a/dir_b/dir_c') # Removes dir_c only.
 
# Recursively remove empty directories.
# removedirs removes all empty directories in the given path.
os.removedirs('dir_a/dir_b/dir_c')
 
# Neither rmdir or removedirs can remove a non-empty directory, for that you need the further file 
# operations in the shutil module.
# This removes the directory 'three' and anything beneath it in the filesystem.
import shutil
shutil.rmtree('one/two/three')

~~~~~~~~~~~~~~~~~~~~
2.3 Users and groups
~~~~~~~~~~~~~~~~~~~~

import os

os.uname()
os.getcwd()
os.geteuid()
os.getlogin()
os.getuid()
os.getenv(varname[, value])
os.putenv(varname, value)
os.getenv("TKHOME")
os.setpgrp()

~~~~~~~~~~~~~~~~~~~~
2.3 Input parameters 
~~~~~~~~~~~~~~~~~~~~
- help line, params, parsing

from optparse import OptionParser
import sys

if __name__ == '__main__':
	parser = OptionParser()
	
	parser.set_defaults(warning=10, critical=5)
	
	parser.add_option('-H', '--host', dest='host')
	parser.add_option('-w', '--warning', dest='warning', type='int')
	parser.add_option('-c', '--critical', dest='critical', type='int')
	parser.add_option('-v', '--verbose', dest='verbose', action='count')
	
	opts, args = parser.parse_args()
	
	if opts.host:
	    result = mem_free_percentage(opts.host, opts.verbose)
	if opts.verbose:
	        print 'Result = %f' % result
	    if result > opts.warning:
	        print 'MEM OK: %.02f percent free' % result
	        sys.exit(0)

~~~~~~~~~~~
2.4 Strings
~~~~~~~~~~~
- append/split/at-char/cut etc.
- index of start, stop
- substring
- length/replace/grep
- capitalize/lower/swapcase
- reverse
- add whitespace between each char
- print string->file, file->string


word = "Hello World"
letter=word[0]
len(word)
print word.count('l')  # count how many times l is in the string
print word.find("H")   # find the word H in the string
print word.index("World")  # find the index of the start of match
print s.count(' ')
print word[1]          #get one char of the word
print word[1:2]        #get one char of the word (same as above)
print word[1:3]        #get the first three char
print word[:3]         #get the first three char
print word[-3:]        #get the last three char
print word[3:]         #get all but the three first char
print word[:-3]        #get all but the three last character
word.split(' ')  # Split on whitespace
word.startswith("H")
word.endswith("d")
print "." * 10
word.replace("Hello", "Goodbye")
print string.upper()
print string.lower()
print string.title()
print string.capitalize()
print string.swapcase()
print ' '.join(reversed(string))
strip()     #removes from both ends
lstrip()    #removes leading characters (Left-strip)
rstrip()    #removes trailing characters (Right-strip)
print ":".join(word)  # #add a : between every char
print " ".join(word)  # add a whitespace between every char

#write to file
text_file = open("Output.txt", "w")
text_file.write("Purchase Amount: %s"%TotalAmount)
text_file.close()

#write file to string
data=myfile.read()

with open ("data.txt", "r") as myfile:
    data=myfile.read().replace('\n', '')
    
with open ("data.txt", "r") as myfile:
    data = ' '.join([line.replace('\n', '') for line in myfile.readlines()])

with open("data.txt") as myfile:
    data="".join(line.rstrip() for line in myfile)    


#3-grams from line
line = 14802 3-GRAM I-GENE I-GENE I-GENE
threegram = line[line.find(" ", line.find(" ")+1)+1:]
bigram = threegram[:threegram.find(" ", threegram.find(" ")+1)]

~~~~~~~~~
2.5 Regex
~~~~~~~~~
- match/replace to regex, count matches
- extract groups and matches o those groups
- lazy matching
- matching from map of regexes 
- search ⇒ find something anywhere in the string and return a match object.
- match ⇒ find something at the beginning of the string and return a match object.

import re
re.I#case-insensitive
re.IGNORECASE
re.M #^ and $ will match at the beginning and at the end of each line and not just at the beginning and the end of the string
re.MULTILINE 
re.S#The dot "." will match every character plus the newline
re.DOTALL
re.X#whitespace are ignored.
re.VERBOSE#
#
if re.match(r'.*\d.*',word):
re.match(r'^.+[A-Z]$',word):

#
running_re = 'id="runstate">running'
match = re.search(running_re,url_content)	
if not match:
	exit(2)
email_state_re = '<span class="([^"]+)">'
match = re.findall(email_state_re,url_content)
match = [x for x in match if x != "mbIsOk"]
if len(match) > 0:
	exit(2)


#Example re.match: attempts to match a pattern at the beginning of the string, (this is what Perl does by default).
import re
line = "Cats are smarter than dogs"
matchObj = re.match( r'(.*) are (.*?) .*', line, re.M|re.I)
if matchObj:#The re.match function returns a match object on success, None on failure
   print "matchObj.group() : ", matchObj.group()
   print "matchObj.group(1) : ", matchObj.group(1)
   print "matchObj.group(2) : ", matchObj.group(2)
else:
   print "No match!!"

#Example re.search: searches for the pattern throughout the string
re.match("c", "abcdef")  # No match
re.search("c", "abcdef") # Match

#finditer vs findall
match()	Determine if the RE matches at the beginning of the string.
search()	Scan through a string, looking for any location where this RE matches.
findall()	Find all substrings where the RE matches, and returns them as a list.
finditer()	Find all substrings where the RE matches, and returns them as an iterator.
group()	Return the string matched by the RE
start()	Return the starting position of the match
end()	Return the ending position of the match
span()	Return a tuple containing the (start, end) positions of the match

#find index of matches
re.finditer(pattern, string[, flags]) 
[(m.start(0), m.end(0)) for m in re.finditer(pattern, string)]

#compile
p = re.compile('ab*', re.IGNORECASE)

#flags
- \d #Matches any decimal digit; this is equivalent to the class [0-9].
- \D #Matches any non-digit character; this is equivalent to the class [^0-9].
- \s #Matches any whitespace character; this is equivalent to the class [ \t\n\r\f\v].
- \S #Matches any non-whitespace character; this is equivalent to the class [^ \t\n\r\f\v].
- \w #Matches any alphanumeric character; this is equivalent to the class [a-zA-Z0-9_].
- \W #Matches any non-alphanumeric character; this is equivalent to the class [^a-zA-Z0-9_].

pattern = '\D+(\d+)\D+'
match = re.match(pattern, "dskjfh767jsfd")
match.groups()

#indexes of matches
match.span()
match.start()
match.end()

p = re.compile("[a-z]")for m in p.finditer('a1b2c3d4')
for m in p.finditer('a1b2c3d4'):
     print m.start(), m.group()
 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
2.6 HTTP (http,soap,get hosts)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- make http requests, post data
- check result, parse/modify verbose request/response
- communicate with wiacek
- https, ssl, http-authentification
- parse html, read codes, headers

#Send request, have cookie, read cookie, handle response exceptions
from HTMLParser import HTMLParser
import urllib2
import cookielib

def check_sb(host, context, account):
    login_url = 'https://%s/%s/loginUser.do' % (host, context)
    logout_url = 'https://%s/%s/logout.jsp' % (host, context)
    cj = cookielib.CookieJar()
    request = urllib2.Request('%s?account=%s&username=monitor&password=wAtch22' % (login_url, account))
    full_url = request.get_full_url()
    if debug:
        print 'URL is: %s' % request.get_full_url()
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
    
    try:
        conn = opener.open(request)
    except urllib2.HTTPError, err:
        print 'Wiacek (%s) - ERROR (%s)' % (account,err)
        sys.exit(2)        
    except Exception, err:
        print 'Wiacek (%s) - ERROR (%s)' % (account, err)
        sys.exit(2) 
    except:
        print 'Wiacek (%s) - ERROR (Unexpected error: %s)' % (account, sys.exc_info()[0])
        sys.exit(2)                 
    
    encoding = conn.headers.getparam('charset')
    data = conn.read().decode(encoding)
    conn.close()
    request = urllib2.Request('%s' % logout_url)
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
    conn = opener.open(request)

    # instantiate the parser and fed it some HTML
    parser = ErrorParser()
    parser.feed(data)

    return (parser.data, full_url,data)

#Send request with http authentification
import urllib
import urllib2, base64
if not host.startswith("http"):
	host = "https://" + host 
tkmra_url = str(host) + "/tkmra/tkmra"
url_content = ""
request = urllib2.Request(tkmra_url)	
base64string = base64.standard_b64encode('%s:%s' % (user,passw))
request.add_header("Authorization", "Basic %s" % base64string)
try:	
	url_content = urllib2.urlopen(request).read()
except Exception as err:

#read cookies
from urllib2 import Request, build_opener, HTTPCookieProcessor, HTTPHandler
import cookielib

cj = cookielib.CookieJar() #Create a CookieJar object to hold the cookies
opener = build_opener(HTTPCookieProcessor(cj), HTTPHandler()) #Create an opener to open pages using the http protocol and to process cookies.

req = Request("http://www.about.com")#create a request object to be used to get the page.

html = f.read()
print html[:50]#see the first few lines of the page

print "the cookies are: "
for cookie in cj:
    print cookie
f = opener.open(req)

#read headers
import urllib2

request = urllib2.Request('http://your.tld/...')
request.add_header('User-Agent', 'some fake agent string')
request.add_header('Referer', 'fake referrer')
response = urllib2.urlopen(request)
print response.info().getheader('Content-Type')# check content type:

response = urllib2.urlopen('http://localhost:8080/')
print 'RESPONSE:', response
print 'URL     :', response.geturl()

headers = response.info()
print 'DATE    :', headers['date']
print 'HEADERS :'
print '---------'
print headers

data = response.read()
print 'LENGTH  :', len(data)
print 'DATA    :'
print '---------'
print data

#download data from URL and store on disk
import urllib

input_file = open(csv_file, 'r')
first_line = input_file.readline().rstrip()
headers = first_line.split(';')
	#make sure target path exists
dir = os.path.dirname(storedir)
if not os.path.exists(dir):
	os.makedirs(dir)

counter = 1   
for line in input_file:
		#remove newline (chomp)
		line = line.rstrip()
		parts = line.split(';')
		url=parts[0]
		file_name= url[url.rindex('/')+1:]
		file_path = storedir+ "/" + file_name
		print "COUNTER=" + str(counter) + "URL=" + url + ", FILE=" + file_name
		counter += 1
		urllib.urlretrieve (url, file_path)



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
2.6.1 Import variables from file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


variables.py:

from email.mime.text import MIMEText

monitored= ['CV-ES','CV-EN']

emailfrom = "tomas@criptos.com"
#emailto = 'tomas@criptos.com'
emailto = 'wiacek@wiacek.nl'
smtpserver = 'localhost'

msgdown = MIMEText("Dear user\n\nUnfortunately, we've been experiencing some trouble in our systems, and the extracion service will be temporarily unavailable.\n\nWe are actively working on the recovery, and we will notify you as soon as it's fixed.\n\nSorry about the inconvenience.\nHave a nice day!\n\wiacek operations team")
msgdown['Subject'] = 'wiacek extraction service down'
msgdown['From'] = 'tomas@criptos.com'
msgdown['To'] = 'tomas@criptos.com'

msgup = MIMEText("Dear user\n\nAfter some work, our services are up and running again. If you still find any issue in your normal operation, don't hesitate to contact us.\n\nSorry about the inconvenience.\nHave a nice day!\n\wiacek operations team")
msgup['Subject'] = 'wiacek extraction service up'
msgup['From'] = 'tomas@criptos.com'
msgup['To'] = 'tomas@criptos.com'

check.py:

from variables import monitored, emailfrom, emailto, smtpserver, msgup, msgdown
# connect to daemon-handler and retrieve status data
dh = telnetlib.Telnet("localhost","8888")
dh.write("LIST-SERVICES\n")
status = dh.read_until("servicedsdsadas",10)
# load json
data = json.loads(status)
# check services
for service in data['services']:
  if service['name'] in monitored:





~~~~~~~~~~~
2.7 Network
~~~~~~~~~~~
- get host details (lookup/reverse lookup)
- telnet to tcp process, read response (textractor)
- port scanning

#establish socket to a hos
import socket
try:
    hostip = socket.gethostbyaddr(host)[2][0]
except socket.gaierror, e:
    sys.stderr.write('Skipping host: %s (%s)\n' % (host, e))
    continue

#read from telnet/process
import telnetlib
import json
import smtplib
import psycopg2
import sys
from variables import monitored, emailfrom, emailto, smtpserver, msgup, msgdown
con = psycopg2.connect(database='tomasdb', user='tomas')
cur = con.cursor()
# connect to daemon-handler and retrieve status data
dh = telnetlib.Telnet("localhost","8888")
dh.write("LIST-SERVICES\n")
status = dh.read_until("servicedsdsadas",10)
# load json
data = json.loads(status)
# check services
for service in data['services']:
  if service['name'] in monitored:
    cur.execute("select status from status where service=%(name)s;", {'name' : service['name'] } )
    current = cur.fetchone();
    print "Current, ouput from DB=" + str(current)
    if current is None:
      print "Service ", service['name'], " does not exist in the DB. Creating new service..."
      cur.execute("insert into status (service, status) VALUES ( %(service)s, %(status)s )", { 'service' : service['name'], 'status' : service['status'] } )
      con.commit()
    print "Service ", service['name'] , " is ", service['status']
    print "Service ", service['name'] , " was ", current[0]
    if service['status'] != current[0]:
      if current[0] == "on":
        print "Service DOWN!!"
        s = smtplib.SMTP(smtpserver)
        s.sendmail(emailfrom, emailto, msgdown.as_string())
      elif service['status'] == "on":
        print "Service restored!"
		s = smtplib.SMTP(smtpserver)
		s.sendmail(emailfrom, emailto, msgup.as_string())
	  else:
		print "Change of status, but the service is down anyways"
	  cur.execute("update status set status=%(status)s where service=%(service)s", { 'service' : service['name'], 'status' : service['status'] } )
	  cur.execute("insert into history (service, status) VALUES ( %(service)s, %(status)s )", { 'service' : service['name'], 'status' : service['status'] } )
	  con.commit()


#DNS lookup
import socket
print socket.gethostbyname('localhost') # result from hosts file
print socket.gethostbyname('google.com') # your os sends out a dns query
print socket.getaddrinfo('google.com', 80)
print socket.gethostbyaddr("69.59.196.211")

#port scanner with exceptions (Ctrl-C pressed, host not found, couldnt connect)
remoteServer    = raw_input("Enter a remote host to scan: ")
remoteServerIP  = socket.gethostbyname(remoteServer)

try:
    for port in range(1,1025):  
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((remoteServerIP, port))
        if result == 0:
            print "Port {}: \t Open".format(port)
        sock.close()
except KeyboardInterrupt:
    print "You pressed Ctrl+C"
    sys.exit()
 
except socket.gaierror:
    print 'Hostname could not be resolved. Exiting'
    sys.exit()
 
except socket.error:
    print "Couldn't connect to server"
    sys.exit()
    
            
~~~~~~~~
2.7 SOAP
~~~~~~~~
- establish soap communication, send/receive data
- store communication dump

import urllib
import suds

url = "http://%s/%s/" % (host,app)
wsdl = "http://%s/%s/soap/search?wsdl" % (host,app)
namespace = "http://home.wiacek.nl/search"    

#check the URL is reachable
get_url_code = urllib.urlopen(url).code
get_wsdl_code = urllib.urlopen(wsdl).code

if get_url_code != 200:
    print "%s CRITICAL: url %s not reachable" % (environment,url) 
    exit(2)
elif get_wsdl_code != 200:
    print "%s CRITICAL: wsdl %s not reachable" % (environment,wsdl) 
    exit(2)

client = suds.client.Client(wsdl)
try:
    result = client.service.search(environment=environment,
                                   password=password, 
                                   accessRoles="all", 
                                   request="")
    
    matchSize = int(result.matchSize)
    
    if matchSize >=0:
        print "%s STATUS OK" % environment
        exit(0)
    else:
        error = "Search webservice return %s results for environment %s" % (matchSize,environment)
        print "%s CRITICAL: %s" % (environment,error)
        exit(2)
            
except Exception as e:
        error = str(e).replace("Server raised fault: ", "")
        print "%s CRITICAL: %s" % (environment,error)
        exit(2)

~~~~~~~~~~
2.7 Socket
~~~~~~~~~~
- start server/client, tcp/http
- establish communication


#SERVER
import socket
import sys

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Bind the socket to the port
server_address = ('localhost', 10000)
print >>sys.stderr, 'starting up on %s port %s' % server_address
sock.bind(server_address)
# Listen for incoming connections
sock.listen(1)
while True:
    # Wait for a connection
    print >>sys.stderr, 'waiting for a connection'
    connection, client_address = sock.accept()
    try:
          print >>sys.stderr, 'connection from', client_address
    
          # Receive the data in small chunks and retransmit it
          while True:
              data = connection.recv(16)
              print >>sys.stderr, 'received "%s"' % data
              if data:
                  print >>sys.stderr, 'sending data back to the client'
                  connection.sendall(data)
              else:
                  print >>sys.stderr, 'no more data from', client_address
                  break
              
    finally:
        # Clean up the connection
        connection.close()

#CLIENT
import socket
import sys
# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Connect the socket to the port where the server is listening
server_address = ('localhost', 10000)
print >>sys.stderr, 'connecting to %s port %s' % server_address
sock.connect(server_address)
try:
    # Send data
    message = 'This is the message.  It will be repeated.'
    print >>sys.stderr, 'sending "%s"' % message
    sock.sendall(message)
    # Look for the response
    amount_received = 0
    amount_expected = len(message)
    
    while amount_received < amount_expected:
        data = sock.recv(16)
        amount_received += len(data)
        print >>sys.stderr, 'received "%s"' % data
finally:
    print >>sys.stderr, 'closing socket'
    sock.close()        
    
~~~~~~~~~
2.8 Loops
~~~~~~~~~
- loop over map/dict/list/files/dirs/
- for and while, with ranges and conditions
- iterate over elements in array
- Iterating by Sequence Index:
- searches for prime numbers from 10 through 20

for k in range(1,sentence_length+1):
    for u in self.possible_tags(k-1):
        for v in self.possible_tags(k):
            max_pi_value = 0

if word not in words:
   words[word] = {}
   words[word][tag] = count
for word, counts in words.iteritems():

#iterate over letter in string
for letter in 'Python':     # First Example
   print 'Current Letter :', letter
   
#iterate over elements in array   
fruits = ['banana', 'apple',  'mango']
for fruit in fruits:        # Second Example
   print 'Current fruit :', fruit

#Iterating by Sequence Index:
fruits = ['banana', 'apple',  'mango']
for index in range(len(fruits)):
   print 'Current fruit :', fruits[index]   

#searches for prime numbers from 10 through 20.
for num in range(10,20):  #to iterate between 10 to 20
   for i in range(2,num): #to iterate on the factors of the number
      if num%i == 0:      #to determine the first factor
         j=num/i          #to calculate the second factor
         print '%d equals %d * %d' % (num,i,j)
         break #to move to the next number, the #first FOR
   else:                  # else part of the loop
      print num, 'is a prime number'
      
#simple while
while (count < 9):
   print 'The count is:', count
   count = count + 1

~~~~~~~~~~~~~~~~~~~~~~~
2.9 Maps, arrays, lists
~~~~~~~~~~~~~~~~~~~~~~~
- loop, check if elements, present
- insert, delete, length, modification, grep
- sort according to differt values (key)
- dictionary - list transitions
- list: create, get element by (negative) index, append, 
- list: insert by index,length, concatenation, find index of element, remove, pop
- list: check if element in list, 
- dict: create, add, remove, delete element, delete all, lenegth, compare
- dict: shallow copy, items, keys, values, update with new keys

#Sort a Python list by dictionary key
peeps = [{'id':'2', 'name':'Christine'}, {'id':'1', 'name':'Steve'}]
peeps.sort(key=lambda peep: peep['id'])

#Lists
li = ["a", "b", "mpilgrim", "z", "example"]
li[0]  
li[-1]
li[1:3]
li.append("new")  
li.insert(2, "new") # inserts a single element into a list
li.extend(["two", "elements"]#concatenates lists
len(li)
li.index("example")#finds the first occurrence of a value in the list and returns the ind
li.remove("z")#removes the first occurrence of a value from a list
li.pop() # it removes the last element of the list, and it returns the value that it removed
li = li + ['example', 'new']
list.sort()
list.reverse()

list = ['larry', 'curly', 'moe']
 if 'curly' in list:
   print 'yay'

#Dictionaries
dict = {'Alice': '2341', 'Beth': '9102', 'Cecil': '3258'}
dict1 = { 'abc': 456 };
dict2 = { 'abc': 123, 98.6: 37 };

dict = {'Name': 'Zara', 'Age': 7, 'Class': 'First'}
print "dict['Name']: ", dict['Name'];
print "dict['Age']: ", dict['Age'];
dict['Age'] = 8; # update existing entry
dict['School'] = "DPS School"; # Add new entry
del dict['Name']; # remove entry with key 'Name'
dict.clear();     # remove all entries in dict
del dict ;        # delete entire dictionary
str(dict)#Produces a printable string representation of a dictionary
cmp(dict1, dict2)#Compares elements of both dict.
len(dict)
dict.copy()#Returns a shallow copy of dictionary dict
dict.items()#Returns a list of dict's (key, value) tuple pairs
dict.keys()#Returns list of dictionary dict's keys
dict.values()#Returns list of dictionary dict's value
dict.update(dict2)#Adds dictionary dict2's key-values pairs to dict

#.items and .iteritems
dict = {'Name': 'Zara', 'Age': 'seven', 'Class': 'First'}
for key, value in dict.iteritems():
     print key + "--" + value 

for key, value in dict.items():
     print key + "--" + value 

#Represent a matrix
dic={('i1','j1'):{'c1':1,'c2':3,'c3':4},('i2','j2'):{'c1':1,'c2':1,'c3':1}}
header=list(max(dic.values()))
print '\t',
print "  ".join(sorted(header))
for x in dic:
    print ",".join(x)+'\t',
    for y in sorted(dic[x]):
        print str(dic[x][y])+"  ",
    print  

#output
		c1  c2  c3
i1,j1   1   3   4  
i2,j2   1   1   1      

~~~~~~~~~~~~~~~~~~
2.10 Comprehension
~~~~~~~~~~~~~~~~~~

#list comprehensions
x = [i for i in range(10)]
squares = [x**2 for x in range(10)]
S = [x**2 for x in range(10)]
V = [2**i for i in range(13)]
M = [x for x in S if x % 2 == 0
noprimes = [j for i in range(2, 8) for j in range(i*2, 50, i)]
primes = [x for x in range(2, 50) if x not in noprimes]

words = 'The quick brown fox jumps over the lazy dog'.split()
stuff = [[w.upper(), w.lower(), len(w)] for w in words]

lowers = [x.lower() for x in ["A","B","C"]]
uppers = [x.upper() for x in ["a","b","c"]]
numbers = [x for x in string if x.isdigit()]
words = [word.split()[0] for word in training_file if len(word.split())>1

#Dictionary comprehension: get paths to all .rst files
import os
restFiles = [os.path.join(d[0], f) for d in os.walk(".")
             for f in d[2] if f.endswith(".rst")]
for r in restFiles:
    print(r)

#Dictionary comprehensions
d = {key: value for (key, value) in sequence}
tags = {tag.split()[2]:tag.split()[0] for tag in counts_line if tag.split()[1] == "1-GRAM"}

#We require a dictionary in which the occurrences of upper and lower case characters are combined:
mcase = {'a':10, 'b': 34, 'A': 7, 'Z':3}
mcase_frequency = { k.lower() : mcase.get( , 0) + mcase.get(k.upper(), 0) for k in mcase.keys() }
# mcase_frequency == {'a': 17, 'z': 3, 'b': 34}
    
#Set comprehension
names = [ 'Bob', 'JOHN', 'alice', 'bob', 'ALICE', 'J', 'Bob' ]
{ name[0].upper() + name[1:].lower() for name in names if len(name) > 1 }


~~~~~~~~~~~~~~~~~~~~~~
2.11 Lambda/Map/reduce
~~~~~~~~~~~~~~~~~~~~~~

g = lambda x: x**2
print g(8)

def make_incrementor (n): return lambda x: x + n
f = make_incrementor(2)
g = make_incrementor(6)
print f(42), g(42)

foo = [2, 18, 9, 22, 17, 24, 8, 12, 27]
print filter(lambda x: x % 3 == 0, foo)#list of all elements that are multiples of 3
print map(lambda x: x * 2 + 10, foo)#computes 2 * x + 10 for every element
print reduce(lambda x, y: x + y, foo)#sum of all elements

#compute prime numbers, "the sieve of Eratosthenes"
nums = range(2, 50)
for i in range(2, 8): 
     nums = filter(lambda x: x == i or x % i, nums)

print map(lambda w: len(w), 'It is raining cats and dogs'.split())

words_replaced = map(lambda x: counted[x[:x.find(" ")]]>4 and x or (len(x.split())>1 and "_RARE_"+x[x.find(" "):] or x),training_file)

~~~~~~~~~~~~
2.13 Classes
~~~~~~~~~~~~
- build classes, inheritance, subclasses, check subclasses
- methods, usage, default values
- load external classes
- dump/load objects to files


- create a subclass of HTMLParser and override the handler methods
class ErrorParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.recording = 0
        self.data = []

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if name == 'class' and value == 'error':
                self.recording = 1

    def handle_endtag(self, tag):
        if tag == 'div' and self.recording:
            self.recording -= 1

    def handle_data(self, data):
        data_stripped = data.strip()
        if debug:
            print data_stripped
        if data_stripped == 'wiacek 401' or \
                data_stripped == 'wiacek 500':
            self.data.append(data_stripped)
        if data_stripped == 'STATUS OK':
            self.data.append(data_stripped)
        if data_stripped == 'wiacek Process CV' or \
                data_stripped == 'wiacek':
            self.data.append(data_stripped)
        if self.recording and data_stripped:
            self.data.append(data_stripped)
...
...
    parser = ErrorParser()
    parser.feed(data)

    return (parser.data, full_url,data)

~~~~~~~~
2.14 XML
~~~~~~~~
- parse XML, traverse children, add/remove elements/attributes
- xpath, store with encoding, apply namespaces, validate

#traverse
import xml.dom.minidom

def traverseTree(document, depth=0):
  tag = document.tagName
  for child in document.childNodes:
    if child.nodeType == child.TEXT_NODE:
      if document.tagName == 'Title':
        print depth*'    ', child.data
    if child.nodeType == xml.dom.Node.ELEMENT_NODE:
      traverseTree(child, depth+1)

filename = 'sample.xml'
dom = xml.dom.minidom.parse(filename)
traverseTree(dom.documentElement)

#parse XML
doc = minidom.parse(f)
node = doc.documentElement   
if node.nodeType == xml.dom.Node.ELEMENT_NODE:
    print 'Element name: %s' % node.nodeName
    for (name, value) in node.attributes.items():
        #print '    Attr -- Name: %s  Value: %s' % (name, value)

nodelist = xml.getElementsByTagName('zAppointments')  
element = xml.getElementsByTagName('zAppointments')[1]

for node in element.childNodes:
     if node.nodeType == node.TEXT_NODE:
      	rc = rc + node.data

Title = element.firstChild.data

#create XML
from xml.dom import minidom
codetable = minidom.Document()
ct_el = codetable.createElement("CodeTable")
ct_info_el = codetable.createElement("CodeTableInfo")
ct_info_item = codetable.createElement("InfoItem")
ct_info_item_text = codetable.createTextNode("Codetable generated from " + u_input_file_name + " at " + timestamp)
ct_info_item.appendChild(ct_info_item_text)
ct_info_el.appendChild(ct_info_item)
ct_el.appendChild(ct_info_el)
	
ct_attr = codetable.createElement("CodeProperty")
ct_attr.setAttribute("name", curr_attribute)
ct_attr_text = codetable.createTextNode(curr_value)
ct_attr.appendChild(ct_attr_text)

#print to file
uglyXml = codetable.toprettyxml(indent="  ")
text_re = re.compile('>\n\s+([^<>\s].*?)\n\s+</', re.DOTALL)
prettyXml = text_re.sub('>\g<1></', uglyXml)	
table_xml = open(codetable_name, 'w+')
table_xml.write(prettyXml)
table_xml.close()

#xpath
easy_install py-dom-xpath
import xpath
xpath.find('//item', doc)


~~~~~~~~~
2.15 YAML
~~~~~~~~~
- parse yaml, traverse, map, insert, delete
- open/store to file, pretty print

import yaml
f = open(test_yaml_file_name, "w")
#this default_flow_style is important, otherwise the file is not yaml
#http://dpinte.wordpress.com/2008/10/31/pyaml-dump-option/
#yaml.dump(data, encoding=('utf-8'|'utf-16-be'|'utf-16-le'))
yaml.safe_dump(
		configMap, f, encoding=('utf-8'),
		default_flow_style=False, width=50, indent=4)
f.close()

~~~~~~~~~~~~~~~~~~~~~
2.16 File compression
~~~~~~~~~~~~~~~~~~~~~
- compress files/dir to a zip/tar

import zipfile
zf = zipfile.ZipFile(zipfile_name, "w")
for dirname, subdirs, files in os.walk(account_folder_name):
    zf.write(dirname)
    for filename in files:
        zf.write(os.path.join(dirname, filename))
zf.close()

~~~~~~~~~~~~~~~~~~~~
2.17 System commands
~~~~~~~~~~~~~~~~~~~~
- run system commands, store/match output
- stop after timeout, timeout
- check system resources (disk/memory), variables
- get working path, store system variables

#RUN PROCESS WITH TIMEOUT
import time
import threading
import signal
import subprocess
def run_popen_with_timeout(command_string, timeout, input_data):
    """
    Run a sub-program in subprocess.Popen, pass it the input_data,
    kill it if the specified timeout has passed.
    returns a tuple of success, stdout, stderr
    found at: http://betabug.ch/blogs/ch-athens/1093
    """
    kill_check = threading.Event()
    def _kill_process_after_a_timeout(pid):
        os.kill(pid, signal.SIGTERM)
        kill_check.set() # tell the main routine that we had to kill
        # use SIGKILL if hard to kill...
        return
    p = subprocess.Popen(command_string, bufsize=1, shell=True,
              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pid = p.pid
    watchdog = threading.Timer(timeout, _kill_process_after_a_timeout, args=(pid, ))
    watchdog.start()
    (stdout, stderr) = p.communicate(input_data)
    watchdog.cancel() # if it's still waiting to run
    success = not kill_check.isSet()
    kill_check.clear()
    return (success, stdout, stderr)
...
...
success, stdout, stderr = run_popen_with_timeout(command_string, float(opts.timeout), "blah")

if not success:
	print '%s (%s:%s) - ERROR - Process did not complete within expected timeout %s sec' % (opts.type, opts.host, opts.port, str(opts.timeout))
	sys.exit(2)
if stdout == "":
	print '%s (%s:%s) - ERROR - Process returned an empty result' % (opts.type, opts.host, opts.port)				
	sys.exit(2)

# system commands
import commands
mount = commands.getoutput('mount -v')
lines = mount.splitlines()
lines = commands.getoutput('mount -v').splitlines()
points = map(lambda line: line.split()[2], lines)
commands.getstatusoutput('ls /bin/ls')
commands.getoutput('ls /bin/ls')

def process(file_path, tmf_path):
        command = 'java -jar /projects/myjar.jar param1 param2 param3 ' + file_path + " " + tmf_path + " false wiacek false"
        trxml_output = commands.getstatusoutput(command)
        #output is an array, lets get the string part
        trxml_multistring = trxml_output[1]
        #and remove first two lines they are comig from java client blah blah
        first, second, trxml_real = trxml_multistring.split('\n',2)
        trxml_file = open(file_path + ".trxml", 'w+')
        trxml_file.write(trxml_real)
        trxml_file.close()

#platform information
import platform
print platform.python_version()
platform.architecture()
platform.architecture()
returns information about the bit architecture 
platform.machine()#returns the machine type, e.g. 'i386'.
platform.node()#returns the computer’s network name (may not be fully qualified!)
platform.platform()#returns a single string identifying the underlying platform with as much usefuli nformation as possible.
platform.processor()#returns the (real) processor name, e.g. 'amdk6'.
platform.python_build()#returns a tuple (buildno, builddate) stating the Python build number anddate as strings.
platform.python_compiler()#returns a string identifying the compiler used for compiling Python.
platform.python_version()#returns the Python version as string 'major.minor.patchlevel'
platform.python_implementation()#returns a string identifying the Python implementation. Possible return values are: ‘CPython’, ‘IronPython’, ‘Jython’, ‘PyPy’.
platform.release()#returns the system’s release, e.g. '2.2.0' or 'NT'
platform.system() #returns the system/OS name, e.g. 'Linux', 'Windows', or 'Java'.
platform.version()  #returns the system’s release version, e.g. '#3 on degas'
platform.uname() #returns a tuple of strings (system, node, release, version, machine, processor)identifying the underlying platform.

#psutil CPU
easy_install psutil
psutil.cpu_times()
for x in range(3):
     psutil.cpu_percent(interval=1)
for x in range(3):
     psutil.cpu_percent(interval=1, percpu=True)

#memory and disks
psutil.NUM_CPUS
psutil.virtual_memory()
psutil.swap_memory()					
psutil.disk_partitions()
psutil.disk_usage('/')
psutil.disk_io_counters()

#network and process
psutil.net_io_counters(pernic=True)
psutil.get_users()
psutil.get_pid_list()
p = psutil.Process(7055)
p.name
p.getcwd()
p.cmdline
p.get_memory_info()
p.get_ext_memory_info()
p.get_nice()
p.set_nice(10)
p.terminate()
p.wait(timeout=3)

~~~~~~~~~~~~~~~~~~~~
2.18 Database access
~~~~~~~~~~~~~~~~~~~~
- establish connection user/password/port/host
- make selects, read input in parts
- mysql/postgresql
- make inserts

# database connection
con = psycopg2.connect(host=opts.dbhost, database=opts.dbname, user=opts.dbuser, password=opts.dbpass)
cur = con.cursor(cursor_factory=psycopg2.extras.DictCursor)

#compute total connections and available connections
cur.execute("SELECT COUNT(*) FROM pg_stat_activity;")
current = cur.fetchone();
used_connections = float(current[0])
cur.execute("SHOW max_connections;")
current = cur.fetchone()
total_available_connections = float(current[0])
current_available_connections = int(total_available_connections-used_connections)
available_pct = current_available_connections/total_available_connections*100.0

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
2.19 Read/write stdout/stderr
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- read from standard in, from user
- store user yes/no question

sys.stdin
sys.stdout
sys.stderr

for i in (sys.stdin, sys.stdout, sys.stderr):
     print i

sys.stdout.write("Another way to do it!\n")
sys.stderr.write('Skipping check (df) on %s (%s)\n' % (host, e))

#redirection
save_stdout = sys.stdout# stdout is saved
fh = open("test.txt","w")
sys.stdout = fh
print("This line goes to test.txt")
sys.stdout = save_stdou #return to normal
fh.close()

#read from input
input_variable = raw_input ("Enter your name: ")
print ("your name is" + input_variable)
userNumber = input('Give me an integer number: ')
userNumber = int(userNumber)
try:
    userNumber = int(userNumber)
except ValueError:
    userNumber = 0
else:
    userNumber = userNumber**2

#For user input in python 3.x
input_variable = input ("Enter your name: ")
print ("your name is" + input_variable)


~~~~~~~~~~~~~~~~~~~~~~~~~~~
2.20 Documentation/Comments
~~~~~~~~~~~~~~~~~~~~~~~~~~~
- classes documentation
- code comments

~~~~~~~~~~~~~~~
2.21 Send email
~~~~~~~~~~~~~~~
- construct and send email

#use email to base64 encode
import email
import email.message
import email.encoders
import StringIO

import smtplib
  source_64_msg = email.message.Message()
  source_64_msg.set_payload(source)
  email.encoders.encode_base64(source_64_msg)

  output_64_msg = email.message.Message()
  output_64_msg.set_payload(output)
  email.encoders.encode_base64(output_64_msg)
  values = { 'assignment_part_sid' : sid, \
             'email_address' : email_address, \
             #'submission' : output, \
             'submission' : output_64_msg.get_payload(), \
             #'submission_aux' : source, \
             'submission_aux' : source_64_msg.get_payload(), \
             'challenge_response' : ch_resp, \
             'state' : state \
           }
  url = submit_url()  
  data = urllib.urlencode(values)
  req = urllib2.Request(url, data)
  response = urllib2.urlopen(req)
  string = response.read().strip()
  result = 0
  return result, string
  
import smtplib  
def sendemail(from_addr, to_addr_list, cc_addr_list,
              subject, message,
              login, password,
              smtpserver='smtp.gmail.com:587'):
    header  = 'From: %s\n' % from_addr
    header += 'To: %s\n' % ','.join(to_addr_list)
    header += 'Cc: %s\n' % ','.join(cc_addr_list)
    header += 'Subject: %s\n\n' % subject
    message = header + message
  
    server = smtplib. SMTP(smtpserver)
    server.starttls()
    server.login(login,password)
    problems = server.sendmail(from_addr, to_addr_list, message)
    server.quit()

~~~~~~~~~~~~~~
2.22 Templates
~~~~~~~~~~~~~~
- use template/replace write into files

from string import Template

collectd_disk_template = '''\
define service {
    use                 $service
    host_name           $hostname
    servicegroups       host_services    
    service_description DISK $partition free
    check_command       check_collectd_percentage!$value_spec!free!used!$warning!$critical
    }
'''

c = Template(collectd_disk_template)
v = {'service': service,
	 'hostname': host,
     'value_spec': 'df/%s' % os.path.splitext(value_spec)[0],
     'warning': config.get('df', 'warning'),
     'critical': config.get('df', 'critical'),
     }

print c.substitute(v)

~~~~~~~~~~~~~~
2.23 QuickSort
~~~~~~~~~~~~~~
- implement quicksort

#!/usr/bin/env python

# Written by Magnus Lie Hetland 

"Everybody's favourite sorting algorithm... :)"

def partition(list, start, end):
    pivot = list[end]                          # Partition around the last value
    bottom = start-1                           # Start outside the area to be partitioned
    top = end                                  # Ditto

    done = 0
    while not done:                            # Until all elements are partitioned...
        while not done:                        # Until we find an out of place element...
            bottom = bottom+1                  # ... move the bottom up.
            if bottom == top:                  # If we hit the top...
                done = 1                       # ... we are done.
                break
            if list[bottom] > pivot:           # Is the bottom out of place?
                list[top] = list[bottom]       # Then put it at the top...
                break                          # ... and start searching from the top.
        while not done:                        # Until we find an out of place element...
            top = top-1                        # ... move the top down.
            if top == bottom:                  # If we hit the bottom...
                done = 1                       # ... we are done.
                break
            if list[top] < pivot:              # Is the top out of place?
                list[bottom] = list[top]       # Then put it at the bottom...
                break                          # ...and start searching from the bottom.
    list[top] = pivot                          # Put the pivot in its place.
    return top                                 # Return the split point

def quicksort(list, start, end):
    if start < end:                            # If there are two or more elements...
        split = partition(list, start, end)    # ... partition the sublist...
        quicksort(list, start, split-1)        # ... and sort both halves.
        quicksort(list, split+1, end)
    else:
        return

if __name__=="__main__":                       # If this script is run as a program:
    import sys
    list = map(int,sys.argv[1:])               # Get all the arguments
    start = 0
    end = len(list)-1
    quicksort(list,start,end)                  # Sort the entire list of arguments
    import string
    print string.join(map(str,list))           # Print out the sorted list

~~~~~~~~~~~
2.24 Search
~~~~~~~~~~~
- implement binary search

from bisect import bisect_left

def binary_search(a, x, lo=0, hi=None):   # can't use a to specify default for hi
    hi = hi if hi is not None else len(a) # hi defaults to len(a)   
    pos = bisect_left(a,x,lo,hi)          # find insertion position
    return (pos if pos != hi and a[pos] == x else -1) # don't walk off the end


def binary_search(a, key, imin=0, imax=None):
    """
    Iterative binary search function
    a:
        can be any iterable object
    """
    if imax is None:
        # if max amount not set, get the total
        imax = len(a) - 1
    while imin <= imax:
        # calculate the midpoint
        mid = (imin + imax)//2
        midval = a[mid]
        # determine which subarray to search
        if midval < key:
            # change min index to search upper subarray
            imin = mid + 1
        elif midval > key:
            # change max index to search lower subarray
            imax = mid - 1
        else:
            # return index number 
            return mid
    raise ValueError

~~~~~~~~~~~~~~~~~~~
2.25 Bit operations
~~~~~~~~~~~~~~~~~~~
- and/or/xor/not
~ Not
^ XOR
| Or
& And


print int('00100001', 2)#to int
print "0x%x" % int('11111111', 2)#to hex string
chr(int('111011', 2))#to character

x = 1        # 0001
x << 2       # Shift left 2 bits: 0100 # Result: 4
x | 2        # Bitwise OR: 0011 # Result: 3
x & 1        # Bitwise AND: 0001  # Result: 1

unsigned char a |= (1 << n);#Set a bit (where n is the bit number, and 0 is the least significant bit):
unsigned char b &= ~(1 << n);#Clear a bit:
unsigned char c ^= (1 << n)#Toggle a bit:
unsigned char e = d & (1 << n);#Test a bit:
x | 2 #is used to set bit 1 of x to 1
x & 1 #is used to test if bit 0 of x is 1 or 0

#bit representation
bin(a|b)
bin(1)
bin(a^b)

~~~~~~~~~
2.26 Math
~~~~~~~~~
- logarithms, abs, round, powers, 
- stddev, varience, 

import math
math.floor(x)
math.fabs#absolute value
math.exp(x)#Return e**x
math.log(x[, base])#With one argument, return the natural logarithm of x (to base e).
math.log1p(x)#Return the natural logarithm of 1+x (base e)
math.log10(x)#Return the base-10 logarithm of x
math.pow(x, y)#Return x raised to the power y
math.sqrt(x)#Return the square root of x.
math.pi#The mathematical constant π = 3.141592..., to available precision.
math.e#The mathematical constant e = 2.718281..., to available precis

#average of a list
floatNums = [float(x) for x in numberList]
    return sum(floatNums) / len(numberList)
   
~~~~~~~~~~~~~~~~~~~~~~~~
2.30 Encoding/encryption
~~~~~~~~~~~~~~~~~~~~~~~~
- base64, md5, sha
- decode/encode/hack

import base64
coded_string = '''Q5YACgA...'''
base64.b64decode(coded_string)
base64.b64decode(coded_string)
print open("FILE-WITH-STRING", "rb").read().decode("base64")

#md5
import hashlib
m = hashlib.md5()
m.update("000005fab4534d05api_key9a0554259914a86fb9e7eb014e4e5d52permswrite")
print m.hexdigest()
m.digest()
m.digest_size
m.block_size

#one liners
print hashlib.md5("whatever your string is").hexdigest()
hashlib.sha224("Nobody inspects the spammish repetition").hexdigest()

~~~~~~~~~~~~~~~
2.31 Exceptions
~~~~~~~~~~~~~~~
- handle exception, parse, rethrow
- class exception defintion
- except an all with raise
- except on specifc and continue

#class exception defintion
class MiscFilesException(Exception):
    def __init__(self, value):
        self.parameter = value
    def __str__(self):
        return repr(self.parameter)

#except an all with raise
try:
    templ_file = open(tmplt_filepath, 'r').read()
    self.phraserules[file_name] = templ_file
except:
    error_message = "Phraserule file " + tmplt_filepath +\
        " cannot be opened, but was selected."
    raise MiscFilesException(error_message)

#except on specifc and continue
try:
    hostip = socket.gethostbyaddr(host)[2][0]
except socket.gaierror, e:
    sys.stderr.write('Skipping host: %s (%s)\n' % (host, e))
    continue
   
~~~~~~~~~~~~~
2.32 Collectd
~~~~~~~~~~~~~
- communicate with collectd unixsocks

import collect

c = collect.Collect('/var/run/collectd-unixsock')

def mem_free_percentage(host, verbose=0):

    output_ram = {}
    mem_specs_ram = ['free', 'buffered', 'used', 'cached']
    for mem_spec in mem_specs_ram:
        output_ram[mem_spec] = float(c.get(
            '%s/memory/memory-%s' % (host, mem_spec)
            )[0].split('=')[1])

	list = c.list()
	values = [val.split()[1] for val in list]
	if host + "/swap/swap-used" in values: 
		...

    output_swap = {}
    mem_specs_swap = ['free', 'used', 'cached']    
    for mem_spec in mem_specs_swap:
        output_swap[mem_spec] = float(c.get(
            '%s/swap/swap-%s' % (host, mem_spec)
            )[0].split('=')[1])    

    total_cached = output_ram['buffered'] + output_ram['cached'] + output_swap['cached']
    used_mem = output_ram['used'] + output_swap['used']
    free_mem = output_ram['free'] + output_swap['free'] + total_cached

    total_mem = used_mem + free_mem

    mem_percent_free = 100 - ((used_mem / total_mem) * 100)

    if verbose:
        print output
        print 'total_mem = %d' % total_mem
        print 'total_cached = %d' % total_cached
        print 'used_mem = %d' % used_mem
        print 'mem_free = %d' % (total_mem - total_cached)
        print 'mem_percent_free = %f' % mem_percent_free

    return float(mem_percent_free)

~~~~~~~~~~~~~~~~~
2.33 ConfigParser
~~~~~~~~~~~~~~~~~

#icc.ini
[main]
datadir = /var/lib/collectd/rrd
debug = true
[host_excludes]
hosts =
	monitor.wiacek.local
	kadaster.wiacek.local

#parser
from ConfigParser import ConfigParser
config = ConfigParser()
config.read('icc.ini')
datadir = config.get('main', 'datadir')
host_excludes = config.get('host_excludes', 'hosts')
if host not in host_excludes:

~~~~~~~~~~~~~~~~~
2.34 JSON
~~~~~~~~~~~~~~~~~

import json
tree = json.loads(open("tree.example").readline())
print tree[2][2]

json.dump(parse_tree,output_file)
output_file.write("\n")

#Response as json
return HttpResponse(simplejson.dumps(yaml_inst), mimetype="application/json")

~~~~~~~~~~~~~~~~~~
2.35 Random
~~~~~~~~~~~~~~~~~~

import random

#Random Element of Sequence
random.choice([1, 2, 3, 4, 5, 6])

#Random Integer
random.randint(start, stop)# Possible results are 0, 1, 2, …, 10
random.randrange(stop)
random.randrange(start, stop)# Possible results are 0, 1, 2, …, 9
print random.randrange(0, 10, 2)# Possible results are 0, 2, 4, 6, 8

#Random Floating-Point Number
random.random()# Possible results are 0.0 to 1.0, not including 1.0

#random floating-point number n in an arbitrary range: lower <= n < upper, 
lower = 5
upper = 10
range_width = upper - lower
print random.random() * range_width + lower

#permute list
numbers = range(5)
random.shuffle(numbers)
print numbers


===========================================================================================
3. Bash programming
===========================================================================================
# !bin/bash
$VAR    Variable
"$VAR"  Variable incl. spaces
${}  Parameter substitution.
[ ]  Test
( )  array initialization.
$()  Redirect standard out to variable
``   Command substitution reassigns the output of a command
{xxx,yyy,zzz,...}#Brace expansion.
{a..z}#Extended Brace expansion. echo {0..3} # 0 1 2 3
$[ ... ] #integer expansion. echo $[$a+$b]   # 10

~~~~~~~~~~~~~~~~~~~~~
3.1 check tcp process
~~~~~~~~~~~~~~~~~~~~~

exec 3<>/dev/tcp/www.google.com/80#file descriptor 3 for reading and writing on the specified TCP/IP socket
echo -e "GET / HTTP/1.1\r\nhost: http://www.google.com\r\nConnection: close\r\n\r\n" >&3#send our HTTP request
cat <&3

exec 3<>/dev/tcp/localhost/8888
echo -en "LIST-SERVICES\n" >&3
cat <&3
{"services":[{"status":"on","name":"CV-EN","port":"50200"},{"status":"on","name":"CV-NL","port":"50100"},{"status":"on","name":"CV-PL","port":"51200"},{"status":"on","name":"CV-IT","port":"50500"},{"status":"on","name":"CV-ES","port":"50600"}]}[root@extern ~]# 

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
3.2 Operations numerical/logical/strings
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#Evaluation
echo $((1+1))
$[1+1]


#Arithmetic operations
echo "Arithmetic Operators"
a=`expr 5 + 3`
a=`expr $a + 1`
a=`expr 5 % 3`


#Logical opertions
b=`expr $x = $y`         # Test equality.
echo "b = $b"            # 0  ( $x -ne $y )
a=3
b=`expr $a \> 10`
b=`expr $a \< 10`
b=`expr $a \<= 3`

#String operations
a=1234zipper43231
echo "The string being operated upon is \"$a\"."

# length: length of string
b=`expr length $a`
echo "Length of \"$a\" is $b."

# index: position of first character in substring
#        that matches a character in string
b=`expr index $a 23`
echo "Numerical position of first \"2\" in \"$a\" is \"$b\"."

# substr: extract substring, starting position & length specified
b=`expr substr $a 2 6`
echo "Substring of \"$a\", starting at position 2,\
and 6 chars long is \"$b\"."

#  The default behavior of the 'match' operations is to
#+ search for the specified match at the BEGINNING of the string.
#
#       Using Regular Expressions ...
b=`expr match "$a" '[0-9]*'`               #  Numerical count.
echo Number of digits at the beginning of \"$a\" is $b.
b=`expr match "$a" '\([0-9]*\)'`           #  Note that escaped parentheses
#                   ==      ==             #+ trigger substring match.
echo "The digits at the beginning of \"$a\" are \"$b\"."

~~~~~~~~~~~~~
3.3 Functions
~~~~~~~~~~~~~

#user yes/no confirmation
##
# Confirm the information $1 with the user.
# The answer is written to the input variable $2
#
function confirm_information {

    QUESTION=$1
    __RESPONSE=$2

    echo $QUESTION
    echo "Is that correct?"
    read userresponse

    while [[ $userresponse != "yes" && $userresponse != "no" ]];
    do
        echo "Please type <yes> if its true, or <no> if its false. Then press <ENTER>."
        read userresponse
    done

    #return value, write to the input variable                                                                                                                                                       
    eval $__RESPONSE="'$userresponse'"

}

#echo usage
usage() {
    echo "usage: ${0##*/} login password language"
    echo -e "\nexample:\n\t${0##*/} wiacek changeme pl port"
    echo -e "\n$@"
    echo -e "-language must not be capitalized"
    exit 2
}
if [ -z "$2" ]; then
    usage "You forgot to add the password"
fi

~~~~~~~~~~~~~~~~~~~~~
3.4 Checks
~~~~~~~~~~~~~~~~~~~~~

#flags
-d	Directory
-e	Exists (also -a)
-f	Regular file
-h	Symbolic link (also -L)
-p	Named pipe
-r	Readable by you
-s	Not empty
-S	Socket
-w	Writable by you
-N	Has been modified since last being read
-x  File is executable

-z  String not null
-n  String not empty

#Folders
if [ -d $DIRECTORY ]; then#True, if <FILE> exists and is a directory.
if [ -f $1 ]; then#True, if <FILE> exists and is a regular file.

#AND and OR
if [ -n "$var"] && [ -e "$var"]; then#-e	Exists (also -a), -n not empty
   echo "\$var is not null and a file named $var exists!"
fi
if [ "$SHELL" == "/bin/bash" ] || [ "$USER" == "sim4000" ]; then
   echo "User oder Shell sind richtig";
fi

#String, emptiness, equality, substring, length, regex, split into array
[ -z $STRING ]#True, if <STRING> is empty.
[ -n $STRING ]#True, if <STRING> is not empty (this is the default operation).
[ $STRING1 == $STRING2 ]
[ "$STRING1" == "$STRING2" ]#Remember to use quotes if the string has spaces or escape characters (newlines).
[ $STRING1 != $STRING2 ]#True, if the strings are not equal.

#Arithmetic tests
if [ "$a" -eq "$b" ]#is equal to
if [ "$a" -ne "$b" ]#is not equal to
if [ "$a" -gt "$b" ]#is greater than
(("$a" > "$b"))
if [ "$a" -ge "$b" ]#is greater than or equal to
(("$a" >= "$b"))
if [ "$a" -lt "$b" ]#is less than
(("$a" < "$b"))
if [ "$a" -le "$b" ]#is less than or equal to
(("$a" <= "$b"))

#Other
if [ ! $? -eq 0 ]; then#if process exited not correctly
if [ -n "${CHECK_USER}" ]; then#-n not empty

#Comppound command
#But with [, you have to quote $b, because it splits the argument and expands things like "a*" 
#(where [[ takes it literally)
[[ -e $b ]]
if [[ $DOC_PARSING_SOAP =~ \($OUTPUT_REGEX\) ]];then#regex
[[ ( -d "$HOME" ) && ( -w "$HOME" ) ]] 
[[ "abc def .d,x--" == a[abc]*\ ?d* ]]; echo $?
[[ "abc def d,x" == a[abc]*\ ?d* ]]; echo $?
[[ "abc def d,x" == a[abc]*\ ?d* || a > 2 ]]; echo $?

~~~~~~~~~~~~~~~~~~~~~~~
3.4 Regular expressions
~~~~~~~~~~~~~~~~~~~~~~~
while [[ $1 ]]
do
    if [[ $1 =~ $regex ]]; then
        echo "$1 matches"
        i=1
        n=${#BASH_REMATCH[*]}
        while [[ $i -lt $n ]]
        do
            echo "  capture[$i]: ${BASH_REMATCH[$i]}"
            let i++
        done
    else
        echo "$1 does not match"
    fi
    shift
done

ls -ld [[:digit:]]*
ls -ld [[:upper:]]*
"alnum", "alpha", "ascii", "blank", 
"cntrl", "digit", "graph", "lower", 
"print", "punct", "space", "upper", 
"word" or "xdigit".



~~~~~~~~~~~~~~
3.5 Executions
~~~~~~~~~~~~~~

CHECK_USER=`id $USER_NAME 2> /dev/null`
if [ -n "${CHECK_USER}" ]; then
STATUS_OUTPUT=`/etc/init.d/rc.wiacek status $SERVICE 2>&1`
FINAL_OUTPUT=`echo "$STATUS_OUTPUT" | awk 'BEGIN{count=0;ts=-1; problems=""}{ if($0 ~ /No such file/){problems=problems",rc.wiacek cannot start"};if(ts!=-1 && $0 !~ /component/ && ($2!="yes" || $5!="yes")){problems=problems","$7"-not running\n"};if ($0 ~ /OK: 0 components running/){problems=problems",service-not-running"};if ($0 ~ /PID +ACTIVE +HOST/) {ts=count}; count++ } END {print problems}'`
TOTAL_PROBLEMS=`expr $TOTAL_PROBLEMS + 1` 
DATE_FOR_BACKUP=`date +20%y-%m-%d`
pass=$(perl -e 'print crypt($ARGV[0], "password")' $PASSWORD)
ERROR=$(./useless.sh 2>&1 >/dev/null)#Redirected stderr to stdout, stdout to /dev/null, and then use the backticks or $() to capture the redirected stderr

~~~~~~~~~~~~~~~~~~~~~~
3.6 Strings and arrays
~~~~~~~~~~~~~~~~~~~~~~

#String, emptiness, equality, substring, length, regex, split into array
[ -z $STRING ]#True, if <STRING> is empty.
[ -n $STRING ]#True, if <STRING> is not empty (this is the default operation).
[ $STRING1 == $STRING2 ]
[ "$STRING1" == "$STRING2" ]#Remember to use quotes if the string has spaces or escape characters (newlines).
[ $STRING1 != $STRING2 ]#True, if the strings are not equal.
PROG="Bash"
echo ${PROG:0} -> Bash
echo ${PROG:1} -> ash
echo ${PROG:1:2} > as
echo ${#PROG} -> > 4
expr length $PROG > 4#length

#Substring Removal
${string#substring}#Deletes shortest match of $substring from front of $string.
${string##substring}#Deletes longest match of $substring from front of $string.
stringZ=abcABC123ABCabc
echo ${stringZ#a*C}      # 123ABCabc
${string%substring}#Deletes shortest match of $substring from back of $string.	
${string%%substring}#Deletes longest match of $substring from back of $string.
stringZ=abcABC123ABCabc
echo ${stringZ%b*c}      # abcABC123ABCa
	
	
#Substring Replacement
${string/substring/replacement}#Replace first match of $substring with $replacement.
${string//substring/replacement}#Replace all matches of $substring with $replacement.	
myString="first column:second column:third column"
myString2="${myString//:/ }" #remove all the colons

#split string into array and iterate
myArray=(this is a story)#default delimitor is space
echo ${myArray[0]} -> this
echo ${myArray[1]} -> is
for i in "${myArray[@]}"
do
   echo "$i"
done

#split string into array with sed and iterate
STR="123,456,567 5,343"
STR_ARRAY=(`echo $STR | sed -e 's/,/\n/g'`)
for x in "${STR_ARRAY[@]}"
do
    echo "> [$x]"
done

#split string into array 
#by redyfing IFS and iterate 
OIFS=$IFS;#store temporarirly
IFS="|";#change delimiter
animals="dog|cat|fish|squirrel|bird|shark";
animalArray=($animals);
for ((i=0; i<${#animalArray[@]}; ++i));
do
    echo "animal $i: ${animalArray[$i]}";
done
IFS=$OIFS;

#split using string replacement
for i in $(psql -t --host $1 --user web $2 -c "select r.address from client c, routing r where c.enabled = 't' and c.id = r.client and r.task = 'preprocessing'" | sort | uniq |xargs); do	
	arrayI=(${i//:/ })
	PORT="${arrayI[1]}"
done

~~~~~~~~~
3.6 Loops
~~~~~~~~~

#for enumeration and sequence
for i in $( ls ); do
	echo item: $i
done

#sequence
for i in `seq 1 10`;
do
    echo $i
done

#to capture re
for i in $(ssh -i /home/$USER/.ssh/id_dsa $USER@$HOST "find $DIR_WITH_SEARCH_CONFIGS -name *.env.conf -maxdepth 1"); do
 
    PASSWORD=$(ssh -i /home/$USER/.ssh/id_dsa $USER@$HOST "cat $i | grep \"password is\" | sed 's#.*password is: \([[:alnum:]]*\).*#\1#'")
    BASE=$(basename $i .env.conf)
    DIRNAME=$(dirname $i)

    echo "define service{"
    echo "       use                   $usage"
    echo "       host_name             $APP_HOST" 
    echo "       service_description   $APP_NAME - $BASE"
    echo "       servicegroups         search_monitoring"
    echo "       check_command         check_search!$APP_NAME!$BASE!$PASSWORD"
    echo "}"

done

#capture postgres output
for i in $(psql -t --host $1 --user web $2 -c "select r.address from client c, routing r where c.enabled = 't' and c.id = r.client and r.task = 'preprocessing'" | sort | uniq |xargs); do
	
	arrayI=(${i//:/ })
	PORT="${arrayI[1]}"
done

#while with counter, and user response yes/np
COUNTER=0
while [  $COUNTER -lt 10 ]; do
    echo The counter is $COUNTER
    let COUNTER=COUNTER+1 
done   

read userresponse
while [[ $userresponse != "yes" && $userresponse != "no" ]];
do
	echo "Please type <yes> if its true, or <no> if its false. Then press <ENTER>."
	read userresponse
done

#endless loop
while :
do
   operation-1
   operation-2
   ...
   operation-n
done

# Same as:
#    while true
#    do
#      ...
#    done

#until
COUNTER=20
until [  $COUNTER -lt 10 ]; do
    echo COUNTER $COUNTER
    let COUNTER-=1
done

~~~~~~~~~~~~~~~~~~~~~~~~~
3.7 Startup script kibana
~~~~~~~~~~~~~~~~~~~~~~~~~

#!/bin/bash
# chkconfig: 2345 96 25
# source function library
. /etc/rc.d/init.d/functions
kibanauser=kibana
servicename=kibana
pidfile=/var/run/kibana/$servicename
lockfile=/var/lock/subsys/$servicename
command="nohup /usr/bin/ruby -C/data/Kibana kibana.rb >/data/Kibana/kibana.log 2>&1 &"

start()
{
        echo $"Starting $servicename "
        daemon --pidfile=$pidfile $command start 1>/dev/null 2>/dev/null
        RETVAL=$?
        sleep 1
        PID=`ps -ef | grep kibana | grep -v grep | sed 's/  */#/g' | cut -d# -f2`
        echo $PID > $pidfile
        [ "$RETVAL" = 0 ] && touch $lockfile
        echo
}

stop()
{
        echo -n $"Stopping $prog: "
        if [ ! -r $pidfile ]; then
                echo "Pidfile $pidfile cannot be read"
                RETVAL=1
                return
        fi
        # Sends TERM signal first and kills finally after 3 seconds
        killproc -p $pidfile -d 3 $servicename
# Send TERM signal only, don't kill
#       killproc -p $pidfile $servicename -15
        RETVAL=$?
        [ $RETVAL = 0 ] && rm -f ${lockfile} ${pidfile}
        echo

}

case "$1" in
        start)
                start
                ;;
        stop)
                stop
                ;;
        restart)
                stop
                sleep 5
                start
                ;;
        status)
                status -p $pidfile $servicename
                RETVAL=$?
                ;;
        *)
                echo $"Usage: $0 {start|stop|restart|status}"
                RETVAL=1
esac
exit $RETVAL

~~~~~~~~~~~~~~~
3.0 Special
~~~~~~~~~~~~~~~

#Send email
echo -e $ERROR | /bin/mail -s "$MESSAGE" "wiacek@wiacek.nl"

#
SCRIPTDIR="$(cd $(dirname "$0");pwd)"

#Add user with password generated with trick
pass=$(perl -e 'print crypt($ARGV[0], "password")' $PASSWORD)
useradd -m -d $HOME_DIR -p $pass $USERNAME

===========================================================================================
4. PostgreSQL
===========================================================================================
