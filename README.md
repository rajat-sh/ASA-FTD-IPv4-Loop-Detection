# Introduction

IPv4 Packet loops are quite common in networks leading to multiple issues. This document list in general how to detect loops and a bash script to automate detection.

# Requisites

Linux PC with tshark installed

# General Idea

To detect loops in IPv4 packets, IP identification field of the IP header is used. If multiple packets with same IP Source Address, IP destination Address and IP identification
number are seen. most likely they are looping packets. Script is working on this logic, finding if multiple packets with same values of IP Source, Destination and identification
are present.

# Caveats and limitations

Script can return some incorrect results. IP-ID field can, nowadays, be set in different manners: for instance, the IP-ID can be set as a global counter (incremented by one at every
new packet), or as a local counter (in which separate counters are kept for different destinations), or as the output of a pseudo-random number generator or finally as a (typically 
null-valued) constant, this is very implementation-dependent. Script works correctly where separate counters are kept for different destinations, however still if the packet rate is
high, IP-ID can wrap around leading to incorrect results.

Additionally following is not considered:

1. Packets with IP-ID of all 0's. Some implementation use all zeros in IP-ID.

   e.g as seen on ASA, show capture capname detail
    1: 23:24:22.526431 0050.568d.992b 0050.568d.c0e2 0x0800 Length: 139
    10.0.3.4.10000 > 10.0.3.6.2123:  [bad udp cksum d16b!] udp 97 (DF) (ttl 64, id 0)

With tshark

   root@rajat-virtual-machine:/home/rajat/myscripts# tshark -r id0.pcap -T fields -e ip.src -e ip.dst -e ip.id
   Running as user "root" and group "root". This could be dangerous.
   10.0.3.4	10.0.0.105	0x00000000
   10.0.0.105	10.0.3.4	0x00000000
	

2. Fragmented packets.
   e.g
   1: 11:05:29.907301 0050.568d.992b 0050.568d.c0e2 0x0800 Length: 1514
      192.168.1.38.1027 > 4.2.2.2.8000:  [bad udp cksum 5b10!] udp 9000 (frag 218:1480@0+) (ttl 64) 
   2: 11:05:29.907316 0050.568d.992b 0050.568d.c0e2 0x0800 Length: 1514
      192.168.1.38 > 4.2.2.2  (frag 218:1480@1480+) (ttl 64) 
   3: 11:05:29.907316 0050.568d.992b 0050.568d.c0e2 0x0800 Length: 1514
      192.168.1.38 > 4.2.2.2  (frag 218:1480@2960+) (ttl 64) 
   4: 11:05:29.907316 0050.568d.992b 0050.568d.c0e2 0x0800 Length: 1514
      192.168.1.38 > 4.2.2.2  (frag 218:1480@4440+) (ttl 64) 
   5: 11:05:29.907316 0050.568d.992b 0050.568d.c0e2 0x0800 Length: 1514
      192.168.1.38 > 4.2.2.2  (frag 218:1480@5920+) (ttl 64) 
   6: 11:05:29.907316 0050.568d.992b 0050.568d.c0e2 0x0800 Length: 1514
      192.168.1.38 > 4.2.2.2  (frag 218:1480@7400+) (ttl 64) 
   7: 11:05:29.907316 0050.568d.992b 0050.568d.c0e2 0x0800 Length: 162
      192.168.1.38 > 4.2.2.2  (frag 218:128@8880) (ttl 64) 


For small data such as capture size of 32 Mbytes on ASA/FTD, mostly this will be correct. 

# Script Usage

root@rajat-virtual-machine:/home/rajat/myscripts# ./dup_packets.sh 

For pcap Usage: ./dup_packets.sh <pcap> <filename or path>
For text Usage: ./dup_packets.sh <text> <filename or path>
Example for pcap: ./dup_packets.sh pcap abc.pcap
Example for text: ./dup_packets.sh text abc.txt
Text file will be output of /show capture capname detail/ from ASA/FTD

**Example with PCAP file when looping packets are found**

root@rajat-virtual-machine:/home/rajat/myscripts# ./dup_packets.sh pcap capi.pcap
Running as user "root" and group "root". This could be dangerous.

Potential duplicate packets
Count	Source IP	   Destination IP	IP Identification
5825	192.168.0.2<------>192.168.0.1-----------0x0000463c

**Example with PCAP file when looping packets are not found**

oot@rajat-virtual-machine:/home/rajat/myscripts# ./dup_packets.sh pcap telnetsample.pcap
Running as user "root" and group "root". This could be dangerous.

Potential duplicate packets
Count	Source IP	   Destination IP	IP Identification

No looping packets found


**Example with text file when looping packets are found**

root@rajat-virtual-machine:/home/rajat/myscripts# ./dup_packets.sh text loop.text

Potential duplicate packets
Count	Source IP	   Destination IP	IP Identification
5652	192.168.0.2----------192.168.0.1<--------->17980


**Example with text file when looping packets are not found**

root@rajat-virtual-machine:/home/rajat/myscripts# ./dup_packets.sh text udpfrag.text

No Looping Packets Found


# Performance Analysis

**If you dealing with only small PCAP files something less than 50 Mbytes you may skip the rest of the discussion.**

However this script provides an interesting example of how to reason about the performance and optimise.

For large text size, script scales well as awk is doing line by line processing and no significant CPU/Memory overhead. Around 1.3 Gbytes text capture, it takes 15 seconds with 19 Mbytes peak RSS, CPU usage
of 99%.

root@rajat-virtual-machine:/home/rajat/myscripts# /usr/bin/time --verbose ./dup_packets.sh text loop2.text

Potential duplicate packets
Count	Source IP	   Destination IP	IP Identification
5256360	192.168.0.2----------192.168.0.1<--------->17980
	Command being timed: "./dup_packets.sh text loop2.text"
	User time (seconds): 14.76
	System time (seconds): 0.78
	**Percent of CPU this job got: 99%
	Elapsed (wall clock) time (h:mm:ss or m:ss): 0:15.54**
	Average shared text size (kbytes): 0
	Average unshared data size (kbytes): 0
	Average stack size (kbytes): 0
	Average total size (kbytes): 0
	**Maximum resident set size (kbytes): 19220**
	Average resident set size (kbytes): 0
	Major (requiring I/O) page faults: 0
	Minor (reclaiming a frame) page faults: 5897
	Voluntary context switches: 8
	Involuntary context switches: 50
	Swaps: 0
	File system inputs: 0
	File system outputs: 0
	Socket messages sent: 0
	Socket messages received: 0
	Signals delivered: 0
	Page size (bytes): 4096
	Exit status: 0
root@rajat-virtual-machine:/home/rajat/myscripts# ls -lh loop2.text 
**-rw-r--r-- 1 root root 1,3G sty  6 16:45 loop2.text**


However for large PCAP files, it becomes really slow, for 300 Mbytes PCAP file, it takes 2 minutes and 24 seconds to finish, with one CPU running at 100% and 656 Mbytes of peak RSS.



root@rajat-virtual-machine:/home/rajat/myscripts# /usr/bin/time --verbose ./dup_packets.sh pcap 300Mbfile.pcap
Running as user "root" and group "root". This could be dangerous.

Potential duplicate packets
Count	Source IP	   Destination IP	IP Identification
41	192.168.1.38<------>192.168.1.1-----------0x00007dea
	Command being timed: "./dup_packets.sh pcap 300Mbfile.pcap"
	User time (seconds): 148.47
	System time (seconds): 2.38
      **Percent of CPU this job got: 104%
	Elapsed (wall clock) time (h:mm:ss or m:ss): 2:24.51**
	Average shared text size (kbytes): 0
	Average unshared data size (kbytes): 0
	Average stack size (kbytes): 0
	Average total size (kbytes): 0
      **Maximum resident set size (kbytes): 656704**
	Average resident set size (kbytes): 0
	Major (requiring I/O) page faults: 0
	Minor (reclaiming a frame) page faults: 161794
	Voluntary context switches: 41476
	Involuntary context switches: 16688
	Swaps: 0
	File system inputs: 0
	File system outputs: 0
	Socket messages sent: 0
	Socket messages received: 0
	Signals delivered: 0
	Page size (bytes): 4096
	Exit status: 0

root@rajat-virtual-machine:/home/rajat/myscripts# ls -lh | grep 300
**-rw-r--r-- 1 tcpdump tcpdump 307M sty  6 16:13 300Mbfile.pcap**

Checking top and "ps aux" max time is spent with tshark command.

root@rajat-virtual-machine:/home/rajat# ps aux | awk '/tshark/{print $3,$6}'
98.0 514156
0.0 980
root@rajat-virtual-machine:/home/rajat# ps aux | grep tshark
**root      204710 98.4  1.8 1156284 528676 pts/0  R+   12:18   1:29 tshark -r 300Mbfile.pcap -T fields -e ip.src -e ip.dst -e ip.id -e ip.flags.mf**
root      204815  0.0  0.0  11776   724 pts/2    S+   12:20   0:00 grep --color=auto tshark

Memory usage of tshark is growing with file-size which is kind of expected, however CPU usage and runtime is the main issue. This job is CPU bound and it
hogs the CPU at 100% for around more than 2 minutes in example above.

It will become really bad with even larger file size, test result will around 2 Gbytes file, it took 14 minutes 54 seconds, 221 Mbytes of max RSS with one CPU at 100% constantly.


root@rajat-virtual-machine:/home/rajat/myscripts# /usr/bin/time --verbose ./dup_packets.sh pcap bigfile.pcap
Running as user "root" and group "root". This could be dangerous.

Potential duplicate packets
Count	Source IP	   Destination IP	IP Identification
245	192.168.1.38<------>192.168.1.1-----------0x000067d2
	Command being timed: "./dup_packets.sh pcap bigfile.pcap"
	User time (seconds): 916.42
	System time (seconds): 12.16
      **Percent of CPU this job got: 103%
	Elapsed (wall clock) time (h:mm:ss or m:ss): 14:54.37**
	Average shared text size (kbytes): 0
	Average unshared data size (kbytes): 0
	Average stack size (kbytes): 0
	Average total size (kbytes): 0
      **Maximum resident set size (kbytes): 2210872**
	Average resident set size (kbytes): 0
	Major (requiring I/O) page faults: 0
	Minor (reclaiming a frame) page faults: 550244
	Voluntary context switches: 257568
	Involuntary context switches: 109790
	Swaps: 0
	File system inputs: 0
	File system outputs: 0
	Socket messages sent: 0
	Socket messages received: 0
	Signals delivered: 0
	Page size (bytes): 4096
	Exit status: 0
root@rajat-virtual-machine:/home/rajat/myscripts# ls -lh bigfile.pcap 
**-rw-r--r-- 1 tcpdump tcpdump 1,9G sty  6 15:30 bigfile.pcap**




**This is good example of problem which can be solved in parallel on multiple CPUs. Tshark is piping the output to awk, we can break the PCAP file into smaller files
and run Tshark on multiple CPUs. The order in which data is sent to awk is not important, it can be any arbitrary order**

In the second version of the script if the PCAP file is more than around 100Mbytes, it is broken into 4 chunks and these are processed by tshark in parallel on 4 CPUs.

For the same file with parallel version of script, it took 8 minutes 25 seconds, almost half time to finish, with max RSS of 833*4 Mbytes of RSS RAM. There is around 1Gbytes
of additional RAM used in parallel version as most likely there is some duplicate data in memory, since there are four tshark loaded in memory, best would have been if tshark 
supported threads then this overhead can be avoided. However more importantly runtime is almost half. This can be further reduced if file is broken into more chunks and more CPUs are allocated.


root@rajat-virtual-machine:/home/rajat/myscripts# /usr/bin/time --verbose ./mcpudup_packets.sh pcap bigfile.pcap
reading from file bigfile.pcap, link-type EN10MB (Ethernet)
Running as user "root" and group "root". This could be dangerous.
Running as user "root" and group "root". This could be dangerous.
Running as user "root" and group "root". This could be dangerous.
Running as user "root" and group "root". This could be dangerous.
Running as user "root" and group "root". This could be dangerous.

Potential duplicate packets
Count	Source IP	   Destination IP	IP Identification
245	192.168.1.38<------>192.168.1.1-----------0x000067d2
	Command being timed: "./mcpudup_packets.sh pcap bigfile.pcap"
	User time (seconds): 1706.50
	System time (seconds): 63.87
      **Percent of CPU this job got: 350%
	Elapsed (wall clock) time (h:mm:ss or m:ss): 8:25.41**
	Average shared text size (kbytes): 0
	Average unshared data size (kbytes): 0
	Average stack size (kbytes): 0
	Average total size (kbytes): 0
      **Maximum resident set size (kbytes): 836256**
	Average resident set size (kbytes): 0
	Major (requiring I/O) page faults: 103
	Minor (reclaiming a frame) page faults: 853173
	Voluntary context switches: 259975
	Involuntary context switches: 161068
	Swaps: 0
	File system inputs: 0
	File system outputs: 9891984
	Socket messages sent: 0
	Socket messages received: 0
	Signals delivered: 0
	Page size (bytes): 4096
	Exit status: 0


root@rajat-virtual-machine:/home/rajat/myscripts# ps aux | grep tshark
root      204917  0.0  0.0  28248 18088 pts/0    S+   12:47   0:00 perl /usr/bin/parallel -j 4 tshark -T fields -e ip.src -e ip.dst -e ip.id -e ip.flags.mf -r {}
root      204934 99.9  2.7 1402164 775916 pts/0  R    12:47   6:05 tshark -T fields -e ip.src -e ip.dst -e ip.id -e ip.flags.mf -r temp.1736336830.PCAP
root      204935 99.9  2.6 1525040 772800 pts/0  R    12:47   6:05 tshark -T fields -e ip.src -e ip.dst -e ip.id -e ip.flags.mf -r temp.1736336830.PCAP1
root      204936 99.9  2.6 1393968 768320 pts/0  R    12:47   6:05 tshark -T fields -e ip.src -e ip.dst -e ip.id -e ip.flags.mf -r temp.1736336830.PCAP2
root      204937 99.9  2.6 1460004 769364 pts/0  R    12:47   6:05 tshark -T fields -e ip.src -e ip.dst -e ip.id -e ip.flags.mf -r temp.1736336830.PCAP3
root      205054  0.0  0.0  11776   720 pts/2    S+   12:54   0:00 grep --color=auto tshark
 



***To run the optimized version use the file mcpudup_packets.sh, it needs tcpdump and parallel utility installed on machine***

***Both versions are attached dup_packets.sh and mcpudup_packets.sh***


