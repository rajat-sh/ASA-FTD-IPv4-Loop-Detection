#!/bin/bash
#version 1
#This is a script to detect duplicate ipv4 packets from pcap files or "show capture capturename detail" output from ASA/FTD.

# Argument validation check
if [ "$#" -ne 2 ]; then
    echo ""
    echo "For pcap Usage: $0 <pcap> <filename or path>"
    echo "For text Usage: $0 <text> <filename or path>"
    echo "Example for pcap: $0 pcap abc.pcap"
    echo "Example for text: $0 text abc.txt"
    echo "Text file will be output of /show capture "capname" detail/ from ASA/FTD"
    echo ""
    exit 1
fi

# Exit Codes
E_NOFILE=91           # Packet capture file does not exist.
E_NOTEXTFILE=92       # File does not look like text file.
E_NOCAPTUREFILE=93    # File does not look like capture file.

#Parameters entered by user

INPUT=$1
filename=$2


if [ ! -f $filename ]
   then
	   echo "Capture File not found"
	   exit $E_NOFILE
fi # Check if capture/text file exists.

case $INPUT in
pcap)
	if file "$filename" | grep -q "pcap capture file"; then
    		:
	else
    		echo "File does not look like capture file"
		exit $E_NOCAPTUREFILE
	fi
	tshark -r $filename -T fields -e ip.src -e ip.dst -e ip.id -e ip.flags.mf  | 
	awk '! /0x00000000/ {
	if($4==0){
		str=$1"<------>"$2"-----------"$3
		$0=str
		a[$0]++}
        }	
	END{
	printf "\n%s\n", "Potential duplicate packets"
	printf "%s\t%s\t   %s\t%s\n","Count","Source IP","Destination IP","IP Identification"
	for(x in a)
	$0= a[x]" "x
        counter=0	
	if($1 != 1){ 
	    printf "%s\t%s\n" ,$1,$2
	    counter = counter + 1
	}

	if(counter == 0){
		printf "\n%s\n","No looping packets found"
	}
	
        }'
    ;;
text)
	if file "$filename" | grep -q text$; then
    		:
	else
    		echo "File does not look like text file"
		exit $E_NOTEXTFILE
	fi
	awk ' BEGIN {
	num_iter = 0
	}

	/ttl/ && !/id 0/ && !/frag/ {
	str1=$1" <----> "$3"----- "$NF
	gsub(")", "", str1)
	gsub(":", "", str1)
	gsub("\.", " ", str1)
	$0=str1
	$0=$1"."$2"."$3"."$4"----------"$7"."$8"."$9"."$10"<--------->"$NF
	a[$0]++
	num_iter++
	
        }	
        END{
	if(num_iter == 0){
		printf "\n%s\n", "No Looping Packets Found"
		exit
	}
	printf "\n%s\n", "Potential duplicate packets"
	printf "%s\t%s\t   %s\t%s\n","Count","Source IP","Destination IP","IP Identification"
	for(x in a){
		$0= a[x]" "x
	}
        counter=0
	
	if($1 != 1 ){
	        	
	    	printf "%s\t%s\n" ,$1,$2
	    	counter = counter + 1
	}

	if(counter == 0){
		printf "\n%s\n","No looping packets found"
	}
	}' $filename 
    ;;
*)
    echo "Enter a valid choice"	
    ;;
esac

