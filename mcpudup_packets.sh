#!/bin/bash
#version 2
#This is a script to detect duplicate packets

# Exit Codes
E_NOFILE=91           # Packet capture file does not exist.
E_NOTEXTFILE=92       # File does not look like text file.
E_NOCAPTUREFILE=93    # File does not look like capture file.

# Argument validation check
if [ "$#" -ne 2 ]; then
    echo ""
    echo "For pcap Usage: $0 <pcap> <filename or path>"
    echo "For text Usage: $0 <text> <filename or path>"
    echo "Example for pcap: $0 pcap abc.pcap"
    echo "Example for text: $0 text abc.txt"
    echo "Text file will be output of /show capture capname detail/ from ASA/FTD"
    echo ""
    exit 1
fi

# Parameters entered by user
INPUT=$1
filename=$2

# Check if capture/text file exists.
if [ ! -f "$filename" ]; then
    echo "Capture File not found"
    exit $E_NOFILE
fi

case "$INPUT" in
pcap)
    if file "$filename" | grep -q "pcap capture file"; then
        :
    else
        echo "File does not look like capture file"
        exit $E_NOCAPTUREFILE
    fi

    myfilesize=$(wc -c "$filename" | awk '{print $1}')
    # Use single-bracket test for portability
    if [ "$myfilesize" -gt 100000000 ]; then
        # Large file path: split, then parallel tshark
        newfilesize=$(( myfilesize / 4000000 ))
        prefix=temp
        suffix=$(date +%s)
        capturefilename=$prefix.$suffix.PCAP

        tcpdump -r "$filename" -w /tmp/"$capturefilename" -C "$newfilesize"
        cp /tmp/"$capturefilename"* .
        rm /tmp/"$capturefilename"*
        ls "$capturefilename"* > "$prefix.$suffix.TEXT"

        parallel -j 4 tshark -T fields -e ip.src -e ip.dst -e ip.id -e ip.flags.mf -r {} :::: "$prefix.$suffix.TEXT" |
        awk '
            ! /0x00000000/ {
                if ($4 == 0) {
                    key = $1 "<------>" $2 "-----------" $3
                    a[key]++
                }
            }
            END {
                printf "\n%-8s %-15s %-15s %-18s\n", "Count", "Source IP", "Destination IP", "IP Identification"
                printf "%-8s %-15s %-15s %-18s\n", "-----", "---------------", "---------------", "------------------"

                counter = 0
                for (x in a) {
                    if (a[x] > 1) {
                        # x format: src<------>dst-----------id
                        split(x, parts, "-----------")
                        split(parts[1], sd, "<------>")
                        src  = sd[1]
                        dst  = sd[2]
                        ipid = parts[2]
                        printf "%-8d %-15s %-15s %-18s\n", a[x], src, dst, ipid
                        counter++
                    }
                }
                if (counter == 0) {
                    printf "\nNo looping packets found\n"
                }
            }'

        rm "$capturefilename"* "$prefix.$suffix.TEXT"
    else
        # Small/normal file path: single tshark
        tshark -r "$filename" -T fields -e ip.src -e ip.dst -e ip.id -e ip.flags.mf |
        awk '
            ! /0x00000000/ {
                if ($4 == 0) {
                    key = $1 "<------>" $2 "-----------" $3
                    a[key]++
                }
            }
            END {
                printf "\n%-8s %-15s %-15s %-18s\n", "Count", "Source IP", "Destination IP", "IP Identification"
                printf "%-8s %-15s %-15s %-18s\n", "-----", "---------------", "---------------", "------------------"

                counter = 0
                for (x in a) {
                    if (a[x] > 1) {
                        # x format: src<------>dst-----------id
                        split(x, parts, "-----------")
                        split(parts[1], sd, "<------>")
                        src  = sd[1]
                        dst  = sd[2]
                        ipid = parts[2]
                        printf "%-8d %-15s %-15s %-18s\n", a[x], src, dst, ipid
                        counter++
                    }
                }
                if (counter == 0) {
                    printf "\nNo looping packets found\n"
                }
            }'
    fi
    ;;

text)
    if file "$filename" | grep -q text$; then
        :
    else
        echo "File does not look like text file"
        exit $E_NOTEXTFILE
    fi

    awk '
        BEGIN {
            num_iter = 0
        }

        /ttl/ && !/id 0/ && !/frag/ {
            str1 = $1" <----> "$3"----- "$NF
            gsub(")", "", str1)
            gsub(":", "", str1)
            gsub("\\.", " ", str1)
            $0 = str1

            # Now fields are: src1 src2 src3 src4 <----> dst1 dst2 dst3 dst4 ----- id
            src  = $1"."$2"."$3"."$4
            dst  = $7"."$8"."$9"."$10
            ipid = $NF
            key  = src"----------"dst"<--------->"ipid

            a[key]++
            num_iter++
        }

        END {
            if (num_iter == 0) {
                printf "\nNo Looping Packets Found\n"
                exit
            }

            printf "\n%-8s %-15s %-15s %-18s\n", "Count", "Source IP", "Destination IP", "IP Identification"
            printf "%-8s %-15s %-15s %-18s\n", "-----", "---------------", "---------------", "------------------"

            counter = 0
            for (x in a) {
                if (a[x] > 1) {
                    # x format: src----------dst<--------->id
                    split(x, parts, "<--------->")
                    ipid = parts[2]
                    split(parts[1], sd, "----------")
                    src = sd[1]
                    dst = sd[2]
                    printf "%-8d %-15s %-15s %-18s\n", a[x], src, dst, ipid
                    counter++
                }
            }

            if (counter == 0) {
                printf "\nNo looping packets found\n"
            }
        }' "$filename"
    ;;
*)
    echo "Enter a valid choice"
    ;;
esac
