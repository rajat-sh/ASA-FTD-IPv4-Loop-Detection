#!/bin/bash
# version 3
# This is a script to detect duplicate IPv4 packets from pcap files or
# "show capture capname detail" output from ASA/FTD.

# Argument validation check
if [ "$#" -ne 2 ]; then
    echo ""
    echo "For pcap Usage: $0 <pcap> <filename or path>"
    echo "For text Usage: $0 <text> <filename or path>"
    echo "Example for pcap: $0 pcap abc.pcap"
    echo "Example for text: $0 text abc.txt"
    echo "Text file will be output of /show capture \"capname\" detail/ from ASA/FTD"
    echo ""
    exit 1
fi

# Exit Codes
E_NOFILE=91           # Packet capture file does not exist.
E_NOTEXTFILE=92       # File does not look like text file.
E_NOCAPTUREFILE=93    # File does not look like capture file.

# Parameters entered by user
INPUT=$1
filename=$2

# Check if capture/text file exists
if [ ! -f "$filename" ]; then
    echo "Capture File not found"
    exit $E_NOFILE
fi

case "$INPUT" in
pcap)
    # Basic file type check for pcap
    if file "$filename" | grep -qi "pcap"; then
        :
    else
        echo "File does not look like capture file"
        exit $E_NOCAPTUREFILE
    fi

    tshark -r "$filename" -T fields -e ip.src -e ip.dst -e ip.id -e ip.flags.mf |
    awk '
        # Exclude IP ID 0x00000000 and only consider non-fragmented packets (MF=0)
        ! /0x00000000/ {
            if ($4 == 0) {
                # Build key: "src<------>dst-----------id"
                str = $1 "<------>" $2 "-----------" $3
                a[str]++
            }
        }
        END {
            printf "\n%-8s %-15s %-15s %-18s\n", "Count", "Source IP", "Destination IP", "IP Identification"
            printf "%-8s %-15s %-15s %-18s\n", "-----", "---------------", "---------------", "------------------"

            counter = 0
            for (x in a) {
                if (a[x] > 1) {
                    # x is "src<------>dst-----------id"
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
    ;;
text)
    # Basic file type check for text
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

        # Typical ASA/FTD line with ttl, but no "id 0" and no "frag"
        /ttl/ && !/id 0/ && !/frag/ {
            # Example original fields:
            # 1=src_ip, 3=dst_ip, NF=... (IP id at the end usually "id 0x1234")
            str1 = $1" <----> "$3"----- "$NF
            gsub(")", "", str1)
            gsub(":", "", str1)
            gsub("\\.", " ", str1)

            # Overwrite $0 so we can break out src/dst octets
            $0 = str1
            # Now fields are: src1 src2 src3 src4 <----> dst1 dst2 dst3 dst4 ----- id
            # We rebuild: "src----------dst<--------->id"
            src  = $1"."$2"."$3"."$4
            dst  = $7"."$8"."$9"."$10
            ipid = $NF
            key  = src "----------" dst "<--------->" ipid

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
                    # x is "src----------dst<--------->id"
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
    echo "Enter a valid choice (pcap | text)"
    ;;
esac
