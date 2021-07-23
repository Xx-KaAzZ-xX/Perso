#!/bin/bash

#Script name : matrice_flux.sh
#Author.
#Description.   Script basé sur Tshark pour mettre au point une matrice de flux à partir d'une capture pcap

file="/tmp/file.pcap"
unique_ip="/tmp/ip.txt"
udp_csv="/tmp/udp_output.csv"
tcp_csv="/tmp/tcp_output.csv"
file_csv="matrice_flux.csv"
tshark -r ${file} -T fields -e ip.dst ip.src | sort -u > ${unique_ip}

cat ${unique_ip} | while read line
do
  #echo "------------"
  #echo " All communications from ${line}"
  #echo "------------"
  tshark -r ${file} -T fields -E separator=, -e ip.src -e ip.dst -e tcp.port ip.src==${line} | sort -u >> ${tcp_csv}
  tshark -r ${file} -T fields -E separator=, -e ip.src -e ip.dst -e udp.port ip.src==${line} | sort -u >> ${udp_csv}
done

##concat tcp and udp packages
echo "IP SOURCE, IP DESTINATION,  TCP/UDP PORT DEST," > ${file_csv}
cat ${tcp_csv} >> ${file_csv}
echo "IT UDP PACKAGES FROM NOW" >> ${file_csv}
cat ${udp_csv} >> ${file_csv}

##cleaning
rm ${unique_ip} ${tcp_csv} ${udp_csv}

exit 0
