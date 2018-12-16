#!/bin/bash

 #.  Description : Script to create local SSH tunnel.


 usage() {
 
   script_name=$(basename $0)
   echo -e "This is the list of available options: "
   echo -e "\t  -h : The host to connect."
   echo -e "\t  -l : The local port."
   echo -e "\t  -r : The remote port."
 }
 
 while getopts "h:l:r:" opt; do
   case $opt in
     h) host="${OPTARG}"
       ;;
     l) l_port="${OPTARG}"
       ;;
     r) r_port="${OPTARG}"
       ;;
   esac
   
 done

 if [ -z ${host} ] || [ -z ${l_port} ] || [ -z ${r_port} ]
 then
   usage
   exit 1
 fi
 
 ssh -fND 127.0.0.1:${l_port} ${host} -p ${r_port}
 test=$(ss -paunt | grep "${r_port}")

 if [[ ! -z ${test} ]]
 then
 	echo -e "SSH tunnel successfully created on port: ${l_port} \n
 			 You can now configure your web browser or proxychains to use it."
 fi

 exit 0