#!/bin/bash
your_name=$(sudo docker ps -a | grep pwn_sandbox)
id=${your_name:0:14}
if [[ $id != '' ]]; then
    echo $id
    sudo docker stop $id
    sudo docker rm $id
fi
IMAGEID=$(sudo docker images | grep pwn_sandbox)
if [[ $IMAGEID != '' ]]; then
    s1=${IMAGEID//*latest/}
    echo ${s1}
    s2=${s1:10:16}
    echo ${s2}
    sudo docker rmi $s2
fi