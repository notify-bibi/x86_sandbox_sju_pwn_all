#!/bin/bash
IMAGEID=$(sudo docker images | grep pwn_sandbox)
if [[ $IMAGEID == '' ]]; then
    sudo docker build -t "pwn_sandbox" .
fi
your_name=$(sudo docker ps -a | grep pwn_sandbox)
id=${your_name:0:14}
if [[ $id == '' ]]; then
    id=`sudo docker run -d -p "0.0.0.0:8888:9999" -h "pwn_sandbox" --name="pwn_sandbox" pwn_sandbox`
fi

sudo docker exec -it ${id} /bin/bash