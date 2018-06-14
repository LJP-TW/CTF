<?php

$t = '".system("ls")."';
$e = urlencode($t);
echo $e.PHP_EOL;


//eval('die("".system("ls -al")."");');
eval('die("' . substr($t, 0, 16) . '");');

?>
