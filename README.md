# PHOB-OLD
PHOB - PHP obfuscator



## Build
```
<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
require_once 'ob.php';

PHOB::config([], ["myVariable" => "vtest"], 'hex', 12, 'mysecretkey', 'mysalt', '', '', 'm');
PHOB::build('raw.php', 'out.php');

echo "Code obfuscated, encrypted and saved\n";
?>
```

## Use
```
<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
require_once 'PHOB.php';

PHOB::use('out.php', function($tempFilePath) {
    include $tempFilePath;
    echo "<br>Callback: " . (isset($vtest) ? $vtest : 'undefined') . " goodbye\n";
});
?>
```
