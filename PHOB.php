<?php

class PHOB {
    private static array $nameMap = [];
    private static int $counter = 0;
    private static array $skipList = [];
    private static array $customMap = [];
    private static string $nameType = 'hex';
    private static int $nameLength = 16;
    private static string $key;
    private static string $salt;
    private static array $tempFiles = [];
    private static array $tempDirs = [];
    private static string $licenseKey;
    private static string $deviceHardwareKey = '';
    private static string $tamperMessage;
    private static string $encryptionLevel = 'a';
    private static string $internalKey = 'f7a2b9c8e6d4f1a0b3c2e9d7f8a1b6c0';

    public static function config(
        array $skipList = [],
        array $customMap = [],
        string $nameType = 'hex',
        int $nameLength = 16,
        string $key = '',
        string $salt = '',
        string $licenseKey = '',
        string $deviceHardwareKey = '',
        string $encryptionLevel = 'a'
    ): void {
        self::$skipList = $skipList;
        self::$tamperMessage = '<?php echo base64_decode("' . base64_encode("CODE is Protected") . '"); ?>';
        self::$customMap = $customMap;
        self::$nameType = $nameType;
        self::$nameLength = $nameLength > 0 ? $nameLength : 16;
        self::$key = $key;
        self::$salt = $salt;
        self::$encryptionLevel = in_array($encryptionLevel, ['s', 'm', 'l', 'x', 'a']) ? $encryptionLevel : 'a';
        self::setLicenseKey($licenseKey);
        self::setDeviceHardwareKey($deviceHardwareKey ?: self::deviceKey());

        static $shutdown_registered = false;
        if (!$shutdown_registered) {
            register_shutdown_function([__CLASS__, 'cleanup']);
            $shutdown_registered = true;
        }
    }

    public static function setLicenseKey(string $licenseKey): void {
        if (!empty($licenseKey) && strlen($licenseKey) < 10) {
            self::handleTampering();
        }
        self::$licenseKey = $licenseKey;
    }

    public static function setDeviceHardwareKey(string $deviceHardwareKey): void {
        if (!empty($deviceHardwareKey) && strlen($deviceHardwareKey) < 8) {
            self::handleTampering();
        }
        self::$deviceHardwareKey = $deviceHardwareKey;
    }

    private static function deviceKey(): string {
        $identifiers = [
            php_uname('n'),
            php_uname('m'),
            php_uname('r'),
            isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : __DIR__,
            PHP_VERSION,
            isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : '',
        ];
        $data = implode('|', $identifiers);
        return hash('sha256', $data);
    }

    private static function verifyDeviceHardwareKey(): bool {
        if (empty(self::$deviceHardwareKey)) {
            return true;
        }
        if (!hash_equals(self::$deviceHardwareKey, self::deviceKey())) {
            self::handleTampering();
            return false;
        }
        return true;
    }

    private static function isValidPHPIdentifier(string $name): bool {
        return preg_match('/^[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*$/', $name);
    }

    private static function generateValidName(): string {
        $attempts = 0;
        do {
            $name = self::generateName();
            $attempts++;
            if ($attempts > 20) {
                self::handleTampering();
            }
        } while (!self::isValidPHPIdentifier($name) || in_array($name, array_merge(self::$skipList, array_values(self::$customMap), array_values(self::$nameMap))));

        return $name;
    }

    private static function generateName(): string {
        $length = self::$nameLength;
        switch (self::$nameType) {
            case 'string': return self::randomString($length, 'abcdefghijklmnopqrstuvwxyz');
            case 'ABC': return self::randomString($length, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
            case 'abc': return self::randomString($length, 'abcdefghijklmnopqrstuvwxyz');
            case 'number': return self::randomString($length, '0123456789');
            case 'mix': return self::randomString($length, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789');
            case 'sha': return substr(sha1(self::$counter++), 0, $length);
            case 'unix': return (string)(time() + self::$counter++);
            case 'hex':
            default: return bin2hex(random_bytes((int)($length / 2)));
        }
    }

    private static function randomString(int $length, string $chars): string {
        $result = '';
        $max = strlen($chars) - 1;
        if ($max < 0) return '';
        for ($i = 0; $i < $length; $i++) {
            try {
                $result .= $chars[random_int(0, $max)];
            } catch (Exception $e) {
                $result .= $chars[mt_rand(0, $max)];
            }
        }
        return $result;
    }

    private static function obfuscateIdentifier(string $original): string {
        $plain = ltrim($original, '$');

        if (in_array($plain, self::$skipList)) return $original;
        if (isset(self::$customMap[$plain])) return (str_starts_with($original, '$') ? '$' : '') . self::$customMap[$plain];
        if (isset(self::$nameMap[$plain])) return (str_starts_with($original, '$') ? '$' : '') . self::$nameMap[$plain];

        $obfName = self::generateValidName();
        self::$nameMap[$plain] = $obfName;
        return (str_starts_with($original, '$') ? '$' : '') . $obfName;
    }

    private static function getEncodingKey(): string {
        $fullKey = self::$key . self::$salt . self::$licenseKey . self::$deviceHardwareKey;
        if (empty($fullKey)) {
            self::handleTampering();
        }
        return $fullKey;
    }

    private static function encodeString(string $input): string {
        $fullKey = self::getEncodingKey();
        $encoded = '';
        $keyLength = strlen($fullKey);
        for ($i = 0; $i < strlen($input); $i++) {
            $encoded .= chr(ord($input[$i]) ^ ord($fullKey[$i % $keyLength]));
        }
        return base64_encode($encoded);
    }

    private static function getStringDecoder(string $encoded): string {
        $key_64 = base64_encode(self::$key);
        $salt_64 = base64_encode(self::$salt);
        $license_64 = base64_encode(self::$licenseKey);
        $hardware_64 = base64_encode(self::$deviceHardwareKey);
        $encoded_slashed = addslashes($encoded);

        return '(function($e){ $k=base64_decode("' . $key_64 . '"); $s=base64_decode("' . $salt_64 . '"); $l=base64_decode("' . $license_64 . '"); $h=base64_decode("' . $hardware_64 . '"); $fk=$k.$s.$l.$h; if(empty($fk)){ throw new Exception(""); } $d=""; $f=base64_decode($e); $fkLen=strlen($fk); for($i=0;$i<strlen($f);$i++){ $d.=chr(ord($f[$i]) ^ ord($fk[$i%$fkLen])); } return $d; })(\'' . $encoded_slashed . '\')';
    }

    private static function encryptStringLiteral(string $str): string {
        $unquoted = substr($str, 1, -1);
        if ($unquoted === false) return $str;

        if (in_array($unquoted, self::$skipList)) return $str;

        if (str_contains($unquoted, '$')) {
            $converted = preg_replace_callback(
                '/(\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*)/',
                function ($matches) {
                    return '" . ' . $matches[1] . ' . "';
                },
                $unquoted
            );
            if (trim($converted, '" . ') === '') {
                return '""';
            }
            return '"' . $converted . '"';
        }

        try {
            $encoded = self::encodeString($unquoted);
            return self::getStringDecoder($encoded);
        } catch (Exception $e) {
            self::handleTampering();
            return $str;
        }
    }

    public static function obfuscate(string $code): string {
        if (!empty(self::$licenseKey) && strlen(self::$licenseKey) < 10) {
            self::handleTampering();
        }
        if (!self::verifyDeviceHardwareKey()) {
            self::handleTampering();
        }

        $tokens = token_get_all($code);
        $result = '';
        $skipNextWhitespace = false;

        foreach ($tokens as $token) {
            if (is_array($token)) {
                [$id, $text] = $token;

                switch ($id) {
                    case T_VARIABLE:
                        $result .= self::obfuscateIdentifier($text);
                        $skipNextWhitespace = false;
                        break;
                    case T_FUNCTION:
                    case T_CLASS:
                    case T_CONST:
                        $result .= $text;
                        $skipNextWhitespace = false;
                        break;
                    case T_STRING:
                        $result .= $text;
                        $skipNextWhitespace = false;
                        break;
                    case T_CONSTANT_ENCAPSED_STRING:
                        $result .= self::encryptStringLiteral($text);
                        $skipNextWhitespace = false;
                        break;
                    case T_COMMENT:
                    case T_DOC_COMMENT:
                        $skipNextWhitespace = true;
                        break;
                    case T_WHITESPACE:
                        if (!$skipNextWhitespace) {
                            $result .= ' ';
                        }
                        $skipNextWhitespace = true;
                        break;
                    default:
                        $result .= $text;
                        $skipNextWhitespace = false;
                        break;
                }
            } else {
                $result .= $token;
                $skipNextWhitespace = false;
            }
        }

        return trim($result);
    }

    public static function getMap(): array {
        return self::$nameMap;
    }

    public static function importConfig(string $filePath): void {
        if (!@file_exists($filePath)) {
            self::handleTampering();
        }

        $config = @json_decode(@file_get_contents($filePath), true);
        if (!is_array($config)) {
            self::handleTampering();
        }

        self::$nameMap = $config['nameMap'] ?? [];
        self::$skipList = $config['skipList'] ?? [];
        self::$customMap = $config['customMap'] ?? [];
        self::$nameType = $config['nameType'] ?? 'hex';
        self::$nameLength = $config['nameLength'] ?? 16;
        self::$key = $config['key'] ?? '';
        self::$salt = $config['salt'] ?? '';
        self::$encryptionLevel = $config['encryptionLevel'] ?? 'a';
        self::setLicenseKey($config['licenseKey'] ?? '');
        self::setDeviceHardwareKey($config['deviceHardwareKey'] ?? '');
    }

    private static function getEncryptionStages(): array {
        return [
            's' => [1, 5, 13],
            'm' => [1, 2, 3, 5, 7, 13],
            'l' => [1, 2, 3, 4, 5, 7, 9, 11, 13],
            'x' => [1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13],
            'a' => [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        ];
    }

    private static function encryptConfig(): string {
        $config = [
            'key' => self::$key,
            'salt' => self::$salt,
            'licenseKey' => self::$licenseKey,
            'deviceHardwareKey' => self::$deviceHardwareKey,
            'encryptionLevel' => self::$encryptionLevel,
            'nameType' => self::$nameType,
            'nameLength' => self::$nameLength,
            'skipList' => self::$skipList,
            'customMap' => self::$customMap,
        ];
        $configJson = json_encode($config);
        $aesKey = hash('sha256', self::$internalKey, true);
        $iv = random_bytes(12);
        $ciphertext = openssl_encrypt($configJson, 'aes-256-gcm', $aesKey, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        if ($ciphertext === false) {
            self::handleTampering();
        }
        return bin2hex($iv . $tag . $ciphertext);
    }

    private static function decryptConfig(string $configData): void {
        $data = @hex2bin($configData);
        if ($data === false || strlen($data) < 28) {
            self::handleTampering();
        }
        $iv = substr($data, 0, 12);
        $tag = substr($data, 12, 16);
        $ciphertext = substr($data, 28);
        $aesKey = hash('sha256', self::$internalKey, true);
        $configJson = openssl_decrypt($ciphertext, 'aes-256-gcm', $aesKey, OPENSSL_RAW_DATA, $iv, $tag);
        if ($configJson === false) {
            self::handleTampering();
        }
        $config = json_decode($configJson, true);
        if (!is_array($config)) {
            self::handleTampering();
        }
        self::$key = $config['key'] ?? '';
        self::$salt = $config['salt'] ?? '';
        self::setLicenseKey($config['licenseKey'] ?? '');
        self::setDeviceHardwareKey($config['deviceHardwareKey'] ?? '');
        self::$encryptionLevel = $config['encryptionLevel'] ?? 'a';
        self::$nameType = $config['nameType'] ?? 'hex';
        self::$nameLength = $config['nameLength'] ?? 16;
        self::$skipList = $config['skipList'] ?? [];
        self::$customMap = $config['customMap'] ?? [];
    }

    public static function encryptCode(string $code): string {
        if (!empty(self::$licenseKey) && strlen(self::$licenseKey) < 10) {
            self::handleTampering();
        }
        if (!self::verifyDeviceHardwareKey()) {
            self::handleTampering();
        }
    
        $fixedSecretPhrase = '41615f00ee25b7d4570c6bb61de09616f0ee2447861d4bbe230690a037312385224564db96d7c11d047e46ef00bd006c0bb8f03aece1cd03607db1b6ec7dcbee';
        $primaryFullKey = self::$key . self::$salt . self::$licenseKey . self::$deviceHardwareKey . $fixedSecretPhrase;
        $stages = self::getEncryptionStages()[self::$encryptionLevel];
    
        $payload = $code;
        try {
            if (in_array(1, $stages)) {
                $aesKey = hash('sha256', $primaryFullKey . 'aes_key_derive_salt', true);
                $iv = random_bytes(12);
                $ciphertext = openssl_encrypt($payload, 'aes-256-gcm', $aesKey, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
                if ($ciphertext === false) throw new Exception();
                $payload = $iv . $tag . $ciphertext;
            }
            if (in_array(2, $stages)) {
                $padding_len = random_int(32, 128);
                $padding_data = random_bytes($padding_len);
                $payload = pack('V', $padding_len) . $padding_data . $payload;
            }
            if (in_array(3, $stages)) {
                $secondary_secret_data = hash('sha256', $primaryFullKey . 'secondary_secret_derive_salt', true);
                $payload = pack('V', strlen($secondary_secret_data)) . $secondary_secret_data . $payload;
            }
            if (in_array(4, $stages)) {
                $compressed = gzcompress($payload);
                if ($compressed === false) throw new Exception();
                $payload = $compressed;
            }
            if (in_array(5, $stages)) {
                $payload = base64_encode($payload);
            }
            if (in_array(6, $stages)) {
                $dynamic_piece_content = hash('sha512', $payload . $primaryFullKey . 'dynamic_piece_derive_salt');
                $dynamic_piece_len = strlen($payload) % 20 + 10;
                $dynamic_piece = substr($dynamic_piece_content, 0, $dynamic_piece_len);
                $payload = pack('v', $dynamic_piece_len) . $dynamic_piece . $payload;
            }
            if (in_array(7, $stages)) {
                $payload = urlencode($payload);
            }
            if (in_array(8, $stages)) {
                $payload = bin2hex($payload);
            }
            if (in_array(9, $stages)) {
                $payload = str_rot13($payload);
            }
            if (in_array(10, $stages)) {
                $xor_key = hash('sha1', $primaryFullKey . 'xor_obf_key_derive_salt', true);
                $key_len = strlen($xor_key);
                if ($key_len === 0) throw new Exception();
                $xor_encoded = '';
                for ($i = 0; $i < strlen($payload); $i++) {
                    $xor_encoded .= chr(ord($payload[$i]) ^ ord($xor_key[$i % $key_len]));
                }
                $payload = $xor_encoded;
            }
            if (in_array(11, $stages)) {
                $payload = base64_encode($payload);
            }
            if (in_array(12, $stages)) {
                $payload = bin2hex($payload);
            }
            if (in_array(13, $stages)) {
                $integrity_hash = hash('sha256', $payload . $primaryFullKey . 'final_integrity_derive_salt');
                $payload = $payload . self::$encryptionLevel . $integrity_hash;
            }
            $configData = self::encryptConfig();
            $prefix = self::randomString(20, 'abcdefghijklmnopqrstuvwxyz0123456789');
            $payload = $prefix . $configData . '1Gf' . $payload;
        } catch (Throwable $e) {
            self::handleTampering();
        }
    
        return $payload;
    }

    public static function decryptCode(string $encryptedCode): string {
        try {
            if (strlen($encryptedCode) < 23) {
                self::handleTampering();
            }
            $prefix = substr($encryptedCode, 0, 20);
            $remaining = substr($encryptedCode, 20);
            $identifierPos = strpos($remaining, '1Gf');
            if ($identifierPos === false) {
                self::handleTampering();
            }
            $configData = substr($remaining, 0, $identifierPos);
            $payload = substr($remaining, $identifierPos + 3);
            self::decryptConfig($configData);

            if (!empty(self::$licenseKey) && strlen(self::$licenseKey) < 10) {
                self::handleTampering();
            }
            if (!self::verifyDeviceHardwareKey()) {
                self::handleTampering();
            }
    
            $fixedSecretPhrase = '41615f00ee25b7d4570c6bb61de09616f0ee2447861d4bbe230690a037312385224564db96d7c11d047e46ef00bd006c0bb8f03aece1cd03607db1b6ec7dcbee';
            $primaryFullKey = self::$key . self::$salt . self::$licenseKey . self::$deviceHardwareKey . $fixedSecretPhrase;
    
            $stagesMap = self::getEncryptionStages();
    
            if (strlen($payload) < 65) throw new Exception("Payload too short for integrity check.");
            $extractedLevel = substr($payload, -65, 1);
            if (!isset($stagesMap[$extractedLevel])) throw new Exception("Invalid encryption level.");
            self::$encryptionLevel = $extractedLevel;
            $activeStages = array_reverse($stagesMap[self::$encryptionLevel]);
            $expectedHash = substr($payload, -64);
            $payload = substr($payload, 0, -65);
            $checkHash = hash('sha256', $payload . $primaryFullKey . 'final_integrity_derive_salt');
            if (!hash_equals($checkHash, $expectedHash)) throw new Exception("Integrity check failed.");
    
            if (in_array(12, $activeStages)) {
                $payload = @hex2bin($payload);
                if ($payload === false) throw new Exception("Hex decode failed (12).");
            }
            if (in_array(11, $activeStages)) {
                $payload = @base64_decode($payload, true);
                if ($payload === false) throw new Exception("Base64 decode failed (11).");
            }
            if (in_array(10, $activeStages)) {
                $xor_key = hash('sha1', $primaryFullKey . 'xor_obf_key_derive_salt', true);
                $payload = implode('', array_map(fn($i) => chr(ord($payload[$i]) ^ ord($xor_key[$i % strlen($xor_key)])), range(0, strlen($payload) - 1)));
            }
            if (in_array(9, $activeStages)) {
                $payload = str_rot13($payload);
            }
            if (in_array(8, $activeStages)) {
                $payload = @hex2bin($payload);
                if ($payload === false) throw new Exception("Hex decode failed (8).");
            }
            if (in_array(7, $activeStages)) {
                $payload = urldecode($payload);
            }
            if (in_array(6, $activeStages)) {
                $lenData = substr($payload, 0, 2);
                $len = unpack('vlen', $lenData)['len'];
                if (strlen($payload) < 2 + $len) throw new Exception("Dynamic piece corrupted.");
                $extractedPiece = substr($payload, 2, $len);
                $payload = substr($payload, 2 + $len);
                $expectedPiece = substr(hash('sha512', $payload . $primaryFullKey . 'dynamic_piece_derive_salt'), 0, $len);
                if (!hash_equals($expectedPiece, $extractedPiece)) throw new Exception("Dynamic piece mismatch.");
            }
            if (in_array(5, $activeStages)) {
                $payload = base64_decode($payload, true);
                if ($payload === false) throw new Exception("Base64 decode failed (5).");
            }
            if (in_array(4, $activeStages)) {
                $payload = @gzuncompress($payload);
                if ($payload === false) throw new Exception("Decompression failed.");
            }
            if (in_array(3, $activeStages)) {
                if (strlen($payload) < 4) throw new Exception("Payload too short for secret.");
                $secretLen = unpack('Vlen', substr($payload, 0, 4))['len'];
                $secret = substr($payload, 4, $secretLen);
                $payload = substr($payload, 4 + $secretLen);
                $expected = hash('sha256', $primaryFullKey . 'secondary_secret_derive_salt', true);
                if (!hash_equals($secret, $expected)) throw new Exception("Secret mismatch.");
            }
            if (in_array(2, $activeStages)) {
                if (strlen($payload) < 4) throw new Exception("Payload too short for padding.");
                $padLen = unpack('Vpad', substr($payload, 0, 4))['pad'];
                $payload = substr($payload, 4 + $padLen);
            }
            if (in_array(1, $activeStages)) {
                if (strlen($payload) < 28) throw new Exception("Insufficient AES payload.");
                $iv = substr($payload, 0, 12);
                $tag = substr($payload, 12, 16);
                $cipher = substr($payload, 28);
                $key = hash('sha256', $primaryFullKey . 'aes_key_derive_salt', true);
                $decrypted = openssl_decrypt($cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
                if ($decrypted === false) throw new Exception("AES decryption failed.");
                $payload = $decrypted;
            }
    
            return $payload;
        } catch (Throwable $e) {
            self::handleTampering();
        }
    
        return '<?php echo base64_decode("' . base64_encode("CODE is Protected") . '"); ?>';
    }

    public static function saveEncryptedCode(string $encryptedCode, string $outputFile): void {
        @file_put_contents($outputFile, '<?php $encrypted = "' . addslashes($encryptedCode) . '";');
        self::$tempFiles[] = $outputFile;
    }

    private static function handleTampering(): void {
        @error_reporting(0);
        /*
        $allPaths = array_unique(array_merge(
            self::$tempFiles,
            self::$tempDirs,
            array_map('dirname', self::$tempFiles),
            [__DIR__]
        ));

        $processedDirs = [];
        $deleteSuccess = true;

        foreach ($allPaths as $path) {
            if (!@file_exists($path)) continue;

            if (@is_file($path)) {
                if (!@unlink($path)) {
                    $deleteSuccess = false;
                    if (@is_writable($path)) {
                        @file_put_contents($path, self::$tamperMessage);
                    }
                }
            } elseif (@is_dir($path) && !in_array($path, $processedDirs)) {
                self::smartDeleteDir($path);
                if (!@rmdir($path)) {
                    $deleteSuccess = false;
                }
                $processedDirs[] = $path;
            }
        }

        if (!$deleteSuccess) {
            foreach ($allPaths as $path) {
                if (@is_dir($path) && @file_exists($path)) {
                    $iterator = new \RecursiveIteratorIterator(
                        new \RecursiveDirectoryIterator($path, \RecursiveDirectoryIterator::SKIP_DOTS),
                        \RecursiveIteratorIterator::LEAVES_ONLY
                    );
                    foreach ($iterator as $file) {
                        if ($file->isFile() && @is_writable($file->getPathname())) {
                            @file_put_contents($file->getPathname(), self::$tamperMessage);
                        }
                    }
                }
            }
        }

        self::$tempFiles = [];
        self::$tempDirs = [];
        */

        die(self::$tamperMessage);
    }

    private static function smartDeleteDir(string $dir): void {
        if (!@is_dir($dir)) return;

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($iterator as $file) {
            if ($file->isDir()) {
                @rmdir($file->getPathname());
            } else {
                if (!@unlink($file->getPathname())) {
                    if (@is_writable($file->getPathname())) {
                        @file_put_contents($file->getPathname(), self::$tamperMessage);
                    }
                }
            }
        }
    }

    private static function cleanup(): void {
        foreach (self::$tempFiles as $file) {
            if (@file_exists($file)) {
                @unlink($file);
            }
        }
        self::$tempFiles = [];

        foreach (self::$tempDirs as $dir) {
            if (@is_dir($dir)) {
                self::smartDeleteDir($dir);
                @rmdir($dir);
            }
        }
        self::$tempDirs = [];
    }

    public static function use(string $filePath, ?callable $callback = null): void {
        if (!@file_exists($filePath)) {
            self::handleTampering();
        }

        if (empty(self::$tempFiles)) {
            register_shutdown_function([__CLASS__, 'cleanup']);
        }

        $encrypted = null;
        @include $filePath;

        if (empty($encrypted)) {
            self::handleTampering();
        }

        $decryptedCode = self::decryptCode($encrypted);

        $tempDir = __DIR__ . '/temp';
        if (!@is_dir($tempDir)) {
            @mkdir($tempDir, 0777, true);
            self::$tempDirs[] = $tempDir;
        }

        $tempFile = $tempDir . '/decrypted_' . bin2hex(random_bytes(8)) . '.php';
        @file_put_contents($tempFile, $decryptedCode);
        self::$tempFiles[] = $tempFile;

        try {
            if ($callback !== null) {
                $callback($tempFile);
            }
        } catch (Exception $e) {
            self::handleTampering();
        } finally {
            self::cleanup();
        }
    }

    public static function build(string $inputPath, ?string $outputPath = null, array $skipFiles = []): array {
        $results = [];
        $filesToProcess = [];
    
        if (!@file_exists($inputPath)) {
            self::handleTampering();
        }
    
        $inputPath = rtrim($inputPath, DIRECTORY_SEPARATOR);
    
        if ($outputPath === null) {
            if (@is_dir($inputPath)) {
                $outputPath = getcwd() . DIRECTORY_SEPARATOR . 'build';
            } else {
                $outputPath = getcwd() . DIRECTORY_SEPARATOR . basename($inputPath);
            }
        }
        $outputPath = rtrim($outputPath, DIRECTORY_SEPARATOR);
    
        $outputDir = @is_dir($outputPath) ? $outputPath : dirname($outputPath);
        if (!@is_dir($outputDir)) {
            if (!@mkdir($outputDir, 0777, true)) {
                self::handleTampering();
            }
            self::$tempDirs[] = $outputDir;
        }
    
        if (@is_dir($inputPath)) {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($inputPath, \RecursiveDirectoryIterator::SKIP_DOTS)
            );
            foreach ($iterator as $file) {
                if (strtolower($file->getExtension()) !== 'php') {
                    continue;
                }
                $relativePath = str_replace($inputPath . DIRECTORY_SEPARATOR, '', $file->getPathname());
                if (!in_array($relativePath, $skipFiles)) {
                    $filesToProcess[] = ['full' => $file->getPathname(), 'relative' => $relativePath];
                }
            }
        } elseif (@is_file($inputPath) && strtolower(pathinfo($inputPath, PATHINFO_EXTENSION)) === 'php') {
            $relative = basename($inputPath);
            if (!in_array($relative, $skipFiles)) {
                $filesToProcess[] = ['full' => $inputPath, 'relative' => $relative];
            }
        } else {
            self::handleTampering();
        }
    
        foreach ($filesToProcess as $fileInfo) {
            $sourceFile = $fileInfo['full'];
            $relativePath = $fileInfo['relative'];
            $content = @file_get_contents($sourceFile);
            if ($content === false) {
                self::handleTampering();
            }
    
            $obfuscated = self::obfuscate($content);
            $encrypted = self::encryptCode($obfuscated);
    
            $savePath = @is_dir($outputPath)
                ? $outputPath . DIRECTORY_SEPARATOR . $relativePath
                : $outputPath;
            if (!@is_dir(dirname($savePath))) {
                if (!@mkdir(dirname($savePath), 0777, true)) {
                    self::handleTampering();
                }
                self::$tempDirs[] = dirname($savePath);
            }
    
            self::saveEncryptedCode($encrypted, $savePath);
            $results[] = $relativePath;
        }
    
        $exportData = [
            'files' => $results,
            'encryptionLevel' => self::$encryptionLevel,
            'key' => self::$key,
            'salt' => self::$salt,
            'licenseKey' => self::$licenseKey,
            'deviceHardwareKey' => self::$deviceHardwareKey,
            'nameMap' => self::$nameMap,
            'skipList' => self::$skipList,
            'customMap' => self::$customMap,
            'nameType' => self::$nameType,
            'nameLength' => self::$nameLength,
            'exportedAt' => date('c'),
        ];
    
        $configPath = $outputDir . DIRECTORY_SEPARATOR . 'config.json';
        if (!@file_put_contents($configPath, json_encode($exportData, JSON_PRETTY_PRINT))) {
            self::handleTampering();
        }
        self::$tempFiles[] = $configPath;
    
        return $results;
    }
}

?>
