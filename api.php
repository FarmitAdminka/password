
<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
require __DIR__ . '/../vendor/autoload.php';

use phpseclib\Crypt\RSA;
require '../vendor/autoload.php';

function gs($length = 10) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
    }
    return $randomString;
}

function gn($length = 10) {
    $characters = '0123456789';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
    }
    return $randomString;
}

function encrypt($password, $publicKey, $keyId) {
    $time = time();
    $session_key = random_bytes(32);
    $iv = random_bytes(12);
    $tag = '';
    $rsa = new RSA();

    $rsa->loadKey($publicKey);
    $rsa->setSignatureMode(RSA::SIGNATURE_PKCS1);
    $enc_session_key = $rsa->encrypt($session_key);
    $encrypted = openssl_encrypt($password, 'aes-256-gcm', $session_key, OPENSSL_RAW_DATA, $iv, $tag, intval($time));

    return "#PWD_FB4A:4:" . $time . ":" . base64_encode(("\x01" . pack('n', intval($keyId)) . $iv . pack('n', strlen($enc_session_key)) . $enc_session_key . $tag . $encrypted));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $password = $_POST['password'] ?? null;
    
    if ($password) {
        $e = "100068716380087"; // ваш email
        $publicKey = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA55fg2033Auq1rDLZOzCS
vTxCQooLg6PXnsYKta7ZZYm8Jo1k47JzWiI9xk5227/yf739qlChZc7BZNM3M+5v
duhOE3uRLEVGK/1o/RxxN1KA6+6GF4koDKJW7XLM2fKtOLJ34RN0hDYHvosp2dKL
pMPnWGp0xP1wE33HRkXkF8ZJaZoj/DozpeUdrUxCS5mU7mpB/9ha3M2xqI6sOxOC
QLzJgLF5twixOf86MQbXY7Y1tl/tqEqU+9hmAQOYJ30XprECFCW7Q8Ttiva/CBOw
dXKKke32IcAETz8N9HVydh5sLQO2F/toEQuHFOXoVQOcZ9rTM1JhTU6Arax1s5HT
twIDAQAB
-----END PUBLIC KEY-----";

        $keyId = 85; 
        $enc_pass = urlencode(encrypt($password, $publicKey, $keyId));

        echo json_encode(['encrypted_password' => $enc_pass]);
    } else {
        echo json_encode(['error' => 'Password not provided']);
    }
} else {
    echo json_encode(['error' => 'Invalid request method']);
}

?>
