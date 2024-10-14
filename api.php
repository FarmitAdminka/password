<?php

require 'vendor/autoload.php';
use phpseclib\Crypt\RSA;

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
    
    if ($encrypted === false) {
        error_log("Ошибка шифрования: " . openssl_error_string(), 3, "/tmp/mylog.log");
        echo json_encode(['error' => 'Ошибка шифрования']);
        exit;
    }
    
    return "#PWD_FB4A:4:" . $time . ":" . base64_encode(("\x01" . pack('n', intval($keyId)) . $iv . pack('n', strlen($enc_session_key)) . $enc_session_key . $tag . $encrypted));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Логируем входящие данные
    error_log("POST данные: " . print_r($_POST, true), 3, "/tmp/mylog.log");
    
    $password = $_POST['password'] ?? '';
    if (empty($password)) {
        error_log("Пароль не предоставлен", 3, "/tmp/mylog.log");
        echo json_encode(['error' => 'Пароль не предоставлен']);
        exit;
    }

    $publicKey = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA55fg2033Auq1rDLZOzCS
vTxCQooLg6PXnsYKta7ZZYm8Jo1k47JzWiI9xk5227/yf739qlChZc7BZNM3M+5v
duhOE3uRLEVGK/1o/RxxN1KA6+6GF4koDKJW7XLM2fKtOLJ34RN0hDYHvosp2dKL
pMPnWGp0xP1wE33HRkXkF8ZJaZoj/DozpeUdrUxCS5mU7mpB/9ha3M2xqI6sOxOC
QLzJgLF5twixOf86MQbXY7Y1tl/tqEqU+9hmAQOYJ30XprECFCW7Q8Ttiva/CBOw
dXKKke32IcAETz8N9HVydh5sLQO2F/toEQuHFOXoVQOcZ9rTM1JhTU6Arax1s5HT
twIDAQAB
-----END PUBLIC KEY-----";
    
    $keyId = 85; // Установите ID ключа
    
    // Зашифруйте пароль
    $encrypted_password = encrypt($password, $publicKey, $keyId);
    
    // Верните зашифрованный пароль в JSON-формате
    header('Content-Type: application/json');
    echo json_encode(['encrypted_password' => $encrypted_password]);
    exit;
}
?>
