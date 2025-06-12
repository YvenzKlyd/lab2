<?php
require_once __DIR__ . '/../vendor/autoload.php';
use Twilio\Rest\Client;

function generateSMSCode() {
    return str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
}

function sendSMS($phone, $code) {
    try {
        $account_sid = 'AC7f744af0b8b460bbd167b9821a922ab9';
        $auth_token = '232445b53ec76e58a74aed1e44e87890';
        $twilio_number = '+639921393686';

        $client = new Client($account_sid, $auth_token);
        
        $message = $client->messages->create(
            $phone,
            [
                'from' => $twilio_number,
                'body' => "Your MFA verification code is: {$code}. This code will expire in 5 minutes."
            ]
        );
        
        return true;
    } catch (Exception $e) {
        error_log("SMS Error: " . $e->getMessage());
        return false;
    }
}

function storeSMSCode($conn, $user_id, $code) {
    try {
        // Delete any existing codes for this user
        $stmt = $conn->prepare("DELETE FROM sms_codes WHERE user_id = ?");
        $stmt->execute([$user_id]);
        
        // Store new code
        $stmt = $conn->prepare("INSERT INTO sms_codes (user_id, code, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))");
        return $stmt->execute([$user_id, $code]);
    } catch (PDOException $e) {
        error_log("SMS Code Storage Error: " . $e->getMessage());
        return false;
    }
}

function verifySMSCode($conn, $user_id, $code) {
    try {
        $stmt = $conn->prepare("SELECT code FROM sms_codes WHERE user_id = ? AND code = ? AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1");
        $stmt->execute([$user_id, $code]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($result) {
            // Delete the used code
            $stmt = $conn->prepare("DELETE FROM sms_codes WHERE user_id = ? AND code = ?");
            $stmt->execute([$user_id, $code]);
            return true;
        }
        return false;
    } catch (PDOException $e) {
        error_log("SMS Code Verification Error: " . $e->getMessage());
        return false;
    }
}

function isPhoneVerified($conn, $user_id) {
    try {
        $stmt = $conn->prepare("SELECT phone_verified FROM users WHERE id = ?");
        $stmt->execute([$user_id]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result && $result['phone_verified'];
    } catch (PDOException $e) {
        error_log("Phone Verification Check Error: " . $e->getMessage());
        return false;
    }
} 