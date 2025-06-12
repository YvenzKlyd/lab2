<?php
require_once __DIR__ . '/../vendor/autoload.php';
use RobThree\Auth\TwoFactorAuth;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

function sanitizeInput($data) {
    return htmlspecialchars(strip_tags(trim($data)));
}

function generateVerificationToken() {
    return bin2hex(random_bytes(32));
}

function hashPassword($password) {
    return password_hash($password, PASSWORD_DEFAULT);
}

function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

function generateTOTPSecret() {
    $tfa = new TwoFactorAuth('MFA System');
    return $tfa->createSecret();
}

function verifyTOTP($secret, $code) {
    try {
        $tfa = new TwoFactorAuth('MFA System');
        // Allow a 30-second window before and after the current time
        return $tfa->verifyCode($secret, $code, 1);
    } catch (Exception $e) {
        error_log("TOTP Verification Error: " . $e->getMessage());
        return false;
    }
}

function generateBackupCodes() {
    $codes = [];
    for ($i = 0; $i < 8; $i++) {
        $codes[] = bin2hex(random_bytes(4));
    }
    return $codes;
}
// this function is about sending verification Email with the email and it’s token by calling the PHPMailer
function sendVerificationEmail($email, $token) {
    $mail = new PHPMailer(true);
// this whole mail in isSMTP to Port by calling this It tells the PHPmailer to use SMTP instead of the built-in mail
    try {
        // Server settings
        $mail->isSMTP(); // this line sets the PHPMailer object to use SMTP (Simple Mail Transfer Protocol) to send via emails
        $mail->Host       = 'smtp.gmail.com'; // Gmail SMTP server
        $mail->SMTPAuth   = true; // it verifies the identity of the sender using a username and password
        $mail->Username   = 'kuraidodavinci@gmail.com'; // this is the Gmail address
        $mail->Password   = 'irxy uiqp myvt rtsz'; // this is the Gmail App Password
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS; // it ensures that emails are transmitted securely, prtotecting sensitive informations
        $mail->Port       = 587; // defines the port used for smtp communications

        // Recipients
        $mail->setFrom('kuraidodavinci@gmail.com', 'MFA System'); // this email acc holds the email verificcations
        $mail->addAddress($email);// by adding email address

        // Content
        $mail->isHTML(true); // allows to include html tags and formatting the email body
        $mail->Subject = 'Email Verification'; // this line sets the subject for the email verification
        $verificationLink = "http://" . $_SERVER['HTTP_HOST'] . "/mfa/verify.php?token=" . $token; // this sends to the user for a verification link before logging in
        $mail->Body    = "Please click the following link to verify your email: <br><br> 
                         <a href='{$verificationLink}'>{$verificationLink}</a>"; // it gives the verification link

        $mail->send(); // this tells about by sending
        return true; //
    } catch (Exception $e) {
        error_log("Email sending failed: {$mail->ErrorInfo}");
        return false; // this lines conclude about a email sending failed. An error inshort.
    }
}

function isLoggedIn() { // this tells about the function of logging in
    return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']); // for confirming by the user logging in
}

function requireLogin() {
    if (!isLoggedIn()) {
        header("Location: login.php");
        exit;
    }
}

function checkMFARequired() {
    return isset($_SESSION['mfa_required']) && $_SESSION['mfa_required'] === true;
}
?> 