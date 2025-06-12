<?php
session_start();
require_once 'config/database.php';
require_once 'includes/functions.php';
require_once 'includes/sms_functions.php';
use RobThree\Auth\TwoFactorAuth;

$error = '';
$success = '';
$qrCode = '';
$secretKey = '';
$smsSent = false;
$userId = null;

// Handle MFA setup request
if (isset($_GET['setup']) && isset($_GET['user_id'])) {
    $userId = sanitizeInput($_GET['user_id']);
    try {
        $stmt = $conn->prepare("SELECT email, phone FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user) {
            // Generate TOTP secret and backup codes
            $tfa = new TwoFactorAuth('MFA System');
            $totp_secret = $tfa->createSecret();
            $backup_codes = generateBackupCodes();
            $backup_codes_json = json_encode($backup_codes);
            
            // Check if MFA secret already exists
            $stmt = $conn->prepare("SELECT id FROM mfa_secrets WHERE user_id = ?");
            $stmt->execute([$userId]);
            
            if ($stmt->rowCount() > 0) {
                // Update existing MFA secret
                $stmt = $conn->prepare("UPDATE mfa_secrets SET secret_key = ?, backup_codes = ? WHERE user_id = ?");
                $stmt->execute([$totp_secret, $backup_codes_json, $userId]);
            } else {
                // Insert new MFA secret
                $stmt = $conn->prepare("INSERT INTO mfa_secrets (user_id, secret_key, backup_codes) VALUES (?, ?, ?)");
                $stmt->execute([$userId, $totp_secret, $backup_codes_json]);
            }
            
            // Generate QR Code
            $qrCode = $tfa->getQRCodeImageAsDataUri('MFA System - ' . $user['email'], $totp_secret);
            $secretKey = $totp_secret;
            
            // Send SMS verification code if phone number exists
            if (!empty($user['phone'])) {
                $smsCode = generateSMSCode();
                if (storeSMSCode($conn, $userId, $smsCode)) {
                    if (sendSMS($user['phone'], $smsCode)) {
                        $smsSent = true;
                    }
                }
            }
            
            $success = "Please set up your MFA below.";
        } else {
            $error = "User not found.";
        }
    } catch(Exception $e) {
        error_log("MFA Setup Error: " . $e->getMessage());
        $error = "MFA setup failed: " . $e->getMessage();
    }
}
// Handle email verification
elseif (isset($_GET['token'])) {
    $token = sanitizeInput($_GET['token']);
    
    try {
        $stmt = $conn->prepare("SELECT id, email, phone FROM users WHERE verification_token = ? AND email_verified = 0");
        $stmt->execute([$token]);
        
        if ($stmt->rowCount() > 0) {
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            $userId = $user['id'];
            
            // Update user as verified
            $stmt = $conn->prepare("UPDATE users SET email_verified = 1, verification_token = NULL WHERE id = ?");
            $stmt->execute([$user['id']]);
            
            // Generate TOTP secret and backup codes
            $tfa = new TwoFactorAuth('MFA System');
            $totp_secret = $tfa->createSecret();
            $backup_codes = generateBackupCodes();
            $backup_codes_json = json_encode($backup_codes);
            
            // Check if MFA secret already exists
            $stmt = $conn->prepare("SELECT id FROM mfa_secrets WHERE user_id = ?");
            $stmt->execute([$user['id']]);
            
            if ($stmt->rowCount() > 0) {
                // Update existing MFA secret
                $stmt = $conn->prepare("UPDATE mfa_secrets SET secret_key = ?, backup_codes = ? WHERE user_id = ?");
                $stmt->execute([$totp_secret, $backup_codes_json, $user['id']]);
            } else {
                // Insert new MFA secret
                $stmt = $conn->prepare("INSERT INTO mfa_secrets (user_id, secret_key, backup_codes) VALUES (?, ?, ?)");
                $stmt->execute([$user['id'], $totp_secret, $backup_codes_json]);
            }
            
            // Generate QR Code
            $qrCode = $tfa->getQRCodeImageAsDataUri('MFA System - ' . $user['email'], $totp_secret);
            $secretKey = $totp_secret;
            
            // Send SMS verification code if phone number exists
            if (!empty($user['phone'])) {
                $smsCode = generateSMSCode();
                if (storeSMSCode($conn, $user['id'], $smsCode)) {
                    if (sendSMS($user['phone'], $smsCode)) {
                        $smsSent = true;
                    }
                }
            }
            
            $success = "Email verified successfully! Please set up your MFA below.";
        } else {
            $error = "Invalid or expired verification token.";
        }
    } catch(Exception $e) {
        error_log("MFA Setup Error: " . $e->getMessage());
        $error = "Verification failed: " . $e->getMessage();
    }
} else {
    $error = "No verification token or setup request provided.";
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Verification - MFA System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h3 class="text-center">Email Verification</h3>
                    </div>
                    <div class="card-body">
                        <?php if ($error): ?>
                            <div class="alert alert-danger"><?php echo $error; ?></div>
                        <?php endif; ?>
                        <?php if ($success): ?>
                            <div class="alert alert-success"><?php echo $success; ?></div>
                            
                            <div class="mt-4">
                                <h5>Set up Two-Factor Authentication</h5>
                                
                                <!-- TOTP Setup -->
                                <div class="mb-4">
                                    <h6>Option 1: Authenticator App</h6>
                                    <p>1. Install an authenticator app on your phone (like Google Authenticator or Microsoft Authenticator)</p>
                                    <p>2. Scan this QR code with your authenticator app:</p>
                                    <div class="text-center mb-3">
                                        <?php if ($qrCode): ?>
                                            <img src="<?php echo $qrCode; ?>" alt="QR Code">
                                        <?php else: ?>
                                            <div class="alert alert-warning">QR Code generation failed. Please try again.</div>
                                        <?php endif; ?>
                                    </div>
                                    <p>3. Or manually enter this secret key in your authenticator app:</p>
                                    <div class="alert alert-info">
                                        <code><?php echo $secretKey; ?></code>
                                    </div>
                                </div>

                                <!-- SMS Setup -->
                                <?php if ($smsSent): ?>
                                <div class="mb-4">
                                    <h6>Option 2: SMS Verification</h6>
                                    <p>A verification code has been sent to your phone number. You can use this code for future logins.</p>
                                    <div class="alert alert-info">
                                        <p>Please save this code securely. You'll need it for future logins.</p>
                                    </div>
                                    <?php if ($userId): ?>
                                    <div class="text-center mt-3">
                                        <form method="POST" action="">
                                            <input type="hidden" name="user_id" value="<?php echo $userId; ?>">
                                            <input type="hidden" name="resend_sms" value="1">
                                            <button type="submit" class="btn btn-link">Resend SMS Code</button>
                                        </form>
                                    </div>
                                    <?php endif; ?>
                                </div>
                                <?php endif; ?>

                                <p>After setting up your preferred method, click the button below to go to login:</p>
                                <div class="text-center">
                                    <a href="login.php" class="btn btn-primary">Go to Login</a>
                                </div>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>