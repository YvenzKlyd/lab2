<?php
session_start();
require_once 'config/database.php';
require_once 'includes/functions.php';
require_once 'includes/sms_functions.php';
use RobThree\Auth\TwoFactorAuth;

$error = '';
$success = '';
$showMfaInfo = false;
$qrCode = '';
$secretKey = '';
$showSmsOption = false;

// Handle MFA verification
if (isset($_POST['mfa_code'])) {
    $mfa_code = sanitizeInput($_POST['mfa_code']);
    $user_id = $_SESSION['temp_user_id'] ?? null;
    
    if (!$user_id) {
        $error = "Session expired. Please login again.";
    } else {
        try {
            $stmt = $conn->prepare("SELECT m.secret_key, u.email, u.phone, u.phone_verified 
                                  FROM mfa_secrets m 
                                  JOIN users u ON m.user_id = u.id 
                                  WHERE m.user_id = ?");
            $stmt->execute([$user_id]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($result && !empty($result['secret_key'])) {
                if (verifyTOTP($result['secret_key'], $mfa_code)) {
                    $_SESSION['user_id'] = $user_id;
                    $_SESSION['mfa_required'] = false;
                    unset($_SESSION['temp_user_id']);
                    header("Location: dashboard.php");
                    exit;
                } else {
                    $error = "Invalid MFA code. Please make sure you're using the latest code from your authenticator app.";
                    $showMfaInfo = true;
                    $showSmsOption = $result['phone_verified'];
                    
                    // Generate QR code
                    $tfa = new TwoFactorAuth('MFA System');
                    $qrCode = $tfa->getQRCodeImageAsDataUri('MFA System - ' . $result['email'], $result['secret_key']);
                    $secretKey = $result['secret_key'];
                }
            } else {
                $error = "MFA setup not found. Please contact support.";
            }
        } catch(PDOException $e) {
            $error = "MFA verification failed: " . $e->getMessage();
        }
    }
}

// Handle SMS verification
if (isset($_POST['sms_code'])) {
    $sms_code = sanitizeInput($_POST['sms_code']);
    $user_id = $_SESSION['temp_user_id'] ?? null;
    
    if (!$user_id) {
        $error = "Session expired. Please login again.";
    } else {
        if (verifySMSCode($conn, $user_id, $sms_code)) {
            $_SESSION['user_id'] = $user_id;
            $_SESSION['mfa_required'] = false;
            unset($_SESSION['temp_user_id']);
            header("Location: dashboard.php");
            exit;
        } else {
            $error = "Invalid SMS code. Please try again.";
            $showSmsOption = true;
        }
    }
}

// Handle initial login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['mfa_code']) && !isset($_POST['sms_code'])) {
    $username = sanitizeInput($_POST['username']);
    $password = $_POST['password'];
    
    try {
        $stmt = $conn->prepare("SELECT id, password, email_verified, phone_verified FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user) {
            if (!$user['email_verified']) {
                $error = "Please verify your email first.";
            } elseif (verifyPassword($password, $user['password'])) {
                $_SESSION['temp_user_id'] = $user['id'];
                $_SESSION['mfa_required'] = true;
                
                // If user has verified phone, show SMS option
                if ($user['phone_verified']) {
                    $showSmsOption = true;
                    // Generate and send SMS code
                    $code = generateSMSCode();
                    if (storeSMSCode($conn, $user['id'], $code)) {
                        $stmt = $conn->prepare("SELECT phone FROM users WHERE id = ?");
                        $stmt->execute([$user['id']]);
                        $phone = $stmt->fetch(PDO::FETCH_ASSOC)['phone'];
                        if (sendSMS($phone, $code)) {
                            $success = "SMS verification code sent to your phone.";
                        }
                    }
                }
            } else {
                $error = "Invalid password.";
            }
        } else {
            $error = "User not found.";
        }
    } catch(PDOException $e) {
        $error = "Login failed: " . $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - MFA System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
        }
        .card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }
        .card:hover {
            transform: translateY(-5px);
        }
        .card-header {
            background: linear-gradient(135deg, #4b6cb7 0%, #182848 100%);
            color: white;
            border-radius: 15px 15px 0 0 !important;
            padding: 1.5rem;
        }
        .card-header h3 {
            margin: 0;
            font-weight: 600;
        }
        .card-body {
            padding: 2rem;
        }
        .form-control {
            border-radius: 8px;
            padding: 0.8rem;
            border: 1px solid #e0e0e0;
            transition: all 0.3s ease;
        }
        .form-control:focus {
            box-shadow: 0 0 0 0.2rem rgba(75, 108, 183, 0.25);
            border-color: #4b6cb7;
        }
        .btn-primary {
            background: linear-gradient(135deg, #4b6cb7 0%, #182848 100%);
            border: none;
            border-radius: 8px;
            padding: 0.8rem;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(75, 108, 183, 0.4);
        }
        .btn-link {
            color: #4b6cb7;
            text-decoration: none;
            font-weight: 500;
        }
        .btn-link:hover {
            color: #182848;
            text-decoration: underline;
        }
        .alert {
            border-radius: 8px;
            border: none;
        }
        .alert-danger {
            background-color: #ffe5e5;
            color: #d63031;
        }
        .alert-success {
            background-color: #e5f9e0;
            color: #27ae60;
        }
        .alert-info {
            background-color: #e3f2fd;
            color: #1976d2;
        }
        .form-text {
            color: #666;
            font-size: 0.85rem;
        }
        .mt-4 h5 {
            color: #182848;
            font-weight: 600;
        }
        .mt-4 p {
            color: #666;
        }
        .text-center.mt-3 p {
            color: #666;
        }
        .text-center.mt-3 a {
            color: #4b6cb7;
            font-weight: 500;
            text-decoration: none;
        }
        .text-center.mt-3 a:hover {
            color: #182848;
            text-decoration: underline;
        }
        img[alt="QR Code"] {
            max-width: 200px;
            border-radius: 8px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
    </style>
</head>
<body class="bg-light">
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h3 class="text-center">Login</h3>
                    </div>
                    <div class="card-body">
                        <?php if ($error): ?>
                            <div class="alert alert-danger"><?php echo $error; ?></div>
                        <?php endif; ?>
                        <?php if ($success): ?>
                            <div class="alert alert-success"><?php echo $success; ?></div>
                        <?php endif; ?>
                        
                        <?php if (isset($_SESSION['mfa_required']) && $_SESSION['mfa_required']): ?>
                            <?php if ($showSmsOption): ?>
                                <form method="POST" action="">
                                    <div class="mb-3">
                                        <label for="sms_code" class="form-label">Enter SMS Code</label>
                                        <input type="text" class="form-control" id="sms_code" name="sms_code" 
                                               pattern="[0-9]{6}" maxlength="6" required
                                               placeholder="Enter 6-digit code">
                                        <div class="form-text">Enter the 6-digit code sent to your phone</div>
                                    </div>
                                    <div class="d-grid">
                                        <button type="submit" class="btn btn-primary">Verify SMS</button>
                                    </div>
                                </form>
                                <div class="text-center mt-3">
                                    <form method="POST" action="">
                                        <input type="hidden" name="username" value="<?php echo $_POST['username'] ?? ''; ?>">
                                        <input type="hidden" name="password" value="<?php echo $_POST['password'] ?? ''; ?>">
                                        <button type="submit" class="btn btn-link">Resend SMS Code</button>
                                    </form>
                                </div>
                                <hr>
                                <p class="text-center">Or use authenticator app:</p>
                            <?php endif; ?>
                            
                            <form method="POST" action="">
                                <div class="mb-3">
                                    <label for="mfa_code" class="form-label">Enter MFA Code</label>
                                    <input type="text" class="form-control" id="mfa_code" name="mfa_code" 
                                           pattern="[0-9]{6}" maxlength="6" required
                                           placeholder="Enter 6-digit code">
                                    <div class="form-text">Enter the 6-digit code from your authenticator app</div>
                                </div>
                                <div class="d-grid">
                                    <button type="submit" class="btn btn-primary">Verify MFA</button>
                                </div>
                            </form>
                            
                            <?php if ($showMfaInfo): ?>
                            <div class="mt-4">
                                <h5>Need help with MFA?</h5>
                                <p>1. Make sure you're using the latest code from your authenticator app</p>
                                <p>2. If you need to set up your authenticator again, scan this QR code:</p>
                                <div class="text-center mb-3">
                                    <img src="<?php echo $qrCode; ?>" alt="QR Code">
                                </div>
                                <p>3. Or manually enter this secret key in your authenticator app:</p>
                                <div class="alert alert-info">
                                    <code><?php echo $secretKey; ?></code>
                                </div>
                            </div>
                            <?php endif; ?>
                        <?php else: ?>
                            <form method="POST" action="">
                                <div class="mb-3">
                                    <label for="username" class="form-label">Username</label>
                                    <input type="text" class="form-control" id="username" name="username" required>
                                </div>
                                <div class="mb-3">
                                    <label for="password" class="form-label">Password</label>
                                    <input type="password" class="form-control" id="password" name="password" required>
                                </div>
                                <div class="d-grid">
                                    <button type="submit" class="btn btn-primary">Login</button>
                                </div>
                            </form>
                        <?php endif; ?>
                        
                        <div class="text-center mt-3">
                            <p>Don't have an account? <a href="register.php">Register here</a></p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    // Add input validation for verification codes
    document.getElementById('mfa_code')?.addEventListener('input', function(e) {
        this.value = this.value.replace(/[^0-9]/g, '').slice(0, 6);
    });
    document.getElementById('sms_code')?.addEventListener('input', function(e) {
        this.value = this.value.replace(/[^0-9]/g, '').slice(0, 6);
    });
    </script>
</body>
</html> 