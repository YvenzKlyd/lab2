<?php
session_start();
require_once 'config/database.php';
require_once 'includes/functions.php';
require_once 'includes/sms_functions.php';

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = sanitizeInput($_POST['username']);
    $email = sanitizeInput($_POST['email']);
    $phone = sanitizeInput($_POST['phone']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];

    // Validate Philippine phone number
    if (!preg_match('/^\+63[0-9]{10}$/', $phone)) {
        $error = "Please enter a valid Philippine phone number starting with +63 followed by 10 digits.";
    } elseif ($password !== $confirm_password) {
        $error = "Passwords do not match!";
    } else {
        try {
            // Check if username, email, or phone already exists
            $stmt = $conn->prepare("SELECT id FROM users WHERE username = ? OR email = ? OR phone = ?");
            $stmt->execute([$username, $email, $phone]);
            
            if ($stmt->rowCount() > 0) {
                $error = "Username, email, or phone number already exists!";
            } else {
                // Generate verification token
                $verification_token = generateVerificationToken();
                
                // Insert new user
                $stmt = $conn->prepare("INSERT INTO users (username, email, phone, password, verification_token) VALUES (?, ?, ?, ?, ?)");
                $stmt->execute([$username, $email, $phone, hashPassword($password), $verification_token]);
                
                $userId = $conn->lastInsertId();
                
                // Send verification email
                $emailSent = sendVerificationEmail($email, $verification_token);
                
                // Send SMS verification code
                $smsCode = generateSMSCode();
                $smsSent = false;
                
                if (storeSMSCode($conn, $userId, $smsCode)) {
                    $smsSent = sendSMS($phone, $smsCode);
                }
                
                if ($emailSent && $smsSent) {
                    $success = "Registration successful! Please check your email and phone for verification codes.";
                } elseif ($emailSent) {
                    $success = "Registration successful! Please check your email for verification. SMS verification failed.";
                } elseif ($smsSent) {
                    $success = "Registration successful! Please check your phone for verification. Email verification failed.";
                } else {
                    $error = "Registration successful but failed to send verification codes.";
                }
            }
        } catch(PDOException $e) {
            $error = "Registration failed: " . $e->getMessage();
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - MFA System</title>
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
        .form-text {
            color: #666;
            font-size: 0.85rem;
        }
        .form-label {
            color: #182848;
            font-weight: 500;
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
    </style>
</head>
<body class="bg-light">
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h3 class="text-center">Register</h3>
                    </div>
                    <div class="card-body">
                        <?php if ($error): ?>
                            <div class="alert alert-danger"><?php echo $error; ?></div>
                        <?php endif; ?>
                        <?php if ($success): ?>
                            <div class="alert alert-success"><?php echo $success; ?></div>
                        <?php endif; ?>
                        
                        <form method="POST" action="">
                            <div class="mb-3">
                                <label for="username" class="form-label">Username</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                            <div class="mb-3">
                                <label for="email" class="form-label">Email</label>
                                <input type="email" class="form-control" id="email" name="email" required>
                            </div>
                            <div class="mb-3">
                                <label for="phone" class="form-label">Phone Number</label>
                                <input type="tel" class="form-control" id="phone" name="phone" 
                                       pattern="\+63[0-9]{10}"
                                       placeholder="+63XXXXXXXXXX"
                                       required>
                                <div class="form-text">Please enter your Philippine mobile number starting with +63 (e.g., +639123456789)</div>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Password</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <div class="mb-3">
                                <label for="confirm_password" class="form-label">Confirm Password</label>
                                <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
                            </div>
                            <div class="d-grid">
                                <button type="submit" class="btn btn-primary">Register</button>
                            </div>
                        </form>
                        <div class="text-center mt-3">
                            <p>Already have an account? <a href="login.php">Login here</a></p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html> 