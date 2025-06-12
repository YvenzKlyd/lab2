<?php
session_start();
require_once 'config/database.php';
require_once 'includes/functions.php';
require_once 'includes/sms_functions.php';

$error = '';
$success = '';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['phone'])) {
        // Add/Update phone number
        $phone = sanitizeInput($_POST['phone']);
        try {
            $stmt = $conn->prepare("UPDATE users SET phone = ? WHERE id = ?");
            if ($stmt->execute([$phone, $_SESSION['user_id']])) {
                // Generate and send SMS code
                $code = generateSMSCode();
                if (storeSMSCode($conn, $_SESSION['user_id'], $code) && sendSMS($phone, $code)) {
                    $success = "Verification code sent to your phone.";
                } else {
                    $error = "Failed to send verification code. Please try again.";
                }
            } else {
                $error = "Failed to update phone number.";
            }
        } catch (PDOException $e) {
            $error = "An error occurred. Please try again.";
        }
    } elseif (isset($_POST['code'])) {
        // Verify SMS code
        $code = sanitizeInput($_POST['code']);
        if (verifySMSCode($conn, $_SESSION['user_id'], $code)) {
            try {
                $stmt = $conn->prepare("UPDATE users SET phone_verified = TRUE WHERE id = ?");
                if ($stmt->execute([$_SESSION['user_id']])) {
                    $success = "Phone number verified successfully!";
                } else {
                    $error = "Failed to verify phone number.";
                }
            } catch (PDOException $e) {
                $error = "An error occurred. Please try again.";
            }
        } else {
            $error = "Invalid or expired verification code.";
        }
    }
}

// Get current phone number
try {
    $stmt = $conn->prepare("SELECT phone, phone_verified FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $error = "Failed to fetch user information.";
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Phone - MFA System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h3 class="text-center">Verify Phone Number</h3>
                    </div>
                    <div class="card-body">
                        <?php if ($error): ?>
                            <div class="alert alert-danger"><?php echo $error; ?></div>
                        <?php endif; ?>
                        <?php if ($success): ?>
                            <div class="alert alert-success"><?php echo $success; ?></div>
                        <?php endif; ?>

                        <?php if (!$user['phone_verified']): ?>
                            <?php if (!$user['phone']): ?>
                                <form method="POST" action="">
                                    <div class="mb-3">
                                        <label for="phone" class="form-label">Phone Number</label>
                                        <input type="tel" class="form-control" id="phone" name="phone" 
                                               placeholder="+1234567890" required>
                                        <div class="form-text">Enter your phone number with country code</div>
                                    </div>
                                    <div class="d-grid">
                                        <button type="submit" class="btn btn-primary">Send Verification Code</button>
                                    </div>
                                </form>
                            <?php else: ?>
                                <form method="POST" action="">
                                    <div class="mb-3">
                                        <label for="code" class="form-label">Verification Code</label>
                                        <input type="text" class="form-control" id="code" name="code" 
                                               pattern="[0-9]{6}" maxlength="6" required
                                               placeholder="Enter 6-digit code">
                                        <div class="form-text">Enter the 6-digit code sent to <?php echo $user['phone']; ?></div>
                                    </div>
                                    <div class="d-grid">
                                        <button type="submit" class="btn btn-primary">Verify Code</button>
                                    </div>
                                </form>
                                <div class="text-center mt-3">
                                    <form method="POST" action="">
                                        <input type="hidden" name="phone" value="<?php echo $user['phone']; ?>">
                                        <button type="submit" class="btn btn-link">Resend Code</button>
                                    </form>
                                </div>
                            <?php endif; ?>
                        <?php else: ?>
                            <div class="alert alert-success">
                                Your phone number <?php echo $user['phone']; ?> is verified.
                            </div>
                        <?php endif; ?>
                        
                        <div class="text-center mt-3">
                            <a href="dashboard.php" class="btn btn-link">Back to Dashboard</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    // Add input validation for verification code
    document.getElementById('code')?.addEventListener('input', function(e) {
        this.value = this.value.replace(/[^0-9]/g, '').slice(0, 6);
    });
    </script>
</body>
</html> 