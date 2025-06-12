<?php
session_start();
require_once 'config/database.php';
require_once 'includes/functions.php';

// Check if user is logged in
requireLogin();

// Get user information
try {
    $stmt = $conn->prepare("SELECT username, email FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
} catch(PDOException $e) {
    die("Error: " . $e->getMessage());
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - SA</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
        }
        .navbar {
            background: linear-gradient(135deg, #4b6cb7 0%, #182848 100%) !important;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .navbar-brand {
            font-weight: 600;
        }
        .nav-link {
            color: rgba(255,255,255,0.9) !important;
            font-weight: 500;
            transition: all 0.3s ease;
        }
        .nav-link:hover {
            color: #fff !important;
            transform: translateY(-1px);
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
        .alert {
            border-radius: 8px;
            border: none;
        }
        .alert-success {
            background-color: #e5f9e0;
            color: #27ae60;
        }
        .list-group-item {
            border: 1px solid #e0e0e0;
            border-radius: 8px !important;
            margin-bottom: 0.5rem;
            transition: all 0.3s ease;
        }
        .list-group-item:hover {
            background-color: #f8f9fa;
            transform: translateX(5px);
        }
        .list-group-item strong {
            color: #182848;
            font-weight: 600;
        }
        h5 {
            color: #182848;
            font-weight: 600;
            margin-bottom: 1.5rem;
        }
    </style>
</head>
<body class="bg-light">
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="#">Secure Authentication</a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="logout.php">Logout</a>
            </div>
        </div>
    </nav>

    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">
                        <h3 class="text-center">Welcome to your Dashboard</h3>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-success">
                            <h4>Login Successful!</h4>
                            <p>You have successfully logged in with MFA.</p>
                        </div>
                        
                        <div class="mt-4">
                            <h5>Your Account Information:</h5>
                            <ul class="list-group">
                                <li class="list-group-item">
                                    <strong>Username:</strong> <?php echo htmlspecialchars($user['username']); ?>
                                </li>
                                <li class="list-group-item">
                                    <strong>Email:</strong> <?php echo htmlspecialchars($user['email']); ?>
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html> 