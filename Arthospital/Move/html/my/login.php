<?php 
// Database connection details
$servername = "localhost";
$username = "root";
$password = "";
$database = "form";

// Create connection
$conn = new mysqli($servername, $username, $password, $database);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Start session for CSRF token
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Process the login form
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("Invalid CSRF token");
    }

    $user_id = htmlspecialchars($_POST['id']);
    $password = $_POST['password']; // Don't hash it here, compare with the hashed password in DB
    $role = htmlspecialchars($_POST['role']);

    // Fetch user from the database
    $query = $conn->prepare("SELECT Password, Type FROM users WHERE Id = ? AND Type = ?");
    $query->bind_param("ss", $user_id, $role);
    $query->execute();
    $query->store_result();

    if ($query->num_rows === 1) {
        $query->bind_result($stored_password, $stored_role);
        $query->fetch();

        // Verify the hashed password
        if (password_verify($password, $stored_password)) {
            $_SESSION['user_id'] = $user_id;
            $_SESSION['role'] = $stored_role;

            echo "Login successful! Welcome, " . htmlspecialchars($user_id) . ".";
            // Redirect based on role
            switch ($stored_role) {
                case 'Doctor':
                    header("Location: Doctor_dashboard.php");
                    exit;
                case 'Admin':
                    header("Location: account_control.php");
                    exit;
                case 'Pharmacist':
                    header("Location: phar.php");
                    exit;
                case 'Reception':
                    header("Location: Reception_dashboard.html");
                    exit;
                case 'Labratory':
                    header("Location: lab_review.php");
                    exit;
                case 'Nurse':
                    header("Location: nurse_dashboard.php");
                    exit;
                case 'Patient':
                    header("Location: patient_dashboard.php");
                    exit;
                default:
                    echo "Invalid role.";
            }
        } else {
            echo "Invalid ID or password.";
        }
    } else {
        echo "No user found with the provided details.";
    }

    $query->close();
}

// Close the database connection
$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link rel="stylesheet" href="css/loginsignup.css">
</head>
<body>
    <header>
        <div class="navbar">
            <div class="icon">
                <h2 class="logo">ART</h2>
            </div>
            <div class="menu">
                <ul>
                    <li><a href="index.html">HOME</a></li>
                    <li><a href="service.html">SERVICE</a></li>
                    <li><a href="about.html">ABOUT US</a></li>
                    <li><a href="Contact.html">CONTACT</a></li>
                    <li><a href="login.php" class="btn btn-login">Log in</a></li>
                    <li><a href="signup.php" class="btn btn-signup">Sign up</a></li>
                </ul>
            </div>
        </div>
    </header>
    <div class="auth-buttons">
        <div class="login">
            <div class="signup-form" id="loginForm">
                <h2>Welcome Back!</h2>
                <p>Login with your details to continue</p>
                <form action="login.php" method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    <input type="text" placeholder="Enter your ID" name="id" required>
                    <input type="password" placeholder="Enter your Password" name="password" required>
                    <label for="role">Select type</label>
                    <select name="role" id="role">
                        <option value="Doctor">Doctor</option>
                        <option value="Admin">Admin</option>
                        <option value="Pharmacist">Pharmacist</option>
                        <option value="Reception">Reception</option>
                        <option value="Labratory">Labratory</option>
                        <option value="Nurse">Nurse</option>
                        <option value="Patient">Patient</option>
                    </select>
                    <button type="submit" name="submit">Login</button>
                    <p>Don't have an account? <a href="signup.php">Sign up here</a></p>
                </form>
            </div>
        </div>
    </div>
<script src="menuicon.js"></script>
</body>
</html>
