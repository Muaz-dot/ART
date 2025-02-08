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

// Process the form data
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // Validate CSRF token
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("Invalid CSRF token");
    }

    // Securely handle user input
    $firstname = htmlspecialchars($_POST['firstname']);
    $lastname = htmlspecialchars($_POST['lastname']);
    $user_id = htmlspecialchars($_POST['id']);
    $password = $_POST['password']; // Raw password from input
    $role = htmlspecialchars($_POST['role']);

    // Server-side password strength validation
    $password_pattern = '/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/';
    if (!preg_match($password_pattern, $password)) {
        die("Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, a digit, and a special character.");
    }

    // Hash the password for secure storage
    $password_hash = password_hash($password, PASSWORD_DEFAULT);

    // Check if the user already exists
    $checkUserQuery = $conn->prepare("SELECT Id FROM users WHERE Id = ?");
    $checkUserQuery->bind_param("s", $user_id);
    $checkUserQuery->execute();
    $checkUserQuery->store_result();

    if ($checkUserQuery->num_rows > 0) {
        echo "User already exists with this ID.";
        $checkUserQuery->close();
        $conn->close();
        exit;
    }
    $checkUserQuery->close();

    // Insert the new user into the database
    $insertQuery = $conn->prepare("INSERT INTO users (Firstname, Lastname, Id, Password, Type) VALUES (?, ?, ?, ?, ?)");
    $insertQuery->bind_param("sssss", $firstname, $lastname, $user_id, $password_hash, $role);

    if ($insertQuery->execute()) {
        echo "Signup successful!";
        header('Location: login.php');
        exit;
    } else {
        echo "Error: " . $insertQuery->error;
    }

    $insertQuery->close();
}

// Close the database connection
$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign up</title>
    <link rel="stylesheet" href="css/loginsignup.css">
    <script>
        // Client-side password validation
        function validatePassword() {
            const password = document.getElementById('password').value;
            const pattern = /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/;
            const message = document.getElementById('password-message');

            if (!pattern.test(password)) {
                message.textContent = "Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, a digit, and a special character.";
                message.style.color = "red";
                return false;
            } else {
                message.textContent = "Password is strong.";
                message.style.color = "green";
                return true;
            }
        }

        // Form submission handler
        function validateForm(event) {
            if (!validatePassword()) {
                event.preventDefault();
            }
        }
    </script>
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
    <div class="signup">
        <div class="signup-form" id="signupForm">
            <h2>Let's Get Started!</h2>
            <p>Add your details to continue</p>
            <form action="signup.php" method="post" onsubmit="validateForm(event)">
                <!-- CSRF Token -->
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

                <input type="text" placeholder="First Name" name="firstname" required>
                <input type="text" placeholder="Last Name" name="lastname" required>
                <input type="text" placeholder="Enter your ID" name="id" required>
                <input type="password" placeholder="Create Password" name="password" id="password" oninput="validatePassword()" required>
                <p id="password-message"></p>
                
                <label for="role" name="role">Select type</label>
                <select name="role" id="signup-role">
                    <option value="Doctor">Doctor</option>
                    <option value="Admin">Admin</option>
                    <option value="Pharmacist">Pharmacist</option>
                    <option value="Reception">Reception</option>
                    <option value="Labratory">Labratory</option>
                    <option value="Nurse">Nurse</option>
                    <option value="Patient">Patient</option>
                </select>
                <button type="submit" name="submit">Sign Up</button>
                <p>Already have an account? <a href="login.php">Log in here</a></p>
            </form>
        </div>
    </div>
    <script src="menuicon.js"></script>
</body>
</html>
