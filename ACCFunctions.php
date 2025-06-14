<?php
session_start();
$conn = mysqli_connect("localhost", "root", "", "comago_marketplace");

// SIGNUP
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['submit'])) {
    // Get form values
    $FName = trim($_POST['FN']);
    $LName = trim($_POST['LN']);
    $StudCode = trim($_POST['studcode']); // Should match "stud_code"
    $Course = trim($_POST['Course']);
    $Year = trim($_POST['Year']);
    $Section = trim($_POST['sect']);
    $BirthDate = trim($_POST['BD']);
    $Gender = $_POST['gender'] ?? '';
    $Address = trim($_POST['ADD']);
    $CellNum = trim($_POST['CellNum']);
    $Email = trim($_POST['Email']);
    $Password = $_POST['PW'];
    $ConfirmPassword = $_POST['CPW'];

    // Validation: check for empty fields
    if (
        empty($FName) || empty($LName) || empty($StudCode) || empty($Course) || empty($Year) || empty($Section) ||
        empty($BirthDate) || empty($Gender) || empty($Address) || empty($CellNum) || empty($Email) ||
        empty($Password) || empty($ConfirmPassword)
    ) {
        header("Location: Signup.php?error=" . urlencode("Please fill in all fields."));
        exit();
    }

    // Password match check
    if ($Password !== $ConfirmPassword) {
        header("Location: Signup.php?error=" . urlencode("Passwords do not match."));
        exit();
    }

    // Check if email already exists
    $check_sql = "SELECT * FROM accounts WHERE Email = ?";
    $stmt = mysqli_prepare($conn, $check_sql);
    mysqli_stmt_bind_param($stmt, "s", $Email);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    if (mysqli_num_rows($result) > 0) {
        header("Location: Signup.php?error=" . urlencode("Email already registered."));
        exit();
    }

    // Insert into DB - all 13 fields except profile_image
    $insert_sql = "INSERT INTO accounts 
(stud_id, FName, LName, Course, Year, sect, BirthDate, Gender, Address, CellNum, Email, Password, ConfirmPassword)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    $stmt = mysqli_prepare($conn, $insert_sql);

    if (!$stmt) {
        die("SQL Prepare Failed: " . mysqli_error($conn));
    }
    $stmt = mysqli_prepare($conn, $insert_sql);
    mysqli_stmt_bind_param(
        $stmt,
        "sssssssssssss",
        $StudCode,
        $FName,
        $LName,
        $Course,
        $Year,
        $Section,
        $BirthDate,
        $Gender,
        $Address,
        $CellNum,
        $Email,
        $Password,
        $ConfirmPassword
    );

    if (mysqli_stmt_execute($stmt)) {
        header("Location: successfull.php");
        exit();
    } else {
        header("Location: Signup.php?error=" . urlencode("Signup failed. Please try again."));
        exit();
    }
}

// LOGIN
if ($_SERVER["REQUEST_METHOD"] == "POST" && !isset($_POST['submit'])) {
    $email = $_POST['Email'];
    $password = $_POST['Password'];

    $sql = "SELECT * FROM accounts WHERE Email = ?";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "s", $email);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    if ($user = mysqli_fetch_assoc($result)) {
        // ✅ Plain text comparison
        if ($password === $user['Password']) {
            $_SESSION['user_id'] = $user['id'] ?? $user['Email'];
            header("Location: sample_mp.php");
            exit();
        } else {
            header("Location: login.php?error=" . urlencode("Incorrect password."));
            exit();
        }
    } else {
        header("Location: login.php?error=" . urlencode("User not found."));
        exit();
    }
}

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['reset'])) {
    $email = trim($_POST['Email']);
    $cell = trim($_POST['Cell']);

    // Check if fields are empty
    if (empty($email) || empty($cell)) {
        header("Location: ForgotPassword.php?error=" . urlencode("Please fill in all fields."));
        exit();
    }

    // Check if user exists with that email and phone
    $sql = "SELECT * FROM accounts WHERE Email = ? AND CellNum = ?";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "ss", $email, $cell);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    if ($user = mysqli_fetch_assoc($result)) {
        // ✅ Identity verified – proceed to password reset
        // You could set a session to allow the next step
        $_SESSION['reset_email'] = $email;

        header("Location: ResetPassword.php"); // Create this file
        exit();
    } else {
        // ❌ No match found
        header("Location: ForgotPassword.php?error=" . urlencode("No account matches the provided email and mobile number."));
        exit();
    }
}

// Handle form submission for new items
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['image'])) {
    $uploadDir = 'uploads/';
    if (!is_dir($uploadDir))
        mkdir($uploadDir, 0755, true);


    $fileTmpPath = $_FILES['image']['tmp_name'];
    $fileName = basename($_FILES['image']['name']);
    $fileExtension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
    $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];


    if (!in_array($fileExtension, $allowedExtensions)) {
        die('Error: Only image files are allowed.');
    }


    $newFileName = uniqid('img_', true) . '.' . $fileExtension;
    $destPath = $uploadDir . $newFileName;


    if (!move_uploaded_file($fileTmpPath, $destPath)) {
        die('Error uploading image.');
    }


    $name = $_POST['name'] ?? '';
    $description = $_POST['description'] ?? '';
    $location = $_POST['location'] ?? '';
    $category = $_POST['category'] ?? '';


    $stmt = $conn->prepare("INSERT INTO products (image, name, description, location, category) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param("sssss", $destPath, $name, $description, $location, $category);


    if ($stmt->execute()) {
        echo "<script>alert('New product added successfully!');</script>";
    } else {
        echo "Error: " . $stmt->error;
    }
    $stmt->close();
}

?>