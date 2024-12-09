<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Allow CORS for API requests
if (strpos($_SERVER['REQUEST_URI'], '/api/') === 0) {
    header("Access-Control-Allow-Origin: *");
    header("Access-Control-Allow-Headers: Content-Type");
    header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
}

// Database connection details for the user
$userServername = "localhost";
$userUsername = "root";
$userPassword = "H&ptiot2024";
$userDbname = "user";

// Database connection details for the sensor
$sensorServername = "localhost";
$sensorUsername = "root";
$sensorPassword = "H&ptiot2024";
$sensorDbname = "sensor";

// Create connection to the user database
$connUser = new mysqli($userServername, $userUsername, $userPassword, $userDbname);

// Create connection to the sensor database
$connSensor = new mysqli($sensorServername, $sensorUsername, $sensorPassword, $sensorDbname);

// Check user database connection
if ($connUser->connect_error) {
    if (strpos($_SERVER['REQUEST_URI'], '/api/') === 0) {
        http_response_code(500);
        echo json_encode(["error" => "User database connection failed: " . $connUser->connect_error]);
        exit();
    } else {
        die("User database connection failed: " . $connUser->connect_error);
    }
}

// Check sensor database connection
if ($connSensor->connect_error) {
    if (strpos($_SERVER['REQUEST_URI'], '/api/') === 0) {
        http_response_code(500);
        echo json_encode(["error" => "Sensor database connection failed: " . $connSensor->connect_error]);
        exit();
    } else {
        die("Sensor database connection failed: " . $connSensor->connect_error);
    }
}

// Handle API Requests
$requestUri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$uriSegments = explode('/', trim($requestUri, '/'));

if (isset($uriSegments[0]) && $uriSegments[0] === 'api') {
    header('Content-Type: application/json');
    
    // Handle Preflight OPTIONS request
    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        http_response_code(200);
        exit();
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($uriSegments[1])) {
        $action = $uriSegments[1];
        $data = json_decode(file_get_contents('php://input'), true);

        if ($action === 'register') {
            // Registration Logic
            if (isset($data['username']) && isset($data['password'])) {
                $reg_username = $connUser->real_escape_string($data['username']);
                $reg_password = password_hash($connUser->real_escape_string($data['password']), PASSWORD_BCRYPT);

                // Check if username already exists


                $stmt = $connUser->prepare("SELECT username FROM users WHERE username = ?");
                $stmt->bind_param("s", $reg_username);
                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows > 0) {
                    echo json_encode(["error" => "Username already exists"]);
                } else {
                    // Insert new user
                    $stmt->close();
                    $stmt = $connUser->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
                    $stmt->bind_param("ss", $reg_username, $reg_password);
                    
                    if ($stmt->execute()) {
                        echo json_encode(["message" => "Registration successful"]);
                    } else {
                        http_response_code(500);
                        echo json_encode(["error" => "Registration failed: " . $stmt->error]);
                    }
                }
                $stmt->close();
            } else {
                http_response_code(400);
                echo json_encode(["error" => "Username and password are required"]);
            }
        } elseif ($action === 'login') {
            // Login Logic
            if (isset($data['username']) && isset($data['password'])) {
                $login_username = $connUser->real_escape_string($data['username']);
                $login_password = $connUser->real_escape_string($data['password']);

                $stmt = $connUser->prepare("SELECT password FROM users WHERE username = ?");
                $stmt->bind_param("s", $login_username);
                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows > 0) {
                    $stmt->bind_result($hashed_password);
                    $stmt->fetch();

                    if (password_verify($login_password, $hashed_password)) {
                        // Optionally, create a token or manage sessions
                        echo json_encode(["message" => "Login successful"]);
                    } else {
                        http_response_code(401);
                        echo json_encode(["error" => "Invalid credentials"]);
                    }
                } else {
                    http_response_code(401);
                    echo json_encode(["error" => "Invalid credentials"]);
                }
                $stmt->close();
            } else {
                http_response_code(400);
                echo json_encode(["error" => "Username and password are required"]);
            }
        } else {
            http_response_code(404);
            echo json_encode(["error" => "Invalid API action"]);
        }
    } else {
        http_response_code(405);
        echo json_encode(["error" => "Method not allowed or missing action"]);
    }
    $connUser->close();
    $connSensor->close();
    exit();
}

// Existing Web Handling Code Below
// ---------------------------------

// Handle User Registration via Web Form
if (isset($_POST['register'])) {
    if (isset($_POST['reg_username']) && isset($_POST['reg_password'])) {
        $reg_username = $connUser->real_escape_string($_POST['reg_username']);
        $reg_password = password_hash($connUser->real_escape_string($_POST['reg_password']), PASSWORD_BCRYPT);

        $stmt = $connUser->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
        $stmt->bind_param("ss", $reg_username, $reg_password);

        if ($stmt->execute()) {
            echo "<div class='alert alert-success'>Registration successful. <a href='#login'>Login here</a></div>";
        } else {
            echo "<div class='alert alert-danger'>Error: " . $stmt->error . "</div>";
        }
        $stmt->close();
    } else {
        echo "<div class='alert alert-warning'>Username and password are required for registration.</div>";
    }
}

// Handle User Login via Web Form
if (isset($_POST['login'])) {
    if (isset($_POST['login_username']) && isset($_POST['login_password'])) {
        $login_username = $connUser->real_escape_string($_POST['login_username']);
        $login_password = $connUser->real_escape_string($_POST['login_password']);

        $stmt = $connUser->prepare("SELECT password FROM users WHERE username = ?");
        $stmt->bind_param("s", $login_username);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $stmt->bind_result($hashed_password);
            $stmt->fetch();
            if (password_verify($login_password, $hashed_password)) {
                $_SESSION['username'] = $login_username;
                header("Location: index.php");
                exit();
            } else {
                echo "<div class='alert alert-danger'>Invalid password</div>";
            }
        } else {
            echo "<div class='alert alert-danger'>Username not found</div>";
        }
        $stmt->close();
    } else {
        echo "<div class='alert alert-warning'>Username and password are required for login.</div>";
    }
}

// Handle User Logout via Web Form
if (isset($_POST['logout'])) {
    session_destroy();
    header("Location: index.php");
    exit();
}
if (isset($_POST['Next'])) {
    session_destroy();
    header("Location: XENON.php");
    exit();
}

// Handle Sensor Data Submission
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['temperature1']) && isset($_POST['humidityAir1']) && isset($_POST['temperature2']) && isset($_POST['humidityAir2']) && isset($_POST['temperature3']) && isset($_POST['humidityAir3']) && isset($_POST['currentValue']) && isset($_POST['lon']) && isset($_POST['lat']) && isset($_POST['oprtime']) && isset($_POST['powerValue']) && isset($_POST['lightToggleCount']) && isset($_POST['opr_flag']) && isset($_POST['time'])) {

    // Receive data from ESP via POST
    $temperature1 = $_POST['temperature1'];
    $humidityAir1 = $_POST['humidityAir1'];
    $temperature2 = $_POST['temperature2'];
    $humidityAir2 = $_POST['humidityAir2'];
    $temperature3 = $_POST['temperature3'];
    $humidityAir3 = $_POST['humidityAir3'];
    $currentValue = $_POST['currentValue'];
    $lon = $_POST['lon'];
    $lat = $_POST['lat'];
    $oprtime = $_POST['oprtime'];
    $powerValue = $_POST['powerValue'];
    $lightToggleCount = $_POST['lightToggleCount'];
    $opr_flag = $_POST['opr_flag'];
    $time = $_POST['time'];

    // Prepare SQL query with new columns
    $stmt = $connSensor->prepare("INSERT INTO Xenon_300_Sensor_Data (nhiet_do1, do_am1, nhiet_do2, do_am2, nhiet_do3, do_am3, lon, lat, currentValue, powerValue, lightToggleCount, opr_flag, opr_time, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

    // Bind values to the query parameters
    // Ensure correct data types: 'd' for double and 's' for string
    $stmt->bind_param("ddddddddddssss", $temperature1, $humidityAir1, $temperature2, $humidityAir2, $temperature3, $humidityAir3, $lon, $lat, $currentValue, $powerValue, $lightToggleCount, $opr_flag, $oprtime, $time);

    // Execute the statement and check for success
    if ($stmt->execute()) {
        echo "<div class='alert alert-success'>New record created successfully</div>";
    } else {
        echo "<div class='alert alert-danger'>Error: " . $stmt->error . "</div>";
    }

    // Close the prepared statement
    $stmt->close();
}

// API: Get Latest Sensor Data
if ($_SERVER['REQUEST_METHOD'] == 'GET' && isset($_GET['latest'])) {
    header('Content-Type: application/json');

    // SQL query to get the latest data with new columns
    $stmt = $connSensor->prepare("SELECT nhiet_do1, do_am1, nhiet_do2, do_am2, nhiet_do3, do_am3, lon, lat, currentValue, powerValue, lightToggleCount, opr_flag, opr_time, created_at FROM Xenon_300_Sensor_Data ORDER BY created_at DESC LIMIT 1");

    $stmt->execute();
    $result_latest = $stmt->get_result();

    // Check if there's a result and return as JSON
    if ($result_latest->num_rows > 0) {
        $latest_data = $result_latest->fetch_assoc();
        echo json_encode($latest_data);
    } else {
        echo json_encode(["error" => "No data found"]);
    }
    $stmt->close();
    exit();
}

// API: Get All Sensor Data
if ($_SERVER['REQUEST_METHOD'] == 'GET' && isset($_GET['all_data'])) {
    header('Content-Type: application/json');

    // SQL query to get all data with new columns
    $stmt = $connSensor->prepare("SELECT id, nhiet_do1, do_am1, nhiet_do2, do_am2, nhiet_do3, do_am3, lon, lat, currentValue, powerValue, lightToggleCount, opr_flag, opr_time, created_at FROM Xenon_300_Sensor_Data ORDER BY created_at DESC");

    $stmt->execute();
    $result = $stmt->get_result();

    // Fetch all data and return as JSON
    $data = [];
    while ($row = $result->fetch_assoc()) {
        $data[] = $row;
    }
    echo json_encode($data);
    $stmt->close();
    exit();
}

// Close database connections
$connUser->close();
$connSensor->close();

// Check if user is logged in
$isLoggedIn = isset($_SESSION['username']);
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sensor Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="Backend/styles.css" rel="stylesheet">
</head>

<body>
    <div class="container">
        <img src="Backend/XENON.jpg" alt="">
        <?php if (!$isLoggedIn): ?>
            <div class="card">
                <div class="card-header">
                    Register
                </div>
                <div class="card-body">
                    <form method="post" action="">
                        <div class="mb-3">
                            <input type="text" name="reg_username" class="form-control" placeholder="Username" required>
                        </div>
                        <div class="mb-3">
                            <input type="password" name="reg_password" class="form-control" placeholder="Password" required>
                        </div>
                        <button type="submit" name="register" class="btn btn-primary">Register</button>
                    </form>
                    <hr>
                    <h5 id="login">Login</h5>
                    <form method="post" action="">
                        <div class="mb-3">
                            <input type="text" name="login_username" class="form-control" placeholder="Username" required>
                        </div>
                        <div class="mb-3">
                            <input type="password" name="login_password" class="form-control" placeholder="Password" required>
                        </div>
                        <button type="submit" name="login" class="btn btn-primary">Login</button>
                    </form>
                </div>
            </div>
        <?php else: ?>
            <div class="card">
                <div class="card-header">
                    Sensor Dashboard
                </div>
                <div class="sensor-data-container">
                    <div class="sensor-data">
                        <p class="label">Temperature1</p>
                        <p class="value" id="temperature1">Loading...</p>
                        <p class="unit">°C</p>
                    </div>
                    <div class="sensor-data">
                        <p class="label">Humidity1</p>
                        <p class="value" id="humidityAir1">Loading...</p>
                        <p class="unit">%</p>
                    </div>
                    <div class="sensor-data">
                        <p class="label">Temperature2</p>
                        <p class="value" id="temperature2">Loading...</p>
                        <p class="unit">°C</p>
                    </div>
                    <div class="sensor-data">
                        <p class="label">Humidity2</p>
                        <p class="value" id="humidityAir2">Loading...</p>
                        <p class="unit">%</p>
                    </div>
                    <div class="sensor-data">
                        <p class="label">Temperature3</p>
                        <p class="value" id="temperature3">Loading...</p>
                        <p class="unit">°C</p>
                    </div>
                    <div class="sensor-data">
                        <p class="label">Humidity3</p>
                        <p class="value" id="humidityAir3">Loading...</p>
                        <p class="unit">%</p>
                    </div>
                </div>
                <p class="timestamp">Last updated: <span id="timestamp">Loading...</span></p>
            </div>

            <form method="post" action="" class="mt-3">
                <button type="submit" name="logout" class="btn btn-danger">Logout</button>
                <button type="submit" name="Next" class="btn btn-danger">XENON</button>
            </form>

            <div class="card mt-4">
                <div class="card-header">
                    All Sensor Data
                </div>
                <div class="card-body">
                    <table class="table table-bordered" id="sensor-data-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Temperature1 (°C)</th>
                                <th>Humidity1 (%)</th>
                                <th>Temperature2 (°C)</th>
                                <th>Humidity2 (%)</th>
                                <th>Temperature3 (°C)</th>
                                <th>Humidity3 (%)</th>
                                <th>Longitude</th>
                                <th>Latitude</th>
                                <th>Current Value</th>
                                <th>TimeFlag</th> <!-- Added column for TimeFlag -->
                                <th>Timestamp</th>
                            </tr>
                        </thead>
                        <tbody>
                            <!-- Data will be populated here via JavaScript -->
                        </tbody>
                    </table>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <script src="Backend/script.js"></script>
</body>

</html>