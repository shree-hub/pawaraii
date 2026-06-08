<?php
/**
 * EDUSAAS - CORE API ENGINE
 * Production-ready backend with strict multi-tenancy enforcement.
 */

session_start();
header('Content-Type: application/json');

// Security Headers to prevent hacking (XSS, Clickjacking)
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: SAMEORIGIN");
header("X-XSS-Protection: 1; mode=block");

// =================================================================
// 1. DATABASE CONFIGURATION (Updated from your screenshot)
// =================================================================
define('DB_HOST', 'sql208.infinityfree.com'); 
define('DB_NAME', 'if0_40816749_epiz_123456_edusaas'); 
define('DB_USER', 'if0_40816749');       
define('DB_PASS', 'SMFNdtzbKf'); // <-- Type your actual password here
// =================================================================

// Connect to Database securely using PDO
try {
    $pdo = new PDO("mysql:host=".DB_HOST.";dbname=".DB_NAME.";charset=utf8mb4", DB_USER, DB_PASS);
    // Set error mode to exception to prevent leaking SQL structure to hackers
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    echo json_encode(['success' => false, 'message' => 'Database connection failed. Check credentials.']);
    exit;
}

// Utility: Clean Input to prevent SQL Injection & XSS
function clean($data) {
    return htmlspecialchars(strip_tags(trim($data)));
}

// Utility: JSON Response format
function response($success, $message, $data = []) {
    echo json_encode(['success' => $success, 'message' => $message, 'data' => $data]);
    exit;
}

// Lightweight module storage for UI CRUD screens. This avoids changing the
// existing school/users schema while still persisting records in MySQL.
function ensureAppRecordsTable($pdo) {
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS app_records (
            id INT AUTO_INCREMENT PRIMARY KEY,
            school_id INT NULL,
            module VARCHAR(60) NOT NULL,
            payload LONGTEXT NOT NULL,
            created_by INT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_module_school (module, school_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ");
}

function allowedModules() {
    return [
        'schools', 'students', 'teachers', 'attendance', 'exams',
        'fees', 'timetable', 'announcements', 'subscriptions'
    ];
}

function moduleAllowedForRole($module, $role) {
    if ($role === 'super_admin') {
        return in_array($module, ['schools', 'subscriptions', 'announcements', 'students', 'teachers', 'attendance', 'exams', 'fees', 'timetable']);
    }
    if ($role === 'school_admin') {
        return in_array($module, ['students', 'teachers', 'attendance', 'exams', 'fees', 'timetable', 'announcements']);
    }
    if ($role === 'teacher') {
        return in_array($module, ['attendance', 'exams', 'announcements']);
    }
    return false;
}

function normalizedPayload($payload) {
    if (!is_array($payload)) return [];
    unset($payload['id']);
    foreach ($payload as $key => $value) {
        if (is_string($value)) $payload[$key] = clean($value);
    }
    return $payload;
}

// Handle Requests (Supports GET and POST)
$input = json_decode(file_get_contents('php://input'), true);
$action = $_GET['action'] ?? $input['action'] ?? '';

// =================================================================
// PUBLIC ROUTES (No login required)
// =================================================================

if ($action === 'login') {
    $email = clean($input['email'] ?? '');
    $password = $input['password'] ?? '';

    if (empty($email) || empty($password)) {
        response(false, 'Email and password are required.');
    }

    // Fetch user from database
    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ? AND status = 'active'");
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    // Verify Password
    if ($user && password_verify($password, $user['password_hash'])) {
        // Prevent Session Fixation attacks
        session_regenerate_id(true); 
        
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['role'] = $user['role'];
        $_SESSION['school_id'] = $user['school_id']; // Will be NULL if it is the super_admin
        
        unset($user['password_hash']); // Never send password hash to frontend
        response(true, 'Login successful', $user);
    }
    response(false, 'Invalid credentials or inactive account.');
}

if ($action === 'logout') {
    session_destroy();
    response(true, 'Logged out successfully');
}

// =================================================================
// PROTECTED ROUTES (Login strictly required)
// =================================================================

if (!isset($_SESSION['user_id'])) {
    response(false, 'Unauthorized. Please log in.');
}

// Global User Session Variables
$user_id = $_SESSION['user_id'];
$role = $_SESSION['role'];
$school_id = $_SESSION['school_id'];

switch ($action) {
    
    // Fetch currently logged-in user profile
    case 'me':
        $stmt = $pdo->prepare("SELECT id, name, email, role, school_id FROM users WHERE id = ?");
        $stmt->execute([$user_id]);
        $userData = $stmt->fetch();
        if ($userData) {
            response(true, 'User data retrieved', $userData);
        } else {
            response(false, 'User not found');
        }
        break;

    // Fetch dashboard numbers
    case 'get_dashboard_stats':
        ensureAppRecordsTable($pdo);
        $stats = [];
        
        if ($role === 'super_admin') {
            // Super Admin sees everything
            $stats['total_schools'] = $pdo->query("SELECT COUNT(*) FROM app_records WHERE module = 'schools'")->fetchColumn();
            $stats['total_users'] = $pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
            
        } elseif ($role === 'school_admin') {
            // STRICT TENANCY: Only count data where school_id matches this user's school_id
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM app_records WHERE module = 'students' AND school_id = ?");
            $stmt->execute([$school_id]);
            $stats['total_students'] = $stmt->fetchColumn();

            $stmt = $pdo->prepare("SELECT COUNT(*) FROM app_records WHERE module = 'teachers' AND school_id = ?");
            $stmt->execute([$school_id]);
            $stats['total_teachers'] = $stmt->fetchColumn();
            
            $stats['revenue'] = 0;
        }
        response(true, 'Stats fetched successfully', $stats);
        break;

    case 'get_records':
        ensureAppRecordsTable($pdo);
        $module = clean($input['module'] ?? '');
        if (!in_array($module, allowedModules())) {
            response(false, 'Invalid module.');
        }
        if (!moduleAllowedForRole($module, $role) && !in_array($role, ['student', 'parent'])) {
            response(false, 'Access denied.');
        }

        if ($role === 'super_admin' && in_array($module, ['schools', 'subscriptions'])) {
            $stmt = $pdo->prepare("SELECT id, payload FROM app_records WHERE module = ? ORDER BY id DESC");
            $stmt->execute([$module]);
        } else {
            $stmt = $pdo->prepare("SELECT id, payload FROM app_records WHERE module = ? AND school_id <=> ? ORDER BY id DESC");
            $stmt->execute([$module, $school_id]);
        }

        $records = [];
        foreach ($stmt->fetchAll() as $row) {
            $payload = json_decode($row['payload'], true) ?: [];
            $payload['id'] = (string)$row['id'];
            $records[] = $payload;
        }
        response(true, 'Records fetched successfully', $records);
        break;

    case 'save_record':
        ensureAppRecordsTable($pdo);
        $module = clean($input['module'] ?? '');
        $id = clean($input['id'] ?? '');
        $payload = normalizedPayload($input['payload'] ?? []);

        if (!in_array($module, allowedModules())) {
            response(false, 'Invalid module.');
        }
        if (!moduleAllowedForRole($module, $role)) {
            response(false, 'Access denied.');
        }
        if (empty($payload)) {
            response(false, 'No data received.');
        }

        $recordSchoolId = ($role === 'super_admin' && in_array($module, ['schools', 'subscriptions'])) ? null : $school_id;
        $json = json_encode($payload);

        if ($id) {
            if ($role === 'super_admin' && in_array($module, ['schools', 'subscriptions'])) {
                $stmt = $pdo->prepare("UPDATE app_records SET payload = ? WHERE id = ? AND module = ?");
                $stmt->execute([$json, $id, $module]);
            } else {
                $stmt = $pdo->prepare("UPDATE app_records SET payload = ? WHERE id = ? AND module = ? AND school_id <=> ?");
                $stmt->execute([$json, $id, $module, $recordSchoolId]);
            }
            response(true, 'Record updated successfully', ['id' => $id]);
        }

        $stmt = $pdo->prepare("INSERT INTO app_records (school_id, module, payload, created_by) VALUES (?, ?, ?, ?)");
        $stmt->execute([$recordSchoolId, $module, $json, $user_id]);
        response(true, 'Record created successfully', ['id' => (string)$pdo->lastInsertId()]);
        break;

    case 'delete_record':
        ensureAppRecordsTable($pdo);
        $module = clean($input['module'] ?? '');
        $id = clean($input['id'] ?? '');

        if (!in_array($module, allowedModules()) || !$id) {
            response(false, 'Invalid delete request.');
        }
        if (!moduleAllowedForRole($module, $role)) {
            response(false, 'Access denied.');
        }

        if ($role === 'super_admin' && in_array($module, ['schools', 'subscriptions'])) {
            $stmt = $pdo->prepare("DELETE FROM app_records WHERE id = ? AND module = ?");
            $stmt->execute([$id, $module]);
        } else {
            $stmt = $pdo->prepare("DELETE FROM app_records WHERE id = ? AND module = ? AND school_id <=> ?");
            $stmt->execute([$id, $module, $school_id]);
        }
        response(true, 'Record deleted successfully');
        break;

    // Fetch the list of students for this specific school
    case 'get_students':
        if (!in_array($role, ['school_admin', 'teacher'])) {
            response(false, 'Access denied. You do not have permission.');
        }
        
        // Notice the WHERE s.school_id = ? -> This prevents cross-school data leaks!
        $stmt = $pdo->prepare("
            SELECT s.id, u.name, u.email, c.name as class_name, s.roll_number 
            FROM students s
            JOIN users u ON s.user_id = u.id
            JOIN classes c ON s.class_id = c.id
            WHERE s.school_id = ?
            ORDER BY c.name, s.roll_number
        ");
        $stmt->execute([$school_id]);
        $students = $stmt->fetchAll();
        
        response(true, 'Students fetched successfully', $students);
        break;

    // Add a new student to this specific school
    case 'add_student':
        if ($role !== 'school_admin') {
            response(false, 'Access denied. Only School Admins can add students.');
        }
        
        $name = clean($input['name'] ?? '');
        $email = clean($input['email'] ?? '');
        $class_id = clean($input['class_id'] ?? '');
        $roll = clean($input['roll_number'] ?? '');
        
        if (!$name || !$email || !$class_id || !$roll) {
            response(false, 'All fields are required.');
        }

        // Default password for all new students is "Student123!"
        $pass = password_hash('Student123!', PASSWORD_BCRYPT); 

        try {
            // Start Transaction: If user creation succeeds but student profile fails, it rolls back to prevent orphan data.
            $pdo->beginTransaction();
            
            // 1. Create the Auth User
            $stmt = $pdo->prepare("INSERT INTO users (school_id, role, name, email, password_hash) VALUES (?, 'student', ?, ?, ?)");
            $stmt->execute([$school_id, $name, $email, $pass]);
            $new_user_id = $pdo->lastInsertId();

            // 2. Create the Student Profile linked to the User
            $stmt = $pdo->prepare("INSERT INTO students (school_id, user_id, class_id, roll_number) VALUES (?, ?, ?, ?)");
            $stmt->execute([$school_id, $new_user_id, $class_id, $roll]);
            
            $pdo->commit();
            response(true, 'Student added successfully');
            
        } catch (Exception $e) {
            $pdo->rollBack();
            // MySQL error 1062 means duplicate entry (email already exists)
            if ($e->getCode() == 23000) {
                response(false, 'Error: A user with this email address already exists.');
            }
            response(false, 'An error occurred while adding the student.');
        }
        break;

    // If an unknown action is sent
    default:
        response(false, 'API Endpoint not found or unrecognized action.');
}
?>
