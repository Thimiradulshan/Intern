<?php
// club_app.php
// Single-file Club Management System (Admin-only) with Add / Search / Update / Delete
// Uses PDO prepared statements and simple CSRF protection.
// Edit DB settings below as needed.

session_start();

/* ---------- CONFIG ---------- */
$dbHost = 'localhost';
$dbName = 'officials_db';
$dbUser = 'root';
$dbPass = ''; // set your DB password

$dsn = "mysql:host=$dbHost;dbname=$dbName;charset=utf8mb4";
$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
];

try {
    $pdo = new PDO($dsn, $dbUser, $dbPass, $options);
} catch (Exception $e) {
    // In production, do not echo exception message
    die("Database connection failed: " . $e->getMessage());
}

/* ---------- HELPERS ---------- */
function e($s) { return htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8'); }

function generate_csrf() {
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf'];
}
function verify_csrf($token) {
    return isset($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], (string)$token);
}

function is_logged_in() {
    return !empty($_SESSION['admin_logged_in']);
}
function require_login() {
    if (!is_logged_in()) {
        header('Location: ?page=login');
        exit;
    }
}

/* ---------- INITIAL ADMIN CREATION (if no admin exists) ---------- */
// If no admin user yet, show small form to create one (secure this file after creating)
$stmt = $pdo->query("SELECT COUNT(*) FROM admins");
$adminCount = (int)$stmt->fetchColumn();

/* ---------- ROUTING ---------- */
$page = $_GET['page'] ?? 'dashboard';
$action = $_POST['action'] ?? ($_GET['action'] ?? '');

$flash = $_SESSION['flash'] ?? '';
unset($_SESSION['flash']);

/* ---------- HANDLE POSTS ---------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CREATE ADMIN (one-time) - only allowed when no admin exists
    if ($action === 'create_admin' && $adminCount === 0) {
        $u = trim($_POST['username'] ?? '');
        $p = $_POST['password'] ?? '';
        $p2 = $_POST['password2'] ?? '';
        if ($u === '' || $p === '' || $p2 === '') {
            $_SESSION['flash'] = "All fields required.";
        } elseif ($p !== $p2) {
            $_SESSION['flash'] = "Passwords do not match.";
        } else {
            $hash = password_hash($p, PASSWORD_DEFAULT);
            $ins = $pdo->prepare("INSERT INTO admins (username, password_hash) VALUES (?, ?)");
            $ins->execute([$u, $hash]);
            $_SESSION['flash'] = "Admin created. Please login.";
            header('Location: ?page=login'); exit;
        }
    }

    // LOGIN
    if ($action === 'login') {
        if (!empty($_SESSION['locked_until']) && time() < $_SESSION['locked_until']) {
            $_SESSION['flash'] = "Too many failed attempts. Try again later.";
            header('Location: ?page=login'); exit;
        }

        $u = trim($_POST['username'] ?? '');
        $p = $_POST['password'] ?? '';
        if ($u === '' || $p === '') {
            $_SESSION['flash'] = "Username and password required.";
            header('Location: ?page=login'); exit;
        }
        $stmt = $pdo->prepare("SELECT * FROM admins WHERE username = ? LIMIT 1");
        $stmt->execute([$u]);
        $admin = $stmt->fetch();
        if ($admin && password_verify($p, $admin['password_hash'])) {
            session_regenerate_id(true);
            $_SESSION['admin_logged_in'] = true;
            $_SESSION['admin_username'] = $admin['username'];
            unset($_SESSION['failed_login']);
            unset($_SESSION['locked_until']);
            header('Location: ?page=dashboard'); exit;
        } else {
            $_SESSION['failed_login'] = ($_SESSION['failed_login'] ?? 0) + 1;
            if ($_SESSION['failed_login'] >= 5) {
                $_SESSION['locked_until'] = time() + 900; // 15 minutes
            }

            
            $_SESSION['flash'] = "Invalid credentials.";
            header('Location: ?page=login'); exit;
        }
    }

    // ADD OFFICIAL
    if ($action === 'add_official') {
        require_login();
        if (!verify_csrf($_POST['csrf'] ?? '')) { $_SESSION['flash'] = "Invalid request."; header('Location: ?page=dashboard'); exit; }

        $org = trim($_POST['organization_name'] ?? '');
        $div = trim($_POST['division'] ?? '');
        $name = trim($_POST['full_name'] ?? '');
        $position = trim($_POST['position'] ?? '');
        $phone = trim($_POST['phone'] ?? '');
        $entry_date = trim($_POST['entry_date'] ?? '');

        if ($org === '' || $div === '' || $name === '' || $position === '' || $entry_date === '') {
            $_SESSION['flash'] = "Please fill required fields.";
            header('Location: ?page=dashboard'); exit;
        }
        // basic date validation YYYY-MM-DD
        if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $entry_date)) {
            $_SESSION['flash'] = "Invalid date format.";
            header('Location: ?page=dashboard'); exit;
        }

        $ins = $pdo->prepare("INSERT INTO officials (organization_name, division, full_name, position, phone, entry_date)
                              VALUES (?, ?, ?, ?, ?, ?)");
        $ins->execute([$org, $div, $name, $position, $phone, $entry_date]);
        $_SESSION['flash'] = "Official added.";
        header('Location: ?page=dashboard'); exit;
    }

    // EDIT OFFICIAL
    if ($action === 'edit_official') {
        require_login();
        if (!verify_csrf($_POST['csrf'] ?? '')) { $_SESSION['flash'] = "Invalid request."; header('Location: ?page=dashboard'); exit; }

        $id = (int)($_POST['id'] ?? 0);
        $org = trim($_POST['organization_name'] ?? '');
        $div = trim($_POST['division'] ?? '');
        $name = trim($_POST['full_name'] ?? '');
        $position = trim($_POST['position'] ?? '');
        $phone = trim($_POST['phone'] ?? '');
        $entry_date = trim($_POST['entry_date'] ?? '');

        if ($id <= 0) { $_SESSION['flash'] = "Invalid ID."; header('Location: ?page=dashboard'); exit; }
        if ($org === '' || $div === '' || $name === '' || $position === '' || $entry_date === '') {
            $_SESSION['flash'] = "Please fill required fields.";
            header("Location: ?page=edit&id=$id"); exit;
        }
        if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $entry_date)) {
            $_SESSION['flash'] = "Invalid date format.";
            header("Location: ?page=edit&id=$id"); exit;
        }

        $upd = $pdo->prepare("UPDATE officials SET organization_name=?, division=?, full_name=?, position=?, phone=?, entry_date=? WHERE id=?");
        $upd->execute([$org,$div,$name,$position,$phone,$entry_date,$id]);
        $_SESSION['flash'] = "Official updated.";
        header('Location: ?page=dashboard'); exit;
    }

    // DELETE OFFICIAL
    if ($action === 'delete_official') {
        require_login();
        if (!verify_csrf($_POST['csrf'] ?? '')) { $_SESSION['flash'] = "Invalid request."; header('Location: ?page=dashboard'); exit; }
        $id = (int)($_POST['id'] ?? 0);
        if ($id > 0) {
            $del = $pdo->prepare("DELETE FROM officials WHERE id = ?");
            $del->execute([$id]);
            $_SESSION['flash'] = "Official deleted.";
        }
        header('Location: ?page=dashboard'); exit;
    }
}

/* ---------- PAGES ---------- */
$csrf = generate_csrf();

/* Helper to fetch officials with optional search */
function fetch_officials($pdo, $q = '') {
    if ($q !== '') {
        $like = "%$q%";
        $stmt = $pdo->prepare("SELECT * FROM officials WHERE organization_name LIKE ? OR division LIKE ? OR full_name LIKE ? OR position LIKE ? ORDER BY entry_date DESC, id DESC");
        $stmt->execute([$like,$like,$like,$like]);
        return $stmt->fetchAll();
    } else {
        $stmt = $pdo->query("SELECT * FROM officials ORDER BY entry_date DESC, id DESC");
        return $stmt->fetchAll();
    }
}

/* ---------- HTML OUTPUT (simple, single file) ---------- */
?><!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Club Management System</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    /* simple CSS */
    :root{--blue:#0078d7;--dark:#004a99;--muted:#6b7280;--bg:#f4f6f9;--card:#fff;--danger:#c0392b;--ok:#0b8457;--radius:8px;--maxw:1100px;}
    *{box-sizing:border-box}body{font-family:Arial,Helvetica,sans-serif;background:var(--bg);color:#222;margin:0;padding:0}
    .wrap{max-width:var(--maxw);margin:26px auto;padding:16px}
    .card{background:var(--card);border-radius:10px;padding:16px;box-shadow:0 8px 24px rgba(16,24,40,0.06)}
    header{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
    header h1{margin:0;color:var(--dark);font-size:20px}
    .small{font-size:13px;color:var(--muted)}
    .top-actions{display:flex;gap:10px;align-items:center}
    .btn{background:var(--blue);color:#fff;padding:8px 12px;border-radius:8px;border:0;cursor:pointer}
    .btn.secondary{background:#6b7280}
    .btn.danger{background:var(--danger)}
    input[type=text], input[type=date], input[type=password], input[type=search], textarea {width:100%;padding:9px;border-radius:8px;border:1px solid #e6eef8}
    .form-row{margin-bottom:10px}
    table{width:100%;border-collapse:collapse;margin-top:12px}
    th, td{padding:10px 8px;border-bottom:1px solid #eef2f7;text-align:left}
    th{background:var(--dark);color:#fff}
    .msg{padding:8px;border-radius:8px;margin-bottom:10px}
    .msg.error{background:#fff0f0;color:var(--danger);border:1px solid #ffd6d6}
    .msg.ok{background:#f0fff6;color:var(--ok);border:1px solid #c9f7de}
    a.link{color:var(--blue);text-decoration:none}
    @media (max-width:800px){header{flex-direction:column;align-items:flex-start;gap:8px}}
  </style>
</head>
<body>
  <div class="wrap">
<?php
// Show flash if any
if ($flash) {
    $cls = strpos($flash, 'error') !== false ? 'msg error' : 'msg ok';
    echo "<div class='msg'>{e($flash)}</div>";
}

// If no admin yet, show admin creation (one-time)
if ($adminCount === 0) {
    if ($page !== 'create_admin') $page = 'create_admin';
}

if ($page === 'create_admin'):
?>
    <div class="card" style="max-width:600px;margin:0 auto">
      <h2>Create Admin (one-time)</h2>
      <p class="small">No admin account found. Create the initial admin. After creating, remove access to this page.</p>
      <?php if (!empty($_SESSION['flash'])) { echo "<div class='msg error'>".e($_SESSION['flash'])."</div>"; unset($_SESSION['flash']); } ?>
      <form method="post">
        <input type="hidden" name="action" value="create_admin">
        <div class="form-row"><label>Username</label><input type="text" name="username" required></div>
        <div class="form-row"><label>Password</label><input type="password" name="password" required></div>
        <div class="form-row"><label>Confirm Password</label><input type="password" name="password2" required></div>
        <div style="display:flex;gap:8px"><button class="btn" type="submit">Create Admin</button><a class="btn secondary" href="?page=login">Go to Login</a></div>
      </form>
    </div>
<?php
    exit;
endif;

// LOGIN PAGE
if ($page === 'login'):
?>
    <div class="card" style="max-width:520px;margin:0 auto">
      <h2>Admin Login</h2>
      <p class="small">Only admin can access this system.</p>
      <?php if (!empty($_SESSION['flash'])) { echo "<div class='msg error'>".e($_SESSION['flash'])."</div>"; unset($_SESSION['flash']); } ?>
      <form method="post">
        <input type="hidden" name="action" value="login">
        <div class="form-row"><label>Username</label><input type="text" name="username" required></div>
        <div class="form-row"><label>Password</label><input type="password" name="password" required></div>
        <div style="display:flex;gap:8px"><button class="btn" type="submit">Login</button><a class="btn secondary" href="?page=create_admin">Create Admin</a></div>
      </form>
    </div>
<?php
    exit;
endif;

// LOGOUT
if ($page === 'logout') {
    session_unset(); session_destroy();
    header('Location: ?page=login'); exit;
}

// All other pages require login
require_login();

/* ------------------- DASHBOARD ------------------- */
if ($page === 'dashboard'):

    $q = trim($_GET['q'] ?? '');
    $officials = fetch_officials($pdo, $q);
?>
    <div class="card">
      <header>
        <h1>Club Management — Dashboard</h1>
        <div class="top-actions small">
          Logged in as: <strong><?= e($_SESSION['admin_username']) ?></strong>
          <a class="btn secondary" href="?page=logout" style="margin-left:8px">Logout</a>
        </div>
      </header>

      <?php if (!empty($_SESSION['flash'])) { echo "<div class='msg ok'>".e($_SESSION['flash'])."</div>"; unset($_SESSION['flash']); } ?>

      <div style="display:flex;gap:8px;align-items:center">
        <form method="get" style="margin-right:auto"><input type="hidden" name="page" value="dashboard"><input type="search" name="q" placeholder="Search organization / name / position / division" value="<?= e($q) ?>" style="padding:8px;border-radius:8px;border:1px solid #e6eef8;width:320px"><button class="btn secondary" type="submit">Search</button></form>
        <a class="btn" href="#add" onclick="document.getElementById('add-form').style.display='block';document.getElementById('table-section').style.display='none'">+ Add Official</a>
      </div>

      <div id="table-section">
        <table>
          <thead>
            <tr><th>No</th><th>Organization</th><th>Division</th><th>Full Name</th><th>Position</th><th>Phone</th><th>Entry Date</th><th>Actions</th></tr>
          </thead>
          <tbody>
            <?php if (empty($officials)): ?>
              <tr><td colspan="8" style="text-align:center">No records found.</td></tr>
            <?php else: foreach ($officials as $i=>$o): ?>
              <tr>
                <td><?= $i+1 ?></td>
                <td><?= e($o['organization_name']) ?></td>
                <td><?= e($o['division']) ?></td>
                <td><?= e($o['full_name']) ?></td>
                <td><?= e($o['position']) ?></td>
                <td><?= e($o['phone']) ?></td>
                <td><?= e($o['entry_date']) ?></td>
                <td>
                  <a class="link" href="?page=edit&id=<?= $o['id'] ?>">Edit</a> |
                  <form method="post" style="display:inline" onsubmit="return confirm('Delete this record?');">
                    <input type="hidden" name="action" value="delete_official">
                    <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
                    <input type="hidden" name="id" value="<?= $o['id'] ?>">
                    <button class="btn danger" type="submit" style="padding:4px 8px;border-radius:6px;background:var(--danger);color:#fff;border:0;cursor:pointer">Delete</button>
                  </form>
                </td>
              </tr>
            <?php endforeach; endif; ?>
          </tbody>
        </table>
      </div>

      <!-- Add form (inline, hidden by default) -->
      <div id="add-form" style="display:none;margin-top:14px">
        <h3>Add New Official</h3>
        <form method="post">
          <input type="hidden" name="action" value="add_official">
          <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
          <div class="form-row"><label>Organization Name</label><input type="text" name="organization_name" required></div>
          <div class="form-row"><label>Division</label><input type="text" name="division" required></div>
          <div class="form-row"><label>Full Name</label><input type="text" name="full_name" required></div>
          <div class="form-row"><label>Position</label><input type="text" name="position" required></div>
          <div class="form-row"><label>Phone</label><input type="text" name="phone"></div>
          <div class="form-row"><label>Entry Date</label><input type="date" name="entry_date" required></div>
          <div style="display:flex;gap:8px"><button class="btn" type="submit">Save</button><button type="button" class="btn secondary" onclick="document.getElementById('add-form').style.display='none';document.getElementById('table-section').style.display='block'">Cancel</button></div>
        </form>
      </div>
    </div>

<?php
endif; // end dashboard

/* ------------------- EDIT PAGE ------------------- */
if ($page === 'edit') {
    $id = (int)($_GET['id'] ?? 0);
    if ($id <= 0) { header('Location: ?page=dashboard'); exit; }
    $stmt = $pdo->prepare("SELECT * FROM officials WHERE id = ?");
    $stmt->execute([$id]);
    $o = $stmt->fetch();
    if (!$o) { echo "<div class='card'><p>Record not found.</p></div>"; exit; }
    ?>

    <div class="card" style="max-width:800px;margin:0 auto">
      <h2>Edit Official</h2>
      <?php if (!empty($_SESSION['flash'])) { echo "<div class='msg error'>".e($_SESSION['flash'])."</div>"; unset($_SESSION['flash']); } ?>
      <form method="post">
        <input type="hidden" name="action" value="edit_official">
        <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
        <input type="hidden" name="id" value="<?= $o['id'] ?>">
        <div class="form-row"><label>Organization Name</label><input type="text" name="organization_name" value="<?= e($o['organization_name']) ?>" required></div>
        <div class="form-row"><label>Division</label><input type="text" name="division" value="<?= e($o['division']) ?>" required></div>
        <div class="form-row"><label>Full Name</label><input type="text" name="full_name" value="<?= e($o['full_name']) ?>" required></div>
        <div class="form-row"><label>Position</label><input type="text" name="position" value="<?= e($o['position']) ?>" required></div>
        <div class="form-row"><label>Phone</label><input type="text" name="phone" value="<?= e($o['phone']) ?>"></div>
        <div class="form-row"><label>Entry Date</label><input type="date" name="entry_date" value="<?= e($o['entry_date']) ?>" required></div>
        <div style="display:flex;gap:8px"><button class="btn" type="submit">Update</button><a class="btn secondary" href="?page=dashboard">Cancel</a></div>
      </form>
    </div>

<?php
} // end edit

?>
  </div>

  <script>
    // small UX: show add form if anchor #add present
    if (location.hash === '#add') {
      const f = document.getElementById('add-form');
      const t = document.getElementById('table-section');
      if (f && t) { f.style.display = 'block'; t.style.display = 'none'; }
    }
  </script>
</body>
</html>
