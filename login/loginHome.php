<?php
    session_start();
    if(!isset($_SESSION['user_login'])){
        header('location:login.html');
    }
?>
<a href="./logout.php">Logout</a>
<h1>Admin Dashboard</h1>