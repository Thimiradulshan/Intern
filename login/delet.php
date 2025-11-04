<?php
host = "localhost";user = "root";
pass = "";db = "login"; 

conn = new mysqli(host, user,pass, db);
if (conn->connect_error) {
  die("Connection failed: " . conn->connect_error);


if (_SERVER["REQUEST_METHOD"] == "POST") {
  id =_POST['id'];

  sql = "DELETE FROM members WHERE id=?";stmt = conn->prepare(sql);
  stmt->bind_param("i",id);

  if (stmt->execute()) 
    echo "Member deleted successfully.<br>";
   else 
    echo "Error: " .conn->error;
  }

  echo "<a href='dashboard.html'>Back to Dashboard</a>";
}
?>