<?php
host = "localhost";user = "root";
pass = "";db = "club_db"; // DB එකේ නම

conn = new mysqli(host, user,pass, db);

if (conn->connect_error) {
  die("Connection failed: " . conn->connect_error);


if (_SERVER["REQUEST_METHOD"] == "POST") {
  division =_POST['division'];
  name =_POST['name'];
  position =_POST['position'];
  contact =_POST['contact'];
  date =_POST['date'];

  sql = "INSERT INTO members (division, name, position, contact, date) VALUES (?, ?, ?, ?, ?)";stmt = conn->prepare(sql);
  stmt->bind_param("sssss",division, name,position, contact,date);

  if (stmt->execute()) 
    echo "<script>alert('Member added successfully!'); window.location.href='dashboard.html';</script>";
   else 
    echo "Error: " .conn->error;
  }
}
?>