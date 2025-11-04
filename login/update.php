<?php
host = "localhost";user = "root";
pass = "";db = "club_db";

conn = new mysqli(host, user,pass, db);
if (conn->connect_error) 
    {
die("Connection failed: " . conn->connect_error);


if (_SERVER["REQUEST_METHOD"] == "POST") {
  id =_POST['id'];
  division =_POST['division'];
  name =_POST['name'];
  position =_POST['position'];
  contact =_POST['contact'];
  date =_POST['date'];

  sql = "UPDATE members SET division=?, name=?, position=?, contact=?, date=? WHERE id=?";stmt = conn->prepare(sql);
  stmt->bind_param("sssssi",division, name,position, contact,date, id);

  if (stmt->execute()) {
    echo "Member updated successfully.<br>";
  } else {
    echo "Error: " . $conn->error;
  }

  echo "<a href='dashboard.html'>Back to Dashboard</a>";
}
}
?>