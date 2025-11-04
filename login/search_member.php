<?php
host = "localhost";user = "root";
pass = "";db = "club_db";

conn = new mysqli(host, user,pass, db);
if (conn->connect_error) {
  die("Connection failed: " . conn->connect_error);


if (_SERVER["REQUEST_METHOD"] == "POST") {
  search =_POST['search_term'];

  sql = "SELECT * FROM members WHERE name LIKE ? OR division LIKE ?";stmt = conn->prepare(sql);
  param = "search%";
  stmt->bind_param("ss",param, param);stmt->execute();
  result =stmt->get_result();

  echo "<h2>Search Results:</h2>";
  echo "<table border='1' cellpadding='10'>
          <tr>
            <th>Division</th>
            <th>Name</th>
            <th>Position</th>
            <th>Contact</th>
            <th>Date</th>
          </tr>";

  if (result->num_rows > 0) 
    while (row = result->fetch_assoc()) 
      echo "<tr>
              <td>row['division']}</td>
              <td>{row['name']</td>
              <td>row['position']}</td>
              <td>{row['contact']</td>
              <td>row['date']}</td>
            </tr>";
    }
  } else {
    echo "<tr><td colspan='5'>No members found.</td></tr>";
  }
  echo "</table>";
  echo "<br><a href='dashboard.html'>Back to Dashboard</a>";
}
?>