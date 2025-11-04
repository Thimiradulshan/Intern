<?php

    $hostname='localhost';
    $un = 'root';
    $pw = '';
    $dbname = 'login';

    $con = mysqli_connect($hostname,$un,$pw,$dbname) or die("Failed to connect with database");