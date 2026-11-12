<?php
$a = $_GET['a'];
mysqli_query($c, "SELECT * FROM t WHERE a=$a");
