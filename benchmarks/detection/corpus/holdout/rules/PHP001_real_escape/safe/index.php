<?php
mysqli_query($c, "SELECT * FROM t WHERE a='" . mysqli_real_escape_string($c, $_GET['a']) . "'");
