<?php
mysqli_query($c, 'SELECT * FROM t WHERE a=' . intval($_GET['a']));
