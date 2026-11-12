<?php
$a = $_GET['a'];
$s = $pdo->prepare('SELECT * FROM t WHERE a=?');
$s->execute([$a]);
