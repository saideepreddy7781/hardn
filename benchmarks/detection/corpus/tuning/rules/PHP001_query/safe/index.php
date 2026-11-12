<?php
$s = $pdo->prepare('SELECT * FROM t WHERE a=?');
$s->execute([$_GET['a']]);
