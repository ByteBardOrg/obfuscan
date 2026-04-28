<?php
$title = htmlspecialchars($_GET["title"] ?? "Home", ENT_QUOTES, "UTF-8");
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title><?= $title ?></title></head>
<body><h1><?= $title ?></h1></body>
</html>
