<?php
/** @var string $title */
$user = $_SESSION['user'] ?? null;
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title><?= h($title) ?> · <?= h(config('app_name')) ?></title>
  <link rel="stylesheet" href="assets/style.css">
</head>
<body>
<?php if ($user !== null): ?>
<header class="topbar">
  <a class="brand" href="index.php"><?= h(config('app_name')) ?></a>
  <form method="post" action="logout.php" class="logout">
    <span class="who">Signed in as <strong><?= h($user) ?></strong></span>
    <?= csrf_field() ?>
    <button type="submit" class="link">Sign out</button>
  </form>
</header>
<?php endif; ?>
