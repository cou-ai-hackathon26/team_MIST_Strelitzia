<?php $host = gethostname(); ?>
<!doctype html>
<html><head><meta charset="utf-8"><title>Bank Portal</title>
<style>body{font-family:system-ui,sans-serif;max-width:640px;margin:3rem auto;color:#123}header{border-bottom:2px solid #0a5;padding-bottom:.5rem}</style>
</head><body>
<header><h1>Bank Portal</h1><small>Internet banking &middot; <?= htmlspecialchars($host) ?></small></header>
<p>Welcome to the customer portal. Account services are available 24/7.</p>
<ul>
  <li><a href="/upload.php">Upload KYC documents</a></li>
</ul>
<footer><small>PHP <?= PHP_VERSION ?></small></footer>
</body></html>
