<?php
$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $n = 0;
    foreach ($_FILES as $f) {
        if (is_array($f['name'])) continue;
        if ($f['error'] === UPLOAD_ERR_OK) {
            $dest = __DIR__ . '/uploads/' . bin2hex(random_bytes(8)) . '.bin';
            if (move_uploaded_file($f['tmp_name'], $dest)) $n++;
        }
    }
    $msg = "Received $n file(s).";
}
?>
<!doctype html>
<html><head><meta charset="utf-8"><title>Bank Portal - KYC upload</title></head><body>
<h1>Upload KYC documents</h1>
<?php if ($msg): ?><p><strong><?= htmlspecialchars($msg) ?></strong></p><?php endif; ?>
<form method="post" enctype="multipart/form-data">
  <input type="file" name="f"> <button type="submit">Upload</button>
</form>
<p><a href="/">Back</a></p>
</body></html>
