<?php
// Minimalist URL collector — PHP 7+
// Single-file app: takes a URL, validates format only (no online check),
// appends it to links.txt, wipes the file if it grows past 500 KB,
// and renders the whole list as a table with line numbers.
declare(strict_types=1);

const FILE_PATH       = __DIR__ . '/links.txt';
const MAX_URL_LENGTH  = 1000;
const MAX_FILE_SIZE   = 500 * 1024; // 500 KB

$message     = '';
$messageType = '';

// Handle a submission.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['url'])) {
    $url = trim((string) $_POST['url']);

    if ($url === '') {
        $message     = 'Please enter a URL.';
        $messageType = 'error';
    } elseif (strlen($url) > MAX_URL_LENGTH) {
        $message     = 'URL is longer than the ' . MAX_URL_LENGTH . '-character limit.';
        $messageType = 'error';
    } elseif (filter_var($url, FILTER_VALIDATE_URL) === false) {
        $message     = 'That does not look like a valid URL.';
        $messageType = 'error';
    } else {
        // If the file is already over the cap, wipe it before appending.
        if (file_exists(FILE_PATH) && filesize(FILE_PATH) > MAX_FILE_SIZE) {
            unlink(FILE_PATH);
        }
        file_put_contents(FILE_PATH, $url . PHP_EOL, FILE_APPEND | LOCK_EX);
        $message     = 'Saved.';
        $messageType = 'ok';
    }
}

// Enforce the size cap on every page load too.
if (file_exists(FILE_PATH) && filesize(FILE_PATH) > MAX_FILE_SIZE) {
    unlink(FILE_PATH);
}

// Read the current contents.
$lines = [];
if (file_exists(FILE_PATH)) {
    $raw = file(FILE_PATH, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($raw !== false) {
        $lines = $raw;
    }
}
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>links.txt</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  body {
    font: 14px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    color: #111;
    background: #fafafa;
    padding: 40px 24px 80px;
  }
  .wrap { max-width: 760px; margin: 0 auto; }
  h1 {
    font-size: 14px;
    font-weight: 600;
    letter-spacing: .04em;
    text-transform: uppercase;
    margin: 0 0 20px;
    opacity: .7;
  }
  form { display: flex; gap: 8px; margin: 0 0 24px; padding-left: 56px; }
  input[type=text] {
    flex: 1;
    padding: 8px 10px;
    border: 1px solid #d0d0d0;
    border-radius: 4px;
    background: #fff;
    color: inherit;
    font: inherit;
  }
  input[type=text]:focus { outline: 2px solid #4a90e2; outline-offset: -1px; }
  button {
    padding: 8px 14px;
    border: 1px solid #d0d0d0;
    border-radius: 4px;
    background: #fff;
    color: inherit;
    font: inherit;
    cursor: pointer;
  }
  button:hover { background: #f0f0f0; }
  .msg {
    padding: 8px 12px;
    border-radius: 4px;
    margin: 0 0 16px 56px;
    font-size: 13px;
  }
  .msg.error { background: #fdecec; color: #8a1f1f; border: 1px solid #f5c2c2; }
  .msg.ok    { background: #ecf7ee; color: #1f6a2b; border: 1px solid #c2e5c8; }
  table {
    width: 100%;
    border-collapse: collapse;
    padding-left: 56px;
  }
  thead th {
    text-align: left;
    font-weight: 600;
    font-size: 12px;
    opacity: .55;
    padding: 6px 12px;
    border-bottom: 1px solid #e3e3e3;
  }
  tbody td {
    padding: 6px 12px;
    border-bottom: 1px solid #eee;
    vertical-align: top;
    word-break: break-all;
  }
  tbody tr:hover td { background: #f5f5f5; }
  td.num {
    width: 56px;
    text-align: right;
    opacity: .45;
    user-select: none;
    padding-right: 18px;
  }
  .empty { padding-left: 56px; opacity: .5; font-style: italic; }
  .meta { padding-left: 56px; margin-top: 12px; opacity: .45; font-size: 12px; }

  @media (prefers-color-scheme: dark) {
    body { color: #eaeaea; background: #111; }
    input[type=text], button { background: #1a1a1a; border-color: #2c2c2c; color: inherit; }
    button:hover { background: #222; }
    .msg.error { background: #2a1414; color: #f4b9b9; border-color: #4a1f1f; }
    .msg.ok    { background: #102a14; color: #b9f4c4; border-color: #1f4a26; }
    thead th { border-bottom-color: #2a2a2a; }
    tbody td { border-bottom-color: #1d1d1d; }
    tbody tr:hover td { background: #181818; }
  }
</style>
</head>
<body>
  <div class="wrap">
    <h1>links.txt</h1>

    <?php if ($message !== ''): ?>
      <div class="msg <?php echo htmlspecialchars($messageType, ENT_QUOTES, 'UTF-8'); ?>">
        <?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?>
      </div>
    <?php endif; ?>

    <form method="post" action="" autocomplete="off">
      <input
        type="text"
        name="url"
        maxlength="<?php echo (int) MAX_URL_LENGTH; ?>"
        placeholder="https://example.com"
        autofocus
        required
      >
      <button type="submit">Save</button>
    </form>

    <?php if (count($lines) === 0): ?>
      <p class="empty">links.txt is empty.</p>
    <?php else: ?>
      <table>
        <thead>
          <tr><th class="num">#</th><th>URL</th></tr>
        </thead>
        <tbody>
          <?php foreach ($lines as $i => $line): ?>
            <tr>
              <td class="num"><?php echo $i + 1; ?></td>
              <td><?php echo htmlspecialchars($line, ENT_QUOTES, 'UTF-8'); ?></td>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    <?php endif; ?>

    <p class="meta">
      <?php echo count($lines); ?> entr<?php echo count($lines) === 1 ? 'y' : 'ies'; ?>
      <?php
        if (file_exists(FILE_PATH)) {
            echo ' · ' . number_format(filesize(FILE_PATH)) . ' bytes';
        }
      ?>
    </p>
  </div>
</body>
</html>