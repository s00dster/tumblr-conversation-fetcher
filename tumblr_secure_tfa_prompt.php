#!/usr/bin/php
<?php
/**
 * tumblr_secure_tfa_prompt.php
 * Enhanced Tumblr CLI login script with:
 *   • Secure 0600 cookie file (auto-deleted)
 *   • Optional Two-Factor Authentication (2FA)
 *   • Interactive prompts for missing email/password/blog
 *   • PHP cURL-extension check
 *   • interactive conversation id prompt
 *   • conversation save option
 *
 * Usage examples:
 *   php tumblr_secure_tfa_prompt.php                     # fully interactive
 *   php tumblr_secure_tfa_prompt.php -u email -p pass -b blog
 *   php tumblr_secure_tfa_prompt.php -b blog -t 123456
 */

error_reporting(E_ALL & ~E_NOTICE & ~E_WARNING);

// 0. Verify cURL extension
if (!function_exists('curl_init')) {
    fwrite(STDERR, "ERROR: PHP cURL extension is not enabled. Please install/enable php-curl.\n");
    exit(1);
}

// 1. Global variables placeholder for cookie file
$cookieFile = '';

// 2. Parse CLI options
$options = getopt(
    'u:p:b:t:s:c:',
    ['username:', 'password:', 'blog:', 'tfa:', 'skip-ssl', 'conversation:', 'help']

);
if (isset($options['h']) || isset($options['help'])) {
    echo "\nUsage: php {$GLOBALS['argv'][0]} -b blogname [options]\n";
    echo "  -u, --username    Tumblr email (prompted if omitted)\n";
    echo "  -p, --password    Password (prompted if omitted)\n";
    echo "  -b, --blog        Blog name (without .tumblr.com)\n";
    echo "  -t, --tfa         2FA code (prompted if omitted when required)\n";
    echo "  -c			      conversation id (prompted if omitted when required)\n";
    echo "  --skip-ssl        Disable SSL verification (not recommended)\n\n";
    exit;
}

// 3. Interactive prompts for missing inputs
$blogName = $options['b'] ?? $options['blog'] ?? '';
$username = $options['u'] ?? $options['username'] ?? '';
$password = $options['p'] ?? $options['password'] ?? '';
$tfa      = $options['t'] ?? $options['tfa'] ?? '';
$conversation = $options['c'] ?? $options['conversation'] ?? '';
$skipSsl  = isset($options['s']) || isset($options['skip-ssl']);

if (empty($blogName)) {
    fwrite(STDOUT, "Enter blog name (without .tumblr.com): ");
    $blogName = trim(fgets(STDIN));
}

if (empty($username)) {
    fwrite(STDOUT, "Enter email: ");
    $username = trim(fgets(STDIN));
}

if (empty($password)) {
    if (function_exists('shell_exec')) shell_exec('stty -echo');
    fwrite(STDOUT, "Enter password: ");
    $password = trim(fgets(STDIN));
    if (function_exists('shell_exec')) shell_exec('stty echo');
    fwrite(STDOUT, "\n");
}

$blog = rtrim($blogName, ".tumblr.com") . ".tumblr.com";

// 4. Secure cookie file setup
$cookieFile = tempnam(sys_get_temp_dir(), 'tumblr_cookie_');
if ($cookieFile === false || !chmod($cookieFile, 0600)) {
    fwrite(STDERR, "ERROR: Unable to create secure cookie file.\n");
    exit(1);
}
register_shutdown_function(function() use ($cookieFile) {
    if (file_exists($cookieFile)) unlink($cookieFile);
    if (function_exists('shell_exec')) shell_exec('stty echo 2>/dev/null');
});

// 5. cURL helper
function setCurlOptions($ch, $url, $postFields = null, $headers = [], $skipSsl = false) {
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    if ($skipSsl) {
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    }
    curl_setopt($ch, CURLOPT_COOKIEFILE, $GLOBALS['cookieFile']);
    curl_setopt($ch, CURLOPT_COOKIEJAR,  $GLOBALS['cookieFile']);
    if (!empty($postFields)) {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postFields));
    }
    if (!empty($headers)) {
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    }
}

// 5a. Legacy cookie setter for conversation export compatibility
function set_curl_cookies($ch) {
    curl_setopt($ch, CURLOPT_COOKIESESSION, true);
    curl_setopt($ch, CURLOPT_COOKIEFILE,    $GLOBALS['cookieFile']);
    curl_setopt($ch, CURLOPT_COOKIEJAR,     $GLOBALS['cookieFile']);
}

// 6. Fetch API auth token
echo "Fetching auth token... ";
$ch = curl_init();
setCurlOptions($ch, 'https://www.tumblr.com/login', null, [], $skipSsl);
$response = curl_exec($ch) ?: '';
curl_close($ch);
if (!preg_match('/"API_TOKEN":"(.*?)"/', $response, $matches)) {
    fwrite(STDERR, "ERROR: Failed to extract API_TOKEN. Tumblr layout may have changed.\n");
    exit(1);
}
$authToken = $matches[1];

// 7. Send username
echo "Sending username... ";
$post = ['authentication' => 'oauth2_cookie', 'email' => $username];
$ch = curl_init();
setCurlOptions($ch, 'https://www.tumblr.com/api/v2/login/mode', $post, ["Authorization: Bearer $authToken"], $skipSsl);
curl_exec($ch);
curl_close($ch);

// 8. Send password and handle 2FA
$attempts = 0;
while (true) {
    if (++$attempts > 3) {
        fwrite(STDERR, "ERROR: Maximum login attempts exceeded.\n");
        exit(1);
    }
    echo "Sending password... ";
    $post = ['grant_type' => 'password', 'username' => $username, 'password' => $password];
    if (!empty($tfa)) {
        $post['tfa_token'] = $tfa;
    }
    $ch = curl_init();
    setCurlOptions($ch, 'https://www.tumblr.com/api/v2/oauth2/token', $post, ["Authorization: Bearer $authToken"], $skipSsl);
    $response = curl_exec($ch) ?: '';
    curl_close($ch);

    $data = json_decode($response, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        fwrite(STDERR, "ERROR: Invalid JSON response during login.\n");
        exit(1);
    }
    if (isset($data['error'])) {
        if (stripos($data['error_description'] ?? '', 'tfa_token') !== false && empty($tfa)) {
            fwrite(STDOUT, "Enter 2FA code: ");
            $tfa = trim(fgets(STDIN));
            continue;
        }
        fwrite(STDERR, "ERROR: Login failed. " . ($data['error_description'] ?? $data['error']) . "\n");
        exit(1);
    }
    echo "Login successful!\n";
    break;
}

// Re‑open cURL handle for further API calls
$ch = curl_init();
set_curl_cookies($ch, $cookieFile);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
if ($skip_ssl) {
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
}


echo "conversations, ";
$uuid = array();
$conv = array();
$next = "xxx";
$q = "https://www.tumblr.com/svc/conversations?participant=" . $blog . "&_=" . time() . "000";
while ($next != "") {
    curl_setopt($ch, CURLOPT_URL, $q);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('X-Requested-With: XMLHttpRequest'));
    curl_setopt($ch, CURLOPT_POST, false);
    $r = curl_exec($ch);
    $r = json_decode($r);
    $next = @$r->response->_links->next->href;
    foreach ($r->response->conversations as $c) {
        foreach ($c->participants as $p) {
            if ($p->name . ".tumblr.com" == $blog) {
                $uuid[$p->uuid] = $p->name;
            }
            if (($conversation == "") && ($partner != "")) {
                if ($p->name == $partner) {
                    $conversation = $c->id;
                    $uuid[$p->uuid] = $p->name;
                    break 3;
                }
            } else if (($conversation != "") && ($partner == "")) {
                if ($c->id == $conversation) {
                    $uuid[$p->uuid] = $p->name;
                    break 3;
                }
            } else if (($conversation == "") && ($partner == "")) {
                $conv[$c->id][] = $p->name;
            }
        }
    }
    $q = "https://www.tumblr.com" . $next;
}

// interactive conversation id prompt if not set in CLI
if ($conversation === '') {
    echo "done.\n\nConversations:\n";
    $menu = [];
    $i = 1;
    foreach ($conv as $id => $participants) {
        // z.B. "[1] abc123: blogname <=> username"
        echo "[$i] $id: " . implode(' <=> ', $participants) . "\n";
        $menu[$i] = $id;
        $i++;
    }

    // select till valid
    do {
        fwrite(STDOUT, "Select conversation by number: ");
        $choice = trim(fgets(STDIN));
    } while (!isset($menu[$choice]));

    $conversation = $menu[$choice];
    echo "Selected conversation ID: $conversation\n\n";
}

    // prompt for saving conversation
    fwrite(STDOUT, "Do you want to save the conversation to a file? (y/N): ");
    $answer = trim(fgets(STDIN));
    if (in_array(strtolower($answer), ['y','yes'], true)) {
        $saveToFile = true;
        $filename   = $conversation . '.txt';
        // start buffer
        ob_start();
    } else {
        $saveToFile = false;
    }



$messages = array();
$next = "xxx";
$q = "https://www.tumblr.com/svc/conversations/messages?conversation_id=" . $conversation .
     "&participant=" . $blog . "&_=" . time() . "000";
while ($next != "") {
    $t = 0;
    curl_setopt($ch, CURLOPT_URL, $q);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('X-Requested-With: XMLHttpRequest'));
    curl_setopt($ch, CURLOPT_POST, false);
    $y = 5;
    while ($y > 0) {
        $r = curl_exec($ch);
        $r = json_decode($r);
        if (is_object($r)) break;
        $y--;
        echo "retry, ";
    }
    $next = @$r->response->messages->_links->next->href;
    $r = $r->response->messages->data;
    if (!is_countable($r)) break;
    if (count($r)) foreach ($r as $i) {
        if ($t == 0) { $t = $i->ts; echo date("d/m/Y, H:i:s", (int)($t / 1000)) . ", "; }
        if ($date != "") {
            $d = date("Ymd", (int)($i->ts / 1000));
            if ((int)$d < (int)$date) break 2;
        } else $d = "";
        if (($d == "") || ($d == $date)) {
            $user = $uuid[$i->participant];
            if ($i->type == "TEXT") {
                $messages[$i->ts] = date("d/m/Y, H:i:s", (int)($i->ts / 1000)) . " " . $user . ": " . $i->message;
            } elseif ($i->type == "IMAGE") {
                $images = array();
                foreach ($i->images as $img) $images[] = $img->original_size->url;
                $messages[$i->ts] = date("d/m/Y, H:i:s", (int)($i->ts / 1000)) . " " . $user . ": " . join(" , ", $images);
            } elseif ($i->type == "POSTREF") {
                if ($i->post->post_url == "")
                    $messages[$i->ts] = date("d/m/Y, H:i:s", (int)($i->ts / 1000)) . " " . $user . ": sent a post that's no longer available.";
                else
                    $messages[$i->ts] = date("d/m/Y, H:i:s", (int)($i->ts / 1000)) . " " . $user . ": " . $i->post->post_url;
            } else {
                echo "\nUNKNOWN\n"; print_r($i);
            }
        }
    }
    $q = "https://www.tumblr.com" . $next;
    if ($rate > 0) usleep((int)(60 / $rate) * 1000000);
}
curl_close($ch);
echo "done.\n\n";

ksort($messages);
if ($file == "") {
    echo join("\n", array_values($messages)) . "\n\n";
} else {
    if (!$split) {
        file_put_contents($file, join("\n", array_values($messages)) . "\n");
    } else {
        $a = explode('.', $file); $e = (count($a) > 1) ? '.' . array_pop($a) : '';
        $m = array();
        if (count($messages)) foreach ($messages as $i => $s) {
            $m[date("Ymd", (int)($i / 1000))][] = $s;
        }
        foreach ($m as $d => $s) {
            file_put_contents(join($a) . "-" . $d . $e, join("\n", array_values($s)) . "\n");
        }
    }
}
// if save prompt was answered with yes save.
if (!empty($saveToFile) && ob_get_length() !== false) {
    $content = ob_get_clean();
    if (file_put_contents($filename, $content) === false) {
        fwrite(STDERR, "Error: Could not write to $filename\n");
        exit(1);
    }
    echo "Conversation output saved to $filename\n";
} else {
    // if no save was prompted free buffer
    if (ob_get_length() !== false) {
        ob_end_flush();
    }
}
?>
