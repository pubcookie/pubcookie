#!/usr/bin/php
<?php
    $main_pass_db = '/usr/pubcookie/users.db';
    $verbose = false;
    $stdin_term = 0;
    $stdin_file = fopen('php://stdin', 'r');

    function debug ($msg) {
        global $verbose;
        if ($verbose) {
            print "debug: $msg\n";
            $f = fopen("/tmp/pubcookie-auth.log","a");
            fwrite($f, "debug: $msg\n");
            fclose($f);
        }
    }

    function authenticate ($user, $pass, $service, $pass_file = '.htpasswd', $def_crypt_type = 'DES') {
        debug("authenticate: user=$user pass=$pass service=$service pass_file=$pass_file");
        // the stuff below is just an example usage that restricts
        // user names and passwords to only alpha-numeric characters.
        if (!ctype_alnum($user)) {
            // invalid user name
            debug("$user: invalid user");
            return FALSE;
        }
        
        if (!ctype_alnum($pass)) {
            // invalid password
            debug("$pass: invalid password");
            return FALSE;
        }
        
        // get the information from the htpasswd file
        if (!file_exists($pass_file) || !is_readable($pass_file)) {
            debug("$pass_file: cannot access");
            return FALSE;
        }

        // the password file exists, open it
        $fp = fopen($pass_file, 'r');
        if (!$fp) {
            debug("$pass_file: cannot open");
            return FALSE;
        }

        while ($line = fgets($fp)){
            // for each line in the file remove line endings
            $line = preg_replace('`[\r\n]$`', '', $line);
            list($fuser, $fpass) = explode(':', $line);
            debug("pass line fuser=$fuser fpass+crypt=$fpass");

            if ($fuser != $user) {
                debug("$fuser: not for us");
                continue;
            }

            // the submitted user name matches this line
            // in the file
            $crypt_type = $def_crypt_type;
            $crypt_type_set = FALSE;
            if (preg_match('/^\{([A-Z0-9]+)\}(.*)$/', $pass, $matches)) {
                $crypt_type_set = TRUE;
                $crypt_type = $matches[1];
                $pass = $matches[2];
                debug("set crypt_type=$crypt_type pass=$pass");
            }

            switch ($crypt_type) {
                case 'DES':
                    // the salt is the first 2 characters for DES encryption
                    $salt = substr($fpass, 0, 2);
                    // use the salt to encode the submitted password
                    $test_pw = crypt($pass, $salt);
                    debug("des encryption: salt=$salt test_pw=$test_pw");
                    break;
                case 'PLAIN':
                    $test_pw = $pass;
                    debug("plain encryption: test_ps=$test_pw");
                    break;
                case 'SHA':
                case 'MD5':
                default:
                    // unsupported crypt type
                    debug("$crypt_type: unsupported crypt type");
                    return FALSE;
            }

            fclose($fp);
            if ($test_pw == $fpass || ($pass == $fpass && $crypt_type_set == FALSE)) {
                // authentication success.
                debug("auth: ok");
                return TRUE;
            } else {
                debug("auth: error");
                return FALSE;
            }
        }

        // user not found
        debug("user not found");
        return FALSE;
    }

    function read_stdin() {
        global $stdin_file;
        global $stdin_term;
        $str = '';

        while (!feof($stdin_file)) {
            $ch = fread($stdin_file, 1);
            if (ord($ch) == $stdin_term) {
                break;
            }
            $str .= $ch;
        }
        return $str;
    }

    $user = read_stdin();
    $pass = read_stdin();
    $service = read_stdin();
    $ret = authenticate($user, $pass, $service, $main_pass_db);
    exit($ret ? 0 : 1);
?>
