rule Leak_Password_Tokens {
    strings:
        // Hashes bcrypt : $2a$, $2b$, $2y$ ... avec 2 chiffres pour coût et 53 char [./0-9A-Za-z]
        $bcrypt_hash = /\$2[aby]?\$\d{2}\$[a-zA-Z0-9.\/]{53}/

        // Hash sha type $id$algo$salt$hash
        $sha_hash = /\$[0-9a-z]{1,2}\$[a-zA-Z0-9.\/]{1,40}\$[a-zA-Z0-9.\/]{5,}/

        // URI avec auth user:pass@
        $uri_auth = /\b[a-z]{2,10}:\/\/[^:\n]+:[^@:\n\/]+@\b/

        //email suivi d'un separateur
        $potential_creds = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\s*[:\/]\s*[a-zA-Z0-9!@#$%^&*()_+=\-]{6,}\b/

        // password = valeur (insensitive)
        $password_eq = /password\s*[=:]\s*["']?[^"'\n]{5,}/ nocase

        // password != ou == valeur entre quotes
        $password_str = /password\s+[!=]=\s*["'][^"'\n]+["']/ nocase

        // token = valeur, quelques clés usuelles
        $token_eq = /(auth[_-]?token|api[_-]?key|client[_-]?secret)\s*[=:]\s*["']?[A-Za-z0-9._\-]{10,}/ nocase

        // JSON ou structure password: "xxxxx"
        $password_json = /"password\w*"\s*[:=]\s*"[^"\n]{5,}/ nocase

        // clés diverses _key, _pass, _secret
        //$generic_key = /\b\w*(_key|_pass(word)?|_secret)\s*[=:]\s*["']?[^"'\s\n]{5,}\b/ nocase

        // AzureStorageKey et AccountKey
        $account_key = /AzureStorageKey.*AccountKey\s*=\s*[^;'"<$\n\s\\]+/ nocase

        // mysql -p password
        $mysql_pass = /mysql.{0,200}\s-p\s+[^\s]+/

        // curl -u user:pass
        $curl_userpass = /curl.{0,200}\s-u\s+[^\s]+/

        // YAML style password: xxx
        $yaml_pass = /password\s*:\s*[^\n\s'"]{5,}/ nocase

        // YAML secret_key_base
        $yaml_key = /secret_key_base\s*:\s*[^\s\n]{5,}/ nocase

        // JSON auth key
        $auth_quote = /"auth"\s*:\s*"[^"\n]{5,}/ nocase

        // Variables client secret, access key, app key
        $client_secret_kv = /CLIENT_SECRET\s*=\s*[^\s\n]{5,200}/ nocase
        $access_key_kv = /ACCESS_KEY\s*=\s*[^\s\n]{5,200}/ nocase
        $app_key_kv = /APP_KEY\s*=\s*[^\s\n]{5,200}/ nocase

        // XML Pass tags
        $xml_pass1 = /<Pass>[^<\n]{5,200}<\/Pass>/ nocase
        $xml_pass2 = /<Pass\s+[^>]+>[^<\n]{5,200}<\/Pass>/ nocase

        // JSON auth key (duplication ok)
        $json_auth = /"auth"\s*:\s*"[^"\n]{5,}/ nocase
        $json_password2 = /"\w*Password"\s*:\s*"[^"\n]{5,200}"/ nocase
        $json_passphrase = /"Passphrase"\s*:\s*"[^"\n]{5,200}"/ nocase
        $json_encrypted = /"encryptedPassword"\s*:\s*"[^"\n]{5,200}"/ nocase

        // PHP style assignment $password = 'xxx';
        $php_password = /\$\w*password\w*\s*=\s*'[^'\n]{5,200}'/ nocase
        $php_passwd = /\$\w*passwd\s*=\s*'[^'\n]{5,200}'/ nocase

        // Environnement vars _PASSWORD, _KEY
        $env_password = /\b\w*_PASSWORD\s*=\s*[^\s\n]{5,200}\b/ nocase
        $env_key = /\b\w*_KEY\s*=\s*[^\s\n]{5,200}\b/ nocase

        // Generic tokens TOKEN = 'xxxxx'
        $token_quote = /TOKEN\s*=\s*['"]\w{5,200}['"]/ nocase

        // Méthode login('user', 'pass')
        $login_call = /\.login\('[^'\n]+',\s*'[^\s\n']{5,200}'/ nocase

        // XML password structures, getbytes keys
        $password_struct = /key\s*=\s*"\w*password\w*"\s+value\s*=\s*"[^"\n]{0,200}"/ nocase
        $key_getbytes = /key\s*=\s*.*GetBytes\("[^"\n]+"\)/ nocase

        // MLAB_PASS variable
        $mlab_pass = /MLAB_PASS\s*=\s*[^\n\s]{5,200}/ nocase

        // Bruit à exclure
        $web_color = /#[0-9a-fA-F]{6}/
        $hex_value = /0x[0-9a-fA-F]{2}/
        $c_format = /%[nsydmv]/
        $system_prefix = /^(}|\${|!join|false$|sha1-|sha256-|sha512-|split$|string\.|this\.|true$|user\.|xml|xsi)/


    condition:
        any of them and
        not 1 of ($web_color, $hex_value, $c_format, $system_prefix)
}

