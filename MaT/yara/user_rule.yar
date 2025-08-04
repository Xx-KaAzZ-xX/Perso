rule user_rules
{
    strings:
        // Définition des motifs utilisés dans d'autres patterns
        //$guid_lower = /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/
        //$email_addr = /[.\-_a-zA-Z0-9]{1,80}@[a-z0-9][a-z0-9\-]{1,80}(?:\.[a-z0-9\-]{1,80})*\.[a-z]{1,10}/i
        //$email_addr = /\b[a-zA-Z0-9._%+-]{1,80}@[a-zA-Z0-9.-]{1,80}\.[a-zA-Z]{2,10}\b/i

        
        // 1. "ClientId": GUID_LOWER
        $clientid = /"\w*ClientId"\s*:\s*"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"/i
        // 2. "TenantId": GUID_LOWER
        $tenantid = /"\w*TenantId"\s*:\s*"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"/i

        // 3. ACCESS_KEY_ID = [18,200]
        $access_key_id = /ACCESS_KEY_ID\s*=\s*[^\n\s]{18,200}/i
        // 4. S3_BUCKET = [5,200]
        $s3_bucket = /S3_BUCKET\s*=\s*[^\n\s]{5,200}/i
        // 5. RDS_HOST = [5,200]
        $rds_host = /RDS_HOST\s*=\s*[^\n\s]{5,200}/i
        // 6. MLAB_URL = [5,200]
        $mlab_url = /MLAB_URL\s*=\s*[^\n\s]{5,200}/i
        // 7. MLAB_DB = [5,200]
        $mlab_db = /MLAB_DB\s*=\s*[^\n\s]{5,200}/i

        // 8. _USERNAME = ['"][5,200]
        $username_eq = /_USERNAME\s*=\s*["'][^\n\s"']{5,200}/i
        // 9. _EMAIL = ["'][5,200]
        $email_eq = /_EMAIL\s*=\s*["'][^\n\s"']{5,200}/i

        // 10. hostname foo.bar.baz
        $hostname = /hostname\s+[^\n\s"'.]+\.[^\n\s"'.]+\.[^\n\s"']+/i

        // 11. username
        $username = /username\s+[^\n\s]{5,200}/i

        // 14. MAILCHIMP_LIST_ID
        $mailchimp = /MAILCHIMP_LIST_ID\s*=\s*['"][^\n\s'"]{5,200}/i

       // 16. AWS AKIA key
        $aws_akia = /(AKIA[A-Z0-9]{16})/      // Note : le ".*" et "[^A-Z0-9][^\n]*" sont ici superflus

        // 18. _USER = ['"][5,200]
        $_user_eq = /_USER\s*=\s*["'][^\n\s"']{5,200}/i

        // Bruit à exclure
        $web_color = /#[0-9a-fA-F]{6}/
        $hex_value = /0x[0-9a-fA-F]{2}/
        $c_format = /%[nsydmv]/
        $system_prefix = /^(}|\${|!join|false$|sha1-|sha256-|sha512-|split$|string\.|this\.|true$|user\.|xml|xsi)/


    condition:
        any of them and
        not 1 of ($web_color, $hex_value, $c_format, $system_prefix)
    
}

