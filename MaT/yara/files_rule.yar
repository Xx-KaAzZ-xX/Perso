rule Detect_Files_Of_Interest {
    meta:
        description = "Detects .onion URLs, SSH key pairs"

    strings:
        $onion_url = /\b[a-z2-7]{16,56}\.onion\b/
        $ssh_private_key = /-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----.*?-----END (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----/s
        $ssh_public_key = /ssh-(rsa|dss|ecdsa|ed25519) [A-Za-z0-9+\/=]+/
        

    condition:
        filesize < 4000MB and
        $onion_url or $ssh_private_key or $ssh_public_key or $potential_creds
}
