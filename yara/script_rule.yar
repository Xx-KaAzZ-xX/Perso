rule Detect_Potential_Malicious Script {
    meta:
        description = "Detects .onion URLs, SSH key pairs into potential malicious scripts"

    strings:
        $onion_url = /\b[a-z2-7]{16,56}\.onion\b/
        $ssh_private_key = /-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----.*?-----END (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----/s
        $ssh_public_key = /ssh-(rsa|dss|ecdsa|ed25519) [A-Za-z0-9+\/=]+/
        $ip = /\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/
        $suspicious_port = /:(4444|8080|1337)\b/
        $ssh_tunnel = /ssh.*-L|\bssh.*-R/
        $netcat = /\bnc\b.*(-l|-\-listen)/
        $socat = /\bsocat\b.*tcp/
        $stunnel = /\bstunnel\b/
        $ssh_tunnel = /ssh.*-L|\bssh.*-R/
        $netcat = /\bnc\b.*(-l|-\-listen)/
        $socat = /\bsocat\b.*tcp/
        $stunnel = /\bstunnel\b/        
        $python_socket = /socket\.(AF_INET|SOCK_STREAM|bind|connect|listen|accept)/
        $node_net = /\brequire\(['"]net['"]\)/
        $perl_socket = /use\s+IO::Socket/
        $cmd_exec = /exec\(|subprocess\.run|os\.system/
        $payload_download = /\b(curl|wget|Invoke-WebRequest)\b/
        $base64 = /base64(encode|decode)?\b/

    condition:
        $onion_url or $ssh_private_key or $ssh_public_key or $ssh_tunnel or $netcat or $socat or $stunnel or $ip or $suspicious_port or $ssh_tunnel or $netcat or $socat or $stunnel or $python_socket or $node_net or $perl_socket or $cmd_exec or $payload_download or $base64
}
