rule Detect_Potential_Malicious_Script {
    meta:
        description = "Detects .onion URLs, SSH key pairs into potential malicious scripts"

    strings:
        $onion_url = /\b[a-z2-7]{16,56}\.onion\b/
        $ip = /\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/
        $port = /:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})\b/
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
        $onion_url or
        ($ip and $port and any of ($perl_socket, $python_socket, $payload_download, $base64, $cmd_exec, $node_net, $stunnel, $socat, $netcat, $ssh_tunnel))
}
