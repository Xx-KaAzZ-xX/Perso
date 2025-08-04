rule Detect_Crypto_Elements {
    meta:
        description = "Detects Bitcoin, Litecoin, Monero addresses excluding MD5 hashes"

    strings:
        $bitcoin_legacy = /\b1[a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z0-9]{24,33}\b/
        $bitcoin_p2sh = /\b3[a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z0-9]{24,33}\b/
        $bitcoin_bech32 = /\bbc1q[a-z0-9]{38,59}\b/
        $bitcoin_taproot = /\bbc1p[a-z0-9]{58}\b/
        $bitcoin_txid = /\b[a-fA-F0-9]{64}\b/
        $monero = /\b4[0-9AB][0-9a-zA-Z]{93}\b/
        $litecoin_legacy = /\bL[a-km-zA-HJ-NP-Z1-9]*[0-9][a-km-zA-HJ-NP-Z1-9]{25,32}\b/
        $litecoin_bech32 = /\bltc1[a-z0-9]{39,59}\b/
        $privateKeyBIP38 = /\b6P[a-km-zA-HJ-NP-Z1-9]{56}\b/
        $privateKeyEscapeBIP38 = /\b6\x00P\x00([a-km-zA-HJ-NP-Z1-9]\x00){56}\b/
        $privateKeyWIFuncompressed = /\b5[a-km-zA-HJ-NP-Z1-9]{50}\b/
        $privateKeyEscapeWIFuncompressed = /\b5\x00([a-km-zA-HJ-NP-Z1-9]\x00){50}\b/
        $privateKeyWIFcompressed = /\b[KL][a-km-zA-HJ-NP-Z1-9]{51}\b/
        $privateKeyEscapeWIFcompressed = /\b[KL]\x00([a-km-zA-HJ-NP-Z1-9]\x00){51}\b/
        $privateWalletNodeBIP32 = /\bxprv[a-km-zA-HJ-NP-Z1-9]{107,108}\b/
        $privateEscapeWalletNodeBIP32 = /\bx\x00p\x00r\x00v\x00([a-km-zA-HJ-NP-Z1-9]\x00){107,108}\b/
        $publicWalletNodeBIP32 = /\bxpub[a-km-zA-HJ-NP-Z1-9]{107,108}\b/
        $publicEscapeWalletNodeBIP32 = /\bx\x00p\x00u\x00b\x00([a-km-zA-HJ-NP-Z1-9]\x00){107,108}\b/
        $ethereum_address = /\b0x[a-fA-F0-9]{40}\b/
        $ethereum_address_unicode = /\b0\x00x\x00([a-fA-F0-9]\x00){40}\b/
        $md5 = /\b[a-f0-9]{32}\b/ // Pattern for MD5 hashes

    condition:
         filesize < 4000MB and
         (
            ($bitcoin_legacy or $bitcoin_p2sh or $bitcoin_bech32 or $bitcoin_taproot or $bitcoin_txid or $monero or $litecoin_legacy or $litecoin_bech32 or
            $privateKeyBIP38 or $privateKeyEscapeBIP38 or $privateKeyWIFuncompressed or $privateKeyEscapeWIFuncompressed or
            $privateKeyWIFcompressed or $privateKeyEscapeWIFcompressed or $privateWalletNodeBIP32 or $privateEscapeWalletNodeBIP32 or
            $publicWalletNodeBIP32 or $publicEscapeWalletNodeBIP32 or $ethereum_address or $ethereum_address_unicode) and not $md5)
}
