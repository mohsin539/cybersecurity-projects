/*
 * REkt first-party rule pack (yaralite subset).
 * Pure signatures only -- never executed, matched inside the sandbox child.
 */

rule rekt_upx_packed {
  meta:
    author = "rekt-first-party"
    severity = "info"
  strings:
    $upx_magic = "UPX!"
    $upx_sec0 = { 55 50 58 30 }
    $upx_sec1 = { 55 50 58 31 }
  condition:
    any of them
}

rule rekt_ctf_flag_marker {
  meta:
    author = "rekt-first-party"
    severity = "info"
  strings:
    $f1 = "flag{" nocase
    $f2 = "ctf{" nocase
    $f3 = "picoCTF{"
  condition:
    any of them
}

rule rekt_base64_table {
  meta:
    author = "rekt-first-party"
    severity = "info"
  strings:
    $b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    $b64url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
  condition:
    any of them
}

rule rekt_suspicious_api_combo {
  meta:
    author = "rekt-first-party"
    severity = "note"
  strings:
    $virtAlloc = "VirtualAlloc"
    $createThread = "CreateThread"
    $loadlib = "LoadLibrary"
  condition:
    2 of them
}

rule rekt_xor_decoder_stub {
  meta:
    author = "rekt-first-party"
    severity = "note"
  strings:
    $loop = { 30 ?? 48 ff c1 48 83 f9 }
    $hint = /x(?:or|0r|0R)\s*[a-z]*key/i
  condition:
    any of them
}
