{
  "type": "anytls",
  "tag": "{{tag}}",
  "server": "{{host}}",
  "server_port": "{{port}}",
  "password": "{{password}}",
  "tls": {
    "enabled": true,
    "server_name": "{{sni}}",
    "utls": { "enabled": true, "fingerprint": "chrome" },
    "certificate_public_key_sha256": "{{?pin_list}}"
  }
}
