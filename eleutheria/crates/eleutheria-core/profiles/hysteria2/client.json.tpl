{
  "type": "hysteria2",
  "tag": "{{tag}}",
  "server": "{{host}}",
  "server_port": "{{port}}",
  "password": "{{password}}",
  "tls": {
    "enabled": true,
    "server_name": "{{sni}}",
    "alpn": ["h3"],
    "certificate_public_key_sha256": "{{?pin_list}}"
  }
}
