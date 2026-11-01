{
  "type": "tuic",
  "tag": "{{tag}}",
  "server": "{{host}}",
  "server_port": "{{port}}",
  "uuid": "{{uuid}}",
  "password": "{{password}}",
  "congestion_control": "bbr",
  "udp_relay_mode": "native",
  "tls": {
    "enabled": true,
    "server_name": "{{sni}}",
    "alpn": ["h3"],
    "certificate_public_key_sha256": "{{?pin_list}}"
  }
}
