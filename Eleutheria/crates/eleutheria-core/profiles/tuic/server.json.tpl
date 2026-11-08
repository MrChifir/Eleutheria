{
  "type": "tuic",
  "tag": "tuic",
  "listen": "::",
  "listen_port": "{{port}}",
  "users": { "$each": "users", "as": "u", "do": { "name": "{{u.name}}", "uuid": "{{u.uuid}}", "password": "{{u.password}}" } },
  "congestion_control": "bbr",
  "tls": {
    "enabled": true,
    "server_name": "{{sni}}",
    "alpn": ["h3"],
    "certificate_path": "{{cert_path}}",
    "key_path": "{{key_path}}"
  }
}
