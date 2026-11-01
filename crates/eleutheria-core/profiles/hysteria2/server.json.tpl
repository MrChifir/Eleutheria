{
  "type": "hysteria2",
  "tag": "hysteria2",
  "listen": "::",
  "listen_port": "{{port}}",
  "users": { "$each": "users", "as": "u", "do": { "name": "{{u.name}}", "password": "{{u.password}}" } },
  "tls": {
    "enabled": true,
    "server_name": "{{sni}}",
    "alpn": ["h3"],
    "certificate_path": "{{cert_path}}",
    "key_path": "{{key_path}}"
  }
}
