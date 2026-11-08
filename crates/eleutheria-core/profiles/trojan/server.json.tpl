{
  "type": "trojan",
  "tag": "trojan",
  "listen": "::",
  "listen_port": "{{port}}",
  "users": { "$each": "users", "as": "u", "do": { "name": "{{u.name}}", "password": "{{u.password}}" } },
  "tls": {
    "enabled": true,
    "server_name": "{{sni}}",
    "certificate_path": "{{cert_path}}",
    "key_path": "{{key_path}}"
  }
}
