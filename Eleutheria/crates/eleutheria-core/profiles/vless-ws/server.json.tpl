{
  "type": "vless",
  "tag": "vless-ws",
  "listen": "::",
  "listen_port": "{{port}}",
  "users": { "$each": "users", "as": "u", "do": { "name": "{{u.name}}", "uuid": "{{u.uuid}}" } },
  "transport": { "type": "ws", "path": "{{ws_path}}" },
  "tls": {
    "enabled": true,
    "server_name": "{{sni}}",
    "certificate_path": "{{cert_path}}",
    "key_path": "{{key_path}}"
  }
}
