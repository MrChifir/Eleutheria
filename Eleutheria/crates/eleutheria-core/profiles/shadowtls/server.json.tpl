[
  {
    "type": "shadowtls",
    "tag": "shadowtls",
    "listen": "::",
    "listen_port": "{{port}}",
    "version": 3,
    "users": { "$each": "users", "as": "u", "do": { "name": "{{u.name}}", "password": "{{u.password}}" } },
    "handshake": { "server": "{{handshake_server}}", "server_port": 443 },
    "strict_mode": true,
    "detour": "shadowtls-ss"
  },
  {
    "type": "shadowsocks",
    "tag": "shadowtls-ss",
    "listen": "127.0.0.1",
    "network": "tcp",
    "method": "{{param.method}}",
    "password": "{{server_key}}",
    "users": { "$each": "users", "as": "u", "do": { "name": "{{u.name}}", "password": "{{u.password}}" } }
  }
]
