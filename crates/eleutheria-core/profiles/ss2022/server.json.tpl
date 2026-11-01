{
  "type": "shadowsocks",
  "tag": "ss2022",
  "listen": "::",
  "listen_port": "{{port}}",
  "method": "{{param.method}}",
  "password": "{{server_key}}",
  "users": { "$each": "users", "as": "u", "do": { "name": "{{u.name}}", "password": "{{u.password}}" } }
}
