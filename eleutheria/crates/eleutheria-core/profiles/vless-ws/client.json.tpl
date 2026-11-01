{
  "type": "vless",
  "tag": "{{tag}}",
  "server": "{{host}}",
  "server_port": "{{port}}",
  "uuid": "{{uuid}}",
  "tls": {
    "enabled": true,
    "server_name": "{{sni}}",
    "utls": { "enabled": true, "fingerprint": "chrome" }
  },
  "transport": {
    "type": "ws",
    "path": "{{ws_path}}",
    "headers": { "Host": "{{sni}}" }
  }
}
