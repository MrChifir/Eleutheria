[
  {
    "type": "shadowsocks",
    "tag": "{{tag}}",
    "method": "{{method}}",
    "password": "{{password}}",
    "detour": "{{tag}}-stls",
    "udp_over_tcp": true
  },
  {
    "type": "shadowtls",
    "tag": "{{tag}}-stls",
    "server": "{{host}}",
    "server_port": "{{port}}",
    "version": 3,
    "password": "{{user_password}}",
    "tls": {
      "enabled": true,
      "server_name": "{{sni}}",
      "utls": { "enabled": true, "fingerprint": "chrome" }
    }
  }
]
