# This script is only for debian 11

## global variables
export DOMAIN="example.com"
export UUIDA=""
export UUIDB=""
export V2RAYPATH=""

## change dns
function dns() {
      ## get local machine if it is a ipv6 only server
      if (ping -c 5 1.1.1.1); then
            echo "nameserver 2606:4700:4700::64
nameserver 2606:4700:4700::6400
nameserver 2606:4700:4700:0:0:0:0:64
nameserver 2606:4700:4700:0:0:0:0:6400
nameserver 2001:67c:2b0::4
nameserver 2001:67c:2b0::6
nameserver 1.1.1.1
nameserver 8.8.8.8" >/etc/resolv.conf
      else
            echo "nameserver 2001:67c:2b0::4
nameserver 2001:67c:2b0::6
nameserver 2001:67c:27e4::64
nameserver 2001:67c:27e4::60" >/etc/resolv.conf
      fi
}

## Install packages
function installPackages() {
      echo "Installing packages..."
      apt update
      apt install -y wget curl vim tmux htop ncdu nginx git ufw mosh unzip
      apt upgrade -y
}

## create essential dir
function createLogDir() {
      echo "Creating essential directories..."
      mkdir -p /var/log/nginx
      mkdir -p /var/log/v2ray
      mkdir -p /etc/nginx/sites-enabled
      mkdir -p /etc/nginx/ssl
}

## Install v2ray-core
function installV2ray() {
      ### if v2ray already installed, exit
      if (v2ray version); then
            echo "V2ray already installed"
            return
      fi

      echo "Installing v2ray-core..."
      bash <(curl -L https://raw.githubusercontent.com/Alex222222222222/V2RayInstallScript/main/installV2ray.sh)
      ### verify v2ray install
      echo "Verifying v2ray install"
      if (v2ray version); then
            echo "v2ray install success"
      else
            echo "v2ray install failed"
            exit 1
      fi
}

## insatll acme.sh
function installAcme() {
      ### if acme already installed, exit
      if (/root/.acme.sh/acme.sh --version); then
            echo "acme.sh already installed"
            return
      fi

      ### collect email for acme.sh install
      echo "Please enter your email for acme.sh install"
      read -p "Email: " email
      echo "Installing acme.sh..."
      curl https://get.acme.sh | sh -s email=$email
      ### verify acme.sh install
      echo "Verifying acme.sh install"
      if (/root/.acme.sh/acme.sh --version); then
            echo "acme.sh install success"
      else
            echo "acme.sh install failed"
            exit 1
      fi
}

## create certificate
function createSSL() {
      ### collect cloudflare api key for acme.sh install
      echo "Please enter your cloudflare api token for acme.sh install"
      read -p "Cloudflare CF_TOKEN: " CF_TOKEN
      echo "Please enter your cloudflare account id for acme.sh install"
      read -p "Cloudflare CF_Account_ID: " CF_Account_ID
      echo "Please enter your cloudflare zone id for acme.sh install"
      read -p "Cloudflare CF_Zone_ID: " CF_Zone_ID
      export CF_Token=$CF_TOKEN
      export CF_Account_ID=$CF_Account_ID
      export CF_Zone_ID=$CF_Zone_ID
      ### collect domain for acme.sh install
      echo "Please enter your domain for acme.sh install"
      read -p "Domain: " domain
      export DOMAIN=$domain
      ### create ssl cert
      echo "Creating certificate..."
      /root/.acme.sh/acme.sh --issue --dns dns_cf -d $domain \
            --cert-file /etc/nginx/ssl/cert.pem \
            --key-file /etc/nginx/ssl/key.pem \
            --fullchain-file /etc/nginx/ssl/fullchain.pem
      ### verify acme.sh install
      echo "Verifying certificate install"
      if (/root/.acme.sh/acme.sh --list | grep $domain); then
            echo "certificate install success"
            return domain
      else
            echo "certificate install failed"
            exit 1
      fi
}

function generateConfig() {
      ### generate config variables
      uuida=$(cat /proc/sys/kernel/random/uuid)
      uuidb=$(cat /proc/sys/kernel/random/uuid)
      port=$(shuf -i 10000-65535 -n 1)
      path=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)
      export UUIDA=$uuida
      export UUIDB=$uuidb
      export V2RAYPATH=$path

      ### clear nginx config dir
      rm -rf /etc/nginx/sites-enabled/*
      ### set nginx config
      echo "Setting nginx config..."
      echo "
      server {
            listen 80;
            listen [::]:80;
            server_name $domain;
            return 301 https://\$host\$request_uri;
      }
      server {
            listen 443 ssl;
            listen [::]:443 ssl;
            ssl_certificate       /etc/nginx/ssl/fullchain.pem;
            ssl_certificate_key   /etc/nginx/ssl/key.pem;
            ssl_protocols         TLSv1 TLSv1.1 TLSv1.2;
            server_name           $domain;
            location /$path/ { # Consistent with the path of V2Ray configuration
                  if (\$http_upgrade != \"websocket\") { # Return 404 error when WebSocket upgrading negotiate failed
                        return 404;
                  }
                  proxy_redirect off;
                  proxy_pass http://127.0.0.1:$port;
                  proxy_http_version 1.1;
                  proxy_set_header Upgrade \$http_upgrade;
                  proxy_set_header Connection \"upgrade\";
                  proxy_set_header Host \$host;
            }
      }
      " >/etc/nginx/sites-enabled/$domain.conf
      ### verify nginx config
      echo "Verifying nginx config"
      if (nginx -t); then
            echo "nginx config install successfully"
      else
            echo "nginx config has problem, need to be check manually"
            exit 1
      fi

      ### set v2ray config
      echo "Setting v2ray config..."
      echo "
      {
            \"log\": {
                  \"access\": \"/var/log/v2ray/access.log\",
                  \"error\": \"/var/log/v2ray/error.log\",
                  \"loglevel\": \"warning\"
            },
            \"inbounds\": [
                  {
                        \"port\": $port,
                        \"listen\": \"127.0.0.1\",
                        \"tag\": \"vmess-in\",
                        \"protocol\": \"vmess\",
                        \"settings\": {
                              \"clients\": [
                                    {
                                          \"id\": \"$uuida\",
                                          \"alterId\": 0
                                    },
                                    {
                                          \"id\": \"$uuidb\",
                                          \"alterId\": 0
                                    }
                              ]
                        },
                        \"streamSettings\": {
                              \"network\": \"ws\",
                              \"wsSettings\": {
                                    \"path\": \"/$path/\"
                              }
                        }
                  }
            ],
            \"outbounds\": [
                  {
                        \"protocol\": \"freedom\",
                        \"settings\": {},
                        \"tag\": \"direct\"
                  },
                  {
                        \"protocol\": \"blackhole\",
                        \"settings\": {},
                        \"tag\": \"blocked\"
                  }
            ],
            \"dns\": {
                  \"servers\": [
                        \"https+local://1.1.1.1/dns-query\",
                        \"2606:4700:4700::64\",
                        \"2606:4700:4700::6400\",
                        \"2606:4700:4700:0:0:0:0:64\",
                        \"2606:4700:4700:0:0:0:0:6400\",
                        \"2001:67c:2b0::4\",
                        \"2001:67c:2b0::6\",
                        \"1.1.1.1\",
                        \"1.0.0.1\",
                        \"8.8.8.8\",
                        \"8.8.4.4\",
                        \"localhost\"
                  ]
            },
            \"routing\": {
                  \"domainStrategy\": \"AsIs\",
                  \"rules\": [
                        {
                              \"type\": \"field\",
                              \"inboundTag\": [
                                    \"vmess-in\"
                              ],
                              \"outboundTag\": \"direct\"
                        }
                  ]
            }
      }
      " >/usr/local/etc/v2ray/config.json
      ### verify v2ray config
      echo "Verifying v2ray config"
      if (v2ray test --config /usr/local/etc/v2ray/config.json); then
            echo "v2ray config install successfully"
      else
            echo "v2ray config has problem, need to be check manually"
            exit 1
      fi
}

## open ufw if it is open
function ufwOpen() {
      ufw enable
      if ! (ufw status); then
            echo "ufw is not installed, please install it manually"
      elif (ufw status | grep inactive); then
            echo "ufw is active, opening port"
            ufw allow "http"
            ufw allow "https"
            ufw allow "mosh"
            ufw allow "nginx full"
            ufw allow "ssh"
            ufw allow 80
            ufw allow 443
            ufw reload
            ufw enable
            ufw reload
      else
            echo "ufw is active, opening port"
            ufw allow "http"
            ufw allow "https"
            ufw allow "mosh"
            ufw allow "nginx full"
            ufw allow "ssh"
            ufw allow 80
            ufw allow 443
            ufw reload
      fi
}

## start systemctl for cron and v2ray and nginx
function systemdInit() {
      ## change v2ray systemd service file. The origin service file will cause permission denied to log folder
      echo "
[Unit]
Description=V2Ray Service
Documentation=https://www.v2fly.org/
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/v2ray run -config /usr/local/etc/v2ray/config.json

[Install]
WantedBy=multi-user.target
" >/etc/systemd/system/v2ray.service

      systemctl enable cron
      systemctl restart cron
      systemctl enable nginx
      systemctl restart nginx
      systemctl enable v2ray
      systemctl restart v2ray

      ## test if v2ray start successfully
      sleep 5
      if (systemctl status v2ray | grep "active (running)"); then
            echo "v2ray start successfully"
      else
            echo "v2ray start failed, please check manually"
            exit 1
      fi
}

## create fake website for GFW active detectation

## export clash config and v2ray config link to /root/config.txt
function exportConfig() {
      echo "exporting config"
      clash="
- name: a_$DOMAIN
      server: $DOMAIN
      port: 443
      type: vmess
      uuid: $UUIDA
      alterId: 0
      cipher: auto
      tls: true
      skip-cert-verify: true
      servername: $DOMAIN
      network: ws
      ws-opts:
      path: /$V2RAYPATH/
      headers:
            Host: $DOMAIN
- name: b_$DOMAIN
      server: $DOMAIN
      port: 443
      type: vmess
      uuid: $UUIDB
      alterId: 0
      cipher: auto
      tls: true
      skip-cert-verify: true
      servername: $DOMAIN
      network: ws
      ws-opts:
      path: /$V2RAYPATH/
      headers:
            Host: $DOMAIN
"

      v2rayRawA="
{
      \"v\": \"2\",
      \"ps\": \"a_$DOMAIN\",
      \"add\": \"$DOMAIN\",
      \"port\": \"443\",
      \"id\": \"$UUIDA\",
      \"aid\": \"0\",
      \"net\": \"ws\",
      \"type\": \"none\",
      \"host\": \"$DOMAIN\",
      \"path\": \"/$V2RAYPATH/\",
      \"tls\": \"tls\"
}
"
      v2rayRawB="
{
      \"v\": \"2\",
      \"ps\": \"b_$DOMAIN\",
      \"add\": \"$DOMAIN\",
      \"port\": \"443\",
      \"id\": \"$UUIDB\",
      \"aid\": \"0\",
      \"net\": \"ws\",
      \"type\": \"none\",
      \"host\": \"$DOMAIN\",
      \"path\": \"/$V2RAYPATH/\",
      \"tls\": \"tls\"
}
"
      v2rayLinkA=$(echo -n $v2rayRawA | base64 -w 0)
      v2rayLinkB=$(echo -n $v2rayRawB | base64 -w 0)
      v2rayLinkA="vmess://$v2rayLinkA"
      v2rayLinkB="vmess://$v2rayLinkB"

      echo "
      clash:
      $clash

      v2rayA:
      $v2rayLinkA

      v2rayB:
      $v2rayLinkB
      " >/root/config.txt
}

dns
installPackages
createLogDir
installV2ray
installAcme
createSSL
generateConfig
ufw
systemdInit
exportConfig
