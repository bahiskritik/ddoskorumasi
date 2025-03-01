# AlmaLinux/CentOS için Kapsamlı DDoS Koruma Sistemi

## İçindekiler
1. [Mevcut Araçların Optimizasyonu](#mevcut-araçların-optimizasyonu)
2. [Kernel Optimizasyonu](#kernel-optimizasyonu)
3. [Ağ Seviyesi Korumalar](#ağ-seviyesi-korumalar)
4. [İleri Seviye Araçlar](#i̇leri-seviye-araçlar)
5. [Uygulama Seviyesi Korumalar](#uygulama-seviyesi-korumalar)
6. [İzleme ve Uyarı Sistemi](#i̇zleme-ve-uyarı-sistemi)
7. [Otomatik Yanıt ve Kurtarma](#otomatik-yanıt-ve-kurtarma)
8. [Düzenli Bakım ve Güncellemeler](#düzenli-bakım-ve-güncellemeler)

## Mevcut Araçların Optimizasyonu

### CSF (ConfigServer Firewall) Optimizasyonu

CSF yapılandırma dosyasını açın:

```bash
nano /etc/csf/csf.conf
```

Aşağıdaki değişiklikleri yapın:

1. SYNFLOOD korumasını etkinleştirin:
```
SYNFLOOD = "1"
SYNFLOOD_RATE = "100/s"
SYNFLOOD_BURST = "150"
```

2. Bağlantı izleme limitlerini artırın:
```
CT_LIMIT = "300"
CT_INTERVAL = "30"
```

3. Bağlantı taşmalarını engelleme:
```
CONNLIMIT = "22;5,80;20,443;30"
```

4. Paket süzme ayarlarını etkinleştirin:
```
PACKET_FILTER = "1"
```

5. SYN-cookies kullanımını etkinleştirin:
```
SYNFLOOD_PROTECT = "1"
```

6. Hızlı portscanleri engelleme:
```
PORTFLOOD = "22;tcp;5;300,80;tcp;20;5,443;tcp;20;5"
```

CSF için özel DDoS tespit scriptini oluşturun:

```bash
cat > /usr/local/sbin/ddos_detect.sh << 'EOL'
#!/bin/bash
# DDoS tespit ve engelleme scripti

CONNECTIONS=$(netstat -ntu | grep ESTABLISHED | wc -l)
MAX_CONN=200

if [ $CONNECTIONS -gt $MAX_CONN ]; then
    IP_LIST=$(netstat -ntu | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -n 10)
    for IP in $(echo "$IP_LIST" | awk '$1 > 15 {print $2}'); do
        if ! grep -q "$IP" /etc/csf/csf.deny; then
            echo "$(date): $IP adresinden yüksek bağlantı - $CONNECTIONS adet" >> /var/log/ddos_suspicious.log
            csf -d $IP "Suspected DDoS - Excessive connections: $CONNECTIONS"
        fi
    done
fi
EOL

chmod +x /usr/local/sbin/ddos_detect.sh
```

Crontab'a ekleyin:
```bash
(crontab -l 2>/dev/null; echo "* * * * * /usr/local/sbin/ddos_detect.sh") | crontab -
```

### fail2ban Optimizasyonu

fail2ban için yeni bir jail oluşturun:

```bash
cat > /etc/fail2ban/jail.d/ddos-protection.conf << 'EOL'
[ddos-protection]
enabled = true
filter = ddos-protection
action = iptables-multiport[name=ddos, port="http,https", protocol=tcp]
logpath = /var/log/ddos_suspicious.log
findtime = 300
maxretry = 3
bantime = 86400
EOL
```

DDoS koruması için özel filtre oluşturun:

```bash
cat > /etc/fail2ban/filter.d/ddos-protection.conf << 'EOL'
[Definition]
failregex = ^.*: <HOST> adresinden yüksek bağlantı - \d+ adet$
ignoreregex =
EOL
```

fail2ban servisini yeniden başlatın:
```bash
systemctl restart fail2ban
```

## Kernel Optimizasyonu

Sysctl yapılandırmasını optimize edin:

```bash
cat > /etc/sysctl.d/99-ddos-protection.conf << 'EOL'
# SYN flood koruması
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096

# Zaman aşımı sürelerini azaltma
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# Bağlantı izleme tablosunu büyütme
net.netfilter.nf_conntrack_max = 1000000
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60

# IPv4 korumalarını etkinleştirme
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# TCP/IP yığını optimizasyonu
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_congestion_control = bbr
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_tw_buckets = 1440000

# IPv6 güvenlik
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOL

# Değişiklikleri hemen uygula
sysctl -p /etc/sysctl.d/99-ddos-protection.conf
```

conntrack modülünü yükleyin:
```bash
modprobe nf_conntrack
echo 'nf_conntrack' >> /etc/modules-load.d/nf_conntrack.conf
```

## Ağ Seviyesi Korumalar

### iptables ile İleri Seviye Kurallar

Özel iptables kuralları oluşturun:

```bash
cat > /usr/local/sbin/setup_iptables.sh << 'EOL'
#!/bin/bash

# Tüm önceki kuralları temizle
iptables -F
iptables -X

# Temel politikalar
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Mevcut bağlantılara izin ver
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Loopback arayüzüne izin ver
iptables -A INPUT -i lo -j ACCEPT

# Bazı yaygın DDoS vektörlerini engelle
# ICMP flood koruması
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 4 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# SYN flood koruması
iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 4 -j ACCEPT

# HTTP/HTTPS DDoS koruması
iptables -A INPUT -p tcp --dport 80 -m limit --limit 20/s --limit-burst 100 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m limit --limit 20/s --limit-burst 100 -j ACCEPT

# Port tarama koruması
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP

# Fragmente paketleri engelle
iptables -A INPUT -f -j DROP

# İzin verilen servisler
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 3/min --limit-burst 3 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

# Bağlantı limitleyici
# Her IP'den en fazla 20 yeni bağlantı/sn
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -m hashlimit --hashlimit-name http --hashlimit-upto 20/sec --hashlimit-burst 100 --hashlimit-mode srcip --hashlimit-htable-expire 300000 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -m hashlimit --hashlimit-name https --hashlimit-upto 20/sec --hashlimit-burst 100 --hashlimit-mode srcip --hashlimit-htable-expire 300000 -j ACCEPT

# UDP flood koruması
iptables -A INPUT -p udp -m limit --limit 10/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p udp -j DROP

# Log ve engelle
iptables -A INPUT -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
iptables -A INPUT -j DROP

# IPv6 için benzer kurallar
ip6tables -F
ip6tables -X
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT ACCEPT
ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 3/min --limit-burst 3 -j ACCEPT
ip6tables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
ip6tables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
ip6tables -A INPUT -j LOG --log-prefix "IP6Tables-Dropped: " --log-level 4
ip6tables -A INPUT -j DROP

# Kuralları kaydet
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
EOL

chmod +x /usr/local/sbin/setup_iptables.sh

# iptables-persistent paketini kur
dnf install -y iptables-persistent

# Kuralları uygula
/usr/local/sbin/setup_iptables.sh
```

### nftables Kullanımı (Alternatif)

nftables kurmak ve yapılandırmak için:

```bash
dnf install -y nftables

cat > /etc/nftables.conf << 'EOL'
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        
        # Mevcut bağlantılara izin ver
        ct state established,related accept
        
        # Loopback arayüzüne izin ver
        iifname lo accept
        
        # ICMP/ICMPv6 flood koruması
        ip protocol icmp limit rate 1/second burst 4 packets accept
        ip6 nexthdr icmpv6 limit rate 1/second burst 4 packets accept
        
        # SYN flood koruması
        tcp flags syn limit rate 1/second burst 4 packets accept
        
        # SSH, HTTP, HTTPS izinleri
        tcp dport ssh ct state new limit rate 3/minute burst 3 packets accept
        tcp dport {http, https} ct state new accept
        
        # Açık portlar için hashlimit koruması
        tcp dport http ct state new limit rate over 20/second drop
        tcp dport https ct state new limit rate over 20/second drop
        
        # Port tarama koruması
        tcp flags & (fin|syn|rst|ack) == fin|syn drop
        tcp flags & (fin|syn|rst|ack) == fin|rst drop
        tcp flags & (fin|syn|rst|ack) == fin|ack drop
        tcp flags & (fin|syn|rst|ack) == fin|psh|ack drop
        tcp flags & (fin|syn|rst|ack) == fin|urg|psh|ack drop
        
        # Fragmente paketleri engelle
        ip frag-off & 0x1fff != 0 drop
        
        # UDP flood koruması
        udp limit rate 10/second burst 20 packets accept
        udp drop
        
        # Loglama
        log prefix "NFTables-Dropped: "
    }
    
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOL

# nftables'ı etkinleştir ve başlat
systemctl enable nftables
systemctl start nftables
```

## İleri Seviye Araçlar

### NGINX ile Ön Koruma

NGINX kurun ve ön koruma olarak yapılandırın:

```bash
dnf install -y nginx

cat > /etc/nginx/conf.d/rate-limiting.conf << 'EOL'
# NGINX DDoS Koruma Yapılandırması

# IP başına hız sınırlama
limit_req_zone $binary_remote_addr zone=ip:10m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

# User-Agent başına hız sınırlama
limit_req_zone $http_user_agent zone=user_agent:10m rate=5r/s;

# Sunucu bloğu içine eklenmesi gereken kurallar (server {} içine)
# limit_req zone=ip burst=20 nodelay;
# limit_conn conn_limit 20;
# limit_req zone=user_agent burst=10 nodelay;
EOL

cat > /etc/nginx/conf.d/security.conf << 'EOL'
# Genel güvenlik başlıkları
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;

# Tarayıcı önbelleğini aktifleştir
add_header Cache-Control "public, max-age=31536000" always;

# Büyük istek gövdelerini engelle
client_max_body_size 10M;

# İstemci tampon boyutlarını ayarla
client_body_buffer_size 128k;
client_header_buffer_size 1k;
large_client_header_buffers 4 4k;
client_body_timeout 10;
client_header_timeout 10;

# Sunucu zaman aşımı değerlerini ayarla
send_timeout 10;
keepalive_timeout 65;
keepalive_requests 100;

# Kötü botları engelle
if ($http_user_agent ~* (scrapy|crawl|spider|bot|curl|wget)) {
    return 403;
}
EOL

# Sunucu bloğunda hız sınırlamalarını etkinleştirin
sed -i '/location \/ {/i \\tlimit_req zone=ip burst=20 nodelay;\n\tlimit_conn conn_limit 20;\n\tlimit_req zone=user_agent burst=10 nodelay;' /etc/nginx/nginx.conf

# NGINX servisini yeniden başlatın
systemctl restart nginx
```

### HAProxy ile Yük Dengeleme ve Ön Koruma

```bash
dnf install -y haproxy

cat > /etc/haproxy/haproxy.cfg << 'EOL'
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /var/lib/haproxy/stats mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

    # Performans ayarları
    maxconn 65536
    spread-checks 5
    tune.ssl.default-dh-param 2048

defaults
    log global
    mode http
    option httplog
    option dontlognull
    option forwardfor
    option http-server-close
    timeout connect 5000
    timeout client 50000
    timeout server 50000
    errorfile 400 /etc/haproxy/errors/400.http
    errorfile 403 /etc/haproxy/errors/403.http
    errorfile 408 /etc/haproxy/errors/408.http
    errorfile 500 /etc/haproxy/errors/500.http
    errorfile 502 /etc/haproxy/errors/502.http
    errorfile 503 /etc/haproxy/errors/503.http
    errorfile 504 /etc/haproxy/errors/504.http

# DDoS koruma ön ucu
frontend main
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/haproxy.pem
    mode http
    
    # ACL tanımları
    acl too_many_connections fe_conn gt 1000
    acl blacklisted_ua hdr_sub(user-agent) -i curl wget scrapy bot spider
    acl bad_headers hdr_cnt(host) gt 1
    acl invalid_host hdr_reg(host) -i ^$
    
    # DDOS koruması
    stick-table type ip size 200k expire 2m store conn_rate(10s),http_req_rate(10s),http_err_rate(20s)
    http-request track-sc0 src
    http-request deny if { sc0_conn_rate gt 200 }
    http-request deny if { sc0_http_req_rate gt 400 }
    http-request deny if { sc0_http_err_rate gt 50 }
    
    # Genel engelleme
    http-request deny if too_many_connections
    http-request deny if blacklisted_ua
    http-request deny if bad_headers
    http-request deny if invalid_host
    
    # HTTP flood koruması
    acl abuse_ua path_end .php .cgi
    acl abuse_ua url_reg .*\.(cgi|php)(\?.*)?$
    acl abuse_post method POST
    http-request deny if abuse_ua abuse_post { sc0_http_req_rate gt 10 }
    
    # HTTP başlık kontrolleri
    acl empty_ua hdr_len(user-agent) eq 0
    http-request deny if empty_ua
    
    # Yönlendirme
    default_backend web_servers

# Backend tanımı
backend web_servers
    mode http
    balance roundrobin
    option httpchk HEAD / HTTP/1.1\r\nHost:\ localhost
    server web1 127.0.0.1:8080 check
EOL

# HAProxy servisini yeniden başlatın
systemctl restart haproxy
```

### mod_evasive ile Apache Koruması (Apache kullanılıyorsa)

```bash
# mod_evasive kurulumu
dnf install -y httpd-devel gcc
wget https://github.com/jzdziarski/mod_evasive/archive/refs/heads/master.zip
unzip master.zip
cd mod_evasive-master
apxs -i -a -c mod_evasive24.c

cat > /etc/httpd/conf.d/mod_evasive.conf << 'EOL'
<IfModule mod_evasive24.c>
    DOSHashTableSize 3097
    DOSPageCount 5
    DOSSiteCount 50
    DOSPageInterval 1
    DOSSiteInterval 1
    DOSBlockingPeriod 60
    DOSLogDir "/var/log/mod_evasive"
    DOSEmailNotify admin@example.com
    DOSWhitelist 127.0.0.1
</IfModule>
EOL

mkdir -p /var/log/mod_evasive
chown apache:apache /var/log/mod_evasive

# Apache'yi yeniden başlat
systemctl restart httpd
```

## Uygulama Seviyesi Korumalar

### ModSecurity WAF Kurulumu

```bash
# ModSecurity kurulumu
dnf install -y mod_security mod_security_crs

# ModSecurity'yi etkinleştirme (Apache için)
cat > /etc/httpd/conf.d/mod_security.conf << 'EOL'
<IfModule mod_security2.c>
    SecRuleEngine On
    SecRequestBodyAccess On
    SecResponseBodyAccess On
    SecResponseBodyMimeType text/plain text/html text/xml application/json
    SecResponseBodyLimit 524288
    
    # OWASP ModSecurity Core Rule Set
    IncludeOptional /etc/httpd/modsecurity.d/*.conf
    IncludeOptional /etc/httpd/modsecurity.d/activated_rules/*.conf
    
    # DDoS yapılandırması
    SecAction "id:900700,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=2"
</IfModule>
EOL

# OWASP Core Rule Set'i etkinleştir
cp /etc/httpd/modsecurity.d/modsecurity.conf-recommended /etc/httpd/modsecurity.d/modsecurity.conf
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/httpd/modsecurity.d/modsecurity.conf

# OWASP CRS'i etkinleştir
cd /etc/httpd/modsecurity.d/activated_rules/
for f in /etc/httpd/modsecurity.d/crs/*.conf; do ln -s $f; done

# Apache'yi yeniden başlat
systemctl restart httpd
```

### NGINX ile ModSecurity (NGINX Kullanılıyorsa)

```bash
dnf install -y epel-release
dnf install -y nginx-mod-security

cat > /etc/nginx/modsec/main.conf << 'EOL'
# ModSecurity ana yapılandırması
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html text/xml application/json
SecResponseBodyLimit 524288

# Temel kuralları içe aktar
Include /etc/nginx/modsec/owasp-crs/crs-setup.conf
Include /etc/nginx/modsec/owasp-crs/rules/*.conf

# DDoS koruması - Paranoia seviyesi
SecAction "id:900700,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=2"
EOL

# NGINX yapılandırmasını güncelle
cat > /etc/nginx/conf.d/modsecurity.conf << 'EOL'
modsecurity on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;
EOL

# NGINX'i yeniden başlat
systemctl restart nginx
```

## İzleme ve Uyarı Sistemi

### Prometheus ve Grafana Kurulumu

```bash
# Prometheus ve Node Exporter kurulumu
dnf install -y prometheus node_exporter

# Grafana kurulumu
cat > /etc/yum.repos.d/grafana.repo << 'EOL'
[grafana]
name=grafana
baseurl=https://packages.grafana.com/oss/rpm
repo_gpgcheck=1
enabled=1
gpgcheck=1
gpgkey=https://packages.grafana.com/gpg.key
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
EOL

dnf install -y grafana

# Servisleri etkinleştir ve başlat
systemctl enable prometheus node_exporter grafana-server
systemctl start prometheus node_exporter grafana-server
```

### Netdata ile Gerçek Zamanlı İzleme

```bash
# Netdata kurulumu
bash <(curl -Ss https://my-netdata.io/kickstart.sh) --non-interactive

# Netdata için iptables kuralı ekle
iptables -A INPUT -p tcp --dport 19999 -j ACCEPT
ip6tables -A INPUT -p tcp --dport 19999 -j ACCEPT
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
```

### DDoS İzleme ve Uyarı Scripti

```bash
cat > /usr/local/sbin/ddos_monitor.sh << 'EOL'
#!/bin/bash

# DDoS izleme ve uyarı scripti
LOG_FILE="/var/log/ddos_monitor.log"
EMAIL="admin@example.com"
SLACK_WEBHOOK="https://hooks.slack.com/services/your/webhook/url"
DISCORD_WEBHOOK="https://discord.com/api/webhooks/your/webhook/url"

# Bağlantı sayılarını kontrol et
CONN_TOTAL=$(netstat -an | grep -c ESTABLISHED)
CONN_80=$(netstat -an | grep :80 | grep -c ESTABLISHED)
CONN_443=$(netstat -an | grep :443 | grep -c ESTABLISHED)
CONN_SYN=$(netstat -an | grep -c SYN_RECV)

# Sistem kaynaklarını kontrol et
LOAD=$(uptime | awk -F'load average:' '{ print $2 }' | cut -d, -f1 | tr -d ' ')
RAM_FREE=$(free -m | grep Mem | awk '{print $4}')
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')

# Ağ trafiğini kontrol et
RX_BYTES=$(cat /proc/net/dev | grep eth0 | awk '{print $2}')
TX_BYTES=$(cat /proc/net/dev | grep eth0 | awk '{print $10}')

# Metrikleri kaydet
echo "$(date) - CONN_TOTAL: $CONN_TOTAL, CONN_80: $CONN_80, CONN_443: $CONN_443, CONN_SYN: $CONN_SYN, LOAD: $LOAD, RAM_FREE: $RAM_FREE, CPU_USAGE: $CPU_USAGE, RX_BYTES: $RX_BYTES, TX_BYTES: $TX_BYTES" >> $LOG_FILE

# Eşik değerlerini kontrol et ve uyarı gönder
if [ $CONN_TOTAL -gt 1000 ] || [ $CONN_SYN -gt 500 ] || [ $(echo "$LOAD > 10" | bc -l) -eq 1 ]; then
    MESSAGE="⚠️ DDoS Alarmı! - $(date) - Toplam Bağlantı: $CONN_TOTAL, SYN: $CONN_SYN, Yük: $LOAD"
    
    # Email uyarısı
    echo "$MESSAGE" | mail -s "DDoS Alarm - $(hostname)" $EMAIL
    
    # Slack uyarısı
    curl -s -X POST -H 'Content-type: application/json' --data "{\"text\":\"$MESSAGE\"}" $SLACK_WEBHOOK
    
    # Discord uyarısı
    curl -s -X POST -H "Content-Type: application/json" --data "{\"content\":\"$MESSAGE\"}" $DISCORD_WEBHOOK
    
    # Günlüğe kaydet
    echo "ALERT: $MESSAGE" >> $LOG_FILE
    
    # Otomatik yanıt - CSF'yi daha agresif yap
    csf --denyhosts 60
    csf --tempban "$(netstat -an | grep SYN_RECV | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -n 20 | awk '$1 > 5 {print $2}')"
fi
EOL

chmod +x /usr/local/sbin/ddos_monitor.sh

# Crontab'a ekle
(crontab -l 2>/dev/null; echo "* * * * * /usr/local/sbin/ddos_monitor.sh") | crontab -
```

## Otomatik Yanıt ve Kurtarma

### DDoS Saldırısı Yanıt Scripti

```bash
cat > /usr/local/sbin/ddos_response.sh << 'EOL'
#!/bin/bash

# DDoS saldırısı tespit edildiğinde otomatik yanıt
LOG_FILE="/var/log/ddos_response.log"

# Mevcut bağlantı durumunu kaydet
echo "$(date) - Yanıt başlangıcı" >> $LOG_FILE
echo "----------------------------" >> $LOG_FILE
echo "Bağlantı durumu:" >> $LOG_FILE
netstat -an | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -n 20 >> $LOG_FILE
echo "SYN durumu:" >> $LOG_FILE
netstat -an | grep SYN_RECV | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -n 20 >> $LOG_FILE

# Şüpheli IP'leri geçici olarak engelle
for IP in $(netstat -an | grep SYN_RECV | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -n 20 | awk '$1 > 10 {print $2}'); do
    if ! grep -q "$IP" /etc/csf/csf.deny; then
        csf -td $IP 3600 "Suspected DDoS - Auto-response"
        echo "$(date) - Engellenen IP: $IP (3600 saniye)" >> $LOG_FILE
    fi
done

# Servis yükünü azalt
systemctl restart nginx 2>/dev/null || systemctl restart httpd 2>/dev/null
systemctl restart php-fpm 2>/dev/null

# CSF'yi katı modda çalıştır
csf -r
sed -i 's/^CT_LIMIT = ".*"/CT_LIMIT = "30"/' /etc/csf/csf.conf
sed -i 's/^CT_INTERVAL = ".*"/CT_INTERVAL = "5"/' /etc/csf/csf.conf
csf -r

# Varsa CDN'ye geçiş yap
if [ -f /usr/local/sbin/switch_to_cdn.sh ]; then
    /usr/local/sbin/switch_to_cdn.sh
    echo "$(date) - CDN'ye geçiş yapıldı" >> $LOG_FILE
fi

echo "$(date) - Yanıt tamamlandı" >> $LOG_FILE
echo "----------------------------" >> $LOG_FILE
EOL

chmod +x /usr/local/sbin/ddos_response.sh
```

### Saldırı Sonrası Kurtarma Scripti

```bash
cat > /usr/local/sbin/ddos_recovery.sh << 'EOL'
#!/bin/bash

# DDoS saldırısı sonrası kurtarma scripti
LOG_FILE="/var/log/ddos_recovery.log"

echo "$(date) - Kurtarma başlangıcı" >> $LOG_FILE

# Geçici banlanan IP'leri temizle
csf -tf
echo "$(date) - Geçici banlar temizlendi" >> $LOG_FILE

# CSF'yi normal ayarlara geri döndür
sed -i 's/^CT_LIMIT = ".*"/CT_LIMIT = "300"/' /etc/csf/csf.conf
sed -i 's/^CT_INTERVAL = ".*"/CT_INTERVAL = "30"/' /etc/csf/csf.conf
csf -r
echo "$(date) - CSF normal ayarlara döndürüldü" >> $LOG_FILE

# Servisleri yeniden başlat
systemctl restart nginx 2>/dev/null || systemctl restart httpd 2>/dev/null
systemctl restart php-fpm 2>/dev/null
systemctl restart mariadb 2>/dev/null || systemctl restart mysql 2>/dev/null
echo "$(date) - Servisler yeniden başlatıldı" >> $LOG_FILE

# Bağlantı tablosunu temizle
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
echo "$(date) - SYN cookies etkinleştirildi" >> $LOG_FILE

# Varsa CDN'den normale dön
if [ -f /usr/local/sbin/switch_from_cdn.sh ]; then
    /usr/local/sbin/switch_from_cdn.sh
    echo "$(date) - CDN'den normale dönüldü" >> $LOG_FILE
fi

echo "$(date) - Kurtarma tamamlandı" >> $LOG_FILE
echo "----------------------------" >> $LOG_FILE
EOL

chmod +x /usr/local/sbin/ddos_recovery.sh
```

## Düzenli Bakım ve Güncellemeler

### Otomatik Güncelleme ve Bakım Scripti

```bash
cat > /usr/local/sbin/security_updates.sh << 'EOL'
#!/bin/bash

# Güvenlik güncellemelerini otomatik uygulama
LOG_FILE="/var/log/security_updates.log"

echo "$(date) - Güvenlik güncellemeleri başlangıcı" >> $LOG_FILE

# Sistem güncellemelerini kontrol et ve yükle
dnf update -y --security >> $LOG_FILE 2>&1
echo "$(date) - Güvenlik güncellemeleri yüklendi" >> $LOG_FILE

# CSF'yi güncelle
cd /usr/local/src
rm -rf csf.tgz
wget https://download.configserver.com/csf.tgz
tar -xzf csf.tgz
cd csf
./install.sh >> $LOG_FILE 2>&1
echo "$(date) - CSF güncellendi" >> $LOG_FILE

# Bağlantı tablosunu temizle
conntrack -F 2>/dev/null
echo "$(date) - Bağlantı tablosu temizlendi" >> $LOG_FILE

# Logları döndür
logrotate -f /etc/logrotate.conf >> $LOG_FILE 2>&1
echo "$(date) - Loglar döndürüldü" >> $LOG_FILE

# Sistem durumunu raporla
echo "Disk kullanımı:" >> $LOG_FILE
df -h >> $LOG_FILE
echo "İnode kullanımı:" >> $LOG_FILE
df -i >> $LOG_FILE
echo "Bellek kullanımı:" >> $LOG_FILE
free -m >> $LOG_FILE
echo "Aktif bağlantılar:" >> $LOG_FILE
netstat -an | grep ESTABLISHED | wc -l >> $LOG_FILE

echo "$(date) - Güvenlik güncellemeleri tamamlandı" >> $LOG_FILE
echo "----------------------------" >> $LOG_FILE
EOL

chmod +x /usr/local/sbin/security_updates.sh

# Crontab'a ekle - Haftada bir Pazar günü saat 03:00'te çalıştır
(crontab -l 2>/dev/null; echo "0 3 * * 0 /usr/local/sbin/security_updates.sh") | crontab -
```

### Güvenlik İzleme ve Rapor Scripti

```bash
cat > /usr/local/sbin/security_monitor.sh << 'EOL'
#!/bin/bash

# Güvenlik izleme ve raporlama scripti
LOG_FILE="/var/log/security_monitor.log"
REPORT_FILE="/var/log/security_report_$(date +%Y%m%d).txt"
EMAIL="admin@example.com"

echo "$(date) - Güvenlik izleme başlangıcı" >> $LOG_FILE
echo "Güvenlik Raporu - $(date)" > $REPORT_FILE
echo "=================================" >> $REPORT_FILE

# Rootkit taraması
echo "Rootkit Taraması:" >> $REPORT_FILE
if [ -x "$(command -v rkhunter)" ]; then
    rkhunter --check --skip-keypress >> $REPORT_FILE 2>&1
else
    echo "rkhunter kurulu değil" >> $REPORT_FILE
fi

# Malware taraması
echo "Malware Taraması:" >> $REPORT_FILE
if [ -x "$(command -v clamav)" ]; then
    clamscan -r --quiet /var/www /home /tmp >> $REPORT_FILE 2>&1
else
    echo "clamav kurulu değil" >> $REPORT_FILE
fi

# Açık portları listele
echo "Açık Portlar:" >> $REPORT_FILE
netstat -tulpn | grep LISTEN >> $REPORT_FILE

# Son başarısız giriş denemeleri
echo "Son Başarısız Giriş Denemeleri:" >> $REPORT_FILE
lastb -n 20 >> $REPORT_FILE 2>&1

# fail2ban durumu
echo "fail2ban Durumu:" >> $REPORT_FILE
fail2ban-client status >> $REPORT_FILE 2>&1

# CSF durumu
echo "CSF Durumu:" >> $REPORT_FILE
csf -l >> $REPORT_FILE 2>&1

# Önemli log dosyalarını kontrol et
echo "Şüpheli Log Kayıtları:" >> $REPORT_FILE
grep -i "fail\|error\|warn\|attack\|hack\|exploit" /var/log/messages | tail -n 50 >> $REPORT_FILE 2>&1
grep -i "fail\|error\|warn\|attack\|hack\|exploit" /var/log/secure | tail -n 50 >> $REPORT_FILE 2>&1
grep -i "fail\|error\|warn\|attack\|hack\|exploit" /var/log/audit/audit.log | tail -n 50 >> $REPORT_FILE 2>&1

# Raporu e-posta ile gönder
if [ -x "$(command -v mail)" ]; then
    cat $REPORT_FILE | mail -s "Güvenlik Raporu - $(hostname) - $(date +%Y-%m-%d)" $EMAIL
    echo "$(date) - Güvenlik raporu e-posta ile gönderildi" >> $LOG_FILE
else
    echo "$(date) - mail komutu kurulu olmadığı için rapor e-posta ile gönderilemedi" >> $LOG_FILE
fi

echo "$(date) - Güvenlik izleme tamamlandı" >> $LOG_FILE
echo "----------------------------" >> $LOG_FILE
EOL

chmod +x /usr/local/sbin/security_monitor.sh

# Crontab'a ekle - Her gün saat 06:00'da çalıştır
(crontab -l 2>/dev/null; echo "0 6 * * * /usr/local/sbin/security_monitor.sh") | crontab -
```
