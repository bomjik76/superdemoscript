#!/bin/bash

# Функция для отображения меню
show_menu() {
    clear
    # Define color codes
    GRAY='\033[90m'
    NC='\033[0m' # No Color
    
    echo -e "${GRAY}1. имя хоста${NC}"
    echo -e "${GRAY}3. часовой пояс${NC}"
    echo -e "${GRAY}4. nftables${NC}"
    echo -e "${GRAY}5. DHCP сервер${NC}"
    echo -e "${GRAY}6. GRE туннель${NC}"
    echo -e "${GRAY}7. FRR (OSPF)${NC}"
    echo -e "${GRAY}8. Создать системного пользователя${NC}"
    echo -e "${GRAY}9. SSH${NC}"
    echo -e "${GRAY}12. NFS${NC}"
    echo -e "${GRAY}13. клиента NFS${NC}"
    echo -e "${GRAY}14. Chrony${NC}"
    echo -e "${GRAY}15. клиента Chrony${NC}"
    echo -e "${GRAY}21.LMS Apache${NC}"
    echo -e "${GRAY}22. MediaWiki${NC}"
    echo -e "${GRAY}24.обратный прокси-сервер Nginx${NC}"
    echo -e "${GRAY}27. BIND${NC}"
    echo -e "${GRAY}28. RAID0${NC}"
    echo -e "${GRAY}29. RAID1${NC}"
    echo -e "${GRAY}30. RAID5${NC}"
    echo -e "${GRAY}32. Ansible${NC}"
    echo -e "${GRAY}33. SAMBA DC${NC}"
    echo -e "${GRAY}34. Войти в SAMBA DC${NC}"
    echo -e "${GRAY}35. статическую трансляцию портов${NC}"
    echo -e "${GRAY}36. Добавить пользователей и группы SAMBA${NC}"
    echo -e "${GRAY}37. Добавить пользователей SAMBA из CSV${NC}"
    echo -e "${GRAY}38. Создать файл sudoers для группы hq${NC}"
    echo -e "${GRAY}39. Выход${NC}"
    echo -e "${GRAY}=${NC}"
}

# Функция для возврата в меню
return_to_menu() {
    echo
    echo -en "${GRAY}Вернуться в главное меню? (y/n): ${NC}"
    read choice
    case "$choice" in
        y|Y) return 0 ;;
        *) clear; exit 0 ;;
    esac
}

# HOSTNAME 
HOSTNAME="isp"
#INTERFACE
INTERFACE_1="enp0s3"
INTERFACE_2="enp0s8"
INTERFACE_3="enp0s9"
#IP
IP2="22.22.22.1/28"
IP3="11.11.0.1/27"
#TIMEZONE
TIMEZONE="Europe/Moscow"
# DHCP параметры
DHCP_SUBNET="192.168.1.0"
DHCP_NETMASK="255.255.255.224"
DHCP_RANGE="192.168.1.2 192.168.1.30"
DHCP_ROUTER="192.168.1.1"
DHCP_DNS="192.168.2.2"
DHCP_DOMAIN="demo.rtk"
# GRE туннель параметры
LOCAL_IP="22.22.22.2"
REMOTE_IP="11.11.0.2"
TUNNEL_LOCAL_IP="10.10.10.1/30"
TUNNEL_REMOTE_IP="10.10.10.2"
TUNNEL_NAME="gre-tunnel0"
#СЕТИ
NETWORK_Left="192.168.1.0/27"
NETWORK_Right="172.16.0.0/24"
NETWORK_2="192.168.2.0/29"
NETWORK_TUNNEL="10.10.10.0/30"
# Параметры пользователя
USERNAME_NET="net_user"
PASSWORD_NET="P@\$\$word"
USER_ID="1111"
USERNAME_SSH="ssh_user"
# Добавляем новые переменные
PORT_SSH="2222"
POPITKA="3"
BANNER_PATH="/etc/ssh-banner"
#backup
BACKUP_DIR="/var/backup"
# Переменные wordpress
DB_NAME="wordpress"
DB_USER="wpuser"
DB_PASS="P@ssw0rd"
ADMIN_USER="Admin"
ADMIN_PASS="P@ssw0rd"
ADMIN_EMAIL="admin@example.com"
SITE_TITLE="C1-21 - Pavel"
SITE_URL="http://192.168.220.5"
#CHRONY
local_stratum="6"
#RAID1 и RAID5
DISK1="/dev/sdb"
DISK2="/dev/sdc"
DISK3="/dev/sdd"
RAID_DEVICE="/dev/md0"
MDADM_CONFIG="/etc/mdadm.conf"
MOUNT_DIR="/obmen"
MOUNT_DIR5="/raid5"
#NFS
NFS_DIR="/obmen/nfs"
EXPORTS_FILE="/etc/exports"
#клиент cups
CUPS_IP="22.22.22.2"  # Укажите IP-адрес CUPS
PRINTER_NAME="Virtual_PDF_Printer"
#client NFS
NFS_SERVER="22.22.22.2"  # IP адрес сервера NFS
NFS_EXPORT="/raid5/nfs"  # Экспортированная папка на сервере
MOUNT_DIRNFS="/mnt/nfs"     # Точка монтирования на клиенте
# клиент CHRONY
CHRONY_SERVER="172.16.220.1"
#PostgreSQL и pgAdmin4
EMAIL="pasha@gmail.com"
ADMIN_PASSWORD="QWEasd11"
POSTGRES_PASSWORD="QWEasd11"
#MediaWiki
MEDIAPORT="8080"
MEDIADB_NAME="mariadb"
MEDIA="mediawiki"
MEDIADB_USER="wiki"
MEDIADB_PASS="WikiP@ssw0rd"
#PROXY NGINX
IPHQ_SRV="192.168.1.2"
IPBR_SRV="192.168.1.3"
name="moodle.au-team.irpo"
name2="wiki.au-team.irpo"
pp1="80"
pp2="8080"
# rsyslog
DB_ROOT_USERRSYS="root"
DB_ROOT_PASSWORDRSYS="QWEasd11"
DB_NAMERSYS="Syslog"
DB_USERRSYS="rsyslog"
DB_PASSWORDRSYS="QWEasd11"
# клиент rsyslog
RSYSLOG_SERVER="192.168.1.1"
#BIND
DOMAIN_NAME="au-team.irpo"
DNS_IP="172.16.1.1"
ALLOWED_NETWORK="any"
FORWARDER="77.88.8.8"
ADMIN_EMAIL="admin.${DOMAIN_NAME}."
# Переменные для Ansible
ANSIBLE_HQ_SRV_IP="192.168.100.2"
ANSIBLE_HQ_CLI_IP="192.168.100.3"
ANSIBLE_HQ_RTR_IP="172.16.4.2"
ANSIBLE_BR_RTR_IP="172.16.5.2"
ANSIBLE_SSH_PORT="2024"
ANSIBLE_SSH_USER="sshuser"
ANSIBLE_USER_CLI="root"
ANSIBLE_USER_RTR="root"
# SAMBA DC
domain_name="demo.rtk"
dc_name="br-srv"
dc_ip="192.168.1.1"
sambaps="QWEasd11"
#статическая трансляцию портов
ip11="172.16.5.2"
ip22="172.16.4.2"
portp="80"
portp2="8080"
#MOODLE
MOODLE_USER="moodle"
MOODLE_PASS="P@ssw0rd"
MOODLE_DB="moodledb"
# Функция настройки имени хоста
configure_hostname() {
    echo -e "${GRAY}Введите новое имя хоста (по умолчанию: $HOSTNAME): ${NC}"
    read new_hostname
    HOSTNAME=${new_hostname:-$HOSTNAME}
    hostnamectl set-hostname $HOSTNAME
    echo "Имя хоста обновлено на $HOSTNAME."
}

# Функция настройки сетевых интерфейсов
configure_network() {
    echo "Настройка сетевых интерфейсов"
    echo -e "${GRAY}Введите имя интерфейса 1 (по умолчанию: $INTERFACE_1): ${NC}"
    read new_if1
    echo -e "${GRAY}Введите имя интерфейса 2 (по умолчанию: $INTERFACE_2): ${NC}"
    read new_if2
    echo -e "${GRAY}Введите имя интерфейса 3 (по умолчанию: $INTERFACE_3): ${NC}"
    read new_if3
    echo -e "${GRAY}Введите IP-адрес для интерфейса 2 (по умолчанию: $IP2): ${NC}"
    read new_ip2
    echo -e "${GRAY}Введите IP-адрес для интерфейса 3 (по умолчанию: $IP3): ${NC}"
    read new_ip3

    INTERFACE_1=${new_if1:-$INTERFACE_1}
    INTERFACE_2=${new_if2:-$INTERFACE_2}
    INTERFACE_3=${new_if3:-$INTERFACE_3}
    IP2=${new_ip2:-$IP2}
    IP3=${new_ip3:-$IP3}

    # Применение настроек сетевых интерфейсов
    nmcli con mod $INTERFACE_2 ipv4.address $IP2
    nmcli con mod $INTERFACE_2 ipv4.method manual
    nmcli con mod $INTERFACE_3 ipv4.address $IP3
    nmcli con mod $INTERFACE_3 ipv4.method manual
    echo "Сетевые интерфейсы обновлены."
}

# Функция настройки часового пояса
configure_timezone() {
    echo "Текущий часовой пояс: $TIMEZONE"
    echo -e "${GRAY}Введите новый часовой пояс (по умолчанию: $TIMEZONE): ${NC}"
    read new_timezone
    TIMEZONE=${new_timezone:-$TIMEZONE}
    timedatectl set-timezone $TIMEZONE
    echo "Часовой пояс обновлен на $TIMEZONE."
}

# Функция настройки nftables
configure_nftables() {
    # Получение имени первого интерфейса в системе
    INTERFACE_1=$(ip -o link show | awk -F': ' '{print $2}' | grep -v 'lo' | head -n 1)
    dnf install -y nftables
    # Создание конфигурации nftables
    CONFIG_FILE1="/etc/nftables/isp.nft"
    CONFIG_FILE2="/etc/sysconfig/nftables.conf"
    cat > $CONFIG_FILE1 << EOF
table inet nat {
    chain POSTROUTING {
        type nat hook postrouting priority srcnat;
        oifname $INTERFACE_1 masquerade
    }
}
EOF
    # Добавление include в nftables.conf
    INCLUDE_LINE='include "/etc/nftables/isp.nft"'
    if ! grep -Fxq "$INCLUDE_LINE" "$CONFIG_FILE2"; then
        echo "$INCLUDE_LINE" | sudo tee -a "$CONFIG_FILE2"
    fi
    # Запуск и автозагрузка nftables
    systemctl enable --now nftables
    # Включение IP-форвардинга
    echo net.ipv4.ip_forward=1 > /etc/sysctl.conf
    sysctl -p
    echo "nftables настроены."
}

# Функция настройки DHCP
configure_dhcp() {
    echo -e "${GRAY}Настройка параметров DHCP сервера${NC}"
    echo -e "${GRAY}Введите подсеть (по умолчанию: $DHCP_SUBNET): ${NC}"
    read new_subnet
    echo -e "${GRAY}Введите маску подсети (по умолчанию 27: $DHCP_NETMASK): ${NC}"
    read new_netmask
    echo -e "${GRAY}Введите диапазон адресов (по умолчанию: $DHCP_RANGE): ${NC}"
    read new_range
    echo -e "${GRAY}Введите адрес маршрутизатора (по умолчанию: $DHCP_ROUTER): ${NC}"
    read new_router
    echo -e "${GRAY}Введите адрес DNS сервера (по умолчанию: $DHCP_DNS): ${NC}"
    read new_dns
    echo -e "${GRAY}Введите доменное имя (по умолчанию: $DHCP_DOMAIN): ${NC}"
    read new_domain

    DHCP_SUBNET=${new_subnet:-$DHCP_SUBNET}
    DHCP_NETMASK=${new_netmask:-$DHCP_NETMASK}
    DHCP_RANGE=${new_range:-$DHCP_RANGE}
    DHCP_ROUTER=${new_router:-$DHCP_ROUTER}
    DHCP_DNS=${new_dns:-$DHCP_DNS}
    DHCP_DOMAIN=${new_domain:-$DHCP_DOMAIN}

    # Применение настроек DHCP
    dnf install dhcp-server -y
    echo -e "${GRAY}Настройка DHCP...${NC}"
    cat <<EOF > /etc/dhcp/dhcpd.conf
default-lease-time 600;
max-lease-time 7200;

subnet $DHCP_SUBNET netmask $DHCP_NETMASK {
    range $DHCP_RANGE;
    option routers $DHCP_ROUTER;
    option domain-name-servers $DHCP_DNS;
    option domain-name "$DHCP_DOMAIN";
    default-lease-time 600;
    max-lease-time 7200;
}
EOF
    systemctl enable --now dhcpd
    echo -e "${GRAY}DHCP настроен.${NC}"
}

# Функция настройки GRE туннеля
configure_gre() {
    echo -e "${GRAY}Настройка параметров GRE туннеля${NC}"
    echo -e "${GRAY}Введите локальный IP (по умолчанию: $LOCAL_IP): ${NC}"
    read new_local_ip
    echo -e "${GRAY}Введите удаленный IP (по умолчанию: $REMOTE_IP): ${NC}"
    read new_remote_ip
    echo -e "${GRAY}Введите локальный IP туннеля (по умолчанию: $TUNNEL_LOCAL_IP): ${NC}"
    read new_tunnel_local_ip
    echo -e "${GRAY}Введите удаленный IP туннеля (по умолчанию: $TUNNEL_REMOTE_IP): ${NC}"
    read new_tunnel_remote_ip
    echo -e "${GRAY}Введите имя туннеля (по умолчанию: $TUNNEL_NAME): ${NC}"
    read new_tunnel_name

    LOCAL_IP=${new_local_ip:-$LOCAL_IP}
    REMOTE_IP=${new_remote_ip:-$REMOTE_IP}
    TUNNEL_LOCAL_IP=${new_tunnel_local_ip:-$TUNNEL_LOCAL_IP}
    TUNNEL_REMOTE_IP=${new_tunnel_remote_ip:-$TUNNEL_REMOTE_IP}
    TUNNEL_NAME=${new_tunnel_name:-$TUNNEL_NAME}

    # Применение настроек GRE туннеля
    nmcli con add type ip-tunnel ip-tunnel.mode gre con-name $TUNNEL_NAME ifname $TUNNEL_NAME \
    remote $REMOTE_IP local $LOCAL_IP
    nmcli con mod $TUNNEL_NAME ipv4.addresses $TUNNEL_LOCAL_IP
    nmcli con mod $TUNNEL_NAME ipv4.method manual
    nmcli con mod $TUNNEL_NAME +ipv4.routes "$NETWORK_Right $TUNNEL_REMOTE_IP"
    nmcli connection modify $TUNNEL_NAME ip-tunnel.ttl 64
    nmcli con up $TUNNEL_NAME
    echo -e "${GRAY}GRE туннель настроен.${NC}"
}

# Функция настройки пользователя
configure_user() {
    echo "Настройка системного пользователя"
    echo -e "${GRAY}Введите имя пользователя (по умолчанию: $USERNAME_NET): ${NC}"
    read new_username
    echo -e "${GRAY}Введите пароль (по умолчанию: $PASSWORD_NET): ${NC}"
    read new_password
    echo -e "${GRAY}Введите ID пользователя (по умолчанию: $USER_ID): ${NC}"
    read new_user_id

    USERNAME_NET=${new_username:-$USERNAME_NET}
    PASSWORD_NET=${new_password:-$PASSWORD_NET}
    USER_ID=${new_user_id:-$USER_ID}

    # Применение настроек пользователя
    useradd -m -s /bin/bash -u "$USER_ID" "$USERNAME_NET"
    echo "$USERNAME_NET:$PASSWORD_NET" | chpasswd
    usermod -aG wheel "$USERNAME_NET"
    sed -i '110 a\'$USERNAME_NET' ALL=(ALL) NOPASSWD:ALL' "/etc/sudoers.d/$USERNAME_NET"
    sed -i '110 a\'$USERNAME_NET' ALL=(ALL) NOPASSWD:ALL' "/etc/sudoers"
    echo "Пользователь $USERNAME_NET создан."
}

# Функция настройки SSH
configure_ssh() {
    # Запрос необходимых переменных
    echo -e "${GRAY}Введите порт SSH (по умолчанию: $PORT_SSH): ${NC}"
    read new_port
    echo -e "${GRAY}Введите имя пользователя для SSH (по умолчанию: $USERNAME_SSH): ${NC}"
    read new_username
    echo -e "${GRAY}Введите максимальное количество попыток входа (по умолчанию: $POPITKA): ${NC}"
    read new_max_auth_tries
    echo -e "${GRAY}Введите время ожидания входа (по умолчанию: 5m): ${NC}"
    read new_login_grace_time

    PORT_SSH=${new_port:-$PORT_SSH}
    USERNAME_SSH=${new_username:-$USERNAME_SSH}
    POPITKA=${new_max_auth_tries:-$POPITKA}
    TIME=${new_login_grace_time:-5m}

    echo "Authorized access only" > $BANNER_PATH

    # Настройка порта SSH
    sed -i 's/^SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
    semanage port -a -t ssh_port_t -p tcp $PORT_SSH
    setenforce 0
    sed -i "20 a Port $PORT_SSH" /etc/ssh/sshd_config
    sed -i "21 a PermitRootLogin no" /etc/ssh/sshd_config
    sed -i "22 a AllowUsers $USERNAME_SSH" /etc/ssh/sshd_config
    sed -i "23 a MaxAuthTries $POPITKA" /etc/ssh/sshd_config
    sed -i "24 a LoginGraceTime $TIME" /etc/ssh/sshd_config
    sed -i "25 a Banner $BANNER_PATH" /etc/ssh/sshd_config
    # Перезапуск службы SSH для применения изменений
    systemctl restart sshd
}

# Функция настройки FRR
configure_frr() {
    echo "Настройка FRR с OSPF"
    
    # Запрос необходимых переменных
    echo -e "${GRAY}Введите имя интерфейса для OSPF (по умолчанию: $TUNNEL_NAME): ${NC}"
    read new_tunnel_name
    echo -e "${GRAY}Введите пароль для OSPF аутентификации: ${NC}"
    read ospf_password
    echo -e "${GRAY}Введите сеть для OSPF (по умолчанию: $NETWORK_Left): ${NC}"
    read new_network_left
    echo -e "${GRAY}Введите вторую сеть для OSPF (по умолчанию: $NETWORK_2): ${NC}"
    read new_network_2

    HOSTNAME=$(hostname)
    TUNNEL_NAME=${new_tunnel_name:-$TUNNEL_NAME}
    NETWORK_Left=${new_network_left:-$NETWORK_Left}
    NETWORK_2=${new_network_2:-$NETWORK_2}

    # Установка FRR
    dnf install -y frr

    # Включение необходимых демонов
    sed -i "s/ospfd=no/ospfd=yes/" /etc/frr/daemons
    sed -i "s/ospf6d=no/ospf6d=yes/" /etc/frr/daemons

    # Создание конфигурационного файла FRR
    cat <<EOL > /etc/frr/frr.conf
frr version 10.1
frr defaults traditional
hostname $HOSTNAME
no ipv6 forwarding
!
interface $TUNNEL_NAME
ip ospf authentication
ip ospf authentication-key $ospf_password
no ip ospf passive
exit
!
router ospf
passive-interface default
network $NETWORK_TUNNEL area 0
network $NETWORK_Left area 0
network $NETWORK_2 area 0
area 0 authentication
exit
!
EOL

    # Включение и запуск службы FRR
    systemctl enable --now frr
    echo "FRR настроен и запущен."
}

# Функция настройки CUPS
configure_cups() {
    echo "Установка и настройка CUPS..."

    # Установка необходимых пакетов
    dnf install -y cups cups-pdf || {
        echo "Ошибка: Не удалось установить пакеты. Проверьте подключение к репозиторию." >&2
        exit 1
    }
    # Запуск службы CUPS
    systemctl enable cups
    systemctl start cups
    # Настройка виртуального PDF-принтера
    PDF_PRINTER_NAME="Virtual_PDF_Printer"
    lpadmin -p "$PDF_PRINTER_NAME" -E -v cups-pdf:/ -m drv:///sample.drv/generic.ppd || {
        echo "Ошибка: Не удалось добавить принтер." >&2
        exit 1
    }
    lpadmin -d "$PDF_PRINTER_NAME"
    echo "Принтер $PDF_PRINTER_NAME успешно добавлен."

    # Настройка веб-интерфейса и удаленного администрирования
    CUPS_CONF="/etc/cups/cupsd.conf"
    echo "Настраиваем веб-интерфейс и удаленное администрирование..."
    if grep -q "^Port 631" "$CUPS_CONF"; then
        echo "Веб-интерфейс уже настроен."
    else
        sed -i 's/^Listen localhost:631/Port 631/' "$CUPS_CONF" || {
            echo "Ошибка: Не удалось изменить $CUPS_CONF." >&2
            exit 1
        }
    fi
    sed -i 's/<Location \/>/<Location \/>\n  Allow All\n/g' $CUPS_CONF
    sed -i 's/<Location \/admin>/<Location \/admin>\n  Allow All\n/g' $CUPS_CONF
    sed -i 's/<Location \/admin\/log>/<Location \/admin\/log>\n  Allow All\n/g' $CUPS_CONF
    sed -i 's/<Location \/admin\/conf>/<Location \/admin\/conf>\n  Allow All\n/g' $CUPS_CONF
    # Перезапуск службы CUPS
    echo "Перезапускаем службу CUPS для применения изменений..."
    systemctl restart cups
    # Проверка статуса
    systemctl status cups --no-pager
    if [ $? -eq 0 ]; then
        echo "CUPS успешно настроен и запущен."
        echo "Веб-интерфейс доступен по адресу: http://<IP-адрес-сервера>:631"
    else
        echo "Ошибка: Не удалось запустить CUPS." >&2
        exit 1
    fi

    echo "Настройка CUPS завершена."
}

# Функция настройки клиента CUPS
configure_cups_client() {
    # Запрос необходимых переменных
    echo -e "${GRAY}Введите IP-адрес CUPS (по умолчанию: $CUPS_IP): ${NC}"
    read input_CUPS_IP
    echo -e "${GRAY}Введите имя принтера (по умолчанию: $PRINTER_NAME): ${NC}"
    read input_printer_name
    CUPS_IP=${input_CUPS_IP:-$CUPS_IP}
    PRINTER_NAME=${input_printer_name:-$PRINTER_NAME}
    # Установка клиента CUPS
    dnf install -y cups-client
    # Настройка подключения к принтеру
    lpadmin -p "$PRINTER_NAME" -E -v ipp://$CUPS_IP:631/printers/$PRINTER_NAME
    lpadmin -d "$PRINTER_NAME"
    echo "Принтер $PRINTER_NAME настроен как принтер по умолчанию."
}

# Функция настройки RAID
configure_raid1() {
    # Запрос необходимых переменных
    echo -e "${GRAY}Введите первый диск для RAID (по умолчанию: $DISK1): ${NC}"
    read input_disk1
    echo -e "${GRAY}Введите второй диск для RAID (по умолчанию: $DISK2): ${NC}"
    read input_disk2
    echo -e "${GRAY}Введите точку монтирования (по умолчанию: $MOUNT_DIR): ${NC}"
    read input_mount_dir
    echo -e "${GRAY}Введите имя RAID устройства (по умолчанию: $RAID_DEVICE): ${NC}"
    read input_raid_device

    DISK1=${input_disk1:-$DISK1}
    DISK2=${input_disk2:-$DISK2}
    MOUNT_DIR=${input_mount_dir:-$MOUNT_DIR}
    RAID_DEVICE=${input_raid_device:-$RAID_DEVICE}

    # Установка необходимых пакетов
    dnf install -y mdadm
    # Создание RAID 1 массива
    mdadm --create --verbose $RAID_DEVICE --level=1 --raid-devices=2 $DISK1 $DISK2
    if [ $? -ne 0 ]; then
        echo "Ошибка создания RAID массива. Проверьте диски $DISK1 и $DISK2."
        exit 1
    fi
    # Сохраняем конфигурацию массива в mdadm.conf
    mdadm --detail --scan >> $MDADM_CONFIG
    # Создаем файловую систему ext4
    mkfs.ext4 $RAID_DEVICE
    # Создаем точку монтирования и монтируем устройство
    mkdir -p $MOUNT_DIR
    mount $RAID_DEVICE $MOUNT_DIR
    # Обеспечиваем автоматическое монтирование через /etc/fstab
    UUID=$(blkid -s UUID -o value $RAID_DEVICE)
    echo "UUID=$UUID $MOUNT_DIR ext4 defaults 0 0" >> /etc/fstab
}

# Функция настройки NFS
configure_nfs() {
    # Запрос необходимых переменных
    echo -e "${GRAY}Введите директорию для NFS (по умолчанию: $NFS_DIR): ${NC}"
    read input_nfs_dir
    NFS_DIR=${input_nfs_dir:-$NFS_DIR}
    # Установка необходимых пакетов
    dnf install -y nfs-utils nfs4-acl-tools
    # Создаем директорию для NFS
    mkdir -p $NFS_DIR
    chmod 777 $NFS_DIR
    # Добавляем запись в /etc/exports
    echo "$NFS_DIR *(rw,sync,no_root_squash)" >> $EXPORTS_FILE
    # Перезапускаем сервис NFS
    systemctl enable nfs-server
    systemctl restart nfs-server
    # Проверяем статус сервиса
    exportfs -a
}

# Функция настройки клиента NFS
configure_nfs_client() {
    # Запрос необходимых переменных
    echo -e "${GRAY}Введите IP адрес NFS сервера (по умолчанию: $NFS_SERVER): ${NC}"
    read input_nfs_server
    echo -e "${GRAY}Введите экспортированную папку (по умолчанию: $NFS_EXPORT): ${NC}"
    read input_nfs_export
    echo -e "${GRAY}Введите точку монтирования (по умолчанию: $MOUNT_DIRNFS): ${NC}"
    read input_mount_dir
    NFS_SERVER=${input_nfs_server:-$NFS_SERVER}
    NFS_EXPORT=${input_nfs_export:-$NFS_EXPORT}
    MOUNT_DIRNFS=${input_mount_dir:-$MOUNT_DIRNFS}

    # Устанавливаем необходимые пакеты
    dnf install -y nfs-utils
    # Создаем точку монтирования
    mkdir -p $MOUNT_DIRNFS
    # Добавляем запись в /etc/fstab для автомонтирования
    if ! grep -q "$NFS_SERVER:$NFS_EXPORT" /etc/fstab; then
        echo "$NFS_SERVER:$NFS_EXPORT $MOUNT_DIRNFS nfs defaults 0 0" >> /etc/fstab
    fi
    # Монтируем экспортированную папку
    mount -a
    # Проверяем статус монтирования
    if mountpoint -q $MOUNT_DIRNFS; then
        echo "NFS успешно смонтирован в $MOUNT_DIRNFS."
    else
        echo "Ошибка монтирования NFS. Проверьте настройки."
        exit 1
    fi
}

# Функция для проверки IP и пинга
check_ip_and_ping() {
    echo "Проверка IP-адресов и доступности ya.ru..."

    # Получение всех IP-адресов
    IP_ADDRESSES=$(hostname -I)
    echo "Ваши текущие IP-адреса: $IP_ADDRESSES"

    # Проверка доступности ya.ru
    if ping -c 1 ya.ru &> /dev/null; then
        echo -e "\e[32mya.ru доступен.\e[0m"  # Зеленый текст
    else
        echo -e "\e[31mya.ru недоступен.\e[0m"  # Красный текст
    fi

    # Пауза перед возвратом в меню
    read -p "Нажмите Enter для продолжения..."
}

# Функция настройки Chrony
configure_chrony() {
    echo "Настройка Chrony..."

    # Установка Chrony
    dnf install -y chrony

    # Настройка конфигурации Chrony
    CHRONY_CONF="/etc/chrony.conf"

    # Закомментируем существующие серверы
    sed -i 's/^server ntp1.vniiftri.ru iburst/#server ntp1.vniiftri.ru iburst/' $CHRONY_CONF
    sed -i 's/^server ntp2.vniiftri.ru iburst/#server ntp2.vniiftri.ru iburst/' $CHRONY_CONF
    sed -i 's/^server ntp3.vniiftri.ru iburst/#server ntp3.vniiftri.ru iburst/' $CHRONY_CONF
    sed -i 's/^server ntp4.vniiftri.ru iburst/#server ntp4.vniiftri.ru iburst/' $CHRONY_CONF

    # Запрос локального stratum
    echo -e "${GRAY}Введите значение local stratum (например, 6): ${NC}"
    read input_local_stratum
    local_stratum=${input_local_stratum:-$local_stratum}
    # Добавление локального сервера
    echo "server 127.0.0.1 iburst prefer" >> $CHRONY_CONF
    echo "local stratum $local_stratum" >> $CHRONY_CONF

    # Запрос сетевых переменных
    echo -e "${GRAY}Введите сеть для разрешения (например, $NETWORK_Left): ${NC}"
    read input_NETWORK_Left
    echo -e "${GRAY}Введите сеть офиса (например, $NETWORK_Right): ${NC}"
    read input_NETWORK_Right
    echo -e "${GRAY}Введите сеть туннеля (например, $NETWORK_TUNNEL): ${NC}"
    read input_NETWORK_TUNNEL
    
    # Использование значений по умолчанию, если пользователь ничего не ввел
    NETWORK_Left=${input_NETWORK_Left:-$NETWORK_Left}
    NETWORK_Right=${input_NETWORK_Right:-$NETWORK_Right}
    NETWORK_TUNNEL=${input_NETWORK_TUNNEL:-$NETWORK_TUNNEL}

    # Разрешение доступа к NTP
    echo "allow $NETWORK_Left" >> $CHRONY_CONF
    echo "allow $NETWORK_Right" >> $CHRONY_CONF
    echo "allow $NETWORK_TUNNEL" >> $CHRONY_CONF

    # Перезапуск службы Chrony
    systemctl restart chronyd
    systemctl enable --now chronyd

    echo "Chrony успешно настроен."
}

# Функция настройки клиента Chrony
configure_chrony_client() {
    # Установка необходимых пакетов
    dnf install -y chrony
    # Запрос IP-адреса NTP сервера
    echo -e "${GRAY}Введите IP-адрес NTP сервера (по умолчанию: $CHRONY_SERVER): ${NC}"
    read input_CHRONY_SERVER
    CHRONY_SERVER=${input_CHRONY_SERVER:-$CHRONY_SERVER}

    # Настройка конфигурации Chrony
    sed -i "s/server ntp1.vniiftri.ru iburst/server $CHRONY_SERVER iburst/" /etc/chrony.conf
    sed -i 's/server ntp2.vniiftri.ru iburst/#server ntp2.vniiftri.ru iburst/' /etc/chrony.conf
    sed -i 's/server ntp3.vniiftri.ru iburst/#server ntp3.vniiftri.ru iburst/' /etc/chrony.conf
    sed -i 's/server ntp4.vniiftri.ru iburst/#server ntp4.vniiftri.ru iburst/' /etc/chrony.conf
    # Включение и запуск Chrony
    systemctl enable --now chronyd
    systemctl restart chronyd
}

# Функция создания backup скрипта
create_backup_script() {
    echo "Создание backup скрипта..."

    # Запрос имени директории для резервного копирования
    echo -e "${GRAY}Введите директорию для резервного копирования (например, $BACKUP_DIR): ${NC}"
    read input_backup_dir
    BACKUP_DIR=${input_backup_dir:-$BACKUP_DIR}
    mkdir -p "$BACKUP_DIR"

    # Создание скрипта резервного копирования
    BACKUP_SCRIPT="$BACKUP_DIR/backup.sh"
    cat <<EOL > "$BACKUP_SCRIPT"
#!/bin/bash

# Системная переменная с текущей датой
data=\$(date +%d.%m.%Y-%H:%M:%S)

# Создание директории с текущей датой/временем
mkdir -p /var/backup/\$data

# Копирование настроек frr
cp -r /etc/frr /var/backup/\$data

# Копирование настроек nftables
cp -r /etc/nftables /var/backup/\$data

# Копирование настроек сетевых интерфейсов
cp -r /etc/NetworkManager/system-connections /var/backup/\$data

# Копирование настроек DHCP
cp -r /etc/dhcp /var/backup/\$data

# Переход в директорию
cd /var/backup

# Архивируем
tar czfv "./\$data.tar.gz" ./\$data

# Удаляем временную директорию
rm -r /var/backup/\$data
EOL

    # Установка прав на выполнение
    chmod +x "$BACKUP_SCRIPT"

    echo "Backup скрипт создан: $BACKUP_SCRIPT"
}

# Функция установки Webmin
install_webmin() {
    echo "Установка Webmin..."

    # Установка необходимых пакетов
    dnf install -y perl perl-Net-SSLeay perl-IO-Tty
    wget -qO /etc/yum.repos.d/webmin.repo https://download.webmin.com/download/yum/webmin.repo
    rpm --import http://www.webmin.com/jcameron-key.asc
    yum install -y webmin
    # Запуск и включение службы Webmin
    systemctl enable --now webmin

    echo "Webmin успешно установлен. Доступен по адресу: https://<IP-адрес-сервера>:10000/"
}

# Функция установки Adminer
install_adminer() {
    echo "Установка Adminer..."
    dnf install -y httpd mariadb-server php php-mysqlnd php-cli wget unzip
    mkdir -p /var/www/html/adminer
    wget -qO /var/www/html/adminer/index.php https://www.adminer.org/latest.php

    echo "Настройка прав доступа для Adminer..."
    chown -R apache:apache /var/www/html/adminer
    chmod -R 755 /var/www/html/adminer

    # Настройка прав доступа
    chown -R apache:apache /var/www/html/adminer
    chmod 755 /var/www/html/adminer

    # Перезапуск Apache
    systemctl restart httpd

    echo "Adminer успешно установлен. Доступен по адресу: http://<IP-адрес-сервера>/adminer/"
}

# Функция установки WordPress
install_wordpress() {
    echo "Установка WordPress..."

    # Запрос необходимых переменных с использованием значений по умолчанию
    echo -e "${GRAY}Введите имя базы данных (по умолчанию: $DB_NAME): ${NC}"
    read input_db_name
    echo -e "${GRAY}Введите имя пользователя базы данных (по умолчанию: $DB_USER): ${NC}"
    read input_db_user
    echo -e "${GRAY}Введите пароль для пользователя базы данных (по умолчанию: $DB_PASS): ${NC}"
    read input_db_pass
    echo -e "${GRAY}Введите имя администратора WordPress (по умолчанию: $ADMIN_USER): ${NC}"
    read input_admin_user
    echo -e "${GRAY}Введите пароль администратора WordPress (по умолчанию: $ADMIN_PASS): ${NC}"
    read input_admin_pass
    echo -e "${GRAY}Введите email администратора WordPress (по умолчанию: $ADMIN_EMAIL): ${NC}"
    read input_admin_email
    echo -e "${GRAY}Введите заголовок сайта (по умолчанию: $SITE_TITLE): ${NC}"
    read input_site_title
    echo -e "${GRAY}Введите URL сайта (по умолчанию: $SITE_URL): ${NC}"
    read input_site_url

    # Использование значений по умолчанию, если пользователь ничего не ввел
    DB_NAME=${input_db_name:-$DB_NAME}
    DB_USER=${input_db_user:-$DB_USER}
    DB_PASS=${input_db_pass:-$DB_PASS}
    ADMIN_USER=${input_admin_user:-$ADMIN_USER}
    ADMIN_PASS=${input_admin_pass:-$ADMIN_PASS}
    ADMIN_EMAIL=${input_admin_email:-$ADMIN_EMAIL}
    SITE_TITLE=${input_site_title:-$SITE_TITLE}
    SITE_URL=${input_site_url:-$SITE_URL}

    # Проверка на пустые значения
    if [[ -z "$DB_NAME" || -z "$DB_USER" || -z "$DB_PASS" || -z "$ADMIN_USER" || -z "$ADMIN_PASS" || -z "$ADMIN_EMAIL" || -z "$SITE_TITLE" || -z "$SITE_URL" ]]; then
        echo "Ошибка: Все поля должны быть заполнены."
        exit 1
    fi
    # Обновление системы и установка необходимых компонентов
    echo "Обновление системы и установка пакетов..."
    dnf update -y
    dnf install -y httpd mariadb-server php php-mysqlnd php-cli wget unzip
    # Запуск и настройка Apache
    echo "Настройка и запуск Apache..."
    systemctl start httpd
    systemctl enable httpd
    # Настройка MariaDB
    echo "Настройка MariaDB..."
    systemctl start mariadb
    systemctl enable mariadb
    # Проверка и создание базы данных и пользователя
    mysql -e "CREATE DATABASE IF NOT EXISTS $DB_NAME;"
    if [ $? -ne 0 ]; then
        echo "Ошибка: Не удалось создать базу данных $DB_NAME."
        exit 1
    fi
    mysql -e "CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';"
    if [ $? -ne 0 ]; then
        echo "Ошибка: Не удалось создать пользователя $DB_USER."
        exit 1
    fi
    mysql -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';"
    if [ $? -ne 0 ]; then
        echo "Ошибка: Не удалось предоставить привилегии пользователю $DB_USER."
        exit 1
    fi

    mysql -e "FLUSH PRIVILEGES;"

    # Установка WordPress
    echo "Установка WordPress..."
    cd /var/www/html
    wget https://wordpress.org/latest.zip
    unzip latest.zip
    mv wordpress/* .
    rm -rf wordpress latest.zip
    chown -R apache:apache /var/www/html
    chmod -R 755 /var/www/html
    # Создание файла конфигурации WordPress
    echo "Настройка конфигурации WordPress..."
    cp wp-config-sample.php wp-config.php
    sed -i "s/database_name_here/$DB_NAME/" wp-config.php
    sed -i "s/username_here/$DB_USER/" wp-config.php
    sed -i "s/password_here/$DB_PASS/" wp-config.php
    # Установка WP-CLI
    echo "Установка WP-CLI..."
    curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
    chmod +x wp-cli.phar
    mv wp-cli.phar /usr/local/bin/wp
    # Завершение настройки WordPress через WP-CLI
    echo "Настройка WordPress через WP-CLI..."
    wp core install --url="$SITE_URL" --title="$SITE_TITLE" --admin_user="$ADMIN_USER" --admin_password="$ADMIN_PASS" --admin_email="$ADMIN_EMAIL" --path="/var/www/html" --allow-root
    # Добавление текста на главную страницу
    echo "Добавление текста на главную страницу..."
    wp post update 1 --post_title="$SITE_TITLE" --post_content="Добро пожаловать! Номер учебной группы: C1-21. Имя: Некрасов Павел." --path="/var/www/html" --allow-root
    # Перезапуск Apache для применения изменений
    echo "Перезапуск Apache..."
    systemctl restart httpd
    echo "Установка WordPress завершена. Перейдите по адресу $SITE_URL для проверки."
}

# Функция установки и настройки веб-сервера LMS Apache
install_lms_apache() {
    # Переменные для Moodle
    echo -e "${GRAY}Введите имя пользователя Moodle (по умолчанию: $MOODLE_USER): ${NC}"
    read input_moodle_user
    echo -e "${GRAY}Введите пароль пользователя Moodle (по умолчанию: $MOODLE_PASS): ${NC}"
    read input_moodle_pass  
    echo -e "${GRAY}Введите имя базы данных Moodle (по умолчанию: $MOODLE_DB): ${NC}"
    read input_moodle_db
    MOODLE_USER=${input_moodle_user:-$MOODLE_USER}
    MOODLE_PASS=${input_moodle_pass:-$MOODLE_PASS}
    MOODLE_DB=${input_moodle_db:-$MOODLE_DB}
    
    # Запрос пароля root для MySQL
    echo -e "${GRAY}Введите пароль root для MySQL (оставьте пустым, если пароль не установлен): ${NC}"
    read MYSQL_ROOT_PASS
    echo ""
    
    # Настройка SELinux
    sed -i 's/^SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
    setenforce 0
    # Установка веб-сервера Apache
    dnf install -y httpd
    systemctl enable httpd --now
    dnf install -y php81-release
    dnf clean all
    dnf makecache
    dnf update php*
    # Установка PHP и необходимых расширений
    echo -e "${GRAY}Установка PHP и необходимых расширений...${NC}"
    dnf install -y php php-mysqlnd php-pdo php-gd php-mbstring php-zip php-intl php-soap
    # Настройка php.ini
    echo -e "${GRAY}Настройка php.ini...${NC}"
    sed -i '8i max_input_vars=6000' /etc/php.ini
    systemctl restart httpd
    systemctl restart php-fpm
    # Установка и настройка MariaDB
    echo -e "${GRAY}Установка и настройка MariaDB...${NC}"
    dnf install -y mariadb-server mariadb
    systemctl enable mariadb --now

    # Автоматизированное выполнение mysql_secure_installation
    echo -e "${GRAY}Настройка безопасности MariaDB...${NC}"
    
    # Формируем параметр пароля для MySQL команд
    if [ -z "$MYSQL_ROOT_PASS" ]; then
        MYSQL_PWD_PARAM=""
    else
        MYSQL_PWD_PARAM="-p$MYSQL_ROOT_PASS"
    fi
    
    # Настраиваем безопасность, если пароль еще не установлен
    if [ -z "$MYSQL_ROOT_PASS" ]; then
        mysql -u root <<EOF
SET PASSWORD FOR 'root'@'localhost' = PASSWORD('$MOODLE_PASS');
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
        # Обновляем пароль после его установки
        MYSQL_ROOT_PASS=$MOODLE_PASS
        MYSQL_PWD_PARAM="-p$MYSQL_ROOT_PASS"
    else
        # Используем существующий пароль
        mysql -u root $MYSQL_PWD_PARAM <<EOF
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
    fi

    # Создание базы данных и пользователя
    echo -e "${GRAY}Создание базы данных и пользователя для LMS...${NC}"
    mysql -u root $MYSQL_PWD_PARAM -e "CREATE DATABASE $MOODLE_DB DEFAULT CHARACTER SET utf8 COLLATE utf8_unicode_ci;"
    mysql -u root $MYSQL_PWD_PARAM -e "CREATE USER '$MOODLE_USER'@'localhost' IDENTIFIED BY '$MOODLE_PASS';"
    mysql -u root $MYSQL_PWD_PARAM -e "GRANT ALL ON $MOODLE_DB.* TO '$MOODLE_USER'@'localhost';"
    mysql -u root $MYSQL_PWD_PARAM -e "FLUSH PRIVILEGES;"

    # Установка Moodle
    echo -e "${GRAY}Установка Moodle...${NC}"
    wget https://download.moodle.org/download.php/direct/stable405/moodle-latest-405.tgz -P /tmp
    tar -xzf /tmp/moodle-latest-405.tgz -C /tmp
    mv -f /tmp/moodle/{.,}* /var/www/html/
    chmod -R 0755 /var/www/html/
    chown -R apache:apache /var/www/html/
    # Создание каталога данных для Moodle
    echo -e "${GRAY}Создание каталога данных для Moodle...${NC}"
    mkdir /var/moodledata
    chown -R apache:apache /var/moodledata
    chmod -R 0755 /var/moodledata
    # Перезапуск Apache"
    systemctl restart httpd

    echo -e "${GRAY}Перейдите по адресу http://<IP-сервера>
    /var/moodledata
    mariadb родной
    $MOODLE_DB
    $MOODLE_USER
    $MOODLE_PASS${NC}"
    read -p "Нажмите Enter для продолжения..."
}

# Функция установки и настройки MediaWiki с использованием Docker
install_mediawiki() {
    # Запрос необходимых переменных с использованием значений по умолчанию
    echo -e "${GRAY}Введите порт для MediaWiki (по умолчанию: $MEDIAPORT): ${NC}"
    read input_media_port
    echo -e "${GRAY}Введите имя контейнера c базой данных (по умолчанию: $MEDIADB_NAME): ${NC}"
    read input_media_db_name
    echo -e "${GRAY}Введите название базы данных (по умолчанию: $MEDIA): ${NC}"
    read input_media
    echo -e "${GRAY}Введите имя пользователя базы данных (по умолчанию: $MEDIADB_USER): ${NC}"
    read input_media_db_user
    echo -e "${GRAY}Введите пароль для пользователя базы данных (по умолчанию: $MEDIADB_PASS): ${NC}"
    read input_media_db_pass
    MEDIAPORT=${input_media_port:-$MEDIAPORT}
    MEDIADB_NAME=${input_media_db_name:-$MEDIADB_NAME}
    MEDIA=${input_media:-$MEDIA}
    MEDIADB_USER=${input_media_db_user:-$MEDIADB_USER}
    MEDIADB_PASS=${input_media_db_pass:-$MEDIADB_PASS}
    # Установка Docker и Docker Compose
    echo "Установка Docker..."
    dnf install -y docker-ce docker-ce-cli docker-compose
    systemctl enable docker --now
    # Создание файла docker-compose.yml
    echo "Создание файла docker-compose.yml..."
    cat <<EOL > ~/wiki.yml
services:
  MediaWiki:
    container_name: wiki
    image: mediawiki
    restart: always
    ports:
      - $MEDIAPORT:80
    links:
      - database
    volumes:
      - images:/var/www/html/images
      # - ./LocalSettings.php:/var/www/html/LocalSettings.php
  database:
    container_name: $MEDIADB_NAME
    image: mariadb
    environment:
      MYSQL_DATABASE: $MEDIA
      MYSQL_USER: $MEDIADB_USER
      MYSQL_PASSWORD: $MEDIADB_PASS
      MYSQL_RANDOM_ROOT_PASSWORD: 'yes'
    volumes:
      - dbvolume:/var/lib/mariadb
volumes:
  dbvolume:
      external: true
  images:

EOL

    # Создание volume для базы данных
    docker volume create dbvolume
    # Запуск стека контейнеров
    docker-compose -f ~/wiki.yml up -d
    echo "Хост базы данных: $MEDIADB_NAME
    Имя базы данных: $MEDIA
    Имя пользователя базы данных: $MEDIADB_USER
    Пароль базы данных: $MEDIADB_PASS
    Название вики: Demo-Wiki
    nano wiki.yml
    docker-compose -f wiki.yml stop
    docker-compose -f wiki.yml up -d"
    read -p "Нажмите Enter для продолжения..."
}

# Функция установки и настройки сервера IPA
install_ipa_server() {
    echo "Установка и настройка сервера IPA..."

    # Запрос имени хоста
    echo -e "${GRAY}Введите имя хоста (по умолчанию: hq-srv.hq.work): ${NC}"
    read new_hostname
    HOSTNAME=${new_hostname:-hq-srv.hq.work}
    hostnamectl set-hostname $HOSTNAME

    # Установка необходимых пакетов
    echo "Установка необходимых пакетов..."
    dnf install -y bind bind-dyndb-ldap ipa-server ipa-server-dns ipa-server-trust-ad

    # Установка сервера IPA
    echo "Установка сервера IPA..."
    echo "Do you want to configure integrated DNS (BIND)? [no]: пишем yes"
    echo "На вопрос на какие сервера необходимо перенаправлять внешние DNS запросы - пишем нет"
    echo "Do you want to configure DNS forwarders? [yes]: пишем  no"
    echo "Do you want to search for nissing reverse zones? (yes): пишем no"
    echo "Do you want to configure chrony with NTP server or pool address? [no]: пишем no"
    echo "На вопрос создание обратной зоны для службы имен - пишем no"
    echo "Continue to configure the system with these values? [no]: пишем yes"
    ipa-server-install --mkhomedir

    # Пауза для продолжения
    read -p "!!!reboot!!! Нажмите Enter для продолжения..."

    echo "Установка и настройка сервера IPA завершены."
}

# Функция установки PostgreSQL и pgAdmin4
install_postgresql_pgadmin() {
    echo "Установка PostgreSQL и pgAdmin4..."

    # Установка необходимых пакетов
    dnf install -y postgresql15-server pgadmin4 pgadmin4-qt pgadmin4-langpack-ru httpd python3-mod_wsgi pgadmin4-httpd

    # Инициализация базы данных PostgreSQL
    postgresql-15-setup initdb

    # Запуск и включение службы PostgreSQL
    systemctl enable postgresql-15.service --now

    # Настройка прав доступа для pgAdmin4
    mkdir -p /var/log/pgadmin4/
    setsebool -P httpd_can_network_connect 1
    setsebool -P httpd_can_network_connect_db 1
    semanage fcontext -a -t httpd_sys_rw_content_t "/var/lib/pgadmin4(/.*)?"
    semanage fcontext -a -t httpd_sys_rw_content_t "/var/log/pgadmin4(/.*)?"
    restorecon -R /var/lib/pgadmin4/
    restorecon -R /var/log/pgadmin4/
    systemctl enable httpd --now

    # Настройка конфигурации pgAdmin4
    cat << EOF >> /usr/lib/pgadmin4/config_local.py 
import os
from config import *
HELP_PATH = '/usr/share/doc/pgadmin4/html/'
DATA_DIR = os.path.realpath(os.path.expanduser(u'/var/lib/pgadmin4'))
LOG_FILE = os.path.join(DATA_DIR, 'pgadmin4.log')
SQLITE_PATH = os.path.join(DATA_DIR, 'pgadmin4.db')
SESSION_DB_PATH = os.path.join(DATA_DIR, 'sessions')
STORAGE_DIR = os.path.join(DATA_DIR, 'storage')
AZURE_CREDENTIAL_CACHE_DIR = os.path.join(DATA_DIR, 'azurecredentialcache')
KERBEROS_CCACHE_DIR = os.path.join(DATA_DIR, 'krbccache')
TEST_SQLITE_PATH = os.path.join(DATA_DIR, 'test_pgadmin4.db')
EOF

    # Запрос имени пользователя и пароля для pgAdmin4
    echo -e "${GRAY}Введите email администратора pgAdmin4 (по умолчанию: $EMAIL): ${NC}"
    read input_admin_email
    while true; do
        if [[ "$input_admin_email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            EMAIL=${input_admin_email:-$EMAIL}
            break
        else
            echo "Некорректный адрес электронной почты. Пожалуйста, попробуйте снова."
        fi
    done

    echo -e "${GRAY}Введите пароль администратора pgAdmin4 (по умолчанию: $ADMIN_PASSWORD): ${NC}"
    read input_admin_password
    while true; do
        if [[ -n "$input_admin_password" ]]; then
            ADMIN_PASSWORD=${input_admin_password:-$ADMIN_PASSWORD}
            break
        else
            echo "Пароль не может быть пустым. Пожалуйста, попробуйте снова."
        fi
    done

    python /usr/lib/pgadmin4/setup.py <<EOF
$EMAIL
$ADMIN_PASSWORD
EOF

    # Настройка прав доступа
    chown -R apache:apache /var/lib/pgadmin4 /var/log/pgadmin4
    systemctl restart httpd

    # Настройка PostgreSQL
    echo "Настройка PostgreSQL..."
    sed -i '/^#listen_addresses = 'localhost'/c\listen_addresses = '*'' /var/lib/pgsql/15/data/postgresql.conf
    sed -i '1 a host all all 0.0.0.0/0 md5' /var/lib/pgsql/15/data/pg_hba.conf

    # Запрос пароля для пользователя postgres
    echo -e "${GRAY}Введите новый пароль для пользователя postgres (по умолчанию: $POSTGRES_PASSWORD): ${NC}"
    read input_postgres_password
    POSTGRES_PASSWORD=${input_postgres_password:-$POSTGRES_PASSWORD}
    if [[ -n "$POSTGRES_PASSWORD" ]]; then
        break
    else
        echo "Пароль не может быть пустым. Пожалуйста, попробуйте снова."
    fi

    su - postgres <<EOF
psql
ALTER USER postgres WITH ENCRYPTED PASSWORD '$POSTGRES_PASSWORD';
EOF

    # Перезапуск службы PostgreSQL
    systemctl restart postgresql-15.service

    echo "Установка PostgreSQL и pgAdmin4 завершена."
    echo "pgAdmin4 доступен по адресу: http://<IP-адрес-сервера>/pgadmin4"
}

# Функция установки и настройки обратного прокси-сервера Nginx
install_nginx_reverse_proxy() {
    # Запрос IP-адресов и доменных имен с использованием значений по умолчанию
    echo -e "${GRAY}Введите IP-адрес HQ-SRV(moodle) (по умолчанию: $IPHQ_SRV): ${NC}"
    read input_ip_hq
    IPHQ_SRV=${input_ip_hq:-$IPHQ_SRV}
    echo -e "${GRAY}Введите IP-адрес BR-SRV(mediwiki) (по умолчанию: $IPBR_SRV): ${NC}"
    read input_ip_br
    IPBR_SRV=${input_ip_br:-$IPBR_SRV}
    echo -e "${GRAY}Введите доменное имя для Moodle (по умолчанию: $name): ${NC}"
    read input_name
    name=${input_name:-$name}
    echo -e "${GRAY}Введите доменное имя для Wiki (по умолчанию: $name2): ${NC}"
    read input_name2
    name2=${input_name2:-$name2}
    echo -e "${GRAY}Введите порт Wiki (по умолчанию: $pp2): ${NC}"
    read input_pp2
    pp2=${input_pp2:-$pp2}
    echo -e "${GRAY}Введите порт для Moodle (по умолчанию: $pp1): ${NC}"
    read input_pp1
    pp1=${input_pp1:-$pp1}
    dnf install -y nginx
    setenforce 0
    setsebool -P httpd_can_network_connect 1
    systemctl enable --now nginx
    # Создание конфигурации Nginx
    sed -i '67d' /etc/nginx/nginx.conf
    cat << EOF >> /etc/nginx/nginx.conf
server {
        listen 80;
        server_name $name;

        location / {
            proxy_pass http://$IPHQ_SRV:$pp1;
        }
}

server {
        listen 80;
        server_name $name2;

        location / {
            proxy_pass http://$IPBR_SRV:$pp2;
        }
}
}
EOF
    # Перезапуск Nginx
    systemctl restart nginx
    systemctl enable --now nginx
}

# Функция установки и настройки rsyslog
install_rsyslog() {
    # Установка необходимых пакетов
    dnf install -y rsyslog
    sed -i "s/SELINUX=enforcing/SELINUX=permissive/" /etc/selinux/config
    setenforce 0
    systemctl enable --now rsyslog 
    # Настрока iptables
    iptables -A INPUT -p tcp --dport 514 -j ACCEPT
    iptables -A INPUT -p udp --dport 514 -j ACCEPT
    semanage port -m -t syslogd_port_t -p tcp 514
    semanage port -m -t syslogd_port_t -p udp 514
    # Включаем прием сообщений от клиентов
    sed -i 's/#module(load="imudp")/module(load="imudp")/' /etc/rsyslog.conf
    sed -i 's/#input(type="imudp" port="514")/input(type="imudp" port="514")/' /etc/rsyslog.conf
    sed -i 's/#module(load="imtcp")/module(load="imtcp")/' /etc/rsyslog.conf
    sed -i 's/#input(type="imtcp" port="514")/input(type="imtcp" port="514")/' /etc/rsyslog.conf
    sed -i '38 a \$template RemoteLogs,"/var/log/rsyslog/%HOSTNAME%/%PROGRAMNAME%.log"' /etc/rsyslog.conf
    sed -i '39 a *.* ?RemoteLogs' /etc/rsyslog.conf
    sed -i '40 a & ~' /etc/rsyslog.conf
    systemctl restart rsyslog.service
    echo "Установка и настройка rsyslog завершены."
}

# Функция настройки клиента rsyslog
configure_rsyslog_client() {
    echo "Настройка клиента rsyslog..."
    systemctl enable --now rsyslog 
    # Запрос IP-адреса сервера rsyslog
    echo -e "${GRAY}Введите IP-адрес сервера rsyslog (по умолчанию: $RSYSLOG_SERVER): ${NC}"
    read input_rsyslog_server
    RSYSLOG_SERVER=${input_rsyslog_server:-$RSYSLOG_SERVER}
    echo "auth.* @@$RSYSLOG_SERVER:514" >> /etc/rsyslog.d/auth.conf
    # Перезапуск службы rsyslog
    systemctl restart rsyslog.service
    echo "Клиент rsyslog настроен для отправки логов на сервер $RSYSLOG_SERVER."
}

# Функция установки и настройки BIND (DNS-сервер)
install_bind() {
    # Переменные конфигурации с значениями по умолчанию
    echo -e "${GRAY}Введите имя домена (по умолчанию: $DOMAIN_NAME): ${NC}"
    read input_domain_name
    DOMAIN_NAME=${input_domain_name:-$DOMAIN_NAME}
    echo -e "${GRAY}Введите внутренний IP-адрес DNS-сервера (по умолчанию: $DNS_IP): ${NC}"
    read input_dns_ip
    DNS_IP=${input_dns_ip:-$DNS_IP}
    echo -e "${GRAY}Введите сеть для разрешения запросов (по умолчанию: $ALLOWED_NETWORK): ${NC}"
    read input_allowed_network
    ALLOWED_NETWORK=${input_allowed_network:-$ALLOWED_NETWORK}
    echo -e "${GRAY}Введите адрес DNS-сервера пересылки (по умолчанию: $FORWARDER): ${NC}"
    read input_forwarder
    FORWARDER=${input_forwarder:-$FORWARDER}
    echo -e "${GRAY}Введите email администратора (по умолчанию: $ADMIN_EMAIL): ${NC}"
    read input_admin_email
    ADMIN_EMAIL=${input_admin_email:-$ADMIN_EMAIL}

dnf install -y bind bind-utils
# Создание основного конфигурационного файла
cat > /etc/named.conf << EOF
options {
    listen-on port 53 { any; };
    listen-on-v6 port 53 { none; };
    directory     "/var/named";
    dump-file     "/var/named/data/cache_dump.db";
    statistics-file "/var/named/data/named_stats.txt";
    memstatistics-file "/var/named/data/named_mem_stats.txt";
    secroots-file "/var/named/data/named.secroots";
    recursing-file "/var/named/data/named.recursing";
    allow-query     { any; };

    recursion yes;
    forwarders { ${FORWARDER}; };
    forward first;
    dnssec-validation no;

    managed-keys-directory "/var/named/dynamic";

    pid-file "/run/named/named.pid";
    session-keyfile "/run/named/session.key";
};

logging {
    channel default_debug {
        file "data/named.run";
        severity dynamic;
    };
};

zone "." IN {
    type hint;
    file "named.ca";
};

zone "${DOMAIN_NAME}" IN {
    type master;
    file "forward.${DOMAIN_NAME}";
    allow-update { none; };
};
EOF

# Извлечение первых трех октетов IP для обратной зоны
IP_OCTETS=(${DNS_IP//./ })
REVERSE_ZONE="${IP_OCTETS[2]}.${IP_OCTETS[1]}.${IP_OCTETS[0]}.in-addr.arpa"
LAST_OCTET="${IP_OCTETS[3]}"

# Добавление обратной зоны
cat >> /etc/named.conf << EOF
zone "${REVERSE_ZONE}" IN {
    type master;
    file "reverse.${DOMAIN_NAME}";
    allow-update { none; };
};
EOF

echo "Создание файла прямой зоны..."
# Создание файла прямой зоны
cat > /var/named/forward.${DOMAIN_NAME} << EOF
\$TTL 86400
@   IN SOA  ${DOMAIN_NAME}. root.${DOMAIN_NAME}. (
        $(date +%Y%m%d%H)  ; Serial
        3600        ; Refresh
        1800        ; Retry
        604800      ; Expire
        86400       ; Minimum TTL
)

    IN  NS  ${DOMAIN_NAME}.
    IN  A       ${DNS_IP}

; Записи A и CNAME из таблицы
hq-rtr          IN  A       ${DNS_IP}
br-rtr          IN  A       ${DNS_IP}
hq-srv          IN  A       ${DNS_IP}
hq-cli          IN  A       ${DNS_IP}
br-srv          IN  A       ${DNS_IP}
moodle          CNAME   hq-rtr.${DOMAIN_NAME}.
wiki            CNAME   hq-rtr.${DOMAIN_NAME}.
EOF

# Установка правильных разрешений
chown root:named /var/named/forward.${DOMAIN_NAME}
chmod 0640 /var/named/forward.${DOMAIN_NAME}
echo "Создание файла обратной зоны..."
# Создание файла обратной зоны
cat > /var/named/reverse.${DOMAIN_NAME} << EOF
\$TTL 86400
@   IN SOA  ${DOMAIN_NAME}. root.${DOMAIN_NAME}. (
        $(date +%Y%m%d%H)  ; Serial
        3600        ; Refresh
        1800        ; Retry
        604800      ; Expire
        86400       ; Minimum TTL
)

    IN  NS  ${DOMAIN_NAME}.

; Обратные записи PTR
${LAST_OCTET}    IN  PTR     hq-rtr.${DOMAIN_NAME}.
${LAST_OCTET}    IN  PTR     hq-srv.${DOMAIN_NAME}.
${LAST_OCTET}    IN  PTR     hq-cli.${DOMAIN_NAME}.
EOF

# Установка правильных разрешений
chown root:named /var/named/reverse.${DOMAIN_NAME}
chmod 640 /var/named/reverse.${DOMAIN_NAME}
echo "Настройка брандмауэра..."
# Настройка брандмауэра
if systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --add-service=dns
    firewall-cmd --reload
fi
# Запуск и включение службы
systemctl enable --now named
echo "Проверка конфигурации..."
# Проверка конфигурации
named-checkconf
if [ $? -eq 0 ]; then
    echo "Конфигурация named верна."
    systemctl restart named
    echo "DNS-сервер успешно настроен и запущен."
    echo "Тестирование DNS-сервера можно выполнить командами:"
    echo "dig @localhost hq-rtr.${DOMAIN_NAME}"
    echo "dig @localhost -x ${DNS_IP}"
else
    echo "Ошибка в конфигурации named."
fi
read -p "Нажмите Enter для продолжения..."
}

# Функция настройки RAID 5
configure_raid5() {
    echo -e "${GRAY}автоматическое монтирование в папку: (по умолчанию: $MOUNT_DIR5): ${NC}"
    read input_MOUNT_DIR5
    echo -e "${GRAY}Введите первый диск для RAID (по умолчанию: $DISK1): ${NC}"
    read input_disk1
    echo -e "${GRAY}Введите второй диск для RAID (по умолчанию: $DISK2): ${NC}"
    read input_disk2
    echo -e "${GRAY}Введите третий диск для RAID (по умолчанию: $DISK3): ${NC}"
    read input_disk3
    DISK1=${input_disk1:-$DISK1}
    DISK2=${input_disk2:-$DISK2}
    DISK3=${input_disk3:-$DISK3}
    MOUNT_DIR5=${input_MOUNT_DIR5:-$MOUNT_DIR5}
    dnf install -y mdadm
    # Создание RAID 5 массива
    mdadm --create --verbose $RAID_DEVICE --level=5 --raid-devices=3 $DISK1 $DISK2 $DISK3
    if [ $? -ne 0 ]; then
        echo "Ошибка создания RAID массива. Проверьте диски $DISK1, $DISK2 и $DISK3."
        exit 1
    fi
    # Сохраняем конфигурацию массива в mdadm.conf
    mdadm --detail --scan --verbose >> $MDADM_CONFIG
    # Создаем файловую систему ext4
    mkfs.ext4 $RAID_DEVICE
    # Создаем точку монтирования и монтируем устройство
    mkdir -p $MOUNT_DIR5
    mount $RAID_DEVICE $MOUNT_DIR5
    # Обеспечиваем автоматическое монтирование через /etc/fstab
    UUID=$(blkid -s UUID -o value $RAID_DEVICE)
    echo "UUID=$UUID $MOUNT_DIR5 ext4 defaults 0 0" >> /etc/fstab
}

# Функция настройки Ansible на сервере BR-SRV
configure_ansible() {
    # Запрос переменных у пользователя
    echo -e "${GRAY}Введите IP-адрес HQ-SRV (по умолчанию: $ANSIBLE_HQ_SRV_IP): ${NC}"
    read input_hq_srv_ip
    ANSIBLE_HQ_SRV_IP=${input_hq_srv_ip:-$ANSIBLE_HQ_SRV_IP}
    echo -e "${GRAY}Введите IP-адрес HQ-CLI (по умолчанию: $ANSIBLE_HQ_CLI_IP): ${NC}"
    read input_hq_cli_ip
    ANSIBLE_HQ_CLI_IP=${input_hq_cli_ip:-$ANSIBLE_HQ_CLI_IP}
    echo -e "${GRAY}Введите IP-адрес HQ-RTR (по умолчанию: $ANSIBLE_HQ_RTR_IP): ${NC}"
    read input_hq_rtr_ip
    ANSIBLE_HQ_RTR_IP=${input_hq_rtr_ip:-$ANSIBLE_HQ_RTR_IP}
    echo -e "${GRAY}Введите IP-адрес BR-RTR (по умолчанию: $ANSIBLE_BR_RTR_IP): ${NC}"
    read input_br_rtr_ip
    ANSIBLE_BR_RTR_IP=${input_br_rtr_ip:-$ANSIBLE_BR_RTR_IP}
    echo -e "${GRAY}Введите порт SSH (по умолчанию: $ANSIBLE_SSH_PORT): ${NC}"
    read input_ssh_port
    ANSIBLE_SSH_PORT=${input_ssh_port:-$ANSIBLE_SSH_PORT}
    echo -e "${GRAY}Введите имя пользователя для SSH (по умолчанию: $ANSIBLE_SSH_USER): ${NC}"
    read input_ssh_user
    ANSIBLE_SSH_USER=${input_ssh_user:-$ANSIBLE_SSH_USER}
    echo -e "${GRAY}Введите имя пользователя для HQ-CLI (по умолчанию: $ANSIBLE_USER_CLI): ${NC}"
    read input_user_cli
    ANSIBLE_USER_CLI=${input_user_cli:-$ANSIBLE_USER_CLI}
    echo -e "${GRAY}Введите имя пользователя для HQ-RTR и BR-RTR (по умолчанию: $ANSIBLE_USER_RTR): ${NC}"
    read input_user_rtr
    ANSIBLE_USER_RTR=${input_user_rtr:-$ANSIBLE_USER_RTR}
    # Установка Ansible
    dnf install -y ansible
    # Создание пары SSH-ключей
    echo "Создание пары SSH-ключей..."
    ssh-keygen -t rsa
    # Копирование SSH-ключей на удаленные устройства
    echo "Копирование SSH-ключей на удаленные устройства..."
    ssh-copy-id -p $ANSIBLE_SSH_PORT $ANSIBLE_SSH_USER@$ANSIBLE_HQ_SRV_IP  # HQ-SRV
    ssh-copy-id $ANSIBLE_USER_CLI@$ANSIBLE_HQ_CLI_IP  # HQ-CLI
    ssh-copy-id $ANSIBLE_USER_RTR@$ANSIBLE_HQ_RTR_IP  # HQ-RTR
    ssh-copy-id $ANSIBLE_USER_RTR@$ANSIBLE_BR_RTR_IP  # BR-RTR
    # Создание файла инвентаря
    echo "Создание файла инвентаря Ansible..."
    cat > /etc/ansible/demo << EOF
[HQ]
$ANSIBLE_HQ_SRV_IP ansible_user=$ANSIBLE_SSH_USER ansible_port=$ANSIBLE_SSH_PORT
$ANSIBLE_HQ_CLI_IP ansible_user=$ANSIBLE_USER_CLI
$ANSIBLE_HQ_RTR_IP ansible_user=$ANSIBLE_USER_RTR
$ANSIBLE_BR_RTR_IP ansible_user=$ANSIBLE_USER_RTR

[BR]
$ANSIBLE_BR_RTR_IP ansible_user=$ANSIBLE_USER_RTR
EOF
    # Настройка конфигурации Ansible
    echo "Настройка конфигурации Ansible..."
    mkdir -p /etc/ansible
    cat > /etc/ansible/ansible.cfg << EOF
[defaults]
interpreter_python = auto_silent
EOF

    # Проверка подключения
    ansible all -i /etc/ansible/demo -m ping
        # Пауза перед возвратом в меню
    echo "Проверка подключения к хостам Ansible...
    ansible all -i /etc/ansible/demo -m ping"
    read -p "Нажмите Enter для продолжения..."
}

# Функция установки и настройки SAMBA DC
install_samba_dc() {
    # Запрос имени домена с значением по умолчанию
    echo -e "${GRAY}Введите имя домена (по умолчанию: $domain_name): ${NC}"
    read input_domain_name
    domain_name=${input_domain_name:-$domain_name}
    DDDD=${domain_name^^}  # Преобразование в верхний регистр
    echo -e "${GRAY}Введите имя контроллера домена (по умолчанию: $dc_name): ${NC}"
    read input_dc_name
    dc_name=${input_dc_name:-$dc_name}
    echo -e "${GRAY}Введите IP-адрес контроллера домена (по умолчанию: $dc_ip): ${NC}"
    read input_dc_ip
    dc_ip=${input_dc_ip:-$dc_ip}
    echo -e "${GRAY}Введите пароль администратора домена (по умолчанию: $sambaps): ${NC}"
    read input_sambaps
    sambaps=${input_sambaps:-$sambaps}
    
cat > /etc/resolv.conf << EOF
nameserver 8.8.8.8 
nameserver $dc_ip
search $domain_name
EOF

    hostnamectl set-hostname $dc_name.$domain_name
    setenforce 0
    sed -i "s/SELINUX=enforcing/SELINUX=permissive/" /etc/selinux/config
    dnf install -y samba* krb5* bind
    # Создание резервной копии конфигурационных файлов
    mv /etc/samba/smb.conf /etc/samba/smb.conf.bak
    cp /etc/krb5.conf /etc/krb5.conf.bak
    chown root:named /etc/krb5.conf
    
    # Настройка файла /etc/krb5.conf
    cat > /etc/krb5.conf << EOF
includedir /etc/krb5.conf.d/

[logging]
    default = FILE:/var/log/krb5libs.log
    kdc = FILE:/var/log/krb5kdc.log
    admin_server = FILE:/var/log/kadmind.log

[libdefaults]
    dns_lookup_realm = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false
    pkinit_anchors = FILE:/etc/pki/tls/certs/ca-bundle.crt
    spake_preauth_groups = edwards25519
    dns_canonicalize_hostname = fallback
    qualify_shortname = ""
    default_realm = $DDDD
    default_ccache_name = KEYRING:persistent:%{uid}

[realms]
    $DDDD = {
    kdc = $dc_name.$domain_name
    admin_server = $dc_name.$domain_name
}

[domain_realm]
    .$domain_name = $DDDD
    $domain_name = $DDDD
EOF

cat > /etc/krb5.conf.d/crypto-policies << EOF
[libdefaults]
    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 RC4-HMAC DES-CBC-CRC DES3-CBC-SHA1 DES-CBC-MD5
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 RC4-HMAC DES-CBC-CRC DES3-CBC-SHA1 DES-CBC-MD5
    preferred_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 RC4-HMAC DES-CBC-CRC DES3-CBC-SHA1 DES-CBC-MD5
EOF

cat > /etc/named.conf << EOF
options {
listen-on port 53 { $dc_ip; };
listen-on-v6 port 53 { ::1; };
directory "/var/named";
dump-file "/var/named/data/cache_dump.db";
statistics-file "/var/named/data/named_stats.txt";
memstatistics-file "/var/named/data/named_mem_stats.txt";
secroots-file "/var/named/data/named.secroots";
recursing-file "/var/named/data/named.recursing";
allow-query { any; };
recursion yes;
dnssec-validation no;
managed-keys-directory "/var/named/dynamic";
geoip-directory "/usr/share/GeoIP";
pid-file "/run/named/named.pid";
session-keyfile "/run/named/session.key";
tkey-gssapi-keytab "/var/lib/samba/bind-dns/dns.keytab";
minimal-responses yes;
forwarders { 8.8.8.8;};
include "/etc/crypto-policies/back-ends/bind.config";
};

logging {
channel default_debug {
file "data/named.run";
severity dynamic;
};
};

zone "." IN {
type hint;
file "named.ca";
};

include "/etc/named.rfc1912.zones";
include "/etc/named.root.key";
include "/var/lib/samba/bind-dns/named.conf";
EOF
first_part=$(echo "$domain_name" | cut -d '.' -f 1)

samba-tool domain provision --realm="$domain_name" --domain="$first_part" --adminpass="$sambaps" --dns-backend=BIND9_DLZ --server-role=dc --use-rfc2307
    # Запуск и включение службы SAMBA
    testparm
    systemctl enable samba named --now
    systemctl status samba named
    # Проверка конфигурации
    testparm
read -p "Нажмите Enter для продолжения..."
}

# Функция настройки статической трансляции портов
configure_port_forwarding() {
    # Запрос IP-адреса и портов с значениями по умолчанию
    echo -e "${GRAY}Введите IP-адрес роутера для проброса порта (по умолчанию: $ip11): ${NC}"
    read input_ip11
    ip11=${input_ip11:-$ip11}
    echo -e "${GRAY}Введите порт роутера для проброса (по умолчанию: $portp): ${NC}"
    read input_portp
    echo -e "${GRAY}Введите IP-адрес сервера на кого пробросить порт  (по умолчанию: $ip22): ${NC}"
    read input_ip22
    ip22=${input_ip22:-$ip22}
    echo -e "${GRAY}Введите порт сервера для проброса (по умолчанию: $portp2): ${NC}"
    read input_portp2
    portp2=${input_portp2:-$portp2}
    # Добавление правил в существующий файл nftables
    cat >> /etc/nftables/isp.nft << EOF
# Проброс порта 80 на порт $BR_SRV_PORT на BR-SRV
table ip filter {
    chain prerouting {
        type nat hook prerouting priority filter; policy accept;
        ip daddr $ip11 tcp dport $portp dnat ip to $ip22:$portp2
    }
}
EOF

    systemctl restart nftables
}

# Функция настройки клиента для входа в домен Samba DC
join_samba_domain() {
    # Запрос имени домена
    echo -e "${GRAY}Введите имя домена (по умолчанию: $domain_name): ${NC}"
    read input_domain_name
    domain_name=${input_domain_name:-$domain_name}
    # Запрос имени контроллера домена
    echo -e "${GRAY}Введите имя контроллера домена (по умолчанию: $dc_name): ${NC}"
    read input_dc_name
    dc_name=${input_dc_name:-$dc_name}
    echo -e "${GRAY}Введите IP-адрес контроллера домена (по умолчанию: $dc_ip): ${NC}"
    read input_dc_ip
    dc_ip=${input_dc_ip:-$dc_ip}

cat > /etc/resolv.conf << EOF
nameserver $dc_ip
search $domain_name
EOF
    echo "$dc_ip $dc_name.$domain_name $dc_name" >> /etc/hosts
    join-to-domain.sh
    read -p "Нажмите Enter для продолжения..."
}

# Функция настройки RAID 0
configure_raid0() {
    # Запрос необходимых переменных
    echo -e "${GRAY}Введите первый диск для RAID (по умолчанию: $DISK1): ${NC}"
    read input_disk1
    echo -e "${GRAY}Введите второй диск для RAID (по умолчанию: $DISK2): ${NC}"
    read input_disk2
    echo -e "${GRAY}Введите точку монтирования (по умолчанию: $MOUNT_DIR): ${NC}"
    read input_mount_dir
    echo -e "${GRAY}Введите имя RAID устройства (по умолчанию: $RAID_DEVICE): ${NC}"
    read input_raid_device

    DISK1=${input_disk1:-$DISK1}
    DISK2=${input_disk2:-$DISK2}
    MOUNT_DIR=${input_mount_dir:-$MOUNT_DIR}
    RAID_DEVICE=${input_raid_device:-$RAID_DEVICE}

    # Установка необходимых пакетов
    dnf install -y mdadm
    # Создание RAID 0 массива
    mdadm --create --verbose $RAID_DEVICE --level=0 --raid-devices=2 $DISK1 $DISK2
    if [ $? -ne 0 ]; then
        echo "Ошибка создания RAID массива. Проверьте диски $DISK1 и $DISK2."
        exit 1
    fi
    # Сохраняем конфигурацию массива в mdadm.conf
    mdadm --detail --scan >> $MDADM_CONFIG
    # Создаем файловую систему ext4
    mkfs.ext4 $RAID_DEVICE
    # Создаем точку монтирования и монтируем устройство
    mkdir -p $MOUNT_DIR
    mount $RAID_DEVICE $MOUNT_DIR
    # Обеспечиваем автоматическое монтирование через /etc/fstab
    UUID=$(blkid -s UUID -o value $RAID_DEVICE)
    echo "UUID=$UUID $MOUNT_DIR ext4 defaults 0 0" >> /etc/fstab
}

# Функция добавления пользователей и групп SAMBA
add_samba_users_and_groups() {
    echo "Добавление пользователей и групп в SAMBA DC..."
    # Запрос имени домена с значением по умолчанию
    echo -e "${GRAY}Введите имя домена (например, hq для user1.hq): ${NC}"
    read samba_user_domain_suffix
    samba_user_domain_suffix=${samba_user_domain_suffix:-hq}

    samba-tool user add user1.$samba_user_domain_suffix QWEasd11
    samba-tool user add user2.$samba_user_domain_suffix QWEasd11
    samba-tool user add user3.$samba_user_domain_suffix QWEasd11
    samba-tool user add user4.$samba_user_domain_suffix QWEasd11
    samba-tool user add user5.$samba_user_domain_suffix QWEasd11
    samba-tool group add $samba_user_domain_suffix
    samba-tool group addmembers $samba_user_domain_suffix user1.$samba_user_domain_suffix,user2.$samba_user_domain_suffix,user3.$samba_user_domain_suffix,user4.$samba_user_domain_suffix,user5.$samba_user_domain_suffix
    samba-tool user list
    echo "Пользователи и группы SAMBA добавлены."
    read -p "Нажмите Enter для продолжения..."
}

# Функция добавления пользователей SAMBA из CSV
add_samba_users_from_csv() {
    echo "Добавление пользователей SAMBA из CSV файла..."
    echo -e "${GRAY}Введите путь к CSV файлу (по умолчанию: /opt/Users.csv): ${NC}"
    read FILE_PATH
    FILE_PATH=${FILE_PATH:-/opt/Users.csv} # Use default if no input

    if [ ! -f "$FILE_PATH" ]; then
        echo "Файл $FILE_PATH не найден!"
        read -p "Нажмите Enter для продолжения..."
        return 1
    fi

    while IFS=';' read -r firstname lastname role phone ou street zip city country password; do
        # Пропускаем первую строку (заголовки), если она есть
        if [[ "$firstname" == "firstname" && "$lastname" == "lastname" ]]; then
            continue
        fi
        echo "Добавление пользователя: $firstname.$lastname"
        samba-tool user add "$firstname.$lastname" "$password"
        # Здесь можно добавить дополнительные команды, например, добавление пользователя в группу
        # samba-tool group addmembers "$ou" "$firstname.$lastname"
    done < <(tail -n +1 "$FILE_PATH") # tail -n +1 to process all lines including the first if it's data

    echo "Пользователи SAMBA из CSV файла добавлены."
    read -p "Нажмите Enter для продолжения..."
}

# Функция создания файла sudoers для группы hq
create_sudoers_hq() {
    echo "Создание файла sudoers для группы hq..."
    
    # Создаем файл с правилами sudo
    cat > /etc/sudoers.d/hq << EOF
%hq ALL=(ALL) NOPASSWD:/usr/bin/cat, /usr/bin/grep, /usr/bin/id
EOF

    echo "Файл /etc/sudoers.d/hq успешно создан."
    echo "Пользователи группы hq могут выполнять команды cat, grep и id с правами sudo без пароля."
}

# --- New Task Functions ---
isp() {
    configure_hostname
    configure_timezone
    configure_nftables
    clear
    exit 0
}

hq-rtr() {
    configure_hostname
    configure_timezone
    configure_nftables
    configure_dhcp
    configure_frr
    configure_gre
    configure_user
    clear
    exit 0
}

br-rtr() {
    configure_hostname
    configure_timezone
    configure_nftables
    configure_frr
    configure_gre
    configure_user
    clear
    exit 0
}

hq-srv() {
    configure_hostname
    configure_timezone
    configure_user
    configure_ssh
    install_bind
    clear
    exit 0
}

cli() {
    configure_hostname
    configure_timezone
    clear
    exit 0
}

br-srv() {
    configure_hostname
    configure_timezone
    configure_user
    configure_ssh
    clear
    exit 0
}

hq-rtr2() {
    configure_chrony
    install_nginx_reverse_proxy
    configure_port_forwarding
    clear
    exit 0
}

br-rtr2() {
    configure_chrony_client
    clear
    exit 0
}

hq-srv2() {
    configure_chrony_client
    install_lms_apache
    configure_nfs
    clear
    exit 0
}

cli2() {
    configure_chrony_client
    configure_nfs_client
    create_sudoers_hq
    clear
    exit 0
}

br-srv2() {
    configure_chrony_client
    install_mediawiki
    configure_ansible
    install_samba_dc
    add_samba_users_and_groups
    add_samba_users_from_csv
    configure_port_forwarding
    clear
    exit 0
}

# --- Main execution ---
if [ -n "$1" ]; then
    case "$1" in
        -isp)
            isp
            ;;
        -hq-rtr)
            hq-rtr
            ;;
        -br-rtr)
            br-rtr
            ;;
        -hq-srv)
            hq-srv
            ;;
        -cli)
            cli
            ;;
        -br-srv)
            br-srv
            ;;
        -hq-rtr2)
            hq-rtr2
            ;;
        -br-rtr2)
            br-rtr2
            ;;
        -hq-srv2)
            hq-srv2
            ;;
        -cli2)
            cli2
            ;;
        -br-srv2)
            br-srv2
            ;;
        *)
            echo "Usage: $0 [--run_task_N]"
            echo "Available tasks: --isp to --isp2"
            echo "If no task is specified, no operation will be performed beyond this message."
            ;;
    esac
else
    echo "юзай --"
fi

# Основной цикл меню
while true; do
    show_menu
    # Use the same gray color for the prompt
    GRAY='\033[90m'
    NC='\033[0m'
    echo -en "${GRAY}Выберите пункт меню (1-38): ${NC}"
    read choice
    # Очистка экрана после выбора
    clear
    
    case $choice in
        1) configure_hostname; return_to_menu ;;
        2) configure_network; return_to_menu ;;
        3) configure_timezone; return_to_menu ;;
        4) configure_nftables; return_to_menu ;;
        5) configure_dhcp; return_to_menu ;;
        6) configure_gre; return_to_menu ;;
        7) configure_frr; return_to_menu ;;
        8) configure_user; return_to_menu ;;
        9) configure_ssh; return_to_menu ;;
        10) configure_cups; return_to_menu ;;
        11) configure_cups_client; return_to_menu ;;
        12) configure_nfs; return_to_menu ;;
        13) configure_nfs_client; return_to_menu ;;
        14) configure_chrony; return_to_menu ;;
        15) configure_chrony_client; return_to_menu ;;
        16) install_postgresql_pgadmin; return_to_menu ;;
        17) create_backup_script; return_to_menu ;;
        18) install_webmin; return_to_menu ;;
        19) install_adminer; return_to_menu ;;
        20) install_wordpress; return_to_menu ;;
        21) install_lms_apache; return_to_menu ;;
        22) install_mediawiki; return_to_menu ;;
        23) install_ipa_server; return_to_menu ;;
        24) install_nginx_reverse_proxy; return_to_menu ;;
        25) install_rsyslog; return_to_menu ;;
        26) configure_rsyslog_client; return_to_menu ;;
        27) install_bind; return_to_menu ;;
        28) configure_raid0; return_to_menu ;;
        29) configure_raid1; return_to_menu ;;
        30) configure_raid5; return_to_menu ;;
        31) check_ip_and_ping; return_to_menu ;;
        32) configure_ansible; return_to_menu ;;
        33) install_samba_dc; return_to_menu ;;
        34) join_samba_domain; return_to_menu ;;
        35) configure_port_forwarding; return_to_menu ;;
        36) add_samba_users_and_groups; return_to_menu ;;
        37) add_samba_users_from_csv; return_to_menu ;;
        38) create_sudoers_hq; return_to_menu ;;
        39) clear; echo "Выход из программы..."; exit 0 ;;
        *) echo "Неверный выбор."; return_to_menu ;;
    esac
done