#!/bin/bash

# Функция для отображения меню
show_menu() {
    clear
    echo "1. Настроить имя хоста"
    echo "2. Настроить сетевые интерфейсы"
    echo "3. Настроить часовой пояс"
    echo "4. Установить и настроить nftables"
    echo "5. Настроить DHCP сервер"
    echo "6. Настроить GRE туннель"
    echo "7. Настроить FRR (OSPF)"
    echo "8. Создать системного пользователя"
    echo "9. Настроить SSH"
    echo "10. Настроить NFS"
    echo "11. Настроить клиента NFS"
    echo "12. Настроить Chrony"
    echo "13. Настроить клиента Chrony"
    echo "14. Установить LMS Apache"
    echo "15. Установить MediaWiki"
    echo "16. Установить обратный прокси-сервер Nginx"
    echo "17. Установить и настроить BIND"
    echo "18. Настроить RAID0"
    echo "19. Настроить RAID1"
    echo "20. Настроить RAID5"
    echo "21. Проверка IP и пинга"
    echo "22. Настроить Ansible"
    echo "23. Установить и настроить SAMBA DC"
    echo "24. Войти в SAMBA DC"
    echo "25. Настроить статическую трансляцию портов"
    echo "26. Выход"
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
# клиент cups
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
FORWARDER="8.8.8.8"
ADMIN_EMAIL="admin.${DOMAIN_NAME}."
# Переменные для Ansible
ANSIBLE_HQ_SRV_IP="192.168.100.2"
ANSIBLE_HQ_CLI_IP="192.168.100.3"
ANSIBLE_HQ_RTR_IP="172.16.4.2"
ANSIBLE_BR_RTR_IP="172.16.5.2"
ANSIBLE_SSH_PORT="2024"
ANSIBLE_SSH_USER="sshuser"
ANSIBLE_USER_CLI="user"
ANSIBLE_USER_RTR="net_admin"
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
    read -p "Введите новое имя хоста (по умолчанию: $HOSTNAME): " new_hostname
    HOSTNAME=${new_hostname:-$HOSTNAME}
    hostnamectl set-hostname $HOSTNAME
    echo "Имя хоста обновлено на $HOSTNAME."
}

# Функция настройки сетевых интерфейсов
configure_network() {
    echo "Настройка сетевых интерфейсов"
    read -p "Введите имя интерфейса 1 (по умолчанию: $INTERFACE_1): " new_if1
    read -p "Введите имя интерфейса 2 (по умолчанию: $INTERFACE_2): " new_if2
    read -p "Введите имя интерфейса 3 (по умолчанию: $INTERFACE_3): " new_if3
    read -p "Введите IP-адрес для интерфейса 2 (по умолчанию: $IP2): " new_ip2
    read -p "Введите IP-адрес для интерфейса 3 (по умолчанию: $IP3): " new_ip3

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
    read -p "Введите новый часовой пояс (по умолчанию: $TIMEZONE): " new_timezone
    TIMEZONE=${new_timezone:-$TIMEZONE}
    timedatectl set-timezone $TIMEZONE
    echo "Часовой пояс обновлен на $TIMEZONE."
}

# Функция настройки nftables
configure_nftables() {
    # Получение имени первого интерфейса в системе
    INTERFACE_1=$(ip -o link show | awk -F': ' '{print $2}' | grep -v 'lo' | head -n 1)
    read -p "Установить и настроить nftables? (y/n): " choice
    case "$choice" in 
        y|Y ) 
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
            ;;
        * ) echo "Настройка nftables отменена.";;
    esac
}

# Функция настройки DHCP
configure_dhcp() {
    echo "Настройка параметров DHCP сервера"
    read -p "Введите подсеть (по умолчанию: $DHCP_SUBNET): " new_subnet
    read -p "Введите маску подсети (по умолчанию: $DHCP_NETMASK): " new_netmask
    read -p "Введите диапазон адресов (по умолчанию: $DHCP_RANGE): " new_range
    read -p "Введите адрес маршрутизатора (по умолчанию: $DHCP_ROUTER): " new_router
    read -p "Введите адрес DNS сервера (по умолчанию: $DHCP_DNS): " new_dns
    read -p "Введите доменное имя (по умолчанию: $DHCP_DOMAIN): " new_domain

    DHCP_SUBNET=${new_subnet:-$DHCP_SUBNET}
    DHCP_NETMASK=${new_netmask:-$DHCP_NETMASK}
    DHCP_RANGE=${new_range:-$DHCP_RANGE}
    DHCP_ROUTER=${new_router:-$DHCP_ROUTER}
    DHCP_DNS=${new_dns:-$DHCP_DNS}
    DHCP_DOMAIN=${new_domain:-$DHCP_DOMAIN}

    # Применение настроек DHCP
    dnf install dhcp-server -y
    echo "Настройка DHCP..."
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
    echo "DHCP настроен."
}

# Функция настройки GRE туннеля
configure_gre() {
    echo "Настройка параметров GRE туннеля"
    read -p "Введите локальный IP (по умолчанию: $LOCAL_IP): " new_local_ip
    read -p "Введите удаленный IP (по умолчанию: $REMOTE_IP): " new_remote_ip
    read -p "Введите локальный IP туннеля (по умолчанию: $TUNNEL_LOCAL_IP): " new_tunnel_local_ip
    read -p "Введите удаленный IP туннеля (по умолчанию: $TUNNEL_REMOTE_IP): " new_tunnel_remote_ip
    read -p "Введите имя туннеля (по умолчанию: $TUNNEL_NAME): " new_tunnel_name

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
    echo "GRE туннель настроен."
}

# Функция настройки пользователя
configure_user() {
    echo "Настройка системного пользователя"
    read -p "Введите имя пользователя (по умолчанию: $USERNAME_NET): " new_username
    read -p "Введите пароль (по умолчанию: $PASSWORD_NET): " new_password
    read -p "Введите ID пользователя (по умолчанию: $USER_ID): " new_user_id

    USERNAME_NET=${new_username:-$USERNAME_NET}
    PASSWORD_NET=${new_password:-$PASSWORD_NET}
    USER_ID=${new_user_id:-$USER_ID}

    # Применение настроек пользователя
    useradd -m -s /bin/bash -u "$USER_ID" "$USERNAME_NET"
    echo "$USERNAME_NET:$PASSWORD_NET" | chpasswd
    usermod -aG wheel "$USERNAME_NET"
    echo "$USERNAME_NET ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$USERNAME_NET"
    echo "Пользователь $USERNAME_NET создан."
}

# Функция настройки SSH
configure_ssh() {
    # Запрос необходимых переменных
    read -p "Введите порт SSH (по умолчанию: $PORT_SSH): " new_port
    read -p "Введите имя пользователя для SSH (по умолчанию: $USERNAME_SSH): " new_username
    read -p "Введите максимальное количество попыток входа (по умолчанию: $POPITKA): " new_max_auth_tries
    read -p "Введите время ожидания входа (по умолчанию: 5m): " new_login_grace_time

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
    read -p "Введите имя интерфейса для OSPF (по умолчанию: $TUNNEL_NAME): " new_tunnel_name
    read -p "Введите пароль для OSPF аутентификации: " ospf_password
    read -p "Введите сеть для OSPF (по умолчанию: $NETWORK_Left): " new_network_left
    read -p "Введите вторую сеть для OSPF (по умолчанию: $NETWORK_2): " new_network_2

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

# Функция настройки RAID
configure_raid1() {
    # Запрос необходимых переменных
    read -p "Введите первый диск для RAID (по умолчанию: $DISK1): " input_disk1
    read -p "Введите второй диск для RAID (по умолчанию: $DISK2): " input_disk2
    read -p "Введите точку монтирования (по умолчанию: $MOUNT_DIR): " input_mount_dir
    read -p "Введите имя RAID устройства (по умолчанию: $RAID_DEVICE): " input_raid_device

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
    read -p "Введите директорию для NFS (по умолчанию: $NFS_DIR): " input_nfs_dir
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
    read -p "Введите IP адрес NFS сервера (по умолчанию: $NFS_SERVER): " input_nfs_server
    read -p "Введите экспортированную папку (по умолчанию: $NFS_EXPORT): " input_nfs_export
    read -p "Введите точку монтирования (по умолчанию: $MOUNT_DIRNFS): " input_mount_dir
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
    read -p "Введите значение local stratum (например, 6): " input_local_stratum
    local_stratum=${input_local_stratum:-$local_stratum}
    # Добавление локального сервера
    echo "server 127.0.0.1 iburst prefer" >> $CHRONY_CONF
    echo "local stratum $local_stratum" >> $CHRONY_CONF

    # Запрос сетевых переменных
    read -p "Введите сеть для разрешения (например, $NETWORK_Left): " input_NETWORK_Left
    read -p "Введите сеть офиса (например, $NETWORK_Right): " input_NETWORK_Right
    read -p "Введите сеть туннеля (например, $NETWORK_TUNNEL): " input_NETWORK_TUNNEL
    
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
    read -p "Введите IP-адрес NTP сервера (по умолчанию: $CHRONY_SERVER): " input_CHRONY_SERVER
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

# Функция установки и настройки веб-сервера LMS Apache
install_lms_apache() {
    # Переменные для Moodle
    read -p "Введите имя пользователя Moodle (по умолчанию: $MOODLE_USER): " input_moodle_user
    read -p "Введите пароль пользователя Moodle (по умолчанию: $MOODLE_PASS): " input_moodle_pass  
    read -p "Введите имя базы данных Moodle (по умолчанию: $MOODLE_DB): " input_moodle_db
    MOODLE_USER=${input_moodle_user:-$MOODLE_USER}
    MOODLE_PASS=${input_moodle_pass:-$MOODLE_PASS}
    MOODLE_DB=${input_moodle_db:-$MOODLE_DB}
    # Настройка SELinux
    sed -i 's/^SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
    setenforce 0
    # Установка веб-сервера Apache
    dnf install -y httpd
    systemctl enable httpd --now
    dnf install -y php83-release
    dnf clean all
    dnf makecache
    dnf update php*
    # Установка PHP и необходимых расширений
    echo "Установка PHP и необходимых расширений..."
    dnf install -y php php-mysqlnd php-pdo php-gd php-mbstring php-zip php-intl php-soap
    # Настройка php.ini
    echo "Настройка php.ini..."
    sed -i '8i max_input_vars=6000' /etc/php.ini
    systemctl restart httpd
    systemctl restart php-fpm
    # Установка и настройка MariaDB
    echo "Установка и настройка MariaDB..."
    dnf install -y mariadb-server mariadb
    systemctl enable mariadb --now

    mysql_secure_installation

    # Создание базы данных и пользователя
    echo "Создание базы данных и пользователя для LMS..."
    mysql -e "CREATE DATABASE $MOODLE_DB DEFAULT CHARACTER SET utf8 COLLATE utf8_unicode_ci;"
    mysql -e "CREATE USER '$MOODLE_USER'@'localhost' IDENTIFIED BY '$MOODLE_PASS';"
    mysql -e "GRANT ALL ON $MOODLE_DB.* TO '$MOODLE_USER'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"
    # Установка Moodle
    echo "Установка Moodle..."
    wget https://packaging.moodle.org/stable405/moodle-latest-405.tgz -P /tmp
    tar -xzf /tmp/moodle-latest-405.tgz -C /tmp
    mv -f /tmp/moodle/{.,}* /var/www/html/
    chmod -R 0755 /var/www/html/
    chown -R apache:apache /var/www/html/
    # Создание каталога данных для Moodle
    echo "Создание каталога данных для Moodle..."
    mkdir /var/moodledata
    chown -R apache:apache /var/moodledata
    chmod -R 0755 /var/moodledata
    # Перезапуск Apache"
    systemctl restart httpd

    echo "Перейдите по адресу http://<IP-сервера>
    /var/moodledata
    mariadb родной
    $MOODLE_DB
    $MOODLE_USER
    $MOODLE_PASS"
    read -p "Нажмите Enter для продолжения..."
}

# Функция установки и настройки MediaWiki с использованием Docker
install_mediawiki() {
    # Запрос необходимых переменных с использованием значений по умолчанию
    read -p "Введите порт для MediaWiki (по умолчанию: $MEDIAPORT): " input_media_port
    read -p "Введите имя контейнера c базой данных (по умолчанию: $MEDIADB_NAME): " input_media_db_name
    read -p "Введите название базы данных (по умолчанию: $MEDIA): " input_media
    read -p "Введите имя пользователя базы данных (по умолчанию: $MEDIADB_USER): " input_media_db_user
    read -p "Введите пароль для пользователя базы данных (по умолчанию: $MEDIADB_PASS): " input_media_db_pass
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
      - dbvolume:/var/lib/mysql
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

# Функция установки и настройки обратного прокси-сервера Nginx
install_nginx_reverse_proxy() {
    # Запрос IP-адресов и доменных имен с использованием значений по умолчанию
    read -p "Введите IP-адрес HQ-SRV(moodle) (по умолчанию: $IPHQ_SRV): " input_ip_hq
    IPHQ_SRV=${input_ip_hq:-$IPHQ_SRV}
    read -p "Введите IP-адрес BR-SRV(mediwiki) (по умолчанию: $IPBR_SRV): " input_ip_br
    IPBR_SRV=${input_ip_br:-$IPBR_SRV}
    read -p "Введите доменное имя для Moodle (по умолчанию: $name): " input_name
    name=${input_name:-$name}
    read -p "Введите доменное имя для Wiki (по умолчанию: $name2): " input_name2
    name2=${input_name2:-$name2}
    read -p "Введите порт Wiki (по умолчанию: $pp2): " input_pp2
    pp2=${input_pp2:-$pp2}
    read -p "Введите порт для Moodle (по умолчанию: $pp1): " input_pp1
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

# Функция установки и настройки BIND (DNS-сервер)
install_bind() {
    # Переменные конфигурации с значениями по умолчанию
    read -p "Введите имя домена (по умолчанию: $DOMAIN_NAME): " input_domain_name
    DOMAIN_NAME=${input_domain_name:-$DOMAIN_NAME}
    read -p "Введите внутренний IP-адрес DNS-сервера (по умолчанию: $DNS_IP): " input_dns_ip
    DNS_IP=${input_dns_ip:-$DNS_IP}
    read -p "Введите сеть для разрешения запросов (по умолчанию: $ALLOWED_NETWORK): " input_allowed_network
    ALLOWED_NETWORK=${input_allowed_network:-$ALLOWED_NETWORK}
    read -p "Введите адрес DNS-сервера пересылки (по умолчанию: $FORWARDER): " input_forwarder
    FORWARDER=${input_forwarder:-$FORWARDER}
    read -p "Введите email администратора (по умолчанию: $ADMIN_EMAIL): " input_admin_email
    ADMIN_EMAIL=${input_admin_email:-$ADMIN_EMAIL}

dnf install -y bind bind-utils
# Создание основного конфигурационного файла
cat > /etc/named.conf << EOF
options {
    listen-on port 53 { $DNS_IP; };
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
moodle          IN  CNAME   hq-rtr
wiki            IN  CNAME   hq-rtr
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
systemctl enable named
systemctl start named
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
    read -p "автоматическое монтирование в папку: (по умолчанию: $MOUNT_DIR5): " input_MOUNT_DIR5
    read -p "Введите первый диск для RAID (по умолчанию: $DISK1): " input_disk1
    read -p "Введите второй диск для RAID (по умолчанию: $DISK2): " input_disk2
    read -p "Введите третий диск для RAID (по умолчанию: $DISK3): " input_disk3
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
    read -p "Введите IP-адрес HQ-SRV (по умолчанию: $ANSIBLE_HQ_SRV_IP): " input_hq_srv_ip
    ANSIBLE_HQ_SRV_IP=${input_hq_srv_ip:-$ANSIBLE_HQ_SRV_IP}
    read -p "Введите IP-адрес HQ-CLI (по умолчанию: $ANSIBLE_HQ_CLI_IP): " input_hq_cli_ip
    ANSIBLE_HQ_CLI_IP=${input_hq_cli_ip:-$ANSIBLE_HQ_CLI_IP}
    read -p "Введите IP-адрес HQ-RTR (по умолчанию: $ANSIBLE_HQ_RTR_IP): " input_hq_rtr_ip
    ANSIBLE_HQ_RTR_IP=${input_hq_rtr_ip:-$ANSIBLE_HQ_RTR_IP}
    read -p "Введите IP-адрес BR-RTR (по умолчанию: $ANSIBLE_BR_RTR_IP): " input_br_rtr_ip
    ANSIBLE_BR_RTR_IP=${input_br_rtr_ip:-$ANSIBLE_BR_RTR_IP}
    read -p "Введите порт SSH (по умолчанию: $ANSIBLE_SSH_PORT): " input_ssh_port
    ANSIBLE_SSH_PORT=${input_ssh_port:-$ANSIBLE_SSH_PORT}
    read -p "Введите имя пользователя для SSH (по умолчанию: $ANSIBLE_SSH_USER): " input_ssh_user
    ANSIBLE_SSH_USER=${input_ssh_user:-$ANSIBLE_SSH_USER}
    read -p "Введите имя пользователя для HQ-CLI (по умолчанию: $ANSIBLE_USER_CLI): " input_user_cli
    ANSIBLE_USER_CLI=${input_user_cli:-$ANSIBLE_USER_CLI}
    read -p "Введите имя пользователя для HQ-RTR и BR-RTR (по умолчанию: $ANSIBLE_USER_RTR): " input_user_rtr
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
    read -p "Введите имя домена (по умолчанию: $domain_name): " input_domain_name
    domain_name=${input_domain_name:-$domain_name}
    DDDD=${domain_name^^}  # Преобразование в верхний регистр
    read -p "Введите имя контроллера домена (по умолчанию: $dc_name): " input_dc_name
    dc_name=${input_dc_name:-$dc_name}
    read -p "Введите IP-адрес контроллера домена (по умолчанию: $dc_ip): " input_dc_ip
    dc_ip=${input_dc_ip:-$dc_ip}
    read -p "Введите пароль администратора домена (по умолчанию: $sambaps): " input_sambaps
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
    read -p "Введите IP-адрес роутера для проброса порта (по умолчанию: $ip11): " input_ip11
    ip11=${input_ip11:-$ip11}
    read -p "Введите порт роутера для проброса (по умолчанию: $portp): " input_portp
    portp=${input_portp:-$portp}
    read -p "Введите IP-адрес сервера на кого пробросить порт  (по умолчанию: $ip22): " input_ip22
    ip22=${input_ip22:-$ip22}
    read -p "Введите порт сервера для проброса (по умолчанию: $portp2): " input_portp2
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
    read -p "Введите имя домена (по умолчанию: $domain_name): " input_domain_name
    domain_name=${input_domain_name:-$domain_name}
    # Запрос имени контроллера домена
    read -p "Введите имя контроллера домена (по умолчанию: $dc_name): " input_dc_name
    dc_name=${input_dc_name:-$dc_name}
    read -p "Введите IP-адрес контроллера домена (по умолчанию: $dc_ip): " input_dc_ip
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
    read -p "Введите первый диск для RAID (по умолчанию: $DISK1): " input_disk1
    read -p "Введите второй диск для RAID (по умолчанию: $DISK2): " input_disk2
    read -p "Введите точку монтирования (по умолчанию: $MOUNT_DIR): " input_mount_dir
    read -p "Введите имя RAID устройства (по умолчанию: $RAID_DEVICE): " input_raid_device

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


# Основной цикл меню
while true; do
    show_menu
    read -p "Выберите пункт меню (1-26): " choice
    case $choice in
        1) configure_hostname ;;
        2) configure_network ;;
        3) configure_timezone ;;
        4) configure_nftables ;;
        5) configure_dhcp ;;
        6) configure_gre ;;
        7) configure_frr ;;
        8) configure_user ;;
        9) configure_ssh ;;
        10) configure_nfs ;;
        11) configure_nfs_client ;;
        12) configure_chrony ;;
        13) configure_chrony_client ;;
        14) install_lms_apache ;;
        15) install_mediawiki ;;
        16) install_nginx_reverse_proxy ;;
        17) install_bind ;;
        18) configure_raid0 ;;
        19) configure_raid1 ;;
        20) configure_raid5 ;;
        21) check_ip_and_ping ;;
        22) configure_ansible ;;
        23) install_samba_dc ;;
        24) join_samba_domain ;;
        25) configure_port_forwarding ;;
        26) echo "Выход из программы..."; exit 0 ;;
        *) echo "Неверный выбор. Нажмите Enter для продолжения..."; read ;;
    esac
done