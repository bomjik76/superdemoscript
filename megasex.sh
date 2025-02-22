#!/bin/bash

# Функция для отображения меню
show_menu() {
    clear
    echo "============================================"
    echo "                  DEMOEBLAN                 "
    echo "============================================"
    echo "1. Настроить имя хоста"
    echo "2. Настроить сетевые интерфейсы"
    echo "3. Настроить часовой пояс"
    echo "4. Установить и настроить nftables"
    echo "5. Настроить DHCP сервер"
    echo "6. Настроить GRE туннель"
    echo "7. Настроить FRR (OSPF)"
    echo "8. Создать системного пользователя"
    echo "9. Настроить SSH"
    echo "10. Настроить CUPS"
    echo "11. Настроить RAID"
    echo "12. Настроить NFS"
    echo "13. Проверка IP и пинга ya.ru"
    echo "14. Настроить Chrony"
    echo "15. Создать backup скрипт"
    echo "16. Установить Webmin"
    echo "17. Установить Adminer"
    echo "18. Установить WordPress"
    echo "19. Установить LMS Apache"
    echo "20. Установить MediaWiki"
    echo "21. Выход"
    echo "============================================"
}

# Переменные по умолчанию
HOSTNAME="isp"
INTERFACE_1="enp0s3"
INTERFACE_2="enp0s8"
INTERFACE_3="enp0s9"
IP2="22.22.22.1/28"
IP3="11.11.0.1/27"
TIMEZONE="Europe/Moscow"

# Дополнительные переменные по умолчанию
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
NETWORK_Left="192.168.1.0/27"
NETWORK_Right="172.16.0.0/24"
NETWORK_2="192.168.2.0/29"
NETWORK_TUNNEL="10.10.10.0/30"

# Параметры пользователя
USERNAME_NET="net_user"
PASSWORD_NET="P@\$\$word"
USER_ID="1111"
USERNAME_SSH="ssh_user"
PASSWORD_SSH="P@ssw0rd"
USER_ID_SSH="1030"

# Добавляем новые переменные
PORT_SSH=2222
POPITKA=3
BANNER_PATH="/etc/ssh-banner"

BACKUP_DIR=/var/backup
# Переменные
DB_NAME="wordpress"
DB_USER="wpuser"
DB_PASS="P@ssw0rd"
ADMIN_USER="Admin"
ADMIN_PASS="P@ssw0rd"
ADMIN_EMAIL="admin@example.com"
SITE_TITLE="C1-21 - Pavel"
SITE_URL="http://192.168.220.5"

# Функция настройки имени хоста
configure_hostname() {
    echo "Текущее имя хоста: $HOSTNAME"
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
    echo "Настройка SSH"
    
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

    echo "Настройка SSH завершена."
}

# Функция настройки FRR
configure_frr() {
    echo "Настройка FRR с OSPF"
    
    # Запрос необходимых переменных
    read -p "Введите имя хоста для FRR (по умолчанию: $HOSTNAME): " new_hostname
    read -p "Введите имя интерфейса для OSPF (по умолчанию: $TUNNEL_NAME): " new_tunnel_name
    read -p "Введите пароль для OSPF аутентификации: " ospf_password
    read -p "Введите сеть для OSPF (по умолчанию: $NETWORK_Left): " new_network_left
    read -p "Введите вторую сеть для OSPF (по умолчанию: $NETWORK_2): " new_network_2

    HOSTNAME=${new_hostname:-$HOSTNAME}
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

# Функция настройки RAID
configure_raid() {
    echo "Настройка RAID массива"

    # Запрос необходимых переменных
    read -p "Введите первый диск для RAID (например, /dev/sdb): " DISK1
    read -p "Введите второй диск для RAID (например, /dev/sdc): " DISK2
    read -p "Введите точку монтирования (например, /obmen): " MOUNT_DIR
    read -p "Введите имя RAID устройства (например, /dev/md0): " RAID_DEVICE
    MDADM_CONFIG="/etc/mdadm.conf"

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

    echo "RAID массив смонтирован в $MOUNT_DIR."
}

# Функция настройки NFS
configure_nfs() {
    echo "Настройка NFS"

    # Запрос необходимых переменных
    read -p "Введите директорию для NFS (например, /obmen/nfs): " NFS_DIR
    EXPORTS_FILE="/etc/exports"

    # Установка необходимых пакетов
    dnf install -y nfs-utils

    # Создаем директорию для NFS
    mkdir -p $NFS_DIR
    chmod 777 $NFS_DIR

    # Добавляем запись в /etc/exports
    echo "$NFS_DIR *(rw,sync,no_root_squash)" >> $EXPORTS_FILE

    # Перезапускаем сервис NFS
    systemctl enable nfs-server
    systemctl restart nfs-server

    # Проверяем статус сервиса
    systemctl status nfs-server
    echo "NFS настроен для $NFS_DIR."
}

# Функция для проверки IP и пинга
check_ip_and_ping() {
    echo "Проверка IP-адресов и доступности ya.ru..."

    # Получение всех IP-адресов
    IP_ADDRESSES=$(hostname -I)
    echo "Ваши текущие IP-адреса: $IP_ADDRESSES"

    # Проверка доступности ya.ru
    if ping -c 1 ya.ru &> /dev/null; then
        echo "ya.ru доступен."
    else
        echo "ya.ru недоступен."
    fi

    # Пауза перед возвратом в меню
    read -p "Нажмите Enter для продолжения..."
}

# Функция настройки Chrony
configure_chrony() {
    echo "Установка и настройка Chrony..."

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
    read -p "Введите значение local stratum (например, 6): " local_stratum

    # Добавление локального сервера
    echo "server 127.0.0.1 iburst prefer" >> $CHRONY_CONF
    echo "local stratum $local_stratum" >> $CHRONY_CONF

    # Запрос сетевых переменных
    read -p "Введите сеть для разрешения (например, $NETWORK_Left): " NETWORK_Left
    read -p "Введите сеть офиса (например, $NETWORK_Right): " NETWORK_Right
    read -p "Введите сеть туннеля (например, $NETWORK_TUNNEL): " NETWORK_TUNNEL
    
    # Разрешение доступа к NTP
    echo "allow $NETWORK_Left" >> $CHRONY_CONF
    echo "allow $NETWORK_Right" >> $CHRONY_CONF
    echo "allow $NETWORK_TUNNEL" >> $CHRONY_CONF

    # Перезапуск службы Chrony
    systemctl restart chronyd
    systemctl enable --now chronyd

    echo "Chrony успешно настроен."
}

# Функция создания backup скрипта
create_backup_script() {
    echo "Создание backup скрипта..."

    # Запрос имени директории для резервного копирования
    read -p "Введите директорию для резервного копирования (например, $BACKUP_DIR): " input_backup_dir
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
    read -p "Введите имя базы данных (по умолчанию: $DB_NAME): " input_db_name
    read -p "Введите имя пользователя базы данных (по умолчанию: $DB_USER): " input_db_user
    read -p "Введите пароль для пользователя базы данных (по умолчанию: $DB_PASS): " input_db_pass
    read -p "Введите имя администратора WordPress (по умолчанию: $ADMIN_USER): " input_admin_user
    read -p "Введите пароль администратора WordPress (по умолчанию: $ADMIN_PASS): " input_admin_pass
    read -p "Введите email администратора WordPress (по умолчанию: $ADMIN_EMAIL): " input_admin_email
    read -p "Введите заголовок сайта (по умолчанию: $SITE_TITLE): " input_site_title
    read -p "Введите URL сайта (по умолчанию: $SITE_URL): " input_site_url

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
    echo "Установка и настройка веб-сервера LMS Apache..."

    # Настройка SELinux
    echo "Настройка SELinux..."
    sed -i 's/^SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
    setenforce 0

    # Установка веб-сервера Apache
    echo "Установка Apache..."
    dnf install -y httpd

    # Запуск службы httpd и добавление в автозагрузку
    echo "Запуск и включение службы Apache..."
    systemctl enable httpd --now

    # Проверка успешной установки Apache
    echo "Проверка установки Apache..."
    if systemctl status httpd | grep "active (running)"; then
        echo "Apache успешно установлен и запущен."
    else
        echo "Ошибка: Apache не запущен."
        exit 1
    fi

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
    mysql -e "CREATE DATABASE moodledb DEFAULT CHARACTER SET utf8 COLLATE utf8_unicode_ci;"
    mysql -e "CREATE USER 'moodleuser'@'localhost' IDENTIFIED BY 'QWEasd11';"
    mysql -e "GRANT ALL ON moodledb.* TO 'moodleuser'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"

    # Установка Moodle
    echo "Установка Moodle..."
    wget https://packaging.moodle.org/stable405/moodle-latest-405.tgz -P /tmp
    tar -xzf /tmp/moodle-latest-405.tgz -C /var/www/html
    chown -R apache:apache /var/www/html/moodle
    chmod -R 0755 /var/www/html/moodle

    # Создание каталога данных для Moodle
    echo "Создание каталога данных для Moodle..."
    mkdir /var/moodledata
    chown -R apache:apache /var/moodledata
    chmod -R 0755 /var/moodledata

    # Перезапуск Apache
    echo "Перезапуск Apache..."
    systemctl restart httpd

    echo "Установка и настройка LMS Apache завершены. Перейдите по адресу http://<IP-сервера>/moodle для завершения настройки."
}

# Функция установки и настройки MediaWiki с использованием Docker
install_mediawiki() {
    echo "Установка и настройка MediaWiki с использованием Docker..."

    # Установка Docker и Docker Compose
    echo "Установка Docker..."
    dnf install -y docker-ce docker-ce-cli
    systemctl enable docker --now

    echo "Установка Docker Compose..."
    dnf install -y docker-compose

    # Создание файла docker-compose.yml
    echo "Создание файла docker-compose.yml..."
    cat <<EOL > ~/wiki.yml
services:
  MediaWiki:
    container_name: wiki
    image: mediawiki
    restart: always
    ports:
      - 8081:80
    links:
      - database
    volumes:
      - images:/var/www/html/images
      # - ./LocalSettings.php:/var/www/html/LocalSettings.php
  database:
    container_name: db
    image: mysql
    environment:
      MYSQL_DATABASE: mediawiki
      MYSQL_USER: wiki
      MYSQL_PASSWORD: P@ssw0rd
      MYSQL_RANDOM_ROOT_PASSWORD: 'yes'
    volumes:
      - dbvolume:/var/lib/mysql
volumes:
  dbvolume:
      external: true
  images:

EOL

    # Создание volume для базы данных
    echo "Создание volume для базы данных..."
    docker volume create dbvolume

    # Запуск стека контейнеров
    echo "Запуск MediaWiki и базы данных..."
    docker-compose -f ~/wiki.yml up -d

    # Проверка доступности MediaWiki
    echo "Проверка доступности MediaWiki на порту 8081..."
    if curl -s --head http://localhost:8081 | grep "200 OK" > /dev/null; then
        echo "MediaWiki доступен по адресу http://localhost:8081"
    else
        echo "Ошибка: MediaWiki недоступен."
        exit 1
    fi
}

# Основной цикл меню
while true; do
    show_menu
    read -p "Выберите пункт меню (1-21): " choice
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
        10) configure_cups ;;
        11) configure_raid ;;
        12) configure_nfs ;;
        13) check_ip_and_ping ;;
        14) configure_chrony ;;
        15) create_backup_script ;;
        16) install_webmin ;;
        17) install_adminer ;;
        18) install_wordpress ;;
        19) install_lms_apache ;;
        20) install_mediawiki ;;
        21) echo "Выход из программы..."; exit 0 ;;
        *) echo "Неверный выбор. Нажмите Enter для продолжения..."; read ;;
    esac
done 