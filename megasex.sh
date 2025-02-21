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
    echo "9. Создать SSH-пользователя"
    echo "10. Настроить SSH"
    echo "11. Настроить CUPS"
    echo "12. Настроить RAID"
    echo "13. Настроить NFS"
    echo "14. Проверка IP и пинга ya.ru"
    echo "15. Выход"
    echo "============================================"
}

# Переменные по умолчанию
HOSTNAME="isp"
INTERFACE_1="enp0s3"
INTERFACE_2="enp0s8"
INTERFACE_3="enp0s9"
IP2="22.22.22.1/28"
IP3="11.11.0.1/27"
TIMEZONE="Asia/Yekaterinburg"

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

# Функция настройки имени хоста
configure_hostname() {
    echo "Текущее имя хоста: $HOSTNAME"
    read -p "Введите новое имя хоста (или Enter для пропуска): " new_hostname
    if [ ! -z "$new_hostname" ]; then
        HOSTNAME=$new_hostname
        hostnamectl set-hostname $HOSTNAME
        echo "Имя хоста обновлено на $HOSTNAME."
    fi
}

# Функция настройки сетевых интерфейсов
configure_network() {
    echo "Настройка сетевых интерфейсов"
    read -p "Введите имя интерфейса 1 (текущее: $INTERFACE_1): " new_if1
    read -p "Введите имя интерфейса 2 (текущее: $INTERFACE_2): " new_if2
    read -p "Введите имя интерфейса 3 (текущее: $INTERFACE_3): " new_if3
    read -p "Введите IP-адрес для интерфейса 2 (текущий: $IP2): " new_ip2
    read -p "Введите IP-адрес для интерфейса 3 (текущий: $IP3): " new_ip3

    [ ! -z "$new_if1" ] && INTERFACE_1=$new_if1
    [ ! -z "$new_if2" ] && INTERFACE_2=$new_if2
    [ ! -z "$new_if3" ] && INTERFACE_3=$new_if3
    [ ! -z "$new_ip2" ] && IP2=$new_ip2
    [ ! -z "$new_ip3" ] && IP3=$new_ip3

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
    read -p "Введите новый часовой пояс (или Enter для пропуска): " new_timezone
    if [ ! -z "$new_timezone" ]; then
        TIMEZONE=$new_timezone
        timedatectl set-timezone $TIMEZONE  # Обновление часового пояса системы
        echo "Часовой пояс обновлен на $TIMEZONE."
    fi
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
    read -p "Введите подсеть (текущая: $DHCP_SUBNET): " new_subnet
    read -p "Введите маску подсети (текущая: $DHCP_NETMASK): " new_netmask
    read -p "Введите диапазон адресов (текущий: $DHCP_RANGE): " new_range
    read -p "Введите адрес маршрутизатора (текущий: $DHCP_ROUTER): " new_router
    read -p "Введите адрес DNS сервера (текущий: $DHCP_DNS): " new_dns
    read -p "Введите доменное имя (текущее: $DHCP_DOMAIN): " new_domain

    [ ! -z "$new_subnet" ] && DHCP_SUBNET=$new_subnet
    [ ! -z "$new_netmask" ] && DHCP_NETMASK=$new_netmask
    [ ! -z "$new_range" ] && DHCP_RANGE=$new_range
    [ ! -z "$new_router" ] && DHCP_ROUTER=$new_router
    [ ! -z "$new_dns" ] && DHCP_DNS=$new_dns
    [ ! -z "$new_domain" ] && DHCP_DOMAIN=$new_domain

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
    read -p "Введите локальный IP (текущий: $LOCAL_IP): " new_local_ip
    read -p "Введите удаленный IP (текущий: $REMOTE_IP): " new_remote_ip
    read -p "Введите локальный IP туннеля (текущий: $TUNNEL_LOCAL_IP): " new_tunnel_local_ip
    read -p "Введите удаленный IP туннеля (текущий: $TUNNEL_REMOTE_IP): " new_tunnel_remote_ip
    read -p "Введите имя туннеля (текущее: $TUNNEL_NAME): " new_tunnel_name

    [ ! -z "$new_local_ip" ] && LOCAL_IP=$new_local_ip
    [ ! -z "$new_remote_ip" ] && REMOTE_IP=$new_remote_ip
    [ ! -z "$new_tunnel_local_ip" ] && TUNNEL_LOCAL_IP=$new_tunnel_local_ip
    [ ! -z "$new_tunnel_remote_ip" ] && TUNNEL_REMOTE_IP=$new_tunnel_remote_ip
    [ ! -z "$new_tunnel_name" ] && TUNNEL_NAME=$new_tunnel_name

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
    read -p "Введите имя пользователя (текущее: $USERNAME_NET): " new_username
    read -p "Введите пароль (текущий: $PASSWORD_NET): " new_password
    read -p "Введите ID пользователя (текущий: $USER_ID): " new_user_id

    [ ! -z "$new_username" ] && USERNAME_NET=$new_username
    [ ! -z "$new_password" ] && PASSWORD_NET=$new_password
    [ ! -z "$new_user_id" ] && USER_ID=$new_user_id

    # Применение настроек пользователя
    useradd -m -s /bin/bash -u "$USER_ID" "$USERNAME_NET"
    echo "$USERNAME_NET:$PASSWORD_NET" | chpasswd
    usermod -aG wheel "$USERNAME_NET"
    echo "$USERNAME_NET ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$USERNAME_NET"
    echo "Пользователь $USERNAME_NET создан."
}

# Функция создания SSH-пользователя
create_ssh_user() {
    echo "Создание пользователя SSH"
    useradd -m -s /bin/bash -u "$USER_ID_SSH" "$USERNAME_SSH"
    echo "$USERNAME_SSH:$PASSWORD_SSH" | chpasswd
    usermod -aG wheel "$USERNAME_SSH"
    echo "$USERNAME_SSH ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$USERNAME_SSH"
    echo "Пользователь $USERNAME_SSH создан."
}

# Функция настройки SSH
configure_ssh() {
    echo "Настройка безопасного удаленного доступа"
    
    # Запрос необходимых переменных
    read -p "Введите порт SSH (текущий: $PORT_SSH): " new_port
    read -p "Введите имя пользователя для SSH (текущее: $USERNAME_SSH): " new_username
    read -p "Введите максимальное количество попыток входа (текущее: $POPITKA): " new_max_auth_tries
    read -p "Введите время ожидания входа (например, 5m): " new_login_grace_time

    # Применение введенных значений
    [ ! -z "$new_port" ] && PORT_SSH=$new_port
    [ ! -z "$new_username" ] && USERNAME_SSH=$new_username
    [ ! -z "$new_max_auth_tries" ] && POPITKA=$new_max_auth_tries
    [ ! -z "$new_login_grace_time" ] && TIME=$new_login_grace_time

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
    read -p "Введите имя хоста для FRR (текущее: $HOSTNAME): " new_hostname
    read -p "Введите имя интерфейса для OSPF (текущее: $TUNNEL_NAME): " new_tunnel_name
    read -p "Введите пароль для OSPF аутентификации: " ospf_password
    read -p "Введите сеть для OSPF (текущая: $NETWORK_Left): " new_network_left
    read -p "Введите вторую сеть для OSPF (текущая: $NETWORK_2): " new_network_2

    # Применение введенных значений
    [ ! -z "$new_hostname" ] && HOSTNAME=$new_hostname
    [ ! -z "$new_tunnel_name" ] && TUNNEL_NAME=$new_tunnel_name
    [ ! -z "$new_network_left" ] && NETWORK_Left=$new_network_left
    [ ! -z "$new_network_2" ] && NETWORK_2=$new_network_2

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

# Основной цикл меню
while true; do
    show_menu
    read -p "Выберите пункт меню (1-15): " choice
    case $choice in
        1) configure_hostname ;;
        2) configure_network ;;
        3) configure_timezone ;;
        4) configure_nftables ;;
        5) configure_dhcp ;;
        6) configure_gre ;;
        7) configure_frr ;;
        8) configure_user ;;
        9) create_ssh_user ;;
        10) configure_ssh ;;
        11) configure_cups ;;
        12) configure_raid ;;
        13) configure_nfs ;;
        14) check_ip_and_ping ;;
        15) echo "Выход из программы..."; exit 0 ;;
        *) echo "Неверный выбор. Нажмите Enter для продолжения..."; read ;;
    esac
done 