#!/bin/bash

# Функция для отображения меню
show_menu() {
    clear
    echo "============================================"
    echo "          Меню настройки сервера            "
    echo "============================================"
    echo "1. Настроить имя хоста"
    echo "2. Настроить сетевые интерфейсы"
    echo "3. Настроить часовой пояс"
    echo "4. Установить и настроить nftables"
    echo "5. Настроить DHCP сервер"
    echo "6. Настроить GRE туннель"
    echo "7. Настроить FRR (OSPF)"
    echo "8. Создать системного пользователя"
    echo "9. Применить все настройки"
    echo "10. Выход"
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

# Функция настройки имени хоста
configure_hostname() {
    echo "Текущее имя хоста: $HOSTNAME"
    read -p "Введите новое имя хоста (или Enter для пропуска): " new_hostname
    if [ ! -z "$new_hostname" ]; then
        HOSTNAME=$new_hostname
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
}

# Функция настройки часового пояса
configure_timezone() {
    echo "Текущий часовой пояс: $TIMEZONE"
    read -p "Введите новый часовой пояс (или Enter для пропуска): " new_timezone
    if [ ! -z "$new_timezone" ]; then
        TIMEZONE=$new_timezone
    fi
}

# Функция настройки nftables
configure_nftables() {
    read -p "Установить и настроить nftables? (y/n): " choice
    case "$choice" in 
        y|Y ) INSTALL_NFTABLES=true;;
        * ) INSTALL_NFTABLES=false;;
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
}

# Функция настройки FRR
configure_frr() {
    read -p "Настроить FRR с OSPF? (y/n): " choice
    case "$choice" in 
        y|Y ) INSTALL_FRR=true;;
        * ) INSTALL_FRR=false;;
    esac
}

# Функция применения настроек
apply_settings() {
    echo "Применение настроек..."
    
    # Установка имени хоста
    hostnamectl set-hostname $HOSTNAME

    # Настройка сетевых интерфейсов
    nmcli con mod $INTERFACE_2 ipv4.address $IP2
    nmcli con mod $INTERFACE_2 ipv4.method manual
    nmcli con mod $INTERFACE_3 ipv4.address $IP3
    nmcli con mod $INTERFACE_3 ipv4.method manual

    # Настройка часового пояса
    timedatectl set-timezone $TIMEZONE

    # Настройка nftables
    if [ "$INSTALL_NFTABLES" = true ]; then
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
    fi

    # Настройка DHCP-сервера
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

    # Настройка GRE туннеля
    nmcli con add type ip-tunnel ip-tunnel.mode gre con-name $TUNNEL_NAME ifname $TUNNEL_NAME \
    remote $REMOTE_IP local $LOCAL_IP
    nmcli con mod $TUNNEL_NAME ipv4.addresses $TUNNEL_LOCAL_IP
    nmcli con mod $TUNNEL_NAME ipv4.method manual
    nmcli con mod $TUNNEL_NAME +ipv4.routes "$NETWORK_Right $TUNNEL_REMOTE_IP"
    nmcli connection modify $TUNNEL_NAME ip-tunnel.ttl 64
    nmcli con up $TUNNEL_NAME

    # Создание пользователя
    useradd -m -s /bin/bash -u "$USER_ID" "$USERNAME_NET"
    echo "$USERNAME_NET:$PASSWORD_NET" | chpasswd
    usermod -aG wheel "$USERNAME_NET"
    echo "$USERNAME_NET ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$USERNAME_NET"

    # Настройка FRR если выбрано
    if [ "$INSTALL_FRR" = true ]; then
        dnf install -y frr
        sed -i "s/ospfd=no/ospfd=yes/" /etc/frr/daemons
        sed -i "s/ospf6d=no/ospf6d=yes/" /etc/frr/daemons
        systemctl enable --now frr

        cat <<EOL > /etc/frr/frr.conf
frr version 10.1
frr defaults traditional
hostname $HOSTNAME
no ipv6 forwarding
!
interface $TUNNEL_NAME
ip ospf authentication
ip ospf authentication-key password
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
        systemctl restart frr
    fi

    echo "Настройки успешно применены!"
    read -p "Нажмите Enter для продолжения..."
}

# Основной цикл меню
while true; do
    show_menu
    read -p "Выберите пункт меню (1-10): " choice
    case $choice in
        1) configure_hostname ;;
        2) configure_network ;;
        3) configure_timezone ;;
        4) configure_nftables ;;
        5) configure_dhcp ;;
        6) configure_gre ;;
        7) configure_frr ;;
        8) configure_user ;;
        9) apply_settings ;;
        10) echo "Выход из программы..."; exit 0 ;;
        *) echo "Неверный выбор. Нажмите Enter для продолжения..."; read ;;
    esac
done 