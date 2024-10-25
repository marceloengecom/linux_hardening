# Nome: Hardening Postgresql e MongoDB
# Descrição: As configurações deste script de automação, ajudam a melhorar a segurança e performance
# dos sistemas de banco de dados PostgreSQL e MongoDB
#
# Antes de executar esse script, verifique se é necessário todas as etapas.
# Caso não seja, desative-a cometando suas intruções
#
# Executar o script com o usuário com privilégio root
#
# Sistemas Operacionais: Oracle Linux 9/rhel
# Autor: Marcelo Costa
# Contato: marceloengecom@gmail.com
# Data: 04 de outubro de 2024
# Versão: 1.0

#!/bin/bash

# Função para exibir informações do menu (ASCII)
show_menu() {
  clear
  echo "================================================================================================================================"
  echo -e "\e[1;32mHARDENING E PERFORMANCE POSTGRES E MONGODB\e[0m"
  echo "" 
  echo -e "\e[1;32m1. Atualizar o sistema \t\t\t\t\t\t 2. Configurar SELinux para PostgreSQL e MOngoDB\e[0m"
  echo -e "\e[1;32m3. Configurar o Firewall e abrir as portas par PostgreSQL e MOngoDB \t 4. Instalar e configurar o fail2ban\e[0m"
  echo ""
  echo "================================================================================================================================"
  echo ""
  echo -e "\e[1;31mO SISTEMA OPERAACIONAL DEVE SER DA FAMÍLIA RHEL/ORACLE LINUX\e[0m"
  echo "  Sistema Operacional: $(cat /etc/redhat-release)"
  echo "  Usuário: $(whoami)"
  echo "  Data - Hora: $(date '+%d-%m-%Y - %H:%M:%S')"
  echo ""  
  echo "  Escolha opção de desejada:"
  echo ""
  echo "1. Aplicar Hardening/Performance PostgreSQL"
  echo "2. Aplicar Hardening/Performance MongoDB"
  echo "3. Sair"
  echo "================================================================================================================================"
}

# Função para o script de hardening do PostgreSQL
harden_postgres() {  
    echo ""
    echo -e "\e[1;32mAPLICANDO HARDENING POSTGRESQL NO RHEL/ORACLE LINUX\e[0m"
    echo ""
    # 1: Atualizar o sistema operacional
    echo -e "\e[1;33mAtualizando o SO...\e[0m"
    dnf update -y

    # 2: Configurar SELinux para PostgreSQL
    # Por padrão, o SELinux já vem habilitado em sistemas derivados do RHEL
    echo -e "\e[1;33mHabilitando o SELinux...\e[0m"
    dnf install -y selinux-policy-targeted
    sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config
    setenforce 1
    # Permitir o PostgreSQL aceitar conexões de rede
    setsebool -P postgresql_can_network_connect 1
    # Permite ao PostgreSQL usar o comando rsync para sincronização de dados ou backups entre servidores.
    setsebool -P postgresql_can_rsync 1


    # 3: Configurar o Firewall (firewalld) e abrir somente as portas básicas e postgresql
    echo -e "\e[1;33mHabilitando o firewall (firewalld)...\e[0m"
    systemctl enable --now firewalld
    # Defnir a zona padrão mais restritiva (public)
    firewall-cmd --set-default-zone=public
    # Liberar o serviço SSH na zona public
    firewall-cmd --zone=public --add-service=ssh --permanent
    # Liberar a porta 323 (Chrony) na zona public
    firewall-cmd --zone=public --add-port=323/udp
    # Liberar a porta padrão do PostgreSQL (5432) na zona especificada (public).    
    firewall-cmd --zone=public --add-service=postgresql --permanent
    # Recarregar operações
    firewall-cmd --reload  
    # Capturar o status atual das regras do firewall e salvar em arquivo
    echo -e "\e[33mSalvando 0 status atual das regras do firewall em /root/info_host.txt...\e[0m"
    echo -e "\nRegras de firewall:\n$(firewall-cmd --list-all)" >> /root/info_host.txt

    # 4: Instalar e configurar o fail2ban
    # O Fail2ban ajuda a proteger contra ataques de força bruta e automaticamente bloqueia IPs que tentam explorar o sistema.
    echo -e "\e[1;33mInstalando e configurando o fail2ban...\e[0m"
    dnf install epel-release -y
    dnf install fail2ban -y
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    # Define o tempo de banimento (bantime) para 3600 segundos, após o limite de tentativas de autenticação falhas.
    sed -i 's/^# bantime =.*/bantime = 3600/g' /etc/fail2ban/jail.local
    # Número máximo de tentativas de autenticação permitidas (3) antes que um IP seja banido.
    sed -i 's/^# maxretry =.*/maxretry = 3/g' /etc/fail2ban/jail.local
    systemctl enable fail2ban
    systemctl start fail2ban
}

# Função para o script de hardening do PostgreSQL
harden_mongodb() {  
    echo ""
    echo -e "\e[1;32mAPLICANDO HARDENING MONGODB NO RHEL/ORACLE LINUX\e[0m"
    echo ""
    # 1: Atualizar o sistema operacional
    echo -e "\e[1;33mAtualizando o SO...\e[0m"
    dnf update -y

    # 2: Configurar SELinux com o MongoDB
    # Por padrão, o SELinux já vem habilitado em sistemas derivados do RHEL
    echo -e "\e[1;33mHabilitando o SELinux...\e[0m"
    dnf install -y selinux-policy-targeted
    sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config
    setenforce 1
    # Permitir aceitar conexões de rede
    setsebool -P mongodb_can_network_connect 1
    # Permite  usar o comando rsync para sincronização de dados ou backups entre servidores.
    setsebool -P mongodb_can_rsync 1
    semanage() {
      # Verifica se o comando 'semanage' está disponível
      if ! command -v semanage &> /dev/null; then
        echo "O comando 'semanage' não está instalado. Instalando o pacote necessário..."
        sudo dnf install -y policycoreutils-python-utils
      fi
      # Adiciona a porta 27017 ao contexto de porta do MongoDB no SELinux
      echo "Adicionando a porta 27017 ao contexto SELinux 'mongod_port_t'..."
      sudo semanage port -a -t mongod_port_t -p tcp 27017

      # Verifica se o comando foi executado com sucesso
      if [ $? -eq 0 ]; then
        echo "Porta 27017 adicionada com sucesso ao SELinux para o MongoDB."
      else
        echo "Falha ao adicionar a porta 27017 ao SELinux."
      fi
    }

    # 3: Configurar o Firewall (firewalld) e abrir somente as portas básicas e postgresql
    echo -e "\e[1;33mHabilitando o firewall (firewalld)...\e[0m"
    systemctl enable --now firewalld
    # Defnir a zona padrão mais restritiva (public)
    firewall-cmd --set-default-zone=public
    # Liberar a porta padrão do MongoDB (27017) na zona especificada (public), permitindo aceitar conexões externas
    firewall-cmd --zone=public --add-service=mongodb --permanent
    # Recarregar operações
    firewall-cmd --reload  
    # Capturar o status atual das regras do firewall e salvar em arquivo
    echo -e "\e[33mSalvando 0 status atual das regras do firewall em /root/info_host.txt...\e[0m"
    echo -e "\nRegras de firewall:\n$(firewall-cmd --list-all)" >> /root/info_host.txt

    # 4: Instalar e configurar o fail2ban
    # O Fail2ban ajuda a proteger contra ataques de força bruta e automaticamente bloqueia IPs que tentam explorar o sistema.
    echo -e "\e[1;33mInstalando e configurando o fail2ban...\e[0m"
    dnf install epel-release -y
    dnf install fail2ban -y
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    # Define o tempo de banimento (bantime) para 3600 segundos, após o limite de tentativas de autenticação falhas.
    sed -i 's/^# bantime =.*/bantime = 3600/g' /etc/fail2ban/jail.local
    # Número máximo de tentativas de autenticação permitidas (3) antes que um IP seja banido.
    sed -i 's/^# maxretry =.*/maxretry = 3/g' /etc/fail2ban/jail.local
    systemctl enable fail2ban
    systemctl start fail2ban
}

  echo -e "\e[1;32m==============================================================\e[0m"
  echo -e "\e[1;32mHARDENING CONCLUÍDO COM SUCESSO! O SISTEMA ESTÁ MAIS SEGURO.\e[0m"
  echo -e "\e[1;32m==============================================================\e[0m"
  echo ""
  
# Menu principal
  show_menu
  read -p "Digite sua opção [1-3]: " option
  case $option in
    1) harden_postgres ;;
    2) harden_mongodb ;;
    3) echo "Saindo..."; exit 0 ;;
    *) echo "Opção inválida, tente novamente." ;;
  esac