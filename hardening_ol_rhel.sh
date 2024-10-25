# Nome: Hardening Linux
# Descrição: As configurações deste script de automação, ajudam a melhorar a segurança, reduzindo
# a superfície de ataque e tornando-o mais resistente a tentativas de acesso não autorizado
#
# Antes de executar esse script, verifique se é necessário todas as etapas.
# Caso não seja, desative-a cometando suas intruções
#
# Executar o script com o usuário root
#
# Referência: CIS Benchmark
# Sistemas testados: Oracle Linux 9
# Autor: Marcelo Costa
# Contato: marceloengecom@gmail.com
# Data: 12 de fevereiro de 2024.
# Revisão: 03 de outubro de 2024.
# Versão: 1.1

#!/bin/bash

# Função para exibir informações do menu (ASCII)
show_menu() {
  clear
  echo "================================================================================================================================"
  echo -e "\e[1;32mHARDENING - FUNÇÕES QUE SERÃO EXECUTADAS: \e[0m"
  echo "" 
  echo -e "\e[1;32m1. Documentar informações do host \t\t\t\t 2. Atualizar o sistema\e[0m"
  echo -e "\e[1;32m3. Verificar os pacotes instalados \t\t\t\t 4. Bloquear o diretório de inicialização (grub)\e[0m"
  echo -e "\e[1;32m5. Habilitar o SELinux \t\t\t\t\t\t 6. Configurar Firewall e abrir portas básicas (22/tcp, 323/udp)\e[0m"
  echo -e "\e[1;32m7. Verificar as portas abertas \t\t\t\t 8. Gerenciar políticas básicas de senha\e[0m"
  echo -e "\e[1;32m9. Permissões de pastas e arquivos de sistema  \t\t\t 10. Randomizar memória\e[0m"
  echo -e "\e[1;32m11. Verificar segurança nas chaves de acesso SSH \t\t 12. Restringir acesso ao CRON apenas para root\e[0m"
  echo -e "\e[1;32m13. Configurar rede para melhorar a segurança \t\t 14. Verificar contas de usuário com senhas vazias\e[0m"
  echo -e "\e[1;32m15. Instalar e configurar o fail2ban \t\t\t\t 16. Monitorar logs com o rsyslog\e[0m"
  echo -e "\e[1;32m17. Configurar configurações básicas do SSH \t\t\t 18.Instalação e detecção de rootkits com o Rootkit Hunter\e[0m"
  echo ""
  echo -e "\e[1;31mHARDENING - FUNÇÕES DESATIVADAS: \e[0m"
  echo -e "\e[1;31m19. Impedir autenticação por senha e pelo usuário root\t\t 20. Desativar IPv6 em todas as interfaces de rede\e[0m"
  echo ""
  echo "================================================================================================================================"
  echo ""
  echo "  Usuário: $(whoami)"
  echo "  Data - Hora: $(date '+%d-%m-%Y - %H:%M:%S')"
  echo ""  
  echo "  Escolha opção de hardening de acordo com seu SO:"
  echo ""
  echo "1. Aplicar Hardening no Oracle Linux/RHEL"
  echo "3. Sair"
  echo "================================================================================================================================"
}

# Função para o script de hardening no Oracle Linux/RHEL
harden_ol_rhel() {  
  echo ""
  echo -e "\e[1;32mAPLICANDO HARDENING AO SISTEMAL ORACLE LINUX/RHEL\e[0m"
  echo ""
  # 1: Documentar as informações do host
  echo -e "\e[1;33mEscrevendo informações do host no arquivo '/root/info_host.txt'...\e[0m"
  # Limpar o conteúdo do arquivo antes de adicionar novas informações
  > /root/info_host.txt
  echo "DATA - HORA: $(date '+%d/%m/%Y - %H:%M:%S')" >> /root/info_host.txt
  echo "Hostname: $(hostname)" >> /root/info_host.txt
  echo "Endereço IP: $(hostname -I)" >> /root/info_host.txt
  echo "Sistema Operacional: $(cat /etc/redhat-release)" >> /root/info_host.txt
  # Exibe o conteúdo do arquivo /root/info_host.txt
  cat /root/info_host.txt
  echo

  # 2: Atualizar o sistema
  echo -e "\e[1;33mAtualizando o sistema...\e[0m"
  dnf update -y
 
  # 3: Verificar os pacotes instalados
  echo -e "\e[1;33mVerificando os pacotes instalados...\e[0m"
  dnf list installed
 
  # 4: Bloquear o diretório de inicialização, a fim de garantir que as configurações do bootloader permaneçam intactas
  # O comando 'chattr + i', permite definir o arquivo como imutável.
  # Lembrar que se desejar modificar, é necessário primeiro remover o atributo, usando 'chattr -i'. 
  echo -e "\e[1;33mBloqueando diretório de inicialização...\e[0m"
  chattr +i /boot/grub2/grub.cfg  
  chattr +i /boot/grub2/device.map
  #chattr +i /boot/grub2/user.cfg
   
  # 5: Habilitar o SELinux
  # Por padrão, o SELinux já vem habilitado em sistemas derivados do RHEL
  echo -e "\e[1;33mHabilitando o SELinux...\e[0m"
  dnf install -y selinux-policy-targeted
  sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config
  setenforce 1


  # 6: Configurar o Firewall (firewalld) e abrir somente as portas básicas
  echo -e "\e[1;33mHabilitando o firewall (firewalld)...\e[0m"
  systemctl enable --now firewalld
  # Escolhi a zona 'public', pois permite alguns serviços e ICMP por padrão, proporcionando maior flexibilidade.
  # Mas poderia escolher uma zona mais restritiva, como a 'drop'.  
  firewall-cmd --set-default-zone=public  
  # Liberar o serviço SSH na zona public
  firewall-cmd --zone=public --add-service=ssh --permanent
  # Liberar a porta 323 (Chrony) na zona public
  firewall-cmd --zone=public --add-port=323/udp
  # Recarregar operações
  firewall-cmd --reload  
  # Capturar o status atual das regras do firewall e salvar no arquivo
  echo -e "\e[33mSalvando 0 status atual das regras do firewall em /root/info_host.txt...\e[0m"
  echo -e "\nRegras de firewall:\n$(firewall-cmd --list-all)" >> /root/info_host.txt
  

  # 7: Verificar as portas abertas
  echo -e "\e[1;33mVerificando as portas abertas...\e[0m"
  # -t: Mostra conexões TCP. -u: Mostra conexões UDP. -l: Filtra os serviços. -n: Exibe os endereços IP e portas
  # -p: Exibe o ID do processo (PID) e o nome do programa que está utilizando a conexão.
  netstat -tulnp  
  echo -e "\nPortas Abertas:\n$(netstat -tulnp)" >> /root/info_host.txt
  
 
  # 8: Gerenciar políticas básicas de senha
  echo -e "\e[1;33mGerenciando políticas de senha...\e[0m"
  echo -e "\e[33mValidade Senha: 180 dias\e[0m"
  # Tempo máximo que uma senha pode ser usada antes de expirar definido em 180 dias
  sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 180/g' /etc/login.defs
  echo -e "\nTempo máximo de senha definido em: 180 dias." >> /root/info_host.txt
  # Tamanho mínimo de 6 caracteres. Aumente se desejar mais complexidade
  sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 6/g' /etc/login.defs
  echo -e "Tamanho mínimo de senha definido em: 6 caracteres." >> /root/info_host.txt
  #sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/g' /etc/login.defs
  #sed -i 's/sha512/sha512 rounds=65536/g' /etc/pam.d/system-auth-ac  
 
  # 9: Permissões de pastas e arquivos de sistema
  # Ajustes de permissões e proprietários em arquivos críticos do sistema operacional, visando reforçar a segurança.
  echo -e "\e[1;33mRealizando permissões de acordo com o padrão...\e[0m"
  # 644 (leitura/escrita para o dono, leitura para os outros)
  chmod 644 /etc/passwd /etc/group /etc/shadow /etc/gshadow
  # Define o dono como root e o grupo como root
  chown root:root /etc/passwd /etc/shadow
  # Ajustando, pois o grupo shadow é o único que deve ter acesso ao arquivo para leitura.
  chown root:shadow /etc/shadow
  # Define o dono como root e o grupo como root
  chown root:root /etc/group /etc/gshadow
  # Ajustando, pois o grupo shadow é o único que deve ter acesso ao arquivo para leitura.
  chown root:shadow /etc/gshadow
  # Propriedade do root:root
  chown root:root /boot/grub2/grub.cfg
  # Apenas o dono (root) tenha acesso a ele. Isso impede que outros usuários leiam, escrevam ou executem o arquivo.
  chmod og-rwx /boot/grub2/grub.cfg
  # Define permissões restritivas no diretório /root, permitindo apenas ao usuário root o acesso completo.
  chmod 700 /root
   
  # 10: Randomiza memória a fim de reforçar segurança
  echo -e "\e[1;33mAtivando a randomização completa do espaço de endereço (ASLR)...\e[0m"
  # Técnica de segurança para dificultar explorações de falhas, randomizando as posições de memória. 2: Randomização completa
  echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
  sysctl -p
  
  # 11: Verificar segurança nas chaves criptografadas de acesso SSH
  # Garantir que o acesso SSH ao usuário root seja restrito apenas ao próprio root e evitando acessos não autorizados.
  echo -e "\e[1;33mVerificando segurança nas chaves de acesso SSH...\e[0m"  
  chmod 700 /root/.ssh/
  chown root:root /root/.ssh/
  ls -lath /root/.ssh
   
  # 12: Restringir acesso ao CRON apenas para root
  echo -e "\e[1;33mRestringir acesso ao CRON apenas para root...\e[0m"
  touch /etc/cron.allow
  echo "root" > /etc/cron.allow
  chmod 400 /etc/cron.allow
  chown root:root /etc/cron.allow
  echo

  # 13: Configurar rede para melhorar a segurança
  echo -e "\e[1;33mConfigurando parâmetros de rede...\e[0m"  
  # O servidor não atuará como um roteador e não encaminhará pacotes entre interfaces de rede. 
  echo -e "\e[33mDesativar o encaminhamento de pacotes IPv4\e[0m"
  grep -qxF "net.ipv4.ip_forward = 0" "/etc/sysctl.conf" || echo "net.ipv4.ip_forward = 0" >> "/etc/sysctl.conf"
  # Evitar que o servidor envie pacotes de redirecionamento, que podem ser explorados em ataques man-in-the-middle.
  echo -e "\e[33mDesativar o redirecionamento de pacotes IPv4\e[0m"
  # Usei o 'grep -qxF' com comparação, para evitar duplicar opções no arquivo /etc/sysctl.conf
  grep -qxF "net.ipv4.conf.all.send_redirects= 0" "/etc/sysctl.conf" || echo "net.ipv4.conf.all.send_redirects= 0" >> "/etc/sysctl.conf"
  grep -qxF "net.ipv4.conf.default.send_redirects= 0" "/etc/sysctl.conf" || echo "net.ipv4.conf.default.send_redirects= 0" >> "/etc/sysctl.conf"
  # SYN Cookies, ajuda a proteger o servidor contra ataques de negação de serviço (DoS) 
  echo -e "\e[33mHabilitar TCP SYN Cookies\e[0m"
  grep -qxF "net.ipv4.tcp_syncookies = 1" "/etc/sysctl.conf" || echo "net.ipv4.tcp_syncookies = 1" >> "/etc/sysctl.conf"
  sudo sysctl -p
  echo
  
  
  # 14: Verificar contas de usuário com senhas vazias
  echo -e "\e[1;33mVerificando contas com senhas vazias...\e[0m"
  # Analisa o arquivo /etc/shadow, onde as senhas dos usuários são armazenadas em formato criptografado.
  # "-F:" -> Delimitador de campo (:)
  # "($2 == "" ) {print $1}" -> Essa condição verifica se o segundo campo (senhas criptografadas) está vazio.
  # Se estiver, ele imprime o primeiro campo, que contém o nome do usuário.
  awk -F: '($2 == "" ) {print $1}' /etc/shadow
  echo
 
  
  # 15: Instalar e configurar o fail2ban
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

 

  # 15: Monitorar logs com o rsyslog
  echo -e "\e[1;33mMonitorando logs do sistema...\e[0m"
  # Todos os logs dos serviços de autenticação (auth) e dos usuários (user.*) serão gravados no arquivo /var/log/user.log.
  echo "auth,user.* /var/log/user.log" >> /etc/rsyslog.conf
  # O registro de todos os logs de nível emerg (emergência) serão gravados no arquivo /var/log/emergency.log
  echo "*.emerg /var/log/emergency.log" >> /etc/rsyslog.conf
  systemctl restart rsyslog
  echo


  # 16: Configurar acesso remoto e configurações básicas do SSH
  echo -e "\e[1;33mConfigurando acesso remoto e configurações básicas do SSH...\e[0m"
  # Nivel de log, definido como verbose
  sed -i 's/^#LogLevel.*/LogLevel VERBOSE/g' /etc/ssh/sshd_config
  # Número máximo de tentativas de conexão, definido em 4
  sed -i 's/^#MaxAuthTries.*/MaxAuthTries 4/g' /etc/ssh/sshd_config
  systemctl restart sshd
  echo

  # 17: Instalação e detecção de rootkits com o Rootkit Hunter
  # Ferramenta popular para verificar a presença de rootkits e outras vulnerabilidades
  # echo -e "\e[1;33mInstalação e detecção de rootkits, usando a ferramenta Rootkit Hunter...\e[0m"
  # dnf install rkhunter -y
  # echo -e "\e[32m\nInstalação concluída.\e[0m"  
  # rkhunter --update
  # echo -e "\e[32m\nAtualização do Rootkit Hunter concluída.\e[0m"  
  # rkhunter --propupd
  # echo -e "\e[32mAtualização das propriedades do Rootkit Hunter concluída.\e[0m"  
  # rkhunter --check --skip-keypress
  # echo -e "\nOs resultados da verificação de rootkits, podem ser obtidos em: /var/log/rkhunter/rkhunter.log\n" >> /root/info_host.txt


  ## DESATIVADO, pois vou fazer acesso root, via ssh
  ## 18: Segurança do SSH (Forçar a autenticação por chaves criptográficas)
  #echo -e "\e[1;33mBloqueando a autenticação por senha e pelo usuário root...\e[0m"
  #sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
  #sed -i 's/^PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
  ## No OL, esse arquivo é criado pelo instalador Anaconda, caso seja habilitado na instalação do SO
  #rm /etc/ssh/sshd_config/01-permitrootlogin.conf
  #systemctl restart sshd


  ## DESATIVADO, pois vou manter o protcolo IPv6
  ## 19: Desabilitar IPv6 para todas as interfaces
  #echo -e "\e[1;33mDesativando o IPv6 em todas as conexões...\e[0m"
  ## Desabilitar IPv6 do instalador anacaonda.
  #echo -e "\e[33mDesabilitando inicialização IPv6 (anaconda)...\e[0m"  
  #echo "NETWORKING_IPV6=no" >> /etc/sysconfig/network
  #echo "IPV6INIT=no" >> /etc/sysconfig/network  
  ## Desabilita o IPv6 para todas as interfaces (all) e para as configurações padrão (default).  
  #echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
  #echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
  #sudo sysctl -p > /dev/null 2>&1

  ## Desabilitar o IPv6 em todas as interfaces do NetworkManager, exceto loopback
  #echo -e "\e[33mDesativando o IPv6 em todas as conexões gerenciadas pelo NetworkManager...\e[0m"
  ## Listar todas as conexões
  #connections=$(nmcli -t -f NAME con show)
  ## Loop através de cada conexão
  #for conn in $connections; do
  #  # Ignorar a conexão de loopback
  #  if [[ "$conn" == "lo" ]]; then
  #      echo -e "\e[33mIgnorando a conexão de loopback: $conn\e[0m"
  #      continue
  #  fi    
  #  echo -e "\e[33mDesativando IPv6 na conexão: $conn\e[0m"    
  #  # Modificar a configuração da conexão para ignorar o IPv6
  #  nmcli con mod "$conn" ipv6.method ignore
  #done
  ## Aplicar as mudanças reiniciando as conexões
  #echo -e "\e[33mReiniciando as conexões para aplicar as alterações...\e[0m"
  #for conn in $connections; do
  #  nmcli con up "$conn"
  #  done
  #echo -e "\e[1;32mIPv6 desativado com sucesso em todas as conexões (exceto loopback)\e[0m"
  #echo
 

  echo -e "\e[1;32m==============================================================\e[0m"
  echo -e "\e[1;32mHARDENING CONCLUÍDO COM SUCESSO! O SISTEMA ESTÁ MAIS SEGURO.\e[0m"
  echo -e "\e[1;32m==============================================================\e[0m"
  echo ""

}
  
# Menu principal
  show_menu
  read -p "Digite sua opção [1-3]: " option
  case $option in
    1) harden_ol_rhel ;;
    3) echo "Saindo..."; exit 0 ;;
    *) echo "Opção inválida, tente novamente." ;;
  esac