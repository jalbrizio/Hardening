#!/bin/bash
#
#
echo "RHEL hardening"
echo " "
sleep 2
cd /etc/pki/rpm-gpg/
wget https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-6
sed -i '/^baseurl\=http\:\/\/download\.fedoraproject\.org/c\baseurl\=http\:\/\/dl\.fedoraproject\.org\/pub\/epel\/6\/\$basearch' /etc/yum.repos.d/epel.repo
sed -i '/^baseurl\=http\:\/\/download\.fedoraproject\.org/c\baseurl\=http\:\/\/dl\.fedoraproject\.org\/pub\/epel\/6\/\$basearch' /etc/yum.repos.d/epel-testing.repo

yum clean all
yum -y install ca-certificates  --disablerepo=epel
yum -y update epel-release
yum -y --enablerepo=epel-testing install mod_evasive mod_security
yum -y --enablerepo=epel-testing update mod_evasive mod_security
echo "1. checking some basic packages which should not be installed:"
for package in inetd xinetd ypserv tftp-server telnet-server rsh-serve
do
      if ! rpm -qa | grep $package >& /etc/null;
      then
      echo "package $package is not installed"
      else
      echo "The $package is installed. Erasing it now."
      yum erase $package
      fi
done
sleep 2
echo " "
echo "2. Checking SElinux settings:"
x=`cat /etc/sysconfig/selinux | grep ^SELINUX | head -n 1 | awk -F= '{print $2}'`
if [ $x == disabled ]
then
    echo "SElinux is disabled"
    echo "Changing it to enforcing"
    sed -i 's/^SELINUX=disabled/SELINUX=enforcing/' /etc/sysconfig/selinux
else
    echo "SElinux is already in enforcing mode"
fi
sleep 2
echo " "
echo "3. Changing different parameters of password aging"
sed -i '/^PASS_MAX_DAYS/c\PASS_MAX_DAYS  60' /etc/login.defs
sed -i '/^PASS_MIN_DAYS/c\PASS_MIN_DAYS  1' /etc/login.defs
sed -i '/^PASS_MIN_LEN/c\PASS_MIN_LEN   8' /etc/login.defs
sed -i '/^PASS_WARN_AGE/c\PASS_WARN_AGE   7' /etc/login.defs
echo "Changes in /etc/login.defs file are done"
sleep 2
echo " "
#echo "Restricting use of previous passwords:"
#echo "None applied"
#sleep 2
echo "4. Verifying empty password accounts:"
x=`awk -F: '($2 == "") {print}' /etc/shadow | wc -l`
if [ $x -lt 1 ]
then
    echo "No account is password less"
else
    echo "At least 1 account is password less.Check the configuration file"
fi
sleep 2
echo " "
echo "5. Checking if No Non-Root Accounts Have UID Set To 0:"
x=`awk -F: '($3 == "0") {print}' /etc/passwd | awk -F: '{print $1}'`
if [ $x == root ]
then
echo "No account other than ROOT has UID 0"
else 
echo "***** Check the file. More than one accounts have UID 0"
fi
sleep 2
echo " "
#echo "6. Disabling root login in system"
#sed -i '/^#PermitRootLogin/a PermitRootLogin no' /etc/ssh/sshd_config
#sed -i 's/^#Port 22/Port 22/' /etc/ssh/sshd_config
#sleep 2
echo "7. Linux kernel hardening:"
cp /etc/sysctl.conf /etc/sysctl.conf.backup
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.forwarding = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.mc_forwarding = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 4096" >> /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
sleep 2
echo "Changes in /etc/sysctl.conf file are done."
sleep 1
echo " "
echo "8. Setting permissions to restrictive for commonly used commands"
chmod 100 /bin/rpm
chmod 100 /bin/tar
chmod 100 /bin/gzip
chmod 100 /bin/ping
chmod 100 /bin/gunzip
chmod 100 /bin/mount
chmod 100 /bin/umount
chmod 100 /usr/bin/gzip
chmod 100 /usr/bin/gunzip
chmod 100 /usr/bin/who
chmod 100 /usr/bin/lastb
chmod 100 /usr/bin/last
chmod 100 /usr/bin/lastlog
chmod 100 /sbin/arping
#chmod 100 /usr/sbin/traceroute
#chmod 400 /etc/syslog-ng/syslog-ng.conf
chmod 400 /etc/hosts.allow
chmod 400 /etc/hosts.deny
#chmod 400 /etc/sysconfig/syslog
chmod 644 /var/log/wtmp
echo "commands permissions changed"
sleep 1
echo " "
#echo "Disk partitions:"
#echo "***None applied yet***"
#sleep 2
#echo "disabling IPv6:"
#echo "None applied"
#sleep 2
echo "9. disabling 'lp' and 'game' users in passwd file:"
sed -i 's/^lp/#lp/' /etc/passwd
sed -i 's/^games/#games/' /etc/passwd
sed -i 's/^lp/#lp/' /etc/group
sed -i 's/^games/#games/' /etc/group
echo "Users are disabled"
sleep 1
echo " "
#echo "creating GRUB password:"
#echo "use of gconftool"
#echo "write verify script"
echo "10. Setting 'Banner' and 'Motd'"
echo "" > /etc/motd
echo "NOTICE: Only authorized YOURCOMPANY staff are permitted access to this system." >> /etc/motd
echo "" >> /etc/motd
echo "        This is a private computing system for authorized users." >> /etc/motd
echo "        Use of this system or its resources is subject to YOURCOMPANY's" >> /etc/motd
echo "        Computing Resource Standards, and is for YOURCOMPANY purposes" >> /etc/motd
echo "        only. All activity is subject to monitoring and review. Use" >> /etc/motd
echo "        of this system or its resources constitutes acknowledgement" >> /etc/motd
echo "        and agreement with this notice." >> /etc/motd
echo "" >> /etc/motd
echo "*****************************************************************************" >> /etc/motd
echo -e "!!!WARNING!!!\n" >> /etc/motd
echo " Your IP, Login Time, Username has been noted and has been sent to the server administrator!" >> /etc/motd
echo " This service is restricted to authorized users only. All activities on this system are logged." >> /etc/motd
echo " Unauthorized access will be fully investigated and reported to the appropriate law enforcement agencies." >> /etc/motd
echo " Disconnect IMMEDIATELY if you are not an authorized user! " >> /etc/motd
echo "*****************************************************************************" >> /etc/motd
echo "" >> /etc/motd
cp /etc/issue /etc/issue.net
#cp /etc/issue /etc/motd
echo "Banner is set."
sleep 1
echo " "
echo "11. turning off unneeded services"
services="acpid atd anacron apmd autofs bluetooth cups firstboot gpm haldaemon messagebus mdmonitor hidd ip6tables kudzu lvm2-monitor netfs nfslock openibd pcmcia pcscd portmap rawdevice rpcgssd rpcidmad smartd telnet xinentd yum-updatesd"
for service in $services; do
service  $service stop
chkconfig $service off
echo "Unneeded services stopped"
sleep 1
echo " "
done
## mod security changes -- using 2.2.8
## cloning the local repo I recieved from the owasp git repo 

echo "setting mod security changes -- using owasp 2.2.8 rules"
cd /usr/local/

git clone https://github.com/jalbrizio/owasp-modsecurity.git

## resets the repo to the 2.2.5 2.2.6 updates
#cd /usr/local/owasp-modsecurity
#git reset --hard  a096f1a5bfbea8420b0bbbe20996b10c9a00d722

## resets the repo to the latest updates
cd /usr/local/owasp-modsecurity
git fetch origin
git reset --hard origin/master

## removing syslink incase you are updating mod security#
rm /etc/httpd/modsecurity.d/activated_rules/*
rm /etc/httpd/modsecurity.d/lua
rm /opt/modsecurity/etc/crs/lua
rm /usr/local/apache/conf/modsec/crs
rm /usr/local/apache/conf/modsec/GeoLiteCity.dat
rm /usr/local/apache/conf/modsec_current/base_rules/GeoLiteCity.dat
rm /etc/apache2/modsecurity-crs/lua
rm /usr/local/apache/conf/crs/lua
rm /usr/local/apache/conf/modsec_current/base_rules/*

## setting symlinks to be used with 2.2.8

ln -s /usr/local/owasp-modsecurity/modsecurity_crs_10_setup.conf.example /etc/httpd/modsecurity.d/activated_rules/modsecurity_crs_10_setup.conf
ln -s /usr/local/owasp-modsecurity/base_rules/modsecurity_* /etc/httpd/modsecurity.d/activated_rules/
ln -s /usr/local/owasp-modsecurity/optional_rules/* /etc/httpd/modsecurity.d/activated_rules/
ln -s /usr/local/owasp-modsecurity/slr_rules/* /etc/httpd/modsecurity.d/activated_rules/
ln -s /usr/local/owasp-modsecurity/experimental_rules/* /etc/httpd/modsecurity.d/activated_rules/
ln -s /usr/local/owasp-modsecurity/lua /etc/httpd/modsecurity.d/
mkdir -p /opt/modsecurity/etc/crs/
ln -s /usr/local/owasp-modsecurity/lua /opt/modsecurity/etc/crs/
ln -s /usr/local/owasp-modsecurity/lua/profile_page_scripts.lua /etc/httpd/modsecurity.d/activated_rules/
mkdir -p /usr/local/apache/conf/modsec/
ln -s /usr/local/owasp-modsecurity/GeoLite2-City.mmdb /usr/local/apache/conf/modsec/GeoLiteCity.dat
ln -s /usr/local/owasp-modsecurity/GeoLite2-City.mmdb /usr/local/apache/conf/modsec_current/base_rules/GeoLiteCity.dat
mkdir -p /etc/apache2/modsecurity-crs/
ln -s /usr/local/owasp-modsecurity/lua /etc/apache2/modsecurity-crs/
mkdir -p /usr/local/apache/conf/crs/
ln -s /usr/local/owasp-modsecurity/lua /usr/local/apache/conf/crs/
mkdir -p /usr/local/apache/conf/modsec_current/base_rules/
ln -s /usr/local/owasp-modsecurity/lua/osvdb.lua /usr/local/apache/conf/modsec_current/base_rules/

### removing Duplicate rules that came from slr_rules and experimental_rules## 
echo "removing Duplicate rules that came from slr_rules and experimental_rules"
rm /etc/httpd/modsecurity.d/activated_rules/modsecurity_crs_46_slr_et_lfi_attacks.conf
rm /etc/httpd/modsecurity.d/activated_rules/modsecurity_crs_46_slr_et_rfi_attacks.conf
rm /etc/httpd/modsecurity.d/activated_rules/modsecurity_crs_46_slr_et_sqli_attacks.conf
rm /etc/httpd/modsecurity.d/activated_rules/modsecurity_crs_46_slr_et_xss_attacks.conf
rm /etc/httpd/modsecurity.d/activated_rules/modsecurity_crs_48_bayes_analysis.conf

echo "# configuration file for the mod_security Apache module" > /etc/httpd/conf.d/mod_security.conf
echo "" >> /etc/httpd/conf.d/mod_security.conf
echo "LoadModule security2_module modules/mod_security2.so" >> /etc/httpd/conf.d/mod_security.conf
echo "LoadModule unique_id_module modules/mod_unique_id.so" >> /etc/httpd/conf.d/mod_security.conf
echo "" >> /etc/httpd/conf.d/mod_security.conf
echo "<IfModule mod_security2.c>" >> /etc/httpd/conf.d/mod_security.conf
echo "        # This is the ModSecurity Core Rules Set." >> /etc/httpd/conf.d/mod_security.conf
echo "" >> /etc/httpd/conf.d/mod_security.conf
echo "        # Basic configuration goes in here" >> /etc/httpd/conf.d/mod_security.conf
echo "#       Include modsecurity.d/*.conf" >> /etc/httpd/conf.d/mod_security.conf
echo "        Include modsecurity.d/activated_rules/*.conf" >> /etc/httpd/conf.d/mod_security.conf
echo "#       Include modsecurity.d/modsecurity_localrules.conf" >> /etc/httpd/conf.d/mod_security.conf
echo "</IfModule>" >> /etc/httpd/conf.d/mod_security.conf
sed -i '/#DOSEmailNotify/c\DOSEmailNotify\ \ \ \ youremail@example\.com' /etc/httpd/conf.d/mod_evasive.conf
sed -i '/#DOSWhitelist\ \ \ 127/c\DOSWhitelist\ \ \ 192\168\.\*' /etc/httpd/conf.d/mod_evasive.conf
sed -i '/#DOSWhitelist\ \ \ 192/c\DOSWhitelist\ \ \ 10\168\.\*' /etc/httpd/conf.d/mod_evasive.conf
service httpd restart
echo "RHEL hardening completed";
