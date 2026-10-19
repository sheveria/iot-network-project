# Golden AMI base config for MikroTik CHR hub (RouterOS 7.x). Applied ONCE when baking the AMI.
# Gives hub_lifecycle Lambda a REST endpoint (HTTPS 443, pinned self-signed cert) on first boot.
# After applying: note the TLS fingerprint -> Terraform var ros_tls_fingerprint
#   /certificate print detail where name=rest-tls     (field "fingerprint", sha256)
# Store provisioner password in Secrets Manager (iot/ros-provisioner) — never in the AMI repo.

/user group
add name=provisioner policy=read,write,policy,test,sensitive,api,rest-api,ftp,reboot

/user
add name=provisioner group=provisioner password="{{PROVISIONER_PASSWORD}}"
# lock down default admin (keep SSH-key access for break-glass only)
set admin password="{{ADMIN_PASSWORD}}"

/certificate
add name=rest-tls common-name=iot-hub-rest key-type=ec key-size=prime256v1 days-valid=3650
sign rest-tls

/ip service
set www-ssl certificate=rest-tls disabled=no port=443 address=10.0.0.0/8 tls-version=only-1.2
set www port=8080 address=10.0.0.0/8
set api disabled=yes
set api-ssl disabled=yes
set telnet disabled=yes
set ftp disabled=yes
set winbox address=10.0.0.0/8

/ip firewall filter
add chain=input connection-state=established,related action=accept
add chain=input protocol=tcp dst-port=443,8080,22 src-address=10.0.0.0/8 action=accept
add chain=input action=drop comment="replaced by hub.rsc on provisioning"
