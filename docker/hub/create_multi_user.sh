awk '{print "echo " $1}' ./users.txt | /bin/bash
awk '{print "useradd -m " $1}' ./users.txt | /bin/bash
awk '{print "echo " $1 ":" $2 " | chpasswd"}' ./users.txt | /bin/bash
awk '{print "sh -c echo \"c.Authenticator.admin_users.add(" $1 ")\" >> /etc/jupyterhub/jupyterhub_config.py"}' ./users.txt | /bin/bash

