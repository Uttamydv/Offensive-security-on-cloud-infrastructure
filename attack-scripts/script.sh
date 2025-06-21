#!/bin/bash
sudo yum update -y
sudo yum install -y httpd
sudo wget https://dev.mysql.com/get/mysql57-community-release-el7-11.noarch.rpm
sudo yum localinstall mysql57-community-release-el7-11.noarch.rpm 
sudo yum install -y mysql-community-server
sudo systemctl start mysqld.service
sudo systemctl enable mysqld.service
sudo systemctl start httpd
sudo systemctl enable httpd
sudo su
echo "<html> <h2> This is my vulnerable server, Don't visit
</h2> </html>" > /var/www/html/index.html
