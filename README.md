# kong

 pull centos

docker run --rm -it centos:centos7
 docker run --rm -it --privileged eeb6ee3f44bd /usr/sbin/init
 
 curl -Lo kong-enterprise-edition-2.8.1.2.rpm $(rpm --eval "https://download.konghq.com/gateway-2.x-centos-%{centos_ver}/Packages/k/kong-enterprise-edition-2.8.1.2.el%{centos_ver}.noarch.rpm")

# install Kong

 sudo yum install kong-enterprise-edition-2.8.1.2.rpm


installation postgres https://www.postgresql.org/download/linux/redhat/
cenos7
 yum install postgresql-server

https://www.digitalocean.com/community/tutorials/how-to-install-and-use-postgresql-on-centos-8 


## postgres repo
yum update -y
yum install https://download.postgresql.org/pub/repos/yum/reporpms/EL-7-x86_64/pgdg-redhat-repo-latest.noarch.rpm

reboot
yum install postgresql11-server postgresql11 -y

/usr/pgsql-11/bin/postgresql-11-setup initdb

systemctl start postgresql-11.service

 systemctl enable postgresql-11.service 

systemctl restart postgresql-11.service

systemctl status postgresql-11.service

## postgresql-setup --initdb



su - postgres

psql

CREATE DATABASE kongdb;

CREATE USER konguser WITH ENCRYPTED PASSWORD '1a2b3c';

GRANT ALL PRIVILEGES ON DATABASE kongdb to konguser;
\c database
\g;
exit;

# config postgres
vi /var/lib/pgsql/11/data/pg_hba.conf
เพิ่ม
host    all   all  127.0.0.1/32  trust

vi /var/lib/pgsql/10/data/postgresql.conf
listen_addresses = 'localhost'

# config kong

cp /etc/kong/kong.conf.default /etc/kong/kong.conf

แก้ไขไฟล์ /etc/kong/kong.conf (ให้เปิด comment โดยการลบ # ที่บรรทัดนั้นๆ)

...
proxy_listen = 0.0.0.0:8000 … และแก้เป็น proxy_listen = 0.0.0.0:80 …
admin_listen = 127.0.0.1:8001 …
database = postgres 
pg_host = 127.0.0.1
pg_port = 5432
pg_timeout = 5000
pg_user = konguser
pg_password = 1a2b3c
pg_database = kongdb
...
#  restart postgresql-10.service
 systemctl restart postgresql.service


 # kong migration


kong check /etc/kong/kong.conf

kong migrations bootstrap

sudo kong migrations up -c /etc/kong/kong.conf

sudo kong start -c /etc/kong/kong.conf

# Konga

# Example https://blog.unixdev.co.th/install-kong-and-konga-on-centos7/

 # https://medium.com/w8t-developer/%E0%B8%A1%E0%B8%B2%E0%B8%A5%E0%B8%AD%E0%B8%87%E0%B9%83%E0%B8%8A%E0%B9%89%E0%B8%87%E0%B8%B2%E0%B8%99-kong-%E0%B8%81%E0%B8%B1%E0%B8%99-part-1-a5a4557d281b

install git hub on root

sudo dnf update -y

sudo dnf install git -y

git --version

useradd -m konga



# install node js on konga 
install nvm

curl https://raw.githubusercontent.com/creationix/nvm/master/install.sh | bash

source ~/.bashrc

nvm install 12.16

npm install npm@latest -g

npm install -g gulp bower sails



git clone https://github.com/pantsel/konga.git

cd konga

npm i


# Add database for konga

su postgres

psql

CREATE USER konga WITH PASSWORD'your_password';

CREATE DATABASE konga OWNER konga;

grant all privileges on database konga to konga;

\q

exit;


Test connect database

$ node ./bin/konga.js prepare --adapter postgres --uri postgresql://konga:your_password@127.0.0.1:5432/konga

node ./bin/konga.js prepare --adapter postgres --uri postgresql://kongauser:1a2b3c@127.0.0.1:5432/kongadb


Copy the configuration file template as .env

cp -r .env_example .env

vi .env

####
HOST=your_ip
PORT=1337
NODE_ENV=production
KONGA_HOOK_TIMEOUT=120000
DB_ADAPTER=postgres
#DB_URI=postgresql://localhost:5432/konga
DB_USER=konga
DB_PASSWORD=your_password
DB_PORT=5432
DB_DATABASE=konga
KONGA_LOG_LEVEL=warn
TOKEN_SECRET=some_secret_token
####

# Start Konga

npm run production &

# stop konga

ps aux | grep -i konga

kill -9 process_id

# SSL cert in konga
 su konga
 cd kong
 vi .env

เพิ่ม 

SSL_KEY_PATH=/home/konga/konga/cert/konga.rtarf.mi.th.key

SSL_CRT_PATH=/home/konga/konga/cert/konga.rtarf.mi.th.crt

restart konga

# firewall 
systemctl restart firewalld

 firewall-cmd --list-all
 
 grep ssh /etc/services
 
 firewall-cmd --reload
 
firewall-cmd --get-default-zone

firewall-cmd --get-active-zones

firewall-cmd --zone=public --permanent --add-port=1337/tcp

 ip -a

# rsyslog tcp

vi /etc/rsyslog.conf

firewall-cmd  --add-port=514/tcp  --zone=public  --permanent
systemctl restart rsyslog

service rsyslog reload

sudo netstat -pnltu

tail -f /var/log/messages

# copy rsyslog from 
cd /usr/share/doc/rsyslog/

psql -U postgres Syslog -f pgsql-createDB.sql



CREATE DATABASE rsyslogdb;

CREATE USER rsysloguser WITH ENCRYPTED PASSWORD '1a2b3c';

GRANT ALL PRIVILEGES ON DATABASE rsyslogdb to rsysloguser;

https://www.ablenet.co.th/2021/06/28/rsyslog/


CREATE DATABASE "Syslog" WITH ENCODING 'SQL_ASCII' TEMPLATE template0;
\c Syslog;
CREATE TABLE SystemEvents
(
        ID serial not null primary key,
        CustomerID bigint,
        ReceivedAt timestamp without time zone NULL,
        DeviceReportedTime timestamp without time zone NULL,
        Facility smallint NULL,
        Priority smallint NULL,
        FromHost varchar(60) NULL,
        Message text,
        NTSeverity int NULL,
        Importance int NULL,
        EventSource varchar(60),
        EventUser varchar(60) NULL,
        EventCategory int NULL,
        EventID int NULL,
        EventBinaryData text NULL,
        MaxAvailable int NULL,
        CurrUsage int NULL,
        MinUsage int NULL,
        MaxUsage int NULL,
        InfoUnitID int NULL ,
        SysLogTag varchar(60),
        EventLogType varchar(60),
        GenericFileName VarChar(60),
        SystemID int NULL
);

CREATE TABLE SystemEventsProperties
(
        ID serial not null primary key,
        SystemEventID int NULL ,
        ParamName varchar(255) NULL ,
        ParamValue text NULL
);



#$IncludeConfig /etc/rsyslog.d/*.conf

#$ModLoad imuxsock # provides support for local system logging (e.g. via logger command)

#$ModLoad imklog   # provides kernel logging support (previously done by rklogd)



## elastic 

https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-elasticsearch-on-centos-8

sudo dnf install java-1.8.0-openjdk.x86_64 -y

sudo rpm -ivh https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-7.9.2-x86_64.rpm


sudo systemctl daemon-reload && sudo systemctl enable elasticsearch.service


sudo nano /etc/elasticsearch/elasticsearch.yml

sudo nano /etc/elasticsearch/jvm.options


...
-Xms512m
-Xmx512m
...

sudo systemctl start elasticsearch.service


# Elastic

https://www.howtoforge.com/how-to-install-elastic-stack-on-centos-8/


https://www.scioshield.uk/how-to-install-elasticsearch-and-kibana-8-0-on-centos-7/

# monitor https://www.tecmint.com/monitor-centos-server-performance/

# start kong when reboot

vi /usr/lib/systemd/system/kong.service

[Unit]
Description= kong service
After=syslog.target network.target

[Service]
User=root
Group=root
Type=forking
ExecStart=/usr/local/bin/kong start
ExecReload=/usr/local/bin/kong reload
ExecStop=/usr/local/bin/kong stop

[Install]
WantedBy=multi-user.target



 systemctl start kong
systemctl stop kong
 systemctl enable kong


