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
 
 # ldap sAMAccoutName
 
vi /usr/local/share/lua/5.1/kong/plugins/ldap-auth/access.lua
-- This software is copyright Kong Inc. and its licensors.
-- Use of the software is subject to the agreement between your organization
-- and Kong Inc. If there is no such agreement, use is governed by and
-- subject to the terms of the Kong Master Software License Agreement found
-- at https://konghq.com/enterprisesoftwarelicense/.
-- [ END OF LICENSE 0867164ffc95e54f04670b5169c09574bdbd9bba ]

local constants = require "kong.constants"
local singletons = require "kong.singletons"
local ldap = require "kong.plugins.ldap-auth.ldap"


local kong = kong
local error = error
local decode_base64 = ngx.decode_base64
local sha1_bin = ngx.sha1_bin
local to_hex = require "resty.string".to_hex
local tostring =  tostring
local match = string.match
local lower = string.lower
local upper = string.upper
local find = string.find
local sub = string.sub
local fmt = string.format
local tcp = ngx.socket.tcp


local AUTHORIZATION = "authorization"
local PROXY_AUTHORIZATION = "proxy-authorization"


local _M = {}


local function retrieve_credentials(authorization_header_value, conf)
  local username, password
  if authorization_header_value then
    local s, e = find(lower(authorization_header_value), "^%s*" ..
                      lower(conf.header_type) .. "%s+")
    if s == 1 then
      local cred = sub(authorization_header_value, e + 1)
      local decoded_cred = decode_base64(cred)
      username, password = match(decoded_cred, "(.-):(.+)")
    end
  end

  return username, password
end


local function ldap_authenticate(given_username, given_password, conf)
  local is_authenticated
  local err, suppressed_err, ok, _
--this incress by top
  local base_dn
  local domain
  local who
--this end by top
  
  local sock = tcp()

  sock:settimeout(conf.timeout)

  local opts

  -- keep TLS connections in a separate pool to avoid reusing non-secure
  -- connections and vice-versa, because STARTTLS use the same port
  if conf.start_tls then
    opts = {
      pool = conf.ldap_host .. ":" .. conf.ldap_port .. ":starttls"
    }
  end

  ok, err = sock:connect(conf.ldap_host, conf.ldap_port, opts)
  if not ok then
    kong.log.err("failed to connect to ", conf.ldap_host, ":",
                   tostring(conf.ldap_port), ": ", err)
    return nil, err
  end

  if conf.start_tls then
    -- convert connection to a STARTTLS connection only if it is a new connection
    local count, err = sock:getreusedtimes()
    if not count then
      -- connection was closed, just return instead
      return nil, err
    end

    if count == 0 then
      local ok, err = ldap.start_tls(sock)
      if not ok then
        return nil, err
      end
    end
  end

  if conf.start_tls or conf.ldaps then
    _, err = sock:sslhandshake(true, conf.ldap_host, conf.verify_ldap_host)
    if err ~= nil then
      return false, fmt("failed to do SSL handshake with %s:%s: %s",
                        conf.ldap_host, tostring(conf.ldap_port), err)
    end
  end
--this by top
  base_dn = conf.base_dn
  base_dn = string.upper(base_dn)

  domain = ""
  for word in string.gmatch(base_dn, 'DC=([^,]+)') do
	domain = domain .. "." .. word
  end
  domain = string.sub(domain, 2)

  who = conf.attribute .. "=" .. given_username .. "," .. conf.base_dn

  if conf.attribute == "sAMAccountName" then
	who = given_username .. "@" .. domain
  end

  is_authenticated, err = ldap.bind_request(sock, who, given_password)

  ok, suppressed_err = sock:setkeepalive(conf.keepalive)
  if not ok then
    kong.log.err("failed to keepalive to ", conf.ldap_host, ":",
                   tostring(conf.ldap_port), ": ", suppressed_err)
  end

  return is_authenticated, err
end


local function cache_key(conf, username, password)
  local hash = to_hex(sha1_bin(fmt("%s:%u:%s:%s:%u:%s:%s",
                                   lower(conf.ldap_host),
                                   conf.ldap_port,
                                   conf.base_dn,
                                   conf.attribute,
                                   conf.cache_ttl,
                                   username,
                                   password)))

  return "ldap_auth_cache:" .. hash
end


local function load_credential(given_username, given_password, conf)
  local ok, err = ldap_authenticate(given_username, given_password, conf)
  if err ~= nil then
    kong.log.err(err)
  end

  if ok == nil then
    return nil
  end

  if ok == false then
    return false
  end

  return {
    id = cache_key(conf, given_username, given_password),
    username = given_username,
    password = given_password,
  }
end


local function authenticate(conf, given_credentials)
  local given_username, given_password = retrieve_credentials(given_credentials, conf)
  if given_username == nil then
    return false
  end

  local credential, err = singletons.cache:get(cache_key(conf, given_username, given_password), {
    ttl = conf.cache_ttl,
    neg_ttl = conf.cache_ttl
  }, load_credential, given_username, given_password, conf)

  if err or credential == nil then
    return error(err)
  end


  return credential and credential.password == given_password, credential
end


local function set_consumer(consumer, credential)
  kong.client.authenticate(consumer, credential)

  local set_header = kong.service.request.set_header
  local clear_header = kong.service.request.clear_header

  if consumer and consumer.id then
    set_header(constants.HEADERS.CONSUMER_ID, consumer.id)
  else
    clear_header(constants.HEADERS.CONSUMER_ID)
  end

  if consumer and consumer.custom_id then
    set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
  else
    clear_header(constants.HEADERS.CONSUMER_CUSTOM_ID)
  end

  if consumer and consumer.username then
    set_header(constants.HEADERS.CONSUMER_USERNAME, consumer.username)
  else
    clear_header(constants.HEADERS.CONSUMER_USERNAME)
  end

  if credential and credential.username then
    set_header(constants.HEADERS.CREDENTIAL_IDENTIFIER, credential.username)
    set_header(constants.HEADERS.CREDENTIAL_USERNAME, credential.username)
  else
    clear_header(constants.HEADERS.CREDENTIAL_IDENTIFIER)
    clear_header(constants.HEADERS.CREDENTIAL_USERNAME)
  end

  if credential then
    clear_header(constants.HEADERS.ANONYMOUS)
  else
    set_header(constants.HEADERS.ANONYMOUS, true)
  end
end


local function do_authentication(conf)
  local authorization_value = kong.request.get_header(AUTHORIZATION)
  local proxy_authorization_value = kong.request.get_header(PROXY_AUTHORIZATION)

  -- If both headers are missing, return 401
  if not (authorization_value or proxy_authorization_value) then
    local scheme = conf.header_type
    if scheme == "ldap" then
      -- ensure backwards compatibility (see GH PR #3656)
      -- TODO: provide migration to capitalize older configurations
      scheme = upper(scheme)
    end

    return false, {
      status = 401,
      message = "Unauthorized",
      headers = { ["WWW-Authenticate"] = scheme .. ' realm="kong"' }
    }
  end

  local is_authorized, credential = authenticate(conf, proxy_authorization_value)
  if not is_authorized then
    is_authorized, credential = authenticate(conf, authorization_value)
  end

  if not is_authorized then
    return false, {status = 401, message = "Invalid authentication credentials" }
  end

  if conf.hide_credentials then
    kong.service.request.clear_header(AUTHORIZATION)
    kong.service.request.clear_header(PROXY_AUTHORIZATION)
  end

  set_consumer(nil, credential)

  return true
end


function _M.execute(conf)
  if conf.anonymous and kong.client.get_credential() then
    -- we're already authenticated, and we're configured for using anonymous,
    -- hence we're in a logical OR between auth methods and we're already done.
    return
  end

  local ok, err = do_authentication(conf)
  if not ok then
    if conf.anonymous then
      -- get anonymous user
      local consumer_cache_key = kong.db.consumers:cache_key(conf.anonymous)
      local consumer, err      = singletons.cache:get(consumer_cache_key, nil,
                                                      kong.client.load_consumer,
                                                      conf.anonymous, true)
      if err then
        return error(err)
      end

      set_consumer(consumer)

   else
      return kong.response.error(err.status, err.message, err.headers)
    end
  end
end


return _M

