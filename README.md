# wafbitninja_multibackend

- Rol para implementar waf con N servidores de backend

## Instrucciones

- Editar el archivo hosts ubicado en el primer nivel de este repositorio apuntando al servidor destino, usuario con privilegios sudo y puerto ssh correspondiente

Ejemplo de inventario    34.141.43.33 ansible_user=cristobal ansible_become=yes ansible_port=10200

- Revisar variables declaradas debajo para personalizar si se desea

- Se debe tener instalado el paquete ansible para lanzar el deploy

- Lanzar la receta ubicado en la ruta padre del repositorio mediante:

ansible-playbook -i hosts site.yml

### Variables a personalizar si se desea editar el valor por defecto

#### Rol "common" roles/common/vars/main.yml

timezone: America/Santiago     # Timezone <br>
reiniciarSistemaSelinux: true  # Reiniciar equipo en caso que selinux este activo <br>
actualizarPaquetes: true       # Realizar un yum update <br>
hostnameVar: "localhost"       # Hostname del servidor <br>

#### Rol "sysctl_hardening" roles/sysctl_hardening/vars/main.yml 

forwardingPaquetes: false  # Modificar a True en caso que el equipo cumpla rol de router/firewall

#### Rol "ssh-hardening" roles/ssh-hardening/vars/main.yml

##### Agregar llaves login usuario ejemplo (el usuario debe existir)

```
llaves: 
  - user: usuario 
    sshKey: ssh-rsa  AAAAB3NzaC1yc2EAAAADAQABAAABAQDFXsPMyC2erjKcVflIHwTX9vINIc4yzcmUE0uJxKLbUtYcbtGTbdk8GvSSiVQkSTjzJl+B79nJ5nIlMou9bMChQjS54B9hbSDdbVohArgazleMq8aToVwy05mdggkvDzdg9U0TpcC6zvaNe94nhBnDO4ShZ/kCSGOpOf5YehVJohKrZkqiBv0fywWk7okLbHBymE+6yxK156KdajT0a/JpqW6WD+3fvdYpZRYSty+FMw/fKVkw75GJHVgne1wzyjTlM29e0L0gszJZvV7YW+050pJiX3s69cBojgD0k9FAqROQpsh/WDUj+h80oWZVX7BosAxOmR7dk#$!ffafff usuario@hostname
```

##### Variables default 

```
sshPort: 22	
LoginGraceTime: 30	
MaxAuthTries: 2
MaxSessions: 4
GSSAPIAuthentication: "no"
X11Forwarding: "no"
usarFirewalld: true
rootlogin: false<br>
PermitRootLogging: "no"
HostbasedAuthentication: "no"
IgnoreRhosts: "yes"
LogLevel: "INFO"
```

#### Rol "bitninja" roles/bitninja/vars/main.yml
APIKEY: "LLENARCONUNAAPIKEYENDEFAULTSOENVARS"


#### Rol "nginx" roles/nginx/vars/main.yml

##### Cargar certificado SSL

Se debe agregar los archivos SSL en el path roles/nginx/files/ respetando el nombre a utilizar en las variables declaradas a continuacion (ssl_bundle_crt y ssl_key)

El formato debe ser concatenado como lo utiliza nginx:  

https://www.digicert.com/es/instalar-certificado-ssl-nginx.htm


##### Cargar en archivo vars la entrada del proxy reverso

- Modificar los valores deseados como resolver, set_real_ip_from, proxy_pass (URL destino).proxy_redirect, set_real_ip_from y si se desea redireccionar desde puerto 80 HTTP a HTTPS

```
ssl_bundle_crt: pruebaunbackend.crt
ssl_key: pruebaunbackend.key


nginx_vhosts:
  - listen: "443 ssl"
    server_name: "pruebaunbackend.abastible.cl"
    access_log: "/var/log/nginx/pruebaunbackend.access.log"
    error_log: "/var/log/nginx/pruebaunbackend.error.log"
    state: "present"
    template: "{{ nginx_vhost_template }}"
    filename: "pruebaunbackend.conf"
    extra_parameters: |
      location / {

          proxy_set_header Upgrade $http_upgrade;
          proxy_set_header        Host $host;
          proxy_set_header        X-Real-IP $remote_addr;
          proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
          proxy_set_header        X-Forwarded-Proto $scheme;

          proxy_pass           https://backend;
          proxy_set_header If-Modified-Since $http_if_modified_since;
          proxy_connect_timeout 7;
          proxy_read_timeout 360;
      }
      ssl_certificate     /etc/nginx/certs/pruebaunbackend.crt;
      ssl_certificate_key /etc/nginx/certs/pruebaunbackend.key;
      ssl_protocols       TLSv1.2 TLSv1.3;
      ssl_ciphers         EECDH+AESGCM:EDH+AESGCM;
      ssl_prefer_server_ciphers on;
      ssl_dhparam /etc/nginx/dhparams.pem; # openssl dhparam -out /etc/nginx/dhparam.pem 4096
      ssl_ecdh_curve secp384r1; # Requires nginx >= 1.1.0
      ssl_session_timeout  10m;
      ssl_session_cache shared:SSL:10m;
      ssl_session_tickets off; # Requires nginx >= 1.5.9
      ssl_stapling on; # Requires nginx >= 1.3.7
      ssl_stapling_verify on; # Requires nginx => 1.3.7
      resolver 8.8.8.8 1.1.1.1 valid=300s;
      resolver_timeout 5s;
      add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
      add_header X-Frame-Options SAMEORIGIN;
      add_header X-Content-Type-Options nosniff;
      add_header X-XSS-Protection "1; mode=block";
      real_ip_header X-Forwarded-For;
      set_real_ip_from 144.217.17.4;

  - server_name: pruebaunbackend.abastible.cl
    listen: 80
    return: '301 https://pruebaunbackend.abastible.cl$request_uri'

nginx_upstreams:
  - name: backend
    strategy: "hash $remote_addr"
    servers: {
      "google.com:443 max_fails=1 fail_timeout=60s",
      "yahoo.com:443 max_fails=1 fail_timeout=60s",
      "taringa.net max_fails=1 fail_timeout=60s"
    }
```

#### Activar WAF 2.0 en panel de plataforma bitninja

- Se debe activar el modulo WAF 2.0 desde el panel central del waf

- Una ves activado, validar el funcionamiento creando el registro DNS a utilizar o utilizar resolucion
local mediante archivo hosts

- Realizar peticion mediante navegador web: https://pruebaunbackend.abastible.cl/info.php?file=/etc/passwd

- La misma debe bloquearse, mostrar opcion continuar y permitir resolver captcha para comprobar que no es robot.
