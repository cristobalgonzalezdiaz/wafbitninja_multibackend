# wafbitninja_backend_unico

- Rol para implementar waf con solo un servidor de backend

## Instrucciones

- Editar el archivo hosts apuntando al servidor destino, usuario con privilegios sudo y puerto ssh correspondiente

Ejemplo de inventario    34.141.43.33 ansible_user=cristobal ansible_become=yes ansible_port=10200

- Revisar variables declaradas debajo para personalizar si se desea

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

##### Agregar llaves login root

llaves: <br>
  - user: root <br>
    sshKey: ssh-rsa <br>  AAAAB3NzaC1yc2EAAAADAQABAAABAQDFXsPMyC2erjKcVflIHwTX9vINIc4yzcmUE0uJxKLbUtYcbtGTbdk8GvSSiVQkSTjzJl+B79nJ5nIlMou9bMChQjS54B9hbSDdbVohArgazleMq8aToVwy05mdggkvDzdg9U0TpcC6zvaNe94nhBnDO4ShZ/kCSGOpOf5YehVJohKrZkqiBv0fywWk7okLbHBymE+6yxK156KdajT0a/JpqW6WD+3fvdYpZRYSty+FMw/fKVkw75GJHVgne1wzyjTlM29e0L0gszJZvV7YW+050pJiX3s69cBojgD0k9FAqROQpsh/WDUj+h80oWZVX7BosAxOmR7dk#$!ffafff usuario@hostname

##### Variables default 

sshPort: 22			<br>
LoginGraceTime: 30		<br>
MaxAuthTries: 2<br>
MaxSessions: 4<br>
GSSAPIAuthentication: "no"<br>
X11Forwarding: "no"<br>
usarFirewalld: true<br>
rootlogin: false<br>
PermitRootLogging: "no"<br>
HostbasedAuthentication: "no"<br>
IgnoreRhosts: "yes"<br>
LogLevel: "INFO"<br>

#### Rol "bitninja" roles/bitninja/vars/main.yml
APIKEY: "LLENARCONUNAAPIKEYENDEFAULTSOENVARS"


#### Rol "nginx" roles/nginx/vars/main.yml

##### Cargar certificado SSL

Se debe agregar los archivos SSL en el path roles/nginx/files/ respetando el nombre a utilizar en las variables declaradas a continuacion (ssl_bundle_crt y ssl_key)

El formato debe ser concatenado como lo utiliza nginx:  

https://www.digicert.com/es/instalar-certificado-ssl-nginx.htm


##### Cargar en archivo vars la entrada del proxy reverso

- Modificar los valores deseados como resolver, set_real_ip_from, proxy_pass (URL destino) y proxy_redirect

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

          proxy_set_header        Host $host;
          proxy_set_header        X-Real-IP $remote_addr;
          proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
          proxy_set_header        X-Forwarded-Proto $scheme;

          proxy_pass           https://http.cat;
          proxy_read_timeout  90;
          proxy_redirect      https://http.cat https://pruebaunbackend.abastible.cl;
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
```
