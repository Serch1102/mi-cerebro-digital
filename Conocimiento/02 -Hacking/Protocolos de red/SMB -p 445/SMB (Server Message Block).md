---
Enumeración: 
Transferencia de archivos:
---

## SMB (Server Message Block):

**Descripción del Protocolo:**
Server Message Block (SMB) es un protocolo de red utilizado para compartir archivos, impresoras y otros recursos entre [[Glosario#^d0278a|nodos]] de una red. Originalmente desarrollado por IBM, ha evolucionado y es ampliamente adoptado en sistemas Windows. Facilita la comunicación entre sistemas cliente y servidor, permitiendo el acceso a recursos compartidos y la transferencia de datos. ^a8a5ef

**Papel en la Ciberseguridad:**
SMB juega un papel clave en la ciberseguridad, ya que su uso extendido lo convierte en un objetivo para posibles ataques. La ==configuración inadecuada== de los recursos compartidos SMB puede llevar a vulnerabilidades y ==exposición no autorizada de datos como usuarios o directorios.==



## Cheatsheet de Comandos SMB:

### Conexión a un recurso compartido:
```bash
smbclient //servidor/recurso -U usuario
```
Este comando establece una conexión al recurso compartido en el servidor especificado, utilizando el nombre de usuario proporcionado.

### Listar recursos compartidos disponibles en un servidor:
```bash
smbclient -L //servidor -U usuario
```
Este comando lista los recursos compartidos disponibles en el servidor especificado, utilizando el nombre de usuario proporcionado.

### Montar un recurso compartido en el sistema de archivos local:
```bash
sudo mount -t cifs //servidor/recurso /mnt/punto_de_montaje -o username=usuario,password=contraseña
```
Este comando monta el recurso compartido en el sistema de archivos local en el punto de montaje especificado, utilizando el nombre de usuario y contraseña proporcionados.

### Desmontar un recurso compartido montado:
```bash
sudo umount /mnt/punto_de_montaje
```
Este comando desmonta el recurso compartido previamente montado en el punto de montaje especificado.

### Transferencia de archivos desde y hacia un recurso compartido:
```bash
smbget //servidor/recurso/archivo
```
Este comando descarga un archivo desde el recurso compartido en el servidor especificado.

```bash
smbput archivo //servidor/recurso/destino
```
Este comando carga un archivo al recurso compartido en el servidor especificado.

### Acceso rápido a recursos compartidos usando navegador de archivos:
```bash
smb://servidor/recurso
```
Este formato de URL permite acceder a un recurso compartido utilizando un navegador de archivos compatible con SMB.

### Escaneo y Mapeo de Recursos Compartidos en un Servidor SMB:
```bash
smbmap -H <IP>
```
Este comando escanea y mapea los recursos compartidos disponibles en el servidor SMB con la dirección IP especificada (10.40.2.10). Proporciona información sobre los recursos compartidos, los permisos de acceso y otros detalles relevantes.



## Precauciones y Consideraciones:
- Al utilizar comandos SMB, asegúrate de tener los permisos adecuados para acceder a los recursos compartidos.
- Protege tus credenciales de inicio de sesión y evita almacenarlas en texto plano.
- Verifica que los recursos compartidos estén configurados correctamente para permitir el acceso desde la red.

Estos comandos te permitirán interactuar con recursos compartidos SMB de forma eficiente y segura en entornos de red.



## Relación entre SMB y SAMBA:

SMB y Samba están relacionados, pero cumplen funciones diferentes:
- **SMB** es el protocolo en sí, utilizado en sistemas Windows y otros sistemas operativos para compartir recursos.
- **Samba** es una implementación de código abierto del protocolo SMB que permite la interoperabilidad entre sistemas Windows y sistemas basados en Unix/Linux.

## Vulnerabilidades Frecuentes en SMB:

1. **Ataques de Fuerza Bruta:** Intentos de adivinar o crackear contraseñas para obtener acceso no autorizado.
2. **Exposición de Recursos Sensibles:** Configuraciones incorrectas pueden exponer datos críticos.
3. **Vulnerabilidades de Software:** Fallos en la implementación del protocolo pueden ser explotados por atacantes.
4. **Diseminación de Malware:** SMB ha sido utilizado como vector de propagación para malware y ransomware, permitiendo la distribución rápida de amenazas a través de una red comprometida.



## Máquinas:

[Symphonos](https://www.vulnhub.com/entry/symfonos-1,322/)