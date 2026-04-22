---
Escalada de privilegios: 
Permisos de archivos:
---

### Comando `getcap`:

El comando `getcap` se utiliza en sistemas Linux para ==mostrar las capacidades extendidas de los archivos del sistema de archivos.== Estas capacidades otorgan permisos especiales a programas, permitiéndoles realizar ciertas operaciones sin necesidad de privilegios elevados. El comando `getcap -r / 2>/dev/null` se utiliza para listar las capacidades extendidas de todos los archivos en el sistema de archivos, ignorando los errores de permisos y redireccionando los mensajes de error a la nada (`/dev/null`).

### Papel en la Escalada de Privilegios:

En el contexto de la escalada de privilegios, el comando `getcap` puede ser utilizado por atacantes para identificar archivos con capacidades extendidas que podrían ser aprovechadas para obtener acceso elevado. Los archivos con ciertas capacidades pueden representar puntos de entrada para posibles ataques de escalada de privilegios si no están configurados adecuadamente.

### Explicación del Comando:

- `getcap`: Invoca el comando para obtener las capacidades extendidas de los archivos.
- `-r /`: Recorre recursivamente el sistema de archivos desde la raíz (`/`).
- `2>/dev/null`: Redirige los mensajes de error estándar (salida stderr, representado por el descriptor de archivo 2) al dispositivo nulo (`/dev/null`), lo que suprime los mensajes de error que podrían surgir debido a permisos insuficientes.

### Ejemplo con Vulnerabilidad:

Supongamos que un archivo binario llamado `vulnerable_binary` tiene una capacidad extendida que le permite ejecutarse con privilegios elevados. Al ejecutar `getcap -r / 2>/dev/null`, se mostraría:

```
/usr/bin/vulnerable_binary = cap_setuid+ep
```

Esta salida indica que el archivo `vulnerable_binary` tiene la capacidad `cap_setuid`, lo que le permite ejecutarse con los mismos privilegios que el usuario que lo posee, y `ep` indica que es un archivo ejecutable con permisos extendidos.

Un atacante podría aprovechar este archivo para ejecutar comandos con privilegios elevados si encuentra una vulnerabilidad en él o en algún proceso relacionado, lo que potencialmente conduciría a una escalada de privilegios en el sistema.