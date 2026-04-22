---
Enumeración:
---
Recopila información sobre usuarios, grupos, recursos compartidos y hasta políticas de seguridad. 

En la máquina [[Empire: Breakout]] utilizamos enum4linux para encontrar usuarios ya que ya teníamos la contraseña

``` bash
enum4linux [opciones] <IP del objetivo>
```

``` bash
enum4linux -a 10.40.2.11
```

`-a` indica que se realice una ==enumeración completa==, lo que significa que enum4linux intentará recopilar la mayor cantidad posible de información sobre el sistema objetivo, incluyendo usuarios, grupos, recursos compartidos, políticas de seguridad y más.

