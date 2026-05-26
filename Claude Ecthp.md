# eCTHPv2 — Guía de Estudio Completa

### Threat Hunting Professional · Solo Recursos Gratuitos

> **Perfil objetivo:** SOC Analyst con base Blue Team que quiere aprobar el eCTHP  
> **Duración estimada:** 10 semanas · 1h/día  
> **Formato del examen:** 40 preguntas tipo test (teoría) + 20 preguntas prácticas con Splunk, ELK y Wireshark en entorno real · 10 horas totales

---

## ÍNDICE

1. [Metodologías de Threat Hunting](https://claude.ai/chat/0fe81f54-15e2-4fe9-b7f5-035fffbc40d9#dominio-1)
2. [Análisis de Tráfico de Red](https://claude.ai/chat/0fe81f54-15e2-4fe9-b7f5-035fffbc40d9#dominio-2)
3. [Análisis de Endpoint](https://claude.ai/chat/0fe81f54-15e2-4fe9-b7f5-035fffbc40d9#dominio-3)
4. [Búsqueda basada en Logs (SIEM)](https://claude.ai/chat/0fe81f54-15e2-4fe9-b7f5-035fffbc40d9#dominio-4)
5. [Post-Explotación y Persistencia (MITRE ATT&CK)](https://claude.ai/chat/0fe81f54-15e2-4fe9-b7f5-035fffbc40d9#dominio-5)
6. [Estrategia de Estudio y Consejos de Examen](https://claude.ai/chat/0fe81f54-15e2-4fe9-b7f5-035fffbc40d9#estrategia)

---

## DOMINIO 1 — Metodologías de Threat Hunting {#dominio-1}

### Conceptos Fundamentales

**¿Qué es Threat Hunting?**  
La búsqueda proactiva de amenazas que han evadido los controles de seguridad automáticos. No esperas alertas — las generas tú a partir de hipótesis.

<mark style="background:#b1ffff">**Threat Hunting Maturity Model (THMM):**</mark>

- <mark style="background:#b1ffff">Nivel 0 — Inicial</mark>: dependencia total de alertas automáticas. Sin hunting real.
- <mark style="background:#b1ffff">Nivel 1 — Mínimo</mark>: búsquedas manuales básicas con IOCs conocidos.
- <mark style="background:#b1ffff">Nivel 2 — Procedural</mark>: aplica procedimientos de hunting documentados.
- <mark style="background:#b1ffff">Nivel 3 — Innovador</mark>: crea nuevas técnicas de detección propias.
- <mark style="background:#b1ffff">Nivel 4 — Líder</mark>: automatiza el hunting, genera inteligencia nueva.

**<mark style="background:#affad1">Tipos de hipótesis de hunting</mark>:**

- <mark style="background:#affad1">Intelligence-driven</mark>: <mark style="background:#affad1">parte de un TTP conocido de un actor de amenaza</mark> ("APT29 usa Cobalt Strike con named pipes personalizados")
- <mark style="background:#affad1">Analytics-driven</mark>: <mark style="background:#affad1">parte de una anomalía estadística detectada en logs</mark>
- <mark style="background:#affad1">Situational-awareness</mark>: <mark style="background:#affad1">parte del contexto del negocio ("Acabamos de hacer una adquisición, hay riesgo de insider threat")</mark>

**<mark style="background:#ff4d4f">Cyber Kill Chain</mark> (Lockheed Martin) — Las 7 fases:**

1. <mark style="background:#ff4d4f">Reconnaissance</mark> — Reconocimiento del objetivo
2. <mark style="background:#ff4d4f">Weaponization — Creación del arma</mark> (exploit + payload)
3. <mark style="background:#ff4d4f">Delivery</mark> — Entrega del arma (email, USB, web)
4. <mark style="background:#ff4d4f">Exploitation — Ejecución del exploit</mark>
5. <mark style="background:#ff4d4f">Installation — Persistencia en el sistema</mark>
6. <mark style="background:#ff4d4f">Command & Control (C2)</mark> — Canal de comunicación atacante→víctima
7. <mark style="background:#ff4d4f">Actions on Objectives — Objetivo final (exfiltración, ransomware...)</mark>

**Diamond Model of Intrusion Analysis:**  
Cuatro vértices: Adversario → Capacidad → Infraestructura → Víctima  
Útil para correlacionar campañas y atribuir actividad.

**MITRE ATT&CK Framework:**  
14 tácticas → múltiples técnicas → sub-técnicas.  
El hunter usa ATT&CK para construir hipótesis: "Si el adversario usa T1059.001 (PowerShell), ¿qué logs debería ver?"

**Proceso de hunting — 4 pasos:**

1. Crear hipótesis (basada en inteligencia o anomalías)
2. Investigar con herramientas y datos
3. Identificar patrones y TTPs
4. Informar y mejorar detecciones automatizadas

---

### Recursos Gratuitos

|Recurso|Tipo|URL|
|---|---|---|
|AttackIQ Academy — MITRE ATT&CK Fundamentals|Curso gratuito|academy.attackiq.com|
|MITRE ATT&CK Navigator|Herramienta interactiva|mitre-attack.github.io/attack-navigator|
|Hunt Evil (Sqrrl)|PDF referencia|threathunting.net/files/hunt-evil-practical-guide-threat-hunting.pdf|
|SANS Threat Hunting Summit (YouTube)|Charlas técnicas|youtube.com → buscar "SANS Threat Hunting Summit"|
|David Bianco — Pyramid of Pain|Artículo fundamental|detect-respond.blogspot.com|

---

### Laboratorio Sugerido — Dominio 1

**Ejercicio: Construir tu primera hipótesis y documentarla**

1. Entra en attack.mitre.org y elige una técnica aleatoria (ej: T1053.005 — Scheduled Task)
2. Lee la descripción, procedimientos de detección y ejemplos de grupos APT que la usan
3. Escribe una hipótesis formal: "Sospecho que [actor/TTP] está usando [técnica] porque [razón]. Para detectarlo buscaré [evidencia] en [fuente de datos]"
4. Documenta en Obsidian con estructura: Hipótesis → Técnica ATT&CK → Fuentes de datos → Query → Resultado

> [!question] NoEntender
>Los adversarios también pueden utilizar Powershell Cmdlet `Invoke-CimMethod`, que aprovecha la clase WMI `PS_ScheduledTask` para crear una tarea programada a través de una ruta XML. (https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md)

> [!tip] Explicación
> -> **`Invoke-CimMethod`**  
> Es un cmdlet de PowerShell que permite llamar métodos de clases CIM/WMI. En cristiano: permite pedirle a Windows que ejecute acciones administrativas internas.
> -> **WMI / CIM**  
> Son interfaces de administración de Windows. Sirven para consultar o modificar configuraciones del sistema: procesos, servicios, usuarios, tareas programadas, etc.
> -> **XML**
> XML es un formato de texto estructurado para guardar datos y configuración. (similar JSON)

> [!abstract] Resumen
> Un atacante puede usar PowerShell + WMI/CIM para registrar una tarea programada definida en XML, evitando herramientas más evidentes como schtasks.exe, y así conseguir persistencia en el sistema.

> [!question] NoEntender
> Similar to System Binary Proxy Execution, adversaries have also abused the Windows Task Scheduler to potentially mask one-time execution under signed/trusted system processes.[3]




---

### Cheat Sheet — Dominio 1

```
THMM NIVELES:     0=Reactivo | 1=IOCs | 2=Procedural | 3=Innovador | 4=Automatizado
KILL CHAIN:       Recon > Weapon > Deliver > Exploit > Install > C2 > Actions
HIPÓTESIS TIPOS:  Intel-driven | Analytics-driven | Situational
MITRE TACTICS:    Recon|Resource Dev|Initial Access|Execution|Persistence|
                  Priv Esc|Defense Evasion|Credential Access|Discovery|
                  Lateral Movement|Collection|C2|Exfiltration|Impact
PYRAMID OF PAIN:  Hash < IP < Domain < Network/Host Artifacts < Tools < TTPs
```

---

## DOMINIO 2 — Análisis de Tráfico de Red {#dominio-2}

### Conceptos Fundamentales

**Protocolos críticos para el hunter:**

|Protocolo|Puerto|Qué buscar|
|---|---|---|
|DNS|UDP/53, TCP/53|Tunneling, DGA, subdominios largos, queries a TLDs inusuales|
|HTTP/HTTPS|80, 443|User-Agents anómalos, métodos inusuales, beaconing regular|
|SMB|TCP/445|Movimiento lateral, Pass-the-Hash, enumeración de shares|
|RDP|TCP/3389|Acceso remoto no autorizado, brute force|
|ICMP|—|Tunneling ICMP, ping sweeps|
|LDAP|TCP/389|Enumeración de Active Directory|
|Kerberos|UDP/88|Kerberoasting, AS-REP Roasting, Golden Ticket|

**Patrones de C2 (Command & Control):**

- Beaconing: tráfico periódico y regular hacia una IP externa (cada 60s, cada 300s...)
- Jitter: variación artificial del beaconing para evadir detección (± 20%)
- Domain Generation Algorithm (DGA): dominios generados aleatoriamente
- Fast Flux: múltiples IPs para el mismo dominio en corto tiempo
- DNS over HTTPS (DoH): tunneling encubierto en HTTPS

**Indicadores de DNS Tunneling:**

- Subdominios con longitud > 50 caracteres
- Caracteres Base64 en los subdominios
- Volumen alto de queries a un mismo dominio
- Respuestas TXT o NULL records con datos binarios
- TTL muy bajo (para actualización frecuente)

**Zeek (antes Bro) — Logs clave:**

- conn.log — Todas las conexiones de red con duración, bytes, estado
- dns.log — Queries y respuestas DNS completas
- http.log — Requests HTTP con User-Agent, URI, códigos de respuesta
- ssl.log — Conexiones TLS con JA3 fingerprint (muy útil para C2)
- weird.log — Comportamiento anómalo detectado por Zeek

---

### Recursos Gratuitos

|Recurso|Tipo|URL|
|---|---|---|
|Malware Traffic Analysis|PCAPs reales con writeups|malware-traffic-analysis.net|
|Wireshark Sample Captures|PCAPs de referencia|wiki.wireshark.org/SampleCaptures|
|TryHackMe — Wireshark: The Basics|Lab guiado gratuito|tryhackme.com/room/wiresharkthebasics|
|TryHackMe — Wireshark: Packet Operations|Lab gratuito|tryhackme.com/room/wiresharkpacketsoperations|
|TryHackMe — Zeek|Lab gratuito|tryhackme.com/room/zeekbro|
|NetworkMiner|Herramienta gratuita de análisis PCAP|netresec.com/?page=NetworkMiner|
|RITA (Real Intelligence Threat Analytics)|Detección de beaconing sobre logs Zeek|github.com/activecountermeasures/rita|

---

### Laboratorio Sugerido — Dominio 2

**Ejercicio A: Análisis de PCAP de infección real**

1. Descarga un PCAP de malware-traffic-analysis.net (elige uno reciente con C2)
2. Abre en Wireshark y aplica estos filtros secuencialmente:
    - `dns` → identifica queries sospechosas
    - `http.request` → revisa User-Agents y URIs
    - `tcp.flags.syn==1 && tcp.flags.ack==0` → escaneos de puertos
3. Exporta los IOCs (IPs, dominios, User-Agents)
4. Valida en VirusTotal y AbuseIPDB
5. Mapea la actividad a la Kill Chain y a TTPs de ATT&CK

**Ejercicio B: Detectar beaconing con seguimiento de conversaciones**

1. En Wireshark: Statistics → Conversations → TCP
2. Ordena por duración o número de packets
3. Identifica conexiones periódicas al mismo destino
4. Compara intervalos de tiempo con Follow TCP Stream

---

### Cheat Sheet — Wireshark y tcpdump

```bash
# WIRESHARK — FILTROS ESENCIALES
dns                              # Todo tráfico DNS
dns.qry.name contains "base64"  # DNS con strings sospechosos
http.request.method == "POST"   # POST requests HTTP
tcp.port == 4444                 # Puerto típico de Metasploit
ip.addr == 192.168.1.1           # Filtrar por IP
!(arp or dns or icmp)           # Excluir ruido habitual
tcp.flags.syn==1&&tcp.flags.ack==0  # SYN scan
frame contains "cmd.exe"         # Buscar strings en payload
ssl.handshake.type == 1          # Client Hello TLS

# TCPDUMP — CAPTURA EN CLI
tcpdump -i eth0 -w captura.pcap              # Captura a archivo
tcpdump -i eth0 port 53 -w dns.pcap          # Solo DNS
tcpdump -i eth0 'tcp[tcpflags]=tcp-syn'      # Solo SYN
tcpdump -i eth0 -r captura.pcap -nn          # Leer archivo sin resolver
tcpdump -i eth0 host 8.8.8.8                 # Filtrar por host
tcpdump -i eth0 not port 22 -c 1000          # Excluir SSH, 1000 paquetes

# ZEEK — LOGS ÚTILES
cat conn.log | zeek-cut id.orig_h id.resp_h service duration  # Conexiones
cat dns.log | zeek-cut query answers TTL                       # Queries DNS
cat http.log | zeek-cut host uri user_agent status_code        # HTTP
cat ssl.log | zeek-cut server_name ja3 ja3s                    # TLS/JA3
```

---

## DOMINIO 3 — Análisis de Endpoint {#dominio-3}

### Conceptos Fundamentales

**Windows Event IDs críticos para hunting:**

|Event ID|Descripción|Por qué importa|
|---|---|---|
|4624|Logon exitoso|Detectar accesos anómalos (tipo 3=red, tipo 10=RemoteInteractive)|
|4625|Logon fallido|Brute force, password spraying|
|4648|Logon con credenciales explícitas|Pass-the-Hash, runas malicioso|
|4688|Creación de proceso|Cadenas de ejecución maliciosa|
|4698|Scheduled Task creada|Persistencia T1053|
|4720|Cuenta de usuario creada|Backdoor de usuario|
|4732|Usuario añadido a grupo|Escalada de privilegios|
|4776|Validación de credenciales NTLM|Lateral movement|
|7045|Nuevo servicio instalado|Persistencia T1543|
|1102|Log de seguridad borrado|Anti-forensics, T1070|

**Sysmon — Event IDs esenciales:**

|Sysmon ID|Descripción|
|---|---|
|1|Process Creation (con línea de comandos completa)|
|2|File creation time changed (timestomping)|
|3|Network Connection|
|7|Image loaded (DLL injection)|
|8|CreateRemoteThread (process injection)|
|10|ProcessAccess (LSASS dumping)|
|11|FileCreate|
|12/13|Registry add/delete|
|15|FileCreateStreamHash (ADS)|
|22|DNS Query|

**Técnicas de evasión comunes a detectar:**

- **Living-off-the-Land (LotL):** uso de binarios legítimos de Windows para ejecutar código malicioso. LOLBins: certutil, mshta, regsvr32, rundll32, wscript, cscript, msiexec, bitsadmin
- **Process Injection:** inyección de código en proceso legítimo (svchost, explorer). Sysmon ID 8 y 10
- **Timestomping:** modificar timestamps de archivos para evadir análisis forense. Sysmon ID 2
- **Fileless Malware:** ejecución en memoria sin tocar disco. Detectable con Script Block Logging (Event 4104)
- **AMSI Bypass:** evasión del Antimalware Scan Interface de Windows

**Artefactos forenses de Windows:**

- Prefetch (.pf) → evidencia de ejecución de programas
- LNK files → archivos de acceso reciente
- Registry Run keys → persistencia
- Scheduled Tasks (XML en C:\Windows\System32\Tasks)
- WMI Subscriptions → persistencia avanzada
- NTFS Alternate Data Streams (ADS) → ocultación de datos

---

### Recursos Gratuitos

|Recurso|Tipo|URL|
|---|---|---|
|TryHackMe — Windows Event Logs|Lab gratuito|tryhackme.com/room/windowseventlogs|
|TryHackMe — Sysmon|Lab gratuito|tryhackme.com/room/sysmon|
|SwiftOnSecurity Sysmon Config|Config referencia|github.com/SwiftOnSecurity/sysmon-config|
|Olaf Hartong Sysmon Modular|Config avanzada|github.com/olafhartong/sysmon-modular|
|EVTX Attack Samples|Samples de logs maliciosos|github.com/sbousseaden/EVTX-ATTACK-SAMPLES|
|Sysinternals Suite|Herramientas Microsoft gratuitas|docs.microsoft.com/sysinternals|
|Eric Zimmerman Tools|Herramientas forenses gratuitas|ericzimmerman.github.io|

---

### Laboratorio Sugerido — Dominio 3

**Ejercicio: Hunting de PowerShell malicioso en tu lab**

Requisitos: Windows 10 VM (VirtualBox/VMware), Sysmon instalado con config de SwiftOnSecurity

```powershell
# 1. Instalar Sysmon con config de referencia
.\Sysmon64.exe -accepteula -i sysmonconfig.xml

# 2. Simular técnica maliciosa (en VM aislada)
# T1059.001 — PowerShell con codificación Base64
$cmd = "Write-Host 'Simulated malware'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell -EncodedCommand $encoded

# 3. Buscar la evidencia en Event Viewer
# Aplicaciones y servicios > Microsoft > Windows > Sysmon/Operational
# Filtrar por Event ID 1, buscar "-EncodedCommand" en CommandLine

# 4. También buscar en PowerShell Script Block Logging
# Event ID 4104 en PowerShell/Operational
```

**Ejercicio: Detectar LSASS dumping (simulación)**

```powershell
# Habilitar auditoría de acceso a LSASS
# Group Policy: Audit Process Access → Success + Failure

# Sysmon ID 10 mostrará acceso a LSASS cuando se intente dump
# Buscar: TargetImage = lsass.exe, GrantedAccess = 0x1010 o 0x1fffff
```

---

### Cheat Sheet — PowerShell para Hunting

```powershell
# CONSULTAR EVENT LOGS
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4688]]" |
  Select-Object TimeCreated, Message | Format-List

# FILTRAR PROCESS CREATION con PowerShell en línea de comandos
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object {$_.Id -eq 1 -and $_.Message -like "*powershell*"} |
  Select-Object TimeCreated, Message

# BUSCAR SCHEDULED TASKS SOSPECHOSAS
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"} |
  Select-Object TaskName, TaskPath, State

# BUSCAR SERVICIOS INSTALADOS RECIENTEMENTE
Get-WinEvent -LogName System |
  Where-Object {$_.Id -eq 7045} |
  Select-Object TimeCreated, Message

# LISTAR CONEXIONES DE RED ACTIVAS CON PROCESO
Get-NetTCPConnection -State Established |
  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort,
  @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).Name}}

# BUSCAR PROCESOS HIJO DE OFFICE (IOC de phishing)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object {$_.Id -eq 1} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    if ($xml.Event.EventData.Data |
      Where-Object {$_.Name -eq "ParentImage" -and $_.'#text' -like "*WINWORD*"}) {
      $_
    }
  }

# BUSCAR ALTERNATE DATA STREAMS
Get-Item -Path C:\Users\* -Stream * |
  Where-Object {$_.Stream -ne ':$DATA'} |
  Select-Object FileName, Stream, Length
```

---

## DOMINIO 4 — Búsqueda basada en Logs / SIEM {#dominio-4}

### Conceptos Fundamentales

**Arquitectura de un SIEM:**

- Agentes → recolectan logs de fuentes (Winlogbeat, Filebeat, NXLog)
- Indexador → procesa e indexa (Elasticsearch, Splunk Indexer)
- Correlación → aplica reglas y detecta patrones
- Visualización → dashboards (Kibana, Splunk Web)
- Alertas → notificaciones sobre detecciones

**Fuentes de datos clave:**

- Windows Event Logs (Security, System, Application, PowerShell, Sysmon)
- Firewall logs (permitidos + bloqueados)
- Proxy/Web logs (URLs, User-Agents, categorías)
- DNS logs (queries y respuestas)
- Authentication logs (AD, VPN, Cloud)
- EDR telemetry (CrowdStrike, Defender, Cortex)

---

### SPL (Splunk Processing Language) — Esencial

**Estructura básica:**

```
index=<fuente> [filtros] | comando1 | comando2 | ...
```

**Queries de hunting fundamentales:**

```splunk
# ── PROCESS CREATION ──────────────────────────────────────────

# Detectar PowerShell con encoding Base64
index=windows EventCode=4688 CommandLine="*-EncodedCommand*" OR
CommandLine="*-enc *" OR CommandLine="*-e *"
| table _time, ComputerName, User, CommandLine

# Detectar LOLBins sospechosos lanzando procesos hijo
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
ParentImage IN ("*mshta.exe","*wscript.exe","*cscript.exe","*regsvr32.exe","*rundll32.exe")
| stats count by ParentImage, Image, CommandLine

# Detectar procesos Office con hijos sospechosos (phishing)
index=windows EventCode=1
ParentImage IN ("*WINWORD.EXE","*EXCEL.EXE","*OUTLOOK.EXE")
Image IN ("*cmd.exe","*powershell.exe","*wscript.exe","*mshta.exe")
| table _time, ComputerName, ParentImage, Image, CommandLine

# ── PERSISTENCIA ──────────────────────────────────────────────

# Scheduled Tasks creadas fuera de rutas estándar
index=windows EventCode=4698
| rex field=Message "Task Name:\s+(?<TaskName>[^\r\n]+)"
| search NOT TaskName IN ("*Microsoft*","*Adobe*","*Google*")
| table _time, ComputerName, User, TaskName

# Nuevos servicios instalados
index=windows EventCode=7045
| table _time, ComputerName, ServiceName, ImagePath, ServiceType

# ── CREDENCIALES ──────────────────────────────────────────────

# Password spraying (muchos fallos de logon desde mismo origen)
index=windows EventCode=4625
| stats count by IpAddress, TargetUserName
| where count > 10
| sort -count

# Pass-the-Hash (logon tipo 3 con NTLM)
index=windows EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM
| stats count by WorkstationName, IpAddress, TargetUserName
| sort -count

# ── RED ──────────────────────────────────────────────────────

# Beaconing: conexiones periódicas al mismo destino externo
index=network
| stats count, min(_time) as first, max(_time) as last by src_ip, dest_ip, dest_port
| eval duration=last-first
| eval avg_interval=duration/count
| where count > 50 AND avg_interval < 120
| sort avg_interval
```

---

### KQL (Kibana Query Language) — Esencial

```kql
# ESTRUCTURA BÁSICA
campo: "valor"
campo: valor AND otro_campo: valor
campo: valor OR campo: otro_valor
NOT campo: valor
campo: [valor_min TO valor_max]

# PROCESS CREATION — Sysmon ECS (Elastic Common Schema)
event.code: "1" AND
process.command_line: (*-EncodedCommand* OR *IEX* OR *Invoke-Expression*)

# POWERSHELL SCRIPT BLOCK LOGGING
event.code: "4104" AND
message: (*DownloadString* OR *IEX* OR *Invoke-Mimikatz* OR *AmsiUtils*)

# LSASS ACCESS
event.code: "10" AND
winlog.event_data.TargetImage: "*lsass.exe" AND
winlog.event_data.GrantedAccess: ("0x1010" OR "0x1fffff" OR "0x1410")

# DNS TUNNELING — Subdominios largos
event.code: "22" AND
dns.question.name.length > 50

# LATERAL MOVEMENT — SMB
event.code: "4624" AND
winlog.event_data.LogonType: "3" AND
winlog.event_data.AuthenticationPackageName: "NTLM"

# SCHEDULED TASKS SOSPECHOSAS
event.code: "4698" AND
NOT winlog.event_data.TaskName: (\Microsoft\* OR \Adobe\*)
```

---

### Recursos Gratuitos

|Recurso|Tipo|URL|
|---|---|---|
|TryHackMe — Splunk 101|Lab gratuito|tryhackme.com/room/splunk101|
|TryHackMe — Investigating with ELK|Lab gratuito|tryhackme.com/room/investigatingwithelk101|
|Boss of the SOC v3 (dataset Splunk)|Dataset gratuito|github.com/splunk/botsv3|
|Splunk Security Content (detecciones ATT&CK)|Repositorio|github.com/splunk/security_content|
|Elastic SIEM (trial 14 días)|Plataforma|cloud.elastic.co|
|Splunk Free (500MB/día)|Plataforma|splunk.com/en_us/download/splunk-enterprise|
|CyberDefenders — BlueYard Labs|Labs Blue Team|cyberdefenders.org|
|Sigma Rules (reglas SIEM agnósticas)|Repositorio|github.com/SigmaHQ/sigma|

---

### Laboratorio Sugerido — Dominio 4

**Ejercicio: Hunting completo con Boss of the SOC (Splunk)**

1. Instala Splunk Free (trial o versión gratuita)
2. Descarga el dataset BOTS v3 de GitHub e ingéstalo
3. Investiga el escenario guiado: hay un APT simulado dentro de la red
4. Preguntas a responder con SPL:
    - ¿Qué proceso padre lanzó cmd.exe por primera vez en el día del ataque?
    - ¿Qué cuenta de usuario fue comprometida?
    - ¿Hubo exfiltración de datos? ¿A qué IP?

---

## DOMINIO 5 — Post-Explotación y Persistencia (MITRE ATT&CK) {#dominio-5}

### Conceptos Fundamentales

**Técnicas de post-explotación más cazadas en el examen:**

**T1059 — Command and Scripting Interpreter**

- .001 PowerShell → detectar con Event 4104, 4688, Sysmon ID 1
- .003 Windows Command Shell → cmd.exe con flags inusuales
- .005 Visual Basic → wscript/cscript ejecutando .vbs o .js

**T1078 — Valid Accounts**

- Uso de credenciales legítimas robadas
- Detectar: logons en horarios inusuales, desde IPs nuevas, con cuentas de servicio

**T1053 — Scheduled Task/Job**

- Persistencia clásica y muy testada en el examen
- Detectar: Event ID 4698, 4702, archivos XML en C:\Windows\System32\Tasks

**T1547 — Boot/Logon Autostart**

- Registry Run Keys: HKCU/HKLM\Software\Microsoft\Windows\CurrentVersion\Run
- Detectar: Sysmon ID 13, auditoría de registry

**T1055 — Process Injection**

- DLL Injection, Process Hollowing, Reflective Injection
- Detectar: Sysmon ID 8 (CreateRemoteThread), ID 10 (ProcessAccess)

**T1003 — OS Credential Dumping**

- LSASS Memory (Mimikatz) → Sysmon ID 10, GrantedAccess 0x1010
- SAM dump → reg save HKLM\SAM
- NTDS.dit → extracción de base de datos AD

**T1021 — Remote Services (Lateral Movement)**

- SMB/Windows Admin Shares → Event 4624 LogonType 3 + acceso a IPC$
- RDP → Event 4624 LogonType 10
- WMI → Event 4688 wmiprvse.exe como padre

**T1070 — Indicator Removal**

- Clear Event Logs → Event ID 1102 (Security log cleared)
- Timestomping → Sysmon ID 2
- File deletion → Sysmon ID 23

**T1048 — Exfiltración**

- DNS Tunneling (T1048.001) → queries DNS voluminosas con subdominios codificados
- HTTPS (T1048.002) → tráfico HTTPS a dominios nuevos/no categorizados
- FTP/SMB alternativos

---

### Técnicas de Evasión de Defensa (T1562)

|Técnica|Qué hace|Cómo detectarlo|
|---|---|---|
|T1562.001|Deshabilitar AV/EDR|Event 7036 (servicio detenido), reg key modificada|
|T1562.002|Deshabilitar Windows Firewall|Event 2004/2006, netsh en CommandLine|
|T1562.003|AMSI Bypass|Script Block 4104 con strings como "AmsiUtils"|
|T1027|Ofuscación|Base64, XOR, char() en comandos PowerShell|
|T1140|Decodificar/Deofuscar|certutil -decode, uso de expand o expand.exe|

---

### Recursos Gratuitos

|Recurso|Tipo|URL|
|---|---|---|
|MITRE ATT&CK Enterprise Matrix|Framework completo|attack.mitre.org/matrices/enterprise|
|Atomic Red Team|Tests de simulación|github.com/redcanaryco/atomic-red-team|
|MITRE CALDERA|Plataforma de emulación gratuita|caldera.mitre.org|
|Red Canary Threat Detection Report|Informe anual gratuito|redcanary.com/threat-detection-report|
|TryHackMe — Lateral Movement|Lab gratuito|tryhackme.com/room/lateralmovementandpivoting|
|CyberDefenders — Malware Analysis labs|Labs gratuitos|cyberdefenders.org|
|ANY.RUN — Sandbox gratuito|Análisis dinámico|app.any.run|

---

### Laboratorio Sugerido — Dominio 5

**Ejercicio: Emulación de APT con Atomic Red Team**

```powershell
# En VM Windows aislada con Sysmon instalado

# 1. Instalar Atomic Red Team
Install-Module -Name invoke-atomicredteam -Force
Import-Module invoke-atomicredteam

# 2. Simular T1059.001 (PowerShell)
Invoke-AtomicTest T1059.001

# 3. Simular T1053.005 (Scheduled Task)
Invoke-AtomicTest T1053.005

# 4. Simular T1003.001 (LSASS Dump)
Invoke-AtomicTest T1003.001

# 5. Revisar logs generados en Sysmon y Event Viewer
# 6. Documentar: ¿Qué evidencia quedó? ¿Qué hubiera detectado tu SIEM?
# 7. Crear una regla Sigma para cada técnica simulada
```

---

## ESTRATEGIA DE ESTUDIO Y CONSEJOS DE EXAMEN {#estrategia}

### Plan Semanal — 10 Semanas (1h/día)

|Semana|Dominio|Actividad|
|---|---|---|
|1–2|Dom. 1 — Metodología|AttackIQ Academy + navegar ATT&CK + construir 3 hipótesis|
|3–5|Dom. 2 — Red|Analizar 5 PCAPs de malware-traffic-analysis + labs THM Wireshark|
|6–8|Dom. 3 — Endpoint|Instalar Sysmon en VM + labs THM Sysmon/EventLogs + Atomic Red Team|
|7–9|Dom. 4 — SIEM|Splunk con BOTS dataset + labs ELK en THM|
|9–10|Dom. 5 + Repaso|CyberDefenders labs completos + simulacros de examen|

_Los dominios 3 y 4 se solapan porque se estudian mejor en paralelo._

---

### Sistema de notas recomendado (Obsidian)

```
📁 eCTHP/
├── 📁 01-Metodologia/
│   ├── THMM.md
│   ├── Kill-Chain.md
│   ├── MITRE-ATT&CK.md
│   └── Hipotesis/  (una nota por hipótesis trabajada)
├── 📁 02-Network/
│   ├── Wireshark-filtros.md
│   ├── Tcpdump.md
│   ├── Protocolos/  (DNS.md, SMB.md, HTTP.md...)
│   └── PCAPs-analizados/
├── 📁 03-Endpoint/
│   ├── Event-IDs.md
│   ├── Sysmon-IDs.md
│   ├── LOLBins.md
│   └── Artefactos-Windows.md
├── 📁 04-SIEM/
│   ├── SPL-queries.md
│   ├── KQL-queries.md
│   └── Sigma-rules/
├── 📁 05-ATT&CK/
│   └── (una nota por técnica: T1059.001.md, T1053.005.md...)
└── 📁 Labs-realizados/
    └── (una nota por lab con: objetivo, herramientas, IOCs, conclusión)
```

---

### Consejos Específicos para el Examen eCTHP

**Parte tipo test (40 preguntas):**

- El material viene directamente de los slides del curso oficial. Si estudias por libre, cubre los conceptos de esta guía y los de AttackIQ Academy.
- Aprende los Event IDs de memoria: 4624, 4625, 4648, 4688, 4698, 4720, 7045, 1102.
- Aprende los Sysmon IDs de memoria: 1, 3, 7, 8, 10, 11, 22.
- ATT&CK: no necesitas memorizar todos los IDs, pero sí las técnicas más comunes de cada táctica.
- La Pyramid of Pain y el THMM aparecen en el test con frecuencia.

**Parte práctica (20 preguntas con Splunk, ELK, Wireshark):**

- Practica tus queries SPL y KQL hasta que sean mecánicas. El tiempo corre.
- En Wireshark, entrena filtros rápidos sin pensar: `dns`, `http.request`, `tcp.flags.syn==1 && tcp.flags.ack==0`.
- En Splunk, empieza siempre con `index=* | head 10` para entender qué datos tienes.
- Lee bien la pregunta: a veces piden el nombre exacto de un campo o el valor de un atributo específico.
- No adivines — en las prácticas, si no encuentras el resultado, revisa el índice o la fuente de datos que estás usando.

**Gestión del tiempo (10 horas totales):**

- Reserva ~3h para la parte test y ~7h para la práctica.
- Si una pregunta práctica te bloquea más de 20 minutos, márcala y continúa.
- Las preguntas de Wireshark suelen ser las más rápidas si tienes práctica con filtros.

**El día antes:**

- Repasa el cheat sheet de Event IDs y SPL/KQL.
- Verifica que tienes acceso a la plataforma del examen.
- No estudies material nuevo — consolida lo que ya sabes.

---

_Guía elaborada para perfil SOC Analyst → Purple Team Consultant · Mayo 2026_