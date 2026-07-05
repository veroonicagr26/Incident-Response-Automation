# Incident Response Automation 🚨

Sistema automatizado de respuesta a incidentes de ciberseguridad.

## Capacidades
- 🔍 Consulta de reputación de IPs y hashes en VirusTotal
- 📋 Generación automática de tickets de incidente en JSON
- ⚠️  Clasificación de severidad (CRÍTICA / MEDIA / BAJA)
- 🔒 Simulación de bloqueo automático vía iptables
- 📝 Log de acciones con timestamp

## Ejemplo de detección
- IP 45.131.214.85 → 11 detecciones maliciosas → Severidad CRÍTICA
  → Bloqueo automático ejecutado
- IP 8.8.8.8 → 0 detecciones → Severidad BAJA → Monitorizar

## Tecnologías
Python 3 · VirusTotal API · python-dotenv
