import requests
import json
import os
import datetime
from dotenv import load_dotenv

load_dotenv("../.env")
VT_API_KEY = os.getenv("VT_API_KEY")

def check_ip_virustotal(ip):
    """Consulta reputación de una IP en VirusTotal"""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "ip": ip,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0)
        }
    return None

def check_hash_virustotal(sha256):
    """Consulta reputación de un hash en VirusTotal"""
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "hash": sha256,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0)
        }
    return None

def generate_ticket(indicator, result, indicator_type):
    """Genera un ticket de incidente estructurado"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    ticket_id = f"INC-{timestamp}"
    severity = "CRÍTICA" if result["malicious"] > 5 else "MEDIA" if result["malicious"] > 0 else "BAJA"
    
    ticket = {
        "ticket_id": ticket_id,
        "timestamp": datetime.datetime.now().isoformat(),
        "indicator_type": indicator_type,
        "indicator": indicator,
        "severity": severity,
        "detecciones_maliciosas": result["malicious"],
        "detecciones_sospechosas": result["suspicious"],
        "estado": "ABIERTO",
        "accion_recomendada": "Bloquear IP y aislar host" if severity == "CRÍTICA" else "Monitorizar"
    }
    
    # Guardar ticket en reports/
    filename = f"../reports/{ticket_id}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(ticket, f, indent=4, ensure_ascii=False)
    
    return ticket

def simulate_block(ip):
    """Simula el bloqueo de una IP"""
    print(f"  🔒 Simulando bloqueo de {ip} en firewall...")
    print(f"  [CMD] iptables -A INPUT -s {ip} -j DROP")
    print(f"  [CMD] iptables -A OUTPUT -d {ip} -j DROP")
    print(f"  ✅ IP {ip} bloqueada")

def log_action(ticket_id, action):
    """Registra acciones en el log"""
    timestamp = datetime.datetime.now().isoformat()
    log_entry = f"[{timestamp}] {ticket_id} — {action}\n"
    with open("../logs/ir_actions.log", "a", encoding="utf-8") as f:
        f.write(log_entry)

# ── PROGRAMA PRINCIPAL ──────────────────────────────────
print("=" * 55)
print("  SISTEMA DE RESPUESTA AUTOMÁTICA A INCIDENTES")
print("=" * 55)

# IPs a analizar — usa la IP maliciosa que encontraste antes
indicators = [
    {"value": "45.131.214.85", "type": "ip"},
    {"value": "8.8.8.8", "type": "ip"},  # control — debería salir limpia
]

for item in indicators:
    print(f"\n🔍 Analizando {item['type'].upper()}: {item['value']}")
    
    if item["type"] == "ip":
        result = check_ip_virustotal(item["value"])
    
    if result:
        print(f"  Detecciones maliciosas: {result['malicious']}")
        print(f"  Detecciones sospechosas: {result['suspicious']}")
        
        ticket = generate_ticket(item["value"], result, item["type"])
        print(f"  📋 Ticket generado: {ticket['ticket_id']}")
        print(f"  ⚠️  Severidad: {ticket['severity']}")
        print(f"  📌 Acción: {ticket['accion_recomendada']}")
        
        log_action(ticket["ticket_id"], f"Análisis completado — Severidad {ticket['severity']}")
        
        if result["malicious"] > 5:
            simulate_block(item["value"])
            log_action(ticket["ticket_id"], f"IP {item['value']} bloqueada automáticamente")
    else:
        print(f"  ❌ No se pudo consultar VirusTotal")

print("\n✅ Respuesta a incidentes completada — revisa reports/ y logs/")