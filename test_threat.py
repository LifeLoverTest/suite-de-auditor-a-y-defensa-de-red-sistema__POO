from threat_intel import ThreatIntelligence

def main():
  intel = ThreatIntelligence()
  servicio = "ssh"
  print(f"[*] Consultando base de datos de amenazas para: {servicio}...")

  cves = intel.consultar_vulnerabilidades_servicio(servicio, limite=3)

  if not cves:
    print("[-] No se encontraron vulnerabilidades o no hay conexion a internet.")
    return

  for v in cves:
    print(f"\n[!] ID: {v.cve_id} | Severidad: {v.severidad} ({v.puntaje_cvss})")
    print(f"    Detalle: {v.descripcion}")

if __name__ == "__main__":
  main()
  
  