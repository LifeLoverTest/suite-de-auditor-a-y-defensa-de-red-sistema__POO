from Puerto_Service import AuditorPuertos
from threat_intel import ThreatIntelligence


def probar_auditor_puertos():
  print("=" * 70)
  print("[1] PROBANDO: AuditorPuertos (psutil + socket)")
  print("=" * 70)
  auditor = AuditorPuertos()
  puertos = auditor.obtener_puertos_en_escucha()

  if not puertos:
    print("[-] No se detectaron puertos o faltan permisos de administrador.")
    return []

  print(f"[✓] Se detectaron {len(puertos)} puertos en escucha:")
  for p in puertos[:5]:  # Mostramos los primeros 5 para verificar
    print(f"    -> Puerto: {p.numero:<5} | Proto: {p.protocolo:<4} | Servicio: {p.servicio_estimado:<12} | Proceso: {p.proceso}")
  return puertos


def probar_threat_intelligence():
  print("\n" + "=" * 70)
  print("[2] PROBANDO: ThreatIntelligence (requests + API CIRCL)")
  print("=" * 70)
  intel = ThreatIntelligence()
  servicio_prueba = "ssh"
  print(f"[*] Consultando vulnerabilidades para servicio de prueba: '{servicio_prueba}'...")
  
  cves = intel.consultar_vulnerabilidades_servicio(servicio_prueba, limite=2)
  if not cves:
    print("[-] No se obtuvieron resultados (verifica tu conexion a Internet).")
    return

  print(f"[✓] Vulnerabilidades obtenidas exitosamente:")
  for cve in cves:
    print(f"    [!] {cve.cve_id} | Severidad: {cve.severidad} ({cve.puntaje_cvss})")
    print(f"        Resumen: {cve.descripcion}")


def probar_flujo_completo(puertos):
  print("\n" + "=" * 70)
  print("[3] PROBANDO: Integracion Flujo Completo (Puertos -> CVEs)")
  print("=" * 70)
  intel = ThreatIntelligence()

  # Buscamos el primer puerto detectado que tenga un servicio conocido
  puerto_candidato = None
  for p in puertos:
    if p.servicio_estimado.lower() not in ["desconocido", "n/a"]:
      puerto_candidato = p
      break

  if not puerto_candidato:
    print("[!] No hay puertos con servicios estandar reconocidos en la maquina local.")
    print("[!] Simulando consulta con servicio estandar 'http'...")
    servicio_a_consultar = "http"
  else:
    print(f"[+] Puerto seleccionado para auditoria: {puerto_candidato.numero} ({puerto_candidato.servicio_estimado})")
    servicio_a_consultar = puerto_candidato.servicio_estimado

  vulnerabilidades = intel.consultar_vulnerabilidades_servicio(servicio_a_consultar, limite=2)
  print(f"[✓] Correlacion completada. Amenazas encontradas para {servicio_a_consultar}: {len(vulnerabilidades)}")
  for v in vulnerabilidades:
    print(f"    -> {v.cve_id} | Severidad: {v.severidad}")


if __name__ == "__main__":
  puertos_detectados = probar_auditor_puertos()
  probar_threat_intelligence()
  probar_flujo_completo(puertos_detectados)