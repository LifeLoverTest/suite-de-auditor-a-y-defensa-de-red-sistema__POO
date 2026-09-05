from Puerto_Service import AuditorPuertos


def main():
  auditor = AuditorPuertos()
  print("[*] Escaneando sockets y puertos abiertos en el sistema operativo...\n")

  puertos = auditor.obtener_puertos_en_escucha()

  if not puertos:
    print("[-] No se detectaron puertos o se requieren permisos de administrador.")
    return

  # Formateo de salida en columnas limpias
  encabezado = f"{'PUERTO':<10} {'PROTO':<8} {'SERVICIO':<15} {'PID':<10} {'PROCESO':<25} {'IP LOCAL'}"
  print(encabezado)
  print("-" * len(encabezado) * 2)

  for p in puertos:
    pid_str = str(p.pid) if p.pid else "N/A"
    print(f"{p.numero:<10} {p.protocolo:<8} {p.servicio_estimado:<15} {pid_str:<10} {p.proceso:<25} {p.ip_origen}")


if __name__ == "__main__":
  main()