import psutil
from models import ProcesoAuditable


class AuditorProcesos:
  """
  Servicio encargado de auditar los procesos en ejecucion y evaluar anomalias basicas.
  Cumple con el RF03.
  """

  def __init__(self, umbral_cpu: float = 80.0):
    self._umbral_cpu = umbral_cpu
    # Rutas sospechosas comunes en Windows donde el malware suele alojarse
    self._patrones_sospechosos = [
      "appdata\\local\\temp",
      "\\temp\\",
      "roaming"
    ]

  def _es_ruta_sospechosa(self, ruta: str) -> bool:
    """Evalua si el binario se ejecuta desde directorios temporales de usuario."""
    if not ruta or ruta.startswith("Acceso"):
      return False
    ruta_normalizada = ruta.lower()
    return any(patron in ruta_normalizada for patron in self._patrones_sospechosos)

  def obtener_procesos_activos(self, limite: int = 50) -> list[ProcesoAuditable]:
    """
    Inspecciona los procesos del sistema y retorna una lista de instancias ProcesoAuditable.
    """
    procesos_auditados: list[ProcesoAuditable] = []

    # Obtenemos los atributos directamente para optimizar el rendimiento
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_info']):
      try:
        info = proc.info
        pid = info.get('pid') or 0
        nombre = info.get('name') or "Desconocido"
        ruta = info.get('exe') or "Acceso denegado / Protegido"

        # Uso de recursos
        cpu = float(info.get('cpu_percent') or 0.0)
        
        # psutil entrega la memoria en bytes (RSS); dividimos por (1024 * 1024) para obtener MB
        mem_bytes = info['memory_info'].rss if info.get('memory_info') else 0
        mem_mb = round(mem_bytes / (1024 * 1024), 2)

        # Evaluamos heuristica basica
        sospechoso = self._es_ruta_sospechosa(ruta)

        proceso = ProcesoAuditable(
          pid=pid,
          nombre=nombre,
          ruta_ejecutable=ruta,
          uso_cpu=cpu,
          uso_memoria_mb=mem_mb,
          es_sospechoso=sospechoso
        )
        procesos_auditados.append(proceso)

      except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        # Si el proceso termino repentinamente o es inaccesible, continuamos con el siguiente
        continue

    # Ordenamos por consumo de memoria de mayor a menor y limitamos la cantidad
    procesos_auditados.sort(key=lambda x: x.uso_memoria_mb, reverse=True)
    return procesos_auditados[:limite]