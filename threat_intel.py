from typing import List
import requests
from models import Vulnerabilidad

class ThreatIntelligence:
  """
  Servicio encargado de correlacionar servicios de red con vulnerabilidades publicadas (CVEs).
  Cumple con el RF02 (Requisito Innovador 1).
  """
  
  def __init__(self, timeout: int = 6):
    self.timeout = timeout
    self._base_url = "https://cve.circl.lu/api/search"
    
  def determinar_severidad(self, cvss: float) -> str:
    """Clasifica la severidad segun el estandar CVSS v3."""
    
    if cvss >= 9.0:
      return "CRITICA"
    elif cvss >= 7.0:
      return "ALTA"
    elif cvss >= 4.0:
      return "MEDIA"
    elif cvss >= 0.0:
      return "BAJA"
    return "DESCONOCIDA"
  
  def consultar_vulnerabilidades_servicio(self, nombre_servicio: str, 
                                          limite: int = 3 ) -> List[Vulnerabilidad]: 
    """
    Realiza una peticion HTTP GET buscando CVEs asociados al nombre del servicio.
    Retorna una lista de objetos Vulnerabilidad.
    """
    vulnerabilidades_detectadas: List[Vulnerabilidad] = []
    if not nombre_servicio or nombre_servicio.lower() in ["desconocido", "n/a"]:
      return vulnerabilidades_detectadas
    
    url_consulta = f"{self._base_url}/{nombre_servicio.lower()}"
    
    try:
      respuesta = requests.get(url_consulta, timeout=self._timeout)
      if respuesta.status_code == 200:
        datos = respuesta.json()
        
        # Si la API retorna un diccionario con lista o una lista directa
        resultados = datos if isinstance(datos, list) else datos.get("data", [])

        for item in resultados[:limite]:
          cve_id = item.get("id", "CVE-DESCONOCIDO")
          resumen = item.get("summary", "Sin descripcion disponible")
          
          # cvss puede ser float, str o None dependiendo del registro
          raw_cvss = item.get("cvss")
          try:
            cvss_score = float(raw_cvss) if raw_cvss is not None else 0.0
          except (ValueError, TypeError):
            cvss_score = 0.0

          severidad = self._determinar_severidad(cvss_score)

          vulnerabilidad = Vulnerabilidad(
            cve_id=cve_id,
            descripcion=resumen[:120] + "..." if len(resumen) > 120 else resumen,
            puntaje_cvss=cvss_score,
            severidad=severidad
          )
          vulnerabilidades_detectadas.append(vulnerabilidad)

    except requests.exceptions.RequestException:
      # Manejo defensivo: caidas de conexion, timeout o fallas de DNS
      pass

    return vulnerabilidades_detectadas