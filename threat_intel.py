from typing import List
import requests
from models import Vulnerabilidad


class ThreatIntelligence:
  """
  Servicio encargado de correlacionar servicios de red con vulnerabilidades publicadas (CVEs).
  Cumple con el RF02 (Requisito Innovador 1).
  """

  def __init__(self, timeout: int = 6):
    self._timeout = timeout
    self._headers = {
      "User-Agent": "SecurityAuditSuite/1.0 (Academic-Research-Client)"
    }
    # Base de conocimientos local de contingencia (fallback offline/resiliencia)
    self._cve_fallback = {
      "ssh": [
        Vulnerabilidad("CVE-2023-38408", "Posible ejecucion remota de codigo en ssh-agent PKCS#11.", 8.1, "ALTA"),
        Vulnerabilidad("CVE-2024-6387", "RegreSSHion: Condicion de carrera de senales en OpenSSH.", 9.8, "CRITICA")
      ],
      "http": [
        Vulnerabilidad("CVE-2021-41773", "Path traversal y ejecucion de codigo en Apache HTTP Server 2.4.49.", 9.8, "CRITICA"),
        Vulnerabilidad("CVE-2023-44487", "Ataque HTTP/2 Rapid Reset que causa denegacion de servicio.", 7.5, "ALTA")
      ],
      "ntp": [
        Vulnerabilidad("CVE-2016-7434", "Fallo de denegacion de servicio mediante paquetes mrulist especialmente diseñados.", 7.5, "ALTA"),
        Vulnerabilidad("CVE-2015-7704", "Vulnerabilidad de saturacion y alteracion de tiempo (Kiss-o'-Death).", 7.5, "ALTA")
      ],
      "epmap": [
        Vulnerabilidad("CVE-2022-26809", "Vulnerabilidad de ejecucion remota de codigo en llamadas a procedimiento remoto (RPC).", 9.8, "CRITICA")
      ],
      "netbios-ns": [
        Vulnerabilidad("CVE-2020-0796", "SMBGhost: Ejecucion remota de codigo en el controlador srv2.sys de Windows.", 10.0, "CRITICA")
      ]
    }

  def _determinar_severidad(self, cvss: float) -> str:
    """Clasifica la severidad segun el estandar CVSS v3."""
    if cvss >= 9.0:
      return "CRITICA"
    elif cvss >= 7.0:
      return "ALTA"
    elif cvss >= 4.0:
      return "MEDIA"
    elif cvss > 0.0:
      return "BAJA"
    return "DESCONOCIDA"

  def consultar_vulnerabilidades_servicio(
    self, nombre_servicio: str, limite: int = 2
  ) -> List[Vulnerabilidad]:
    """
    Consulta CVEs asociados al servicio mediante peticion HTTP GET.
    Si la API responde con error o no hay red, recurre a la base interna de contingencia.
    """
    servicio_limpio = nombre_servicio.lower().strip()
    if not servicio_limpio or servicio_limpio in ["desconocido", "n/a", "desconocido / sin permisos"]:
      return []

    vulnerabilidades: List[Vulnerabilidad] = []
    # Endpoint de consulta publica por patron
    url = f"https://cve.circl.lu/api/cve-for/{servicio_limpio}"

    try:
      respuesta = requests.get(url, headers=self._headers, timeout=self._timeout)

      if respuesta.status_code == 200:
        datos = respuesta.json()
        resultados = datos if isinstance(datos, list) else datos.get("data", [])

        for item in resultados[:limite]:
          cve_id = item.get("id", "CVE-DESCONOCIDO")
          resumen = item.get("summary", "Sin descripcion reportada")
          
          raw_cvss = item.get("cvss")
          try:
            cvss_score = float(raw_cvss) if raw_cvss is not None else 0.0
          except (ValueError, TypeError):
            cvss_score = 0.0

          vulnerabilidades.append(
            Vulnerabilidad(
              cve_id=cve_id,
              descripcion=resumen[:110] + "..." if len(resumen) > 110 else resumen,
              puntaje_cvss=cvss_score,
              severidad=self._determinar_severidad(cvss_score)
            )
          )

    except requests.exceptions.RequestException:
      pass

    # Si la API externa no devolvio registros (404, rate limit o sin red), aplicar contingencia
    if not vulnerabilidades and servicio_limpio in self._cve_fallback:
      return self._cve_fallback[servicio_limpio][:limite]

    return vulnerabilidades