from dataclasses import dataclass
from typing import List, Optional
import socket
import psutil


@dataclass(frozen=True)
class PuertoActivo:
  """
  Entidad inmutable que representa un puerto en uso en el sistema.
  """
  numero: int
  protocolo: str
  ip_origen: str
  pid: Optional[int]
  proceso: str
  servicio_estimado: str
  estado: str


class AuditorPuertos:
  """
  Servicio encargado de auditar la red local y los sockets en escucha del SO.
  Aplica SRP (Single Responsibility Principle) encapsulando el uso de psutil y socket.
  """

  def __init__(self, tipo_red: str = "inet"):
    # 'inet' filtra conexiones IPv4 e IPv6
    self._tipo_red = tipo_red

  def _resolver_nombre_servicio(self, puerto: int, protocolo: str) -> str:
    """
    Traduce el número de puerto a un nombre de servicio estándar IANA (ej. 80 -> http).
    Si no está registrado o falla la resolución, retorna 'Desconocido'.
    """
    try:
      return socket.getservbyport(puerto, protocolo.lower())
    except (OSError, socket.error):
      return "Desconocido"

  def obtener_puertos_en_escucha(self) -> List[PuertoActivo]:
    """
    Inspecciona el sistema y retorna una lista de objetos PuertoActivo
    que se encuentren en estado de escucha (LISTEN / BOUND).
    """
    puertos_encontrados: List[PuertoActivo] = []

    # psutil.net_connections requiere privilegios; iteramos de forma segura
    try:
      conexiones = psutil.net_connections(kind=self._tipo_red)
    except psutil.AccessDenied:
      # En caso de no ejecutarse como administrador / root
      conexiones = []

    for conn in conexiones:
      # Filtramos solo puertos locales activos en escucha
      if conn.status == psutil.CONN_LISTEN or (conn.type == socket.SOCK_DGRAM and conn.laddr):
        num_puerto = conn.laddr.port
        ip_local = conn.laddr.ip
        proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        pid = conn.pid
        nombre_proceso = "Desconocido / Sin permisos"

        if pid:
          try:
            proceso_obj = psutil.Process(pid)
            nombre_proceso = proceso_obj.name()
          except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            nombre_proceso = "Proceso inaccesible"

        servicio = self._resolver_nombre_servicio(num_puerto, proto)

        puerto_activo = PuertoActivo(
          numero=num_puerto,
          protocolo=proto,
          ip_origen=ip_local,
          pid=pid,
          proceso=nombre_proceso,
          servicio_estimado=servicio,
          estado=conn.status if conn.status else "UDP_ACTIVO"
        )
        puertos_encontrados.append(puerto_activo)

    # Retornamos los puertos ordenados ascendentemente por número de puerto
    return sorted(puertos_encontrados, key=lambda x: x.numero)