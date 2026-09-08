from dataclasses import dataclass


@dataclass(frozen=True)
class Vulnerabilidad:
  """
  Entidad inmutable que representa una vulnerabilidad detectada en el sistema.
  """
  cve_id: str
  descripcion: str
  puntaje_cvss: float
  severidad: str
  
  def es_critica(self) -> bool:
    """
    Retorna True si el puntaje CVSS es considerado critico (>= 9.0).
    """
    return self.puntaje_cvss >= 9.0
  
@dataclass(frozen=True)
class ProcesoAuditable:
  """Entidad que representa un proceso en ejecucion inspeccionado en el sistema.
  Cumple con el RF03.
  """
  
  pid: int
  nombre: str
  ruta_ejecutable: str
  uso_cpu: float
  uso_memoria_mb: float
  es_sospechoso: bool
  
  def resumen_consumo(self) -> str:
    """Retorna un texto formateado del consumo de recursos."""
    return f"CPU: {self.uso_cpu}% | RAM: {self.uso_memoria_mb:.2f} MB"
