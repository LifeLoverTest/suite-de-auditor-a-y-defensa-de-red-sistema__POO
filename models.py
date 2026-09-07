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
  
  