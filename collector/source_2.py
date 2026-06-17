"""
Recolector concreto para la fuente AlienVault OTX (Open Threat Exchange).

OTX es una plataforma comunitaria de inteligencia sobre amenazas que agrupa
IOCs en "pulses".  El acceso requiere una clave de API personal que debe
configurarse en la variable de entorno OTX_API_KEY (fichero .env).

Referencia: https://otx.alienvault.com/api
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

import requests
from dotenv import load_dotenv

from collector.base_collector import BaseCollector

load_dotenv()

logger = logging.getLogger(__name__)

OTX_SUBSCRIBED_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
HTTP_TIMEOUT = 15   # segundos
PULSE_LIMIT  = 20   # pulses por petición

# Mapeo del vocabulario de tipos OTX al vocabulario interno del proyecto.
# Los tipos "FileHash-*" (MD5, SHA1, SHA256, …) se resuelven dinámicamente
# en _map_ioc_type() porque el algoritmo viaja embebido en el nombre del tipo.
OTX_TYPE_MAP: dict[str, str] = {
    "IPv4":     "ip",
    "IPv6":     "ip",
    "domain":   "domain",
    "hostname": "domain",
    "URL":      "url",
}


class OTXCollector(BaseCollector):
    """Recolector de IOCs desde la API REST de AlienVault OTX.

    Descarga los pulses a los que el usuario está suscrito y extrae cada
    indicador individual, mapeándolo al contrato de BaseCollector.

    El nivel de confianza se fija en "medium" para todos los IOCs de esta
    fuente porque OTX es una plataforma de inteligencia comunitaria sin
    verificación activa centralizada, a diferencia de URLhaus.  Esto queda
    documentado en la sección de fuentes del TFM.

    La clave de API se lee en el constructor desde la variable de entorno
    OTX_API_KEY (cargada mediante python-dotenv).  Si la clave no está
    configurada, el constructor falla de forma temprana con un ValueError
    para evitar errores silenciosos en tiempo de ejecución.
    """

    def __init__(self, max_retries: int = 3, retry_delay: float = 2.0) -> None:
        """Inicializa el colector leyendo la clave de API desde el entorno.

        Args:
            max_retries: Número máximo de reintentos ante fallos de red,
                         heredado de BaseCollector.
            retry_delay: Segundos base entre reintentos (backoff lineal),
                         heredado de BaseCollector.

        Raises:
            ValueError: Si la variable de entorno OTX_API_KEY no está
                        definida o está vacía.
        """
        super().__init__(max_retries=max_retries, retry_delay=retry_delay)

        api_key = os.getenv("OTX_API_KEY")
        if not api_key:
            raise ValueError(
                "La variable de entorno OTX_API_KEY no está configurada. "
                "Añádela al fichero .env antes de instanciar OTXCollector."
            )
        self._api_key: str = api_key

    # ------------------------------------------------------------------
    # Implementación del contrato abstracto
    # ------------------------------------------------------------------

    def fetch(self) -> dict:
        """Consulta el endpoint /pulses/subscribed de OTX y devuelve el JSON.

        Realiza un GET autenticado con el header X-OTX-API-KEY.  Gestiona
        explícitamente el caso 401 (clave inválida) con un mensaje de error
        orientativo, y lanza una excepción genérica para cualquier otro
        código de error HTTP.

        Returns:
            Diccionario Python con el JSON completo devuelto por la API,
            incluyendo la clave "results" con la lista de pulses.

        Raises:
            requests.RequestException: Si la clave de API es rechazada
                (HTTP 401), si el servidor devuelve otro código de error,
                o si se agota el timeout de la petición.
        """
        response = requests.get(
            OTX_SUBSCRIBED_URL,
            headers={"X-OTX-API-KEY": self._api_key},
            params={"limit": PULSE_LIMIT},
            timeout=HTTP_TIMEOUT,
        )

        if response.status_code == 401:
            raise requests.RequestException(
                "OTX rechazó la autenticación (HTTP 401). "
                "Verifica que OTX_API_KEY sea válida y esté activa en tu cuenta."
            )
        if response.status_code != 200:
            raise requests.RequestException(
                f"OTX devolvió HTTP {response.status_code} "
                f"al consultar {OTX_SUBSCRIBED_URL}"
            )

        return response.json()

    def parse(self, raw_data: dict) -> list[dict]:
        """Transforma la respuesta JSON de OTX en una lista de diccionarios IOC.

        Itera sobre cada pulse en raw_data["results"] y, dentro de cada
        pulse, sobre cada indicador individual.  Los indicadores con tipos
        no reconocidos se omiten con un warning.  Los indicadores que fallen
        por cualquier otro motivo también se omiten individualmente sin
        detener el procesamiento del lote.

        Args:
            raw_data: Diccionario JSON devuelto por fetch(), con la clave
                      "results" conteniendo la lista de pulses.

        Returns:
            Lista de diccionarios IOC normalizados según el contrato de
            BaseCollector.
        """
        pulses = raw_data.get("results", [])
        if not pulses:
            logger.warning(
                "OTXCollector: la respuesta de la API no contiene pulses "
                "en la clave 'results'."
            )
            return []

        # Un único instante de recolección compartido por todos los IOCs
        # del ciclo, coherente con la estrategia de URLhausCollector.
        retrieved_at = datetime.now(timezone.utc)
        iocs: list[dict] = []

        for pulse in pulses:
            pulse_id = pulse.get("id", "?")
            for indicator in pulse.get("indicators", []):
                try:
                    ioc = self._indicator_to_ioc(indicator, pulse, retrieved_at)
                    if ioc is not None:
                        iocs.append(ioc)
                except Exception as exc:
                    logger.warning(
                        "OTXCollector: indicador ignorado en pulse '%s' "
                        "(indicator_id=%s): %s",
                        pulse_id,
                        indicator.get("id", "?"),
                        exc,
                    )

        return iocs

    def to_dict(self) -> list[dict]:
        """Retorna la lista de IOCs almacenada internamente por parse().

        Returns:
            Lista de diccionarios IOC listos para ser procesados por el
            módulo normalizer del proyecto.
        """
        return self._iocs

    # ------------------------------------------------------------------
    # Auxiliares privados
    # ------------------------------------------------------------------

    def _indicator_to_ioc(
        self,
        indicator: dict,
        pulse: dict,
        retrieved_at: datetime,
    ) -> dict | None:
        """Convierte un indicador OTX y su pulse contenedor en el dict IOC estándar.

        Devuelve None (en lugar de lanzar excepción) cuando el tipo del
        indicador no está mapeado, para que parse() pueda continuar con
        el siguiente indicador sin coste adicional de captura de excepción.

        Args:
            indicator:    Diccionario del indicador individual tal como lo
                          devuelve la API de OTX.
            pulse:        Diccionario del pulse que contiene al indicador,
                          necesario para extraer tags, malware_families y
                          la fecha de última modificación.
            retrieved_at: Instante de descarga compartido por el ciclo
                          completo de recolección.

        Returns:
            Diccionario IOC conforme al contrato de BaseCollector, o None
            si el tipo del indicador no está en el vocabulario conocido.
        """
        otx_type = indicator.get("type", "")
        ioc_type, hash_algorithm = self._map_ioc_type(otx_type)

        if ioc_type is None:
            logger.warning(
                "OTXCollector: tipo de indicador no reconocido '%s' — omitido.",
                otx_type,
            )
            return None

        return {
            "ioc_type":         ioc_type,
            "value":            indicator.get("indicator", ""),
            "hash_algorithm":   hash_algorithm,
            "source_name":      "alienvault_otx",
            "source_id":        str(indicator.get("id", "")),
            "retrieved_at":     retrieved_at,
            "first_seen":       self._parse_datetime(indicator.get("created")),
            "last_seen":        self._parse_datetime(pulse.get("modified")),
            "confidence_level": "medium",
            "threat_type":      self._extract_threat_type(pulse),
            "tags":             list(pulse.get("tags", [])),
            "status":           "active" if indicator.get("is_active") == 1 else "inactive",
            "raw_payload":      dict(indicator),
        }

    @staticmethod
    def _map_ioc_type(otx_type: str) -> tuple[str | None, str | None]:
        """Traduce el tipo de indicador OTX al vocabulario interno del proyecto.

        Para los tipos "FileHash-*", el algoritmo se extrae del propio nombre
        (p. ej. "FileHash-SHA256" → ioc_type="hash", hash_algorithm="sha256").
        Cualquier tipo no reconocido devuelve (None, None) para que el
        llamador pueda omitirlo con un warning.

        Args:
            otx_type: Cadena de tipo tal como la devuelve OTX ("IPv4",
                      "domain", "FileHash-MD5", etc.).

        Returns:
            Tupla (ioc_type, hash_algorithm).  hash_algorithm es None salvo
            cuando ioc_type es "hash".  Ambos son None si el tipo es
            desconocido.
        """
        if otx_type in OTX_TYPE_MAP:
            return OTX_TYPE_MAP[otx_type], None

        if otx_type.startswith("FileHash-"):
            algorithm = otx_type.removeprefix("FileHash-").lower()
            return "hash", algorithm

        return None, None

    @staticmethod
    def _extract_threat_type(pulse: dict) -> str | None:
        """Determina el tipo de amenaza a partir de los metadatos del pulse.

        Aplica la siguiente jerarquía de prioridad:
        1. Primer elemento de malware_families.
        2. Primer tag del pulse, si malware_families está vacío.
        3. None, si no hay ninguna de las anteriores.

        La API de OTX documenta malware_families como list[dict] con campo
        "display_name", pero en la práctica devuelve list[str].  Este método
        maneja ambas variantes para mayor robustez.

        Args:
            pulse: Diccionario del pulse contenedor del indicador.

        Returns:
            Cadena con el tipo de amenaza, o None si no hay información.
        """
        malware_families = pulse.get("malware_families") or []
        if malware_families:
            first = malware_families[0]
            if isinstance(first, dict):
                return first.get("display_name") or None
            return str(first) if first else None

        tags = pulse.get("tags") or []
        return tags[0] if tags else None

    @staticmethod
    def _parse_datetime(value: str | None) -> datetime | None:
        """Convierte una cadena ISO 8601 de OTX en un objeto datetime con zona UTC.

        datetime.fromisoformat() en Python < 3.11 no admite el sufijo 'Z'
        (notación UTC compacta).  Se normaliza sustituyendo 'Z' por '+00:00'
        antes de parsear, garantizando compatibilidad con Python 3.9+.

        Args:
            value: Cadena de fecha ISO 8601 (p. ej. "2024-01-15T10:30:00"
                   o "2024-01-15T10:30:00Z"), cadena vacía, o None.

        Returns:
            Objeto datetime con tzinfo si la cadena incluye zona horaria,
            datetime naive si no la incluye, o None si el valor está
            vacío o es imparseable.
        """
        if not value:
            return None

        # Normalizar sufijo 'Z' → '+00:00' para compatibilidad con Python < 3.11
        normalized = value
        if value.endswith("Z"):
            normalized = value[:-1] + "+00:00"

        try:
            return datetime.fromisoformat(normalized)
        except ValueError:
            logger.warning(
                "OTXCollector: no se pudo parsear la fecha '%s' como ISO 8601.",
                value,
            )
            return None
