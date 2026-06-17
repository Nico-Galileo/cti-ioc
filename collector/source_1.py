"""
Recolector concreto para la fuente URLhaus (abuse.ch).

URLhaus publica un feed CSV con URLs maliciosas verificadas activamente.
La descarga se realiza desde el endpoint público de abuse.ch y no requiere
autenticación ni clave de API.

Referencia: https://urlhaus.abuse.ch/api/
"""

from __future__ import annotations

import csv
import io
import logging
from datetime import datetime, timezone
from typing import Any

import requests

from collector.base_collector import BaseCollector

logger = logging.getLogger(__name__)

FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
HTTP_TIMEOUT = 15  # segundos

# Formato de fecha usado por URLhaus en las columnas dateadded y last_online
DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# Nombres de columna del CSV (el header está en una línea comentada con #,
# por lo que se declaran explícitamente en lugar de leerlos del fichero)
CSV_FIELDNAMES = [
    "id",
    "dateadded",
    "url",
    "url_status",
    "last_online",
    "threat",
    "tags",
    "urlhaus_link",
    "reporter",
]


class URLhausCollector(BaseCollector):
    """Recolector de IOCs desde el feed CSV de URLhaus (abuse.ch).

    URLhaus mantiene y verifica activamente cada URL publicada en su feed
    antes de hacerla pública.  Esta verificación activa justifica el nivel
    de confianza "high" asignado a todos los IOCs de esta fuente, tal como
    se documenta en el TFM.

    El feed CSV reciente contiene las URLs añadidas en los últimos días.
    Cada URL se clasifica como "active" si su estado es "online" en el
    momento de la descarga, o "inactive" en caso contrario.
    """

    # ------------------------------------------------------------------
    # Implementación del contrato abstracto
    # ------------------------------------------------------------------

    def fetch(self) -> str:
        """Descarga el feed CSV reciente de URLhaus mediante HTTP GET.

        Realiza una petición GET al endpoint público con un timeout fijo
        de 15 segundos.  Si el servidor responde con un código de error,
        lanza una excepción para que la lógica de reintentos de
        BaseCollector la gestione.

        Returns:
            Texto crudo del CSV tal como lo devuelve el servidor de abuse.ch.

        Raises:
            requests.RequestException: Si el servidor responde con un código
                HTTP distinto de 200, o si se agota el timeout de la petición.
        """
        response = requests.get(FEED_URL, timeout=HTTP_TIMEOUT)
        if response.status_code != 200:
            raise requests.RequestException(
                f"URLhaus devolvió HTTP {response.status_code} "
                f"al descargar el feed CSV desde {FEED_URL}"
            )
        return response.text

    def parse(self, raw_data: str) -> list[dict]:
        """Transforma el texto CSV de URLhaus en una lista de diccionarios IOC.

        Filtra las líneas de comentario (prefijo '#'), parsea el contenido
        restante con csv.DictReader y construye el diccionario IOC normalizado
        para cada fila.  Las filas que fallen individualmente se registran
        como warning en el log y se omiten sin interrumpir el proceso.

        Args:
            raw_data: Texto CSV crudo devuelto por fetch().

        Returns:
            Lista de diccionarios IOC normalizados según el contrato de
            BaseCollector.  Puede estar vacía si el feed no contiene datos
            o todos los registros son inválidos.
        """
        # Filtrar comentarios (incluyendo la línea de cabecera comentada)
        # y descartar líneas en blanco.
        lines = [
            line
            for line in raw_data.splitlines()
            if line.strip() and not line.startswith("#")
        ]

        if not lines:
            logger.warning(
                "URLhausCollector: el feed CSV no contiene filas de datos "
                "tras filtrar las líneas de comentario."
            )
            return []

        # Se captura el instante de descarga una sola vez para que todos
        # los IOCs del mismo ciclo de recolección compartan el mismo valor.
        retrieved_at = datetime.now(timezone.utc)

        reader = csv.DictReader(
            io.StringIO("\n".join(lines)),
            fieldnames=CSV_FIELDNAMES,
        )

        iocs: list[dict] = []
        for row in reader:
            try:
                iocs.append(self._row_to_ioc(row, retrieved_at))
            except Exception as exc:
                logger.warning(
                    "URLhausCollector: fila ignorada por error de parseo "
                    "(id=%s): %s",
                    row.get("id", "?"),
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

    def _row_to_ioc(self, row: dict[str, str], retrieved_at: datetime) -> dict:
        """Convierte una fila del CSV de URLhaus en el diccionario IOC estándar.

        Aplica strip a todos los valores para eliminar espacios residuales
        del CSV y valida que los campos obligatorios ('id' y 'url') no estén
        vacíos antes de construir el diccionario.

        Args:
            row:          Diccionario con las columnas del CSV tal como las
                          entrega csv.DictReader.
            retrieved_at: Instante de descarga compartido por todas las filas
                          del mismo ciclo de recolección.

        Returns:
            Diccionario IOC conforme al contrato definido en BaseCollector.

        Raises:
            ValueError: Si 'id' o 'url' están vacíos, ya que son campos
                        mínimos para identificar y usar el indicador.
        """
        # strip defensivo en todos los campos (el CSV de URLhaus puede
        # incluir espacios entre la coma separadora y la comilla)
        cleaned: dict[str, str] = {
            k: (v.strip() if v else "") for k, v in row.items()
        }

        source_id = cleaned["id"]
        value = cleaned["url"]

        if not source_id or not value:
            raise ValueError(
                f"Campos obligatorios vacíos — id={source_id!r}, url={value!r}"
            )

        return {
            "ioc_type":         "url",
            "value":            value,
            "hash_algorithm":   None,
            "source_name":      "urlhaus",
            "source_id":        source_id,
            "retrieved_at":     retrieved_at,
            "first_seen":       self._parse_datetime(cleaned.get("dateadded")),
            "last_seen":        self._parse_datetime(cleaned.get("last_online")),
            "confidence_level": "high",
            "threat_type":      cleaned.get("threat") or None,
            "tags":             self._parse_tags(cleaned.get("tags")),
            "status":           "active" if cleaned.get("url_status") == "online" else "inactive",
            "raw_payload":      dict(cleaned),
        }

    @staticmethod
    def _parse_datetime(value: str | None) -> datetime | None:
        """Convierte una cadena de texto en un objeto datetime con zona horaria UTC.

        URLhaus no incluye información de zona horaria en sus fechas, pero
        su documentación oficial indica que todas las marcas temporales son
        UTC.  Se añade tzinfo=timezone.utc para mantener la coherencia con
        el campo retrieved_at y evitar comparaciones entre datetimes con y
        sin zona horaria en el resto del pipeline.

        Args:
            value: Cadena con formato 'YYYY-MM-DD HH:MM:SS', cadena vacía,
                   o None.

        Returns:
            Objeto datetime con tzinfo=UTC, o None si el valor está vacío
            o no puede parsearse.
        """
        if not value:
            return None
        try:
            return datetime.strptime(value, DATETIME_FORMAT).replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            logger.warning(
                "URLhausCollector: no se pudo parsear la fecha '%s' "
                "con el formato esperado '%s'.",
                value,
                DATETIME_FORMAT,
            )
            return None

    @staticmethod
    def _parse_tags(value: str | None) -> list[str]:
        """Convierte la cadena de tags separados por coma en una lista de strings.

        Descarta entradas vacías y aplica strip a cada tag individual para
        eliminar espacios residuales.

        Args:
            value: Cadena con tags separados por coma, cadena vacía, o None.

        Returns:
            Lista de strings con los tags limpios, o lista vacía si no hay
            ninguno.
        """
        if not value:
            return []
        return [tag.strip() for tag in value.split(",") if tag.strip()]
