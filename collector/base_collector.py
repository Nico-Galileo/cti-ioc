"""
Módulo base para todos los recolectores de indicadores de compromiso (IOCs).

Define el contrato abstracto que deben cumplir las implementaciones concretas
(URLhausCollector, OTXCollector, etc.) y orquesta el flujo de recolección.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

import requests

logger = logging.getLogger(__name__)


class BaseCollector(ABC):
    """Clase base abstracta para recolectores de IOCs desde fuentes OSINT.

    Define el contrato que toda fuente de inteligencia debe implementar:
    obtención de datos crudos, transformación a estructura IOC normalizada
    y exposición de la lista final.  El método run() orquesta estos pasos
    y centraliza la lógica de reintentos y logging.
    """

    def __init__(self, max_retries: int = 3, retry_delay: float = 2.0) -> None:
        """Inicializa los parámetros de resiliencia compartidos por todos los recolectores.

        Args:
            max_retries: Número máximo de intentos ante fallos de red.
            retry_delay: Segundos base de espera entre reintentos (se aplica backoff lineal).
        """
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._iocs: list[dict] = []

    # ------------------------------------------------------------------
    # Métodos abstractos — contrato obligatorio para cada fuente concreta
    # ------------------------------------------------------------------

    @abstractmethod
    def fetch(self) -> Any:
        """Obtiene los datos crudos desde la fuente externa (API o descarga).

        La implementación concreta debe realizar la petición HTTP (u otro
        protocolo) y devolver la respuesta sin procesar: puede ser un objeto
        requests.Response, un dict JSON, bytes de un CSV, etc.  No debe
        transformar ni filtrar el contenido; esa responsabilidad recae en
        parse().

        Returns:
            Datos crudos en el formato nativo de la fuente (tipo variable
            según la implementación concreta).

        Raises:
            requests.RequestException: Ante errores de red o HTTP.  run()
                captura esta excepción para aplicar la lógica de reintentos.
        """
        ...

    @abstractmethod
    def parse(self, raw_data: Any) -> list[dict]:
        """Transforma los datos crudos en una lista de diccionarios IOC normalizados.

        Recibe exactamente lo que retornó fetch() y produce una lista de
        diccionarios con la estructura estándar del proyecto.  Cada elemento
        representa un indicador de compromiso individual.

        Estructura obligatoria de cada diccionario IOC:

            {
                "ioc_type":        str,           # "ip", "domain", "url" o "hash"
                "value":           str,           # valor del indicador
                "hash_algorithm":  str | None,    # "md5", "sha256", etc. (solo si ioc_type=="hash")
                "source_name":     str,           # "urlhaus" o "alienvault_otx"
                "source_id":       str,           # identificador único en la fuente
                "retrieved_at":    datetime,      # momento de la recolección
                "first_seen":      datetime | None,
                "last_seen":       datetime | None,
                "confidence_level": str,          # "low", "medium" o "high"
                "threat_type":     str | None,    # p. ej. "malware", "phishing"
                "tags":            list[str],
                "status":          str,           # "active" o "inactive"
                "raw_payload":     dict,          # payload original sin modificar
            }

        Args:
            raw_data: Datos crudos devueltos por fetch().

        Returns:
            Lista de diccionarios IOC con la estructura definida arriba.
        """
        ...

    @abstractmethod
    def to_dict(self) -> list[dict]:
        """Devuelve la lista final de IOCs normalizados, lista para el normalizador.

        Este método constituye la interfaz pública de salida del recolector.
        Típicamente retorna self._iocs (almacenado por parse()), pero la
        implementación concreta puede aplicar filtros adicionales, deduplicar
        o reordenar antes de entregar la lista.

        Returns:
            Lista de diccionarios IOC listos para ser procesados por el módulo
            normalizer del proyecto.
        """
        ...

    # ------------------------------------------------------------------
    # Método de orquestación — implementado en la clase base
    # ------------------------------------------------------------------

    def run(self) -> list[dict]:
        """Orquesta el flujo completo de recolección: fetch → parse → to_dict.

        Ejecuta los tres pasos en secuencia, aplicando reintentos con backoff
        lineal ante errores de red en la fase de obtención.  Registra en el
        log el inicio del proceso, la cantidad de IOCs obtenidos y cualquier
        error que interrumpa la ejecución.

        Returns:
            Lista de diccionarios IOC normalizados (resultado de to_dict()).

        Raises:
            requests.RequestException: Si se agotan todos los reintentos sin
                obtener respuesta de la fuente.
            Exception: Cualquier error no relacionado con la red que ocurra
                durante el parseo.
        """
        source = self.__class__.__name__
        logger.info("Iniciando recolección con %s", source)

        raw_data = self._fetch_with_retries()

        try:
            self._iocs = self.parse(raw_data)
        except Exception as exc:
            logger.error("Error al parsear datos en %s: %s", source, exc)
            raise

        logger.info(
            "Recolección completada en %s — IOCs obtenidos: %d",
            source,
            len(self._iocs),
        )

        return self.to_dict()

    # ------------------------------------------------------------------
    # Método auxiliar interno — no forma parte del contrato público
    # ------------------------------------------------------------------

    def _fetch_with_retries(self) -> Any:
        """Llama a fetch() aplicando reintentos con backoff lineal ante errores de red.

        Este método no es parte del contrato abstracto; es un auxiliar interno
        de run() que centraliza la lógica de resiliencia para no duplicarla en
        cada implementación concreta.

        Returns:
            Datos crudos devueltos por fetch() en el primer intento exitoso.

        Raises:
            requests.RequestException: Si todos los intentos fallan.
        """
        source = self.__class__.__name__
        last_exc: Exception | None = None

        for attempt in range(1, self.max_retries + 1):
            try:
                return self.fetch()
            except (requests.RequestException, ConnectionError, TimeoutError) as exc:
                last_exc = exc
                if attempt < self.max_retries:
                    wait = self.retry_delay * attempt
                    logger.warning(
                        "%s — intento %d/%d fallido (%s). Reintentando en %.1fs…",
                        source,
                        attempt,
                        self.max_retries,
                        exc,
                        wait,
                    )
                    time.sleep(wait)
                else:
                    logger.error(
                        "%s — todos los reintentos agotados (%d/%d). Último error: %s",
                        source,
                        attempt,
                        self.max_retries,
                        exc,
                    )

        raise last_exc  # type: ignore[misc]
