"""
Modelos ORM de SQLAlchemy para la plataforma CTI-IOC.

Define la tabla "iocs" que almacena los indicadores de compromiso normalizados
provenientes de todas las fuentes OSINT (URLhaus, AlienVault OTX, etc.).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    DateTime,
    Index,
    JSON,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base declarativa compartida por todos los modelos del proyecto."""
    pass


class IOC(Base):
    """Modelo ORM que representa un indicador de compromiso (IOC) almacenado.

    Cada fila corresponde a un IOC único proveniente de una fuente OSINT
    concreta.  La restricción UNIQUE sobre (source_name, source_id) garantiza
    que no se dupliquen indicadores del mismo origen durante recolecciones
    sucesivas.

    Los campos first_seen, last_seen y retrieved_at preservan la zona horaria
    para permitir comparaciones temporales correctas en consultas multi-fuente.
    """

    __tablename__ = "iocs"

    # ------------------------------------------------------------------
    # Clave primaria
    # ------------------------------------------------------------------

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        doc="Identificador UUID generado automáticamente al insertar.",
    )

    # ------------------------------------------------------------------
    # Campos del contrato IOC
    # ------------------------------------------------------------------

    ioc_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        doc='Tipo del indicador: "ip", "domain", "url" o "hash".',
    )

    value: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
        doc="Valor del indicador (URL completa, IP, dominio o hash hex).",
    )

    hash_algorithm: Mapped[Optional[str]] = mapped_column(
        String(10),
        nullable=True,
        doc='Algoritmo hash cuando ioc_type es "hash" (ej. "sha256", "md5").',
    )

    source_name: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        doc='Nombre de la fuente OSINT: "urlhaus" o "alienvault_otx".',
    )

    source_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Identificador del IOC tal como lo asigna la fuente original.",
    )

    retrieved_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        doc="Instante UTC en que este IOC fue descargado por el recolector.",
    )

    first_seen: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="Primera vez que la fuente registró este indicador.",
    )

    last_seen: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="Última vez que la fuente detectó actividad de este indicador.",
    )

    confidence_level: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        doc='Nivel de confianza asignado por el recolector: "low", "medium" o "high".',
    )

    threat_type: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        doc='Categoría de amenaza (ej. "malware_download", "phishing", "TencShell").',
    )

    tags: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        doc="Lista de etiquetas asociadas al IOC, almacenada como JSON.",
    )

    status: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        doc='Estado del indicador según la fuente: "active" o "inactive".',
    )

    raw_payload: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
        doc="Payload original completo de la fuente, sin modificar, en JSON.",
    )

    # ------------------------------------------------------------------
    # Campo de auditoría interna (no confundir con first_seen/last_seen)
    # ------------------------------------------------------------------

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        doc="Instante UTC en que se insertó este registro en la base de datos local.",
    )

    # ------------------------------------------------------------------
    # Índices y restricciones
    # ------------------------------------------------------------------

    __table_args__ = (
        # Evita duplicados del mismo IOC proveniente de la misma fuente.
        UniqueConstraint("source_name", "source_id", name="uq_ioc_source"),
        # Índices para las consultas más frecuentes de la API y el dashboard.
        Index("ix_ioc_ioc_type", "ioc_type"),
        Index("ix_ioc_value", "value"),
        Index("ix_ioc_source_name", "source_name"),
    )

    def __repr__(self) -> str:
        return (
            f"<IOC id={self.id!r} type={self.ioc_type!r} "
            f"value={self.value[:40]!r} source={self.source_name!r}>"
        )
