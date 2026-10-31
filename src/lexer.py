"""
Módulo de Análisis Léxico para CyberGuard DSL (Lenguaje de Reglas de Ciberseguridad y Firewall).
Compatible con el analizador léxico base de INFO1148 y extendido con soporte para:
- Posición, línea y columna de cada token (para mensajes de error localizados).
- Palabra reservada ELSE, separador COMA (,) y comentarios de línea (# o //).
"""

import re
from dataclasses import dataclass
from typing import List, Tuple


@dataclass(frozen=True)
class Token:
    """Representa un token léxico con metadatos de ubicación."""
    tipo: str
    lexema: str
    linea: int
    columna: int
    posicion: int

    def to_tuple(self) -> Tuple[str, str]:
        """Retorna la representación clásica (TIPO_TOKEN, lexema)."""
        return (self.tipo, self.lexema)


PALABRAS_RESERVADAS = {
    'WHEN',
    'THEN',
    'ELSE',
    'AND',
    'OR',
    'NOT',
    'TRUE',
    'FALSE',
}

ESPECIFICACION_TOKENS = [
    ('COMENTARIO', r'(?:#|//)[^\n]*'),
    ('NUM',        r'\d+'),
    ('OP_REL',     r'>=|<=|==|!=|>|<'),
    ('PUNTO_COMA', r';'),
    ('COMA',       r','),
    ('PARENT_IZQ', r'\('),
    ('PARENT_DER', r'\)'),
    ('ID',         r'[A-Za-z_][A-Za-z0-9_]*'),
    ('ESPACIO',    r'[ \t\r\n]+'),
    ('ERROR',      r'.'),
]

PATRON_LEXICO = re.compile(
    '|'.join(f'(?P<{nombre}>{expresion})' for nombre, expresion in ESPECIFICACION_TOKENS)
)


class ErrorLexico(ValueError):
    """Excepción lanzada cuando se encuentra un carácter no válido en el alfabeto."""
    def __init__(self, mensaje: str, lexema: str, linea: int, columna: int, posicion: int):
        super().__init__(mensaje)
        self.lexema = lexema
        self.linea = linea
        self.columna = columna
        self.posicion = posicion


def tokenizar_detallado(cadena: str) -> List[Token]:
    """
    Convierte una cadena de entrada en una lista de objetos Token con ubicación exacta.
    """
    tokens: List[Token] = []
    indice_token = 1

    for coincidencia in PATRON_LEXICO.finditer(cadena):
        tipo = coincidencia.lastgroup
        lexema = coincidencia.group()
        inicio = coincidencia.start()

        linea = cadena.count('\n', 0, inicio) + 1
        ultimo_salto = cadena.rfind('\n', 0, inicio)
        columna = inicio + 1 if ultimo_salto == -1 else (inicio - ultimo_salto)

        if tipo in ('ESPACIO', 'COMENTARIO'):
            continue
        elif tipo == 'ID' and lexema.upper() in PALABRAS_RESERVADAS:
            tipo = lexema.upper()
            lexema = lexema.upper()
        elif tipo == 'ERROR':
            raise ErrorLexico(
                f"Error léxico en línea {linea}, columna {columna} (posición {indice_token}): "
                f"símbolo no reconocido '{lexema}'.",
                lexema=lexema,
                linea=linea,
                columna=columna,
                posicion=indice_token,
            )

        tokens.append(Token(
            tipo=tipo,
            lexema=lexema,
            linea=linea,
            columna=columna,
            posicion=indice_token,
        ))
        indice_token += 1

    return tokens


def analizador_lexico(cadena: str) -> List[Tuple[str, str]]:
    """
    Convierte una cadena de entrada en una lista de tuplas [(TIPO_TOKEN, lexema), ...].
    Mantiene compatibilidad directa con la firma entregada en anlizador_lexico1.ipynb.
    """
    return [t.to_tuple() for t in tokenizar_detallado(cadena)]
