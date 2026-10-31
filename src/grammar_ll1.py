"""
Módulo de Definición Formal de la Gramática Libre de Contexto (GLC),
cálculo algorítmico de conjuntos FIRST y FOLLOW, y construcción de la Tabla LL(1)
para CyberGuard DSL.
"""

import sys
from typing import Dict, List, Set, Tuple

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

EPSILON = 'ε'
EOF = '$'

SIMBOLO_INICIAL = '<programa>'

NO_TERMINALES: List[str] = [
    '<programa>',
    '<resto_programa>',
    '<regla>',
    '<condicion>',
    '<resto_or>',
    '<termino_and>',
    '<resto_and>',
    '<factor_not>',
    '<primario>',
    '<comparacion>',
    '<valor>',
    '<lista_acciones>',
    '<resto_acciones>',
    '<accion>',
    '<complemento_accion>',
    '<clausula_else>',
]

TERMINALES: List[str] = [
    'WHEN',
    'THEN',
    'ELSE',
    'AND',
    'OR',
    'NOT',
    'TRUE',
    'FALSE',
    'ID',
    'NUM',
    'OP_REL',
    'PARENT_IZQ',
    'PARENT_DER',
    'COMA',
    'PUNTO_COMA',
]

# Producciones de la GLC en forma LL(1) (sin recursión izquierda, factorizada y no ambigua)
PRODUCCIONES: Dict[str, List[List[str]]] = {
    '<programa>': [
        ['<regla>', '<resto_programa>'],
    ],
    '<resto_programa>': [
        ['<regla>', '<resto_programa>'],
        [EPSILON],
    ],
    '<regla>': [
        ['WHEN', '<condicion>', 'THEN', '<lista_acciones>', '<clausula_else>', 'PUNTO_COMA'],
    ],
    '<condicion>': [
        ['<termino_and>', '<resto_or>'],
    ],
    '<resto_or>': [
        ['OR', '<termino_and>', '<resto_or>'],
        [EPSILON],
    ],
    '<termino_and>': [
        ['<factor_not>', '<resto_and>'],
    ],
    '<resto_and>': [
        ['AND', '<factor_not>', '<resto_and>'],
        [EPSILON],
    ],
    '<factor_not>': [
        ['NOT', '<factor_not>'],
        ['<primario>'],
    ],
    '<primario>': [
        ['PARENT_IZQ', '<condicion>', 'PARENT_DER'],
        ['<comparacion>'],
    ],
    '<comparacion>': [
        ['ID', 'OP_REL', '<valor>'],
    ],
    '<valor>': [
        ['NUM'],
        ['TRUE'],
        ['FALSE'],
        ['ID'],
    ],
    '<lista_acciones>': [
        ['<accion>', '<resto_acciones>'],
    ],
    '<resto_acciones>': [
        ['COMA', '<accion>', '<resto_acciones>'],
        [EPSILON],
    ],
    '<accion>': [
        ['ID', '<complemento_accion>'],
    ],
    '<complemento_accion>': [
        ['ID'],
        ['PARENT_IZQ', '<valor>', 'PARENT_DER'],
        [EPSILON],
    ],
    '<clausula_else>': [
        ['ELSE', '<lista_acciones>'],
        [EPSILON],
    ],
}


def es_no_terminal(simbolo: str) -> bool:
    """Determina si un símbolo es un no terminal de la gramática."""
    return simbolo in PRODUCCIONES


def calcular_first_secuencia(secuencia: List[str], first: Dict[str, Set[str]]) -> Set[str]:
    """Calcula el conjunto FIRST para una secuencia arbitraria de símbolos α."""
    if not secuencia or secuencia == [EPSILON]:
        return {EPSILON}

    resultado: Set[str] = set()
    todos_anulables = True

    for simbolo in secuencia:
        if simbolo == EPSILON:
            continue
        if not es_no_terminal(simbolo):
            resultado.add(simbolo)
            todos_anulables = False
            break
        else:
            simbolos_first = first[simbolo]
            resultado.update(s for s in simbolos_first if s != EPSILON)
            if EPSILON not in simbolos_first:
                todos_anulables = False
                break

    if todos_anulables:
        resultado.add(EPSILON)

    return resultado


def calcular_first() -> Dict[str, Set[str]]:
    """Calcula los conjuntos FIRST para todos los no terminales mediante punto fijo."""
    first: Dict[str, Set[str]] = {nt: set() for nt in NO_TERMINALES}

    cambio = True
    while cambio:
        cambio = False
        for nt in NO_TERMINALES:
            for produccion in PRODUCCIONES[nt]:
                nuevos = calcular_first_secuencia(produccion, first)
                if not nuevos.issubset(first[nt]):
                    first[nt].update(nuevos)
                    cambio = True

    return first


def calcular_follow(first: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
    """Calcula los conjuntos FOLLOW para todos los no terminales mediante punto fijo."""
    follow: Dict[str, Set[str]] = {nt: set() for nt in NO_TERMINALES}
    follow[SIMBOLO_INICIAL].add(EOF)

    cambio = True
    while cambio:
        cambio = False
        for a in NO_TERMINALES:
            for produccion in PRODUCCIONES[a]:
                for i, simbolo in enumerate(produccion):
                    if not es_no_terminal(simbolo):
                        continue
                    beta = produccion[i + 1:]
                    first_beta = calcular_first_secuencia(beta, first)
                    antes = len(follow[simbolo])

                    follow[simbolo].update(s for s in first_beta if s != EPSILON)
                    if not beta or EPSILON in first_beta:
                        follow[simbolo].update(follow[a])

                    if len(follow[simbolo]) > antes:
                        cambio = True

    return follow


def construir_tabla_ll1(
    first: Dict[str, Set[str]],
    follow: Dict[str, Set[str]],
) -> Tuple[Dict[Tuple[str, str], List[List[str]]], List[str]]:
    """
    Construye la tabla predictiva LL(1).
    Retorna:
        (tabla, conflictos)
        donde tabla[(NoTerminal, Terminal)] = lista de cuerpos de producción asignados.
    """
    tabla: Dict[Tuple[str, str], List[List[str]]] = {}
    conflictos: List[str] = []

    for nt in NO_TERMINALES:
        for produccion in PRODUCCIONES[nt]:
            first_alpha = calcular_first_secuencia(produccion, first)
            for terminal in first_alpha:
                if terminal != EPSILON:
                    clave = (nt, terminal)
                    tabla.setdefault(clave, []).append(produccion)

            if EPSILON in first_alpha:
                for terminal_follow in follow[nt]:
                    clave = (nt, terminal_follow)
                    tabla.setdefault(clave, []).append(produccion)

    for (nt, term), prods in tabla.items():
        if len(prods) > 1:
            conflictos.append(
                f"Conflicto en M[{nt}, {term}]: múltiples producciones {prods}"
            )

    return tabla, conflictos


def formatear_produccion(nt: str, cuerpo: List[str]) -> str:
    """Devuelve una representación legible de una producción A -> α."""
    return f"{nt} -> {' '.join(cuerpo)}"


if __name__ == '__main__':
    first_sets = calcular_first()
    follow_sets = calcular_follow(first_sets)
    tabla, lista_conflictos = construir_tabla_ll1(first_sets, follow_sets)

    print("=== CONJUNTOS FIRST Y FOLLOW ===")
    for nt in NO_TERMINALES:
        print(f"{nt:22s} | FIRST = {sorted(first_sets[nt])} | FOLLOW = {sorted(follow_sets[nt])}")

    print(f"\n¿Es LL(1) sin conflictos?: {len(lista_conflictos) == 0}")
    print(f"Total de entradas en la tabla LL(1): {len(tabla)}")
