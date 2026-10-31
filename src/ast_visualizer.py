"""
Módulo de Visualización de Árboles Sintácticos y AST para CyberGuard DSL.
Permite exportar y visualizar árboles en:
1. Texto jerárquico estructurado (ASCII/Unicode Tree).
2. Formato DOT de Graphviz.
3. Diagramas Mermaid (para documentación Markdown/GitHub).
4. Gráficos vectoriales SVG nativos (sin requerir binarios externos).
"""

import html
import os
import sys
from typing import Dict, List, Tuple

_DIR_SRC = os.path.dirname(os.path.abspath(__file__))
if _DIR_SRC not in sys.path:
    sys.path.insert(0, _DIR_SRC)

from parser import NodoSintactico


def formatear_etiqueta(nodo: NodoSintactico) -> str:
    """Formatea la etiqueta y el valor léxico de un nodo."""
    if nodo.valor is not None and nodo.valor != nodo.etiqueta:
        return f"{nodo.etiqueta}: {nodo.valor}"
    return nodo.etiqueta


def arbol_a_texto(nodo: NodoSintactico, prefijo: str = "", es_ultimo: bool = True, es_raiz: bool = True) -> str:
    """
    Genera una representación jerárquica en texto (estilo comando 'tree').
    """
    etiqueta = formatear_etiqueta(nodo)
    if es_raiz:
        lineas = [etiqueta]
    else:
        conector = "└── " if es_ultimo else "├── "
        lineas = [f"{prefijo}{conector}{etiqueta}"]

    nuevo_prefijo = "" if es_raiz else (prefijo + ("    " if es_ultimo else "│   "))
    total_hijos = len(nodo.hijos)

    for idx, hijo in enumerate(nodo.hijos):
        ultimo_hijo = idx == (total_hijos - 1)
        lineas.append(arbol_a_texto(hijo, nuevo_prefijo, ultimo_hijo, es_raiz=False))

    return "\n".join(lineas)


def arbol_a_dot(nodo: NodoSintactico, titulo: str = "ArbolSintactico") -> str:
    """
    Genera código fuente en formato Graphviz DOT para representar el árbol.
    """
    lineas = [
        f'digraph {titulo} {{',
        '    rankdir=TB;',
        '    node [fontname="Consolas", fontsize=10, shape=box, style="rounded,filled"];',
        '    edge [color="#555555"];',
    ]
    contador = [0]

    def recorrer(actual: NodoSintactico) -> int:
        id_actual = contador[0]
        contador[0] += 1
        etiqueta = formatear_etiqueta(actual).replace('"', '\\"')
        es_hoja = len(actual.hijos) == 0
        color_fondo = "#E8F5E9" if es_hoja else "#E3F2FD"
        color_borde = "#2E7D32" if es_hoja else "#1565C0"
        lineas.append(
            f'    n{id_actual} [label="{etiqueta}", fillcolor="{color_fondo}", color="{color_borde}"];'
        )
        for hijo in actual.hijos:
            id_hijo = recorrer(hijo)
            lineas.append(f"    n{id_actual} -> n{id_hijo};")
        return id_actual

    recorrer(nodo)
    lineas.append("}")
    return "\n".join(lineas)


def arbol_a_mermaid(nodo: NodoSintactico) -> str:
    """
    Genera un diagrama Mermaid (flowchart TD) del árbol sintáctico o AST.
    """
    lineas = ["flowchart TD"]
    contador = [0]

    def recorrer(actual: NodoSintactico) -> str:
        id_actual = f"N{contador[0]}"
        contador[0] += 1
        etiqueta = formatear_etiqueta(actual).replace('"', "'")
        lineas.append(f'    {id_actual}["{etiqueta}"]')
        for hijo in actual.hijos:
            id_hijo = recorrer(hijo)
            lineas.append(f"    {id_actual} --> {id_hijo}")
        return id_actual

    recorrer(nodo)
    return "\n".join(lineas)


def guardar_arbol_svg(nodo: NodoSintactico, ruta_archivo: str, titulo: str = "Árbol Sintáctico / AST") -> None:
    """
    Genera y guarda una imagen vectorial SVG de alta calidad del árbol sintáctico o AST,
    calculando automáticamente las posiciones de cada subárbol sin dependencias externas.
    """
    ancho_nodo = 150
    alto_nodo = 38
    espacio_x = 24
    espacio_y = 68

    posiciones: Dict[int, Tuple[float, float, NodoSintactico]] = {}
    aristas: List[Tuple[int, int]] = []
    contador = [0]
    cursor_hoja = [0.0]

    def asignar_posiciones(actual: NodoSintactico, profundidad: int) -> Tuple[int, float]:
        id_actual = contador[0]
        contador[0] += 1

        if not actual.hijos:
            x = cursor_hoja[0] * (ancho_nodo + espacio_x)
            cursor_hoja[0] += 1.0
        else:
            xs_hijos: List[float] = []
            for hijo in actual.hijos:
                id_hijo, x_hijo = asignar_posiciones(hijo, profundidad + 1)
                aristas.append((id_actual, id_hijo))
                xs_hijos.append(x_hijo)
            x = (xs_hijos[0] + xs_hijos[-1]) / 2.0

        y = profundidad * (alto_nodo + espacio_y)
        posiciones[id_actual] = (x, y, actual)
        return id_actual, x

    asignar_posiciones(nodo, 0)

    margen_x = 40
    margen_y = 65
    max_x = max(pos[0] for pos in posiciones.values()) + ancho_nodo + margen_x * 2
    max_y = max(pos[1] for pos in posiciones.values()) + alto_nodo + margen_y + 30

    ancho_svg = max(int(max_x), 500)
    alto_svg = max(int(max_y), 250)

    elementos_svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {ancho_svg} {alto_svg}" '
        f'width="{ancho_svg}" height="{alto_svg}" style="background-color:#FAFAFA; font-family:Consolas, monospace;">',
        f'<text x="{ancho_svg / 2:.1f}" y="32" text-anchor="middle" font-size="16" font-weight="bold" fill="#1A237E">'
        f'{html.escape(titulo)}</text>',
    ]

    # Dibujar aristas primero
    for id_padre, id_hijo in aristas:
        px, py, _ = posiciones[id_padre]
        hx, hy, _ = posiciones[id_hijo]
        x1 = px + margen_x + ancho_nodo / 2
        y1 = py + margen_y + alto_nodo
        x2 = hx + margen_x + ancho_nodo / 2
        y2 = hy + margen_y
        elementos_svg.append(
            f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
            f'stroke="#607D8B" stroke-width="2" />'
        )

    # Dibujar nodos
    for _, (x, y, nod) in posiciones.items():
        rx = x + margen_x
        ry = y + margen_y
        es_hoja = len(nod.hijos) == 0
        es_epsilon = nod.etiqueta == 'ε'

        if es_epsilon:
            fill = "#FFF8E1"
            stroke = "#F57F17"
            text_color = "#E65100"
        elif es_hoja:
            fill = "#E8F5E9"
            stroke = "#2E7D32"
            text_color = "#1B5E20"
        else:
            fill = "#E3F2FD"
            stroke = "#1565C0"
            text_color = "#0D47A1"

        etiqueta = html.escape(formatear_etiqueta(nod))
        elementos_svg.append(
            f'<rect x="{rx:.1f}" y="{ry:.1f}" width="{ancho_nodo}" height="{alto_nodo}" '
            f'rx="7" ry="7" fill="{fill}" stroke="{stroke}" stroke-width="2" />'
        )
        elementos_svg.append(
            f'<text x="{rx + ancho_nodo / 2:.1f}" y="{ry + alto_nodo / 2 + 4:.1f}" '
            f'text-anchor="middle" font-size="12" font-weight="bold" fill="{text_color}">{etiqueta}</text>'
        )

    elementos_svg.append("</svg>")

    with open(ruta_archivo, "w", encoding="utf-8") as f:
        f.write("\n".join(elementos_svg))
