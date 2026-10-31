"""
Punto de Entrada Principal (CLI y Demostración Funcional) del Proyecto INFO1148:
Analizador Sintáctico LL(1) para CyberGuard DSL (Reglas de Ciberseguridad y Firewall).
"""

import argparse
import os
import sys

_DIR_RAIZ = os.path.dirname(os.path.abspath(__file__))
_DIR_SRC = os.path.join(_DIR_RAIZ, "src")
_DIR_TESTS = os.path.join(_DIR_RAIZ, "tests")
for _ruta in (_DIR_SRC, _DIR_TESTS):
    if _ruta not in sys.path:
        sys.path.insert(0, _ruta)

from ast_visualizer import arbol_a_dot, arbol_a_mermaid, arbol_a_texto, guardar_arbol_svg
from grammar_ll1 import (
    NO_TERMINALES,
    PRODUCCIONES,
    calcular_first,
    calcular_follow,
    construir_tabla_ll1,
    formatear_produccion,
)
from parser import analizar_programa
from test_suite import ejecutar_pruebas

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def mostrar_gramatica_y_tabla() -> None:
    print("=" * 100)
    print("1. GRAMÁTICA LIBRE DE CONTEXTO (GLC) EN FORMA LL(1) - CYBERGUARD DSL")
    print("=" * 100)
    num_prod = 1
    for nt in NO_TERMINALES:
        cuerpos = [" ".join(c) for c in PRODUCCIONES[nt]]
        print(f"  ({num_prod:02d}) {nt:22s} -> {' | '.join(cuerpos)}")
        num_prod += 1

    first = calcular_first()
    follow = calcular_follow(first)
    tabla, conflictos = construir_tabla_ll1(first, follow)

    print("\n" + "=" * 100)
    print("2. CONJUNTOS FIRST Y FOLLOW")
    print("=" * 100)
    print(f"{'No Terminal':24s} | {'FIRST':36s} | {'FOLLOW'}")
    print("-" * 100)
    for nt in NO_TERMINALES:
        f_str = "{ " + ", ".join(sorted(first[nt])) + " }"
        fl_str = "{ " + ", ".join(sorted(follow[nt])) + " }"
        print(f"{nt:24s} | {f_str:36s} | {fl_str}")

    print("\n" + "=" * 100)
    print("3. RESUMEN DE LA TABLA PREDICTIVA LL(1)")
    print("=" * 100)
    print(f"  - Total de celdas activas M[NoTerminal, Terminal]: {len(tabla)}")
    print(f"  - Conflictos detectados (FIRST/FIRST o FIRST/FOLLOW): {len(conflictos)}")
    print(f"  - ¿La gramática es estrictamente LL(1)?: {'SÍ' if not conflictos else 'NO'}")
    print("-" * 100)
    for (nt, term), prods in sorted(tabla.items()):
        prod_str = formatear_produccion(nt, prods[0])
        print(f"  M[{nt:22s}, {term:10s}] =  {prod_str}")


def demostrar_analisis(sentencia: str, guardar_archivos: bool = True) -> None:
    print("\n" + "=" * 100)
    print("4. DEMOSTRACIÓN DE ANÁLISIS LÉXICO, SINTÁCTICO Y GENERACIÓN DE ÁRBOLES")
    print("=" * 100)
    print(f"Entrada analizada:\n  {sentencia}\n")

    resultado = analizar_programa(sentencia)
    print(f"Estado: {resultado['mensaje']}\n")

    if not resultado["valido"]:
        return

    print("Tokens reconocidos [(TIPO, lexema, línea, columna)]:")
    for t in resultado["tokens"]:
        print(f"  ({t.tipo:11s}, '{t.lexema}', lín={t.linea}, col={t.columna})")

    print("\n--- ÁRBOL DE SINTAXIS ABSTRACTA (AST) ---")
    print(arbol_a_texto(resultado["ast"]))

    print("\n--- ÁRBOL SINTÁCTICO CONCRETO (DERIVACIÓN LL(1)) ---")
    print(arbol_a_texto(resultado["arbol_sintactico"]))

    if guardar_archivos:
        dir_salida = os.path.join(os.path.dirname(os.path.abspath(__file__)), "outputs")
        os.makedirs(dir_salida, exist_ok=True)
        ruta_ast_svg = os.path.join(dir_salida, "ast_ejemplo.svg")
        ruta_cst_svg = os.path.join(dir_salida, "arbol_sintactico_ejemplo.svg")
        ruta_ast_dot = os.path.join(dir_salida, "ast_ejemplo.dot")
        ruta_cst_dot = os.path.join(dir_salida, "arbol_sintactico_ejemplo.dot")

        guardar_arbol_svg(resultado["ast"], ruta_ast_svg, titulo="AST - CyberGuard DSL")
        guardar_arbol_svg(
            resultado["arbol_sintactico"],
            ruta_cst_svg,
            titulo="Árbol Sintáctico LL(1) - CyberGuard DSL",
        )

        with open(ruta_ast_dot, "w", encoding="utf-8") as f:
            f.write(arbol_a_dot(resultado["ast"], "AST_CyberGuard"))
        with open(ruta_cst_dot, "w", encoding="utf-8") as f:
            f.write(arbol_a_dot(resultado["arbol_sintactico"], "ArbolSintactico_CyberGuard"))

        print("\nArchivos gráficos generados exitosamente:")
        print(f"  - SVG AST:              {ruta_ast_svg}")
        print(f"  - SVG Árbol Sintáctico: {ruta_cst_svg}")
        print(f"  - Graphviz DOT (AST):   {ruta_ast_dot}")
        print(f"  - Graphviz DOT (CST):   {ruta_cst_dot}")


def main() -> None:
    parser_cli = argparse.ArgumentParser(
        description="Analizador Sintáctico LL(1) para CyberGuard DSL - INFO1148"
    )
    parser_cli.add_argument(
        "-e",
        "--entrada",
        type=str,
        help="Analiza una sentencia específica proporcionada por línea de comandos.",
    )
    args = parser_cli.parse_args()

    if args.entrada is not None:
        demostrar_analisis(args.entrada, guardar_archivos=False)
        return

    mostrar_gramatica_y_tabla()
    sentencia_demo = (
        "WHEN (intentos_ssh > 3 OR puerto_destino == 22) AND NOT ip_confiable == TRUE "
        "THEN bloquear_ip(ip_origen), alertar soc_admin ELSE registrar_acceso;"
    )
    demostrar_analisis(sentencia_demo, guardar_archivos=True)

    print("\n" + "=" * 100)
    print("5. EJECUCIÓN DE LA BATERÍA DE CASOS DE PRUEBA (30 CASOS)")
    print("=" * 100)
    ejecutar_pruebas(mostrar_tabla=True)


if __name__ == "__main__":
    main()
