"""
Módulo de Análisis Sintáctico Predictivo LL(1) para CyberGuard DSL.
Incluye:
1. Analizador Sintáctico por Descenso Recursivo (con construcción de Árbol Sintáctico y AST).
2. Analizador Sintáctico Predictivo manejado por Tabla LL(1) con pila explícita.
3. Manejo detallado y contextual de errores sintácticos (Sección 6.7).
"""

import os
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

_DIR_SRC = os.path.dirname(os.path.abspath(__file__))
if _DIR_SRC not in sys.path:
    sys.path.insert(0, _DIR_SRC)

from grammar_ll1 import (
    EOF,
    EPSILON,
    NO_TERMINALES,
    PRODUCCIONES,
    SIMBOLO_INICIAL,
    calcular_first,
    calcular_follow,
    construir_tabla_ll1,
    es_no_terminal,
)
from lexer import ErrorLexico, Token, tokenizar_detallado

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


@dataclass
class NodoSintactico:
    """Nodo para representar tanto el Árbol Sintáctico concreto como el AST."""
    etiqueta: str
    valor: Optional[str] = None
    hijos: List["NodoSintactico"] = field(default_factory=list)

    def agregar_hijo(self, hijo: "NodoSintactico") -> None:
        self.hijos.append(hijo)


class ErrorSintactico(SyntaxError):
    """Excepción para errores sintácticos con ubicación y contexto explicativo."""
    def __init__(
        self,
        mensaje: str,
        posicion: Optional[int] = None,
        linea: Optional[int] = None,
        columna: Optional[int] = None,
        token_encontrado: Optional[str] = None,
        esperado: Optional[str] = None,
    ):
        super().__init__(mensaje)
        self.mensaje = mensaje
        self.posicion = posicion
        self.linea = linea
        self.columna = columna
        self.token_encontrado = token_encontrado
        self.esperado = esperado


class ParserDescensoRecursivo:
    """
    Analizador sintáctico predictivo por Descenso Recursivo LL(1).
    Cada no terminal de la gramática se implementa como un método dedicado.
    Construye simultáneamente el Árbol de Derivación Sintáctico y el AST.
    """

    def __init__(self, entrada: Union[str, List[Token], List[Tuple[str, str]]]):
        if isinstance(entrada, str):
            self.tokens: List[Token] = tokenizar_detallado(entrada)
        elif entrada and isinstance(entrada[0], tuple):
            self.tokens = [
                Token(tipo=t[0], lexema=t[1], linea=1, columna=i + 1, posicion=i + 1)
                for i, t in enumerate(entrada)  # type: ignore[arg-type]
            ]
        else:
            self.tokens = list(entrada)  # type: ignore[arg-type]

        self.pos: int = 0
        self.total: int = len(self.tokens)

    @property
    def token_actual(self) -> Token:
        """Retorna el token actual o el marcador de fin de entrada ($)."""
        if self.pos < self.total:
            return self.tokens[self.pos]
        ultima_linea = self.tokens[-1].linea if self.tokens else 1
        ultima_col = (self.tokens[-1].columna + len(self.tokens[-1].lexema)) if self.tokens else 1
        return Token(EOF, EOF, ultima_linea, ultima_col, self.total + 1)

    @property
    def token_anterior(self) -> Optional[Token]:
        """Retorna el token inmediatamente anterior si existe."""
        if self.pos > 0 and (self.pos - 1) < self.total:
            return self.tokens[self.pos - 1]
        return None

    def _error(self, detalle: str, esperado: Optional[str] = None) -> ErrorSintactico:
        tok = self.token_actual
        ubicacion = (
            f"cerca de la posición {tok.posicion} (línea {tok.linea}, columna {tok.columna})"
            if tok.tipo != EOF
            else f"al final de la entrada (posición {tok.posicion}, línea {tok.linea})"
        )
        mensaje_completo = f"Error sintáctico: {detalle} [{ubicacion}]."
        return ErrorSintactico(
            mensaje_completo,
            posicion=tok.posicion,
            linea=tok.linea,
            columna=tok.columna,
            token_encontrado=tok.lexema,
            esperado=esperado,
        )

    def consumir(self, tipo_esperado: str, mensaje_error: Optional[str] = None) -> Token:
        """Consume el token actual si coincide con tipo_esperado; si no, lanza ErrorSintactico."""
        tok = self.token_actual
        if tok.tipo == tipo_esperado:
            self.pos += 1
            return tok

        if mensaje_error:
            raise self._error(mensaje_error, esperado=tipo_esperado)

        encontrado_str = "fin de entrada" if tok.tipo == EOF else f"'{tok.lexema}' ({tok.tipo})"
        raise self._error(
            f"se esperaba {tipo_esperado}, pero se encontró {encontrado_str}",
            esperado=tipo_esperado,
        )

    def analizar(self) -> Tuple[NodoSintactico, NodoSintactico]:
        """
        Ejecuta el análisis sintáctico completo desde el símbolo inicial <programa>.
        Retorna (arbol_sintactico, ast).
        """
        if self.total == 0:
            raise self._error(
                "la entrada está vacía; se esperaba al menos una regla iniciada con la palabra reservada WHEN",
                esperado="WHEN",
            )

        arbol, reglas_ast = self.parse_programa()

        if self.token_actual.tipo != EOF:
            tok = self.token_actual
            raise self._error(
                f"símbolo inesperado '{tok.lexema}'; "
                f"se esperaba la palabra reservada WHEN para iniciar una nueva regla o el fin del programa",
                esperado="WHEN / $",
            )

        ast_raiz = NodoSintactico("Programa", hijos=reglas_ast)
        return arbol, ast_raiz

    # 1. <programa> -> <regla> <resto_programa>
    def parse_programa(self) -> Tuple[NodoSintactico, List[NodoSintactico]]:
        nodo = NodoSintactico("<programa>")
        if self.token_actual.tipo != 'WHEN':
            tok = self.token_actual
            raise self._error(
                f"se esperaba la palabra reservada WHEN al inicio de la regla, "
                f"pero se encontró '{tok.lexema}'",
                esperado="WHEN",
            )
        hijo_regla, ast_regla = self.parse_regla()
        hijo_resto, ast_resto = self.parse_resto_programa()
        nodo.agregar_hijo(hijo_regla)
        nodo.agregar_hijo(hijo_resto)
        return nodo, [ast_regla] + ast_resto

    # 2. <resto_programa> -> <regla> <resto_programa> | ε
    def parse_resto_programa(self) -> Tuple[NodoSintactico, List[NodoSintactico]]:
        nodo = NodoSintactico("<resto_programa>")
        if self.token_actual.tipo == 'WHEN':
            hijo_regla, ast_regla = self.parse_regla()
            hijo_resto, ast_resto = self.parse_resto_programa()
            nodo.agregar_hijo(hijo_regla)
            nodo.agregar_hijo(hijo_resto)
            return nodo, [ast_regla] + ast_resto
        elif self.token_actual.tipo == EOF:
            nodo.agregar_hijo(NodoSintactico(EPSILON))
            return nodo, []
        else:
            tok = self.token_actual
            raise self._error(
                f"símbolo inesperado '{tok.lexema}'; "
                f"se esperaba la palabra reservada WHEN para una nueva regla o fin de programa",
                esperado="WHEN",
            )

    # 3. <regla> -> WHEN <condicion> THEN <lista_acciones> <clausula_else> PUNTO_COMA
    def parse_regla(self) -> Tuple[NodoSintactico, NodoSintactico]:
        nodo = NodoSintactico("<regla>")

        tok_when = self.consumir(
            'WHEN',
            "se esperaba la palabra reservada WHEN al inicio de la regla",
        )
        nodo.agregar_hijo(NodoSintactico("WHEN", tok_when.lexema))

        hijo_cond, ast_cond = self.parse_condicion()
        nodo.agregar_hijo(hijo_cond)

        if self.token_actual.tipo != 'THEN':
            tok = self.token_actual
            if tok.tipo in ('ID', 'NUM', 'TRUE', 'FALSE', 'PARENT_IZQ', 'NOT'):
                raise self._error(
                    f"se esperaba la palabra reservada THEN o un operador lógico (AND, OR) "
                    f"antes de '{tok.lexema}'",
                    esperado="THEN / AND / OR",
                )
            elif tok.tipo == 'PARENT_DER':
                raise self._error(
                    f"paréntesis de cierre ')' sin abrir",
                    esperado="THEN",
                )
            raise self._error(
                "se esperaba la palabra reservada THEN después de la condición",
                esperado="THEN",
            )

        tok_then = self.consumir('THEN')
        nodo.agregar_hijo(NodoSintactico("THEN", tok_then.lexema))

        hijo_acciones, ast_acciones = self.parse_lista_acciones()
        nodo.agregar_hijo(hijo_acciones)

        hijo_else, ast_else = self.parse_clausula_else()
        nodo.agregar_hijo(hijo_else)

        if self.token_actual.tipo != 'PUNTO_COMA':
            tok = self.token_actual
            if tok.tipo == EOF:
                raise self._error(
                    "se esperaba ';' al final de la regla antes de finalizar la entrada",
                    esperado="PUNTO_COMA (;)",
                )
            elif tok.tipo == 'WHEN':
                raise self._error(
                    "se esperaba ';' al final de la regla antes de iniciar el siguiente WHEN",
                    esperado="PUNTO_COMA (;)",
                )
            raise self._error(
                f"símbolo inesperado '{tok.lexema}'; "
                f"se esperaba ';' para cerrar la regla o ',' para separar múltiples acciones",
                esperado="PUNTO_COMA (;)",
            )

        tok_pc = self.consumir('PUNTO_COMA')
        nodo.agregar_hijo(NodoSintactico("PUNTO_COMA", tok_pc.lexema))

        hijos_ast = [
            NodoSintactico("Condicion", hijos=[ast_cond]),
            NodoSintactico("AccionesTHEN", hijos=ast_acciones),
        ]
        if ast_else is not None:
            hijos_ast.append(NodoSintactico("AccionesELSE", hijos=ast_else))

        ast_regla = NodoSintactico("Regla", hijos=hijos_ast)
        return nodo, ast_regla

    # 4. <condicion> -> <termino_and> <resto_or>
    def parse_condicion(self) -> Tuple[NodoSintactico, NodoSintactico]:
        nodo = NodoSintactico("<condicion>")
        hijo_izq, ast_izq = self.parse_termino_and()
        hijo_resto, ast_completo = self.parse_resto_or(ast_izq)
        nodo.agregar_hijo(hijo_izq)
        nodo.agregar_hijo(hijo_resto)
        return nodo, ast_completo

    # 5. <resto_or> -> OR <termino_and> <resto_or> | ε
    def parse_resto_or(self, ast_acumulado: NodoSintactico) -> Tuple[NodoSintactico, NodoSintactico]:
        nodo = NodoSintactico("<resto_or>")
        if self.token_actual.tipo == 'OR':
            tok_or = self.consumir('OR')
            nodo.agregar_hijo(NodoSintactico("OR", tok_or.lexema))
            hijo_der, ast_der = self.parse_termino_and()
            nuevo_ast = NodoSintactico("OpLogico", valor="OR", hijos=[ast_acumulado, ast_der])
            hijo_resto, ast_final = self.parse_resto_or(nuevo_ast)
            nodo.agregar_hijo(hijo_der)
            nodo.agregar_hijo(hijo_resto)
            return nodo, ast_final
        else:
            nodo.agregar_hijo(NodoSintactico(EPSILON))
            return nodo, ast_acumulado

    # 6. <termino_and> -> <factor_not> <resto_and>
    def parse_termino_and(self) -> Tuple[NodoSintactico, NodoSintactico]:
        nodo = NodoSintactico("<termino_and>")
        hijo_izq, ast_izq = self.parse_factor_not()
        hijo_resto, ast_completo = self.parse_resto_and(ast_izq)
        nodo.agregar_hijo(hijo_izq)
        nodo.agregar_hijo(hijo_resto)
        return nodo, ast_completo

    # 7. <resto_and> -> AND <factor_not> <resto_and> | ε
    def parse_resto_and(self, ast_acumulado: NodoSintactico) -> Tuple[NodoSintactico, NodoSintactico]:
        nodo = NodoSintactico("<resto_and>")
        if self.token_actual.tipo == 'AND':
            tok_and = self.consumir('AND')
            nodo.agregar_hijo(NodoSintactico("AND", tok_and.lexema))
            hijo_der, ast_der = self.parse_factor_not()
            nuevo_ast = NodoSintactico("OpLogico", valor="AND", hijos=[ast_acumulado, ast_der])
            hijo_resto, ast_final = self.parse_resto_and(nuevo_ast)
            nodo.agregar_hijo(hijo_der)
            nodo.agregar_hijo(hijo_resto)
            return nodo, ast_final
        else:
            nodo.agregar_hijo(NodoSintactico(EPSILON))
            return nodo, ast_acumulado

    # 8. <factor_not> -> NOT <factor_not> | <primario>
    def parse_factor_not(self) -> Tuple[NodoSintactico, NodoSintactico]:
        nodo = NodoSintactico("<factor_not>")
        if self.token_actual.tipo == 'NOT':
            tok_not = self.consumir('NOT')
            nodo.agregar_hijo(NodoSintactico("NOT", tok_not.lexema))
            hijo_sub, ast_sub = self.parse_factor_not()
            nodo.agregar_hijo(hijo_sub)
            return nodo, NodoSintactico("OpUnario", valor="NOT", hijos=[ast_sub])
        else:
            hijo_prim, ast_prim = self.parse_primario()
            nodo.agregar_hijo(hijo_prim)
            return nodo, ast_prim

    # 9. <primario> -> PARENT_IZQ <condicion> PARENT_DER | <comparacion>
    def parse_primario(self) -> Tuple[NodoSintactico, NodoSintactico]:
        nodo = NodoSintactico("<primario>")
        tok = self.token_actual

        if tok.tipo == 'PARENT_IZQ':
            tok_izq = self.consumir('PARENT_IZQ')
            nodo.agregar_hijo(NodoSintactico("PARENT_IZQ", tok_izq.lexema))
            hijo_cond, ast_cond = self.parse_condicion()
            nodo.agregar_hijo(hijo_cond)
            if self.token_actual.tipo != 'PARENT_DER':
                raise self._error(
                    "se esperaba el paréntesis de cierre ')' para cerrar la agrupación",
                    esperado="PARENT_DER ())",
                )
            tok_der = self.consumir('PARENT_DER')
            nodo.agregar_hijo(NodoSintactico("PARENT_DER", tok_der.lexema))
            return nodo, ast_cond

        elif tok.tipo == 'ID':
            hijo_comp, ast_comp = self.parse_comparacion()
            nodo.agregar_hijo(hijo_comp)
            return nodo, ast_comp

        else:
            prev = self.token_anterior
            if prev and prev.tipo in ('WHEN', 'AND', 'OR', 'NOT', 'PARENT_IZQ'):
                raise self._error(
                    f"se esperaba una condición (identificador, NOT o '(') después de '{prev.lexema}', "
                    f"pero se encontró '{tok.lexema}'",
                    esperado="ID / NOT / (",
                )
            raise self._error(
                f"símbolo inesperado '{tok.lexema}' en la condición; se esperaba un identificador o '('",
                esperado="ID / (",
            )

    # 10. <comparacion> -> ID OP_REL <valor>
    def parse_comparacion(self) -> Tuple[NodoSintactico, NodoSintactico]:
        nodo = NodoSintactico("<comparacion>")
        tok_id = self.consumir(
            'ID',
            "se esperaba un identificador al inicio de la comparación",
        )
        nodo.agregar_hijo(NodoSintactico("ID", tok_id.lexema))

        if self.token_actual.tipo != 'OP_REL':
            tok = self.token_actual
            raise self._error(
                f"se esperaba un operador relacional (>, <, >=, <=, ==, !=) después del identificador "
                f"'{tok_id.lexema}', pero se encontró '{tok.lexema}'",
                esperado="OP_REL",
            )
        tok_op = self.consumir('OP_REL')
        nodo.agregar_hijo(NodoSintactico("OP_REL", tok_op.lexema))

        hijo_val, ast_val = self.parse_valor(operador_previo=tok_op.lexema)
        nodo.agregar_hijo(hijo_val)

        ast_comp = NodoSintactico(
            "Comparacion",
            valor=tok_op.lexema,
            hijos=[
                NodoSintactico("Identificador", valor=tok_id.lexema),
                ast_val,
            ],
        )
        return nodo, ast_comp

    # 11. <valor> -> NUM | TRUE | FALSE | ID
    def parse_valor(self, operador_previo: Optional[str] = None) -> Tuple[NodoSintactico, NodoSintactico]:
        nodo = NodoSintactico("<valor>")
        tok = self.token_actual

        if tok.tipo in ('NUM', 'TRUE', 'FALSE', 'ID'):
            self.consumir(tok.tipo)
            nodo.agregar_hijo(NodoSintactico(tok.tipo, tok.lexema))
            etiqueta_ast = {
                'NUM': 'Numero',
                'TRUE': 'Booleano',
                'FALSE': 'Booleano',
                'ID': 'Identificador',
            }[tok.tipo]
            return nodo, NodoSintactico(etiqueta_ast, valor=tok.lexema)

        contexto = f"después del operador {operador_previo}" if operador_previo else "como argumento"
        raise self._error(
            f"se esperaba un valor (NUM, TRUE, FALSE o ID) {contexto}, pero se encontró '{tok.lexema}'",
            esperado="NUM / TRUE / FALSE / ID",
        )

    # 12. <lista_acciones> -> <accion> <resto_acciones>
    def parse_lista_acciones(self) -> Tuple[NodoSintactico, List[NodoSintactico]]:
        nodo = NodoSintactico("<lista_acciones>")
        hijo_acc, ast_acc = self.parse_accion()
        hijo_resto, ast_resto = self.parse_resto_acciones()
        nodo.agregar_hijo(hijo_acc)
        nodo.agregar_hijo(hijo_resto)
        return nodo, [ast_acc] + ast_resto

    # 13. <resto_acciones> -> COMA <accion> <resto_acciones> | ε
    def parse_resto_acciones(self) -> Tuple[NodoSintactico, List[NodoSintactico]]:
        nodo = NodoSintactico("<resto_acciones>")
        if self.token_actual.tipo == 'COMA':
            tok_coma = self.consumir('COMA')
            nodo.agregar_hijo(NodoSintactico("COMA", tok_coma.lexema))
            hijo_acc, ast_acc = self.parse_accion()
            hijo_resto, ast_resto = self.parse_resto_acciones()
            nodo.agregar_hijo(hijo_acc)
            nodo.agregar_hijo(hijo_resto)
            return nodo, [ast_acc] + ast_resto
        else:
            nodo.agregar_hijo(NodoSintactico(EPSILON))
            return nodo, []

    # 14. <accion> -> ID <complemento_accion>
    def parse_accion(self) -> Tuple[NodoSintactico, NodoSintactico]:
        nodo = NodoSintactico("<accion>")
        tok = self.token_actual
        if tok.tipo != 'ID':
            prev = self.token_anterior
            despues_de = f"después de '{prev.lexema}'" if prev else "en la acción"
            raise self._error(
                f"se esperaba un identificador de acción {despues_de}, pero se encontró '{tok.lexema}'",
                esperado="ID",
            )
        tok_id = self.consumir('ID')
        nodo.agregar_hijo(NodoSintactico("ID", tok_id.lexema))

        hijo_comp, ast_arg = self.parse_complemento_accion(nombre_accion=tok_id.lexema)
        nodo.agregar_hijo(hijo_comp)

        hijos_ast = [ast_arg] if ast_arg is not None else []
        ast_accion = NodoSintactico("Accion", valor=tok_id.lexema, hijos=hijos_ast)
        return nodo, ast_accion

    # 15. <complemento_accion> -> ID | PARENT_IZQ <valor> PARENT_DER | ε
    def parse_complemento_accion(self, nombre_accion: str) -> Tuple[NodoSintactico, Optional[NodoSintactico]]:
        nodo = NodoSintactico("<complemento_accion>")
        tok = self.token_actual

        if tok.tipo == 'ID':
            tok_obj = self.consumir('ID')
            nodo.agregar_hijo(NodoSintactico("ID", tok_obj.lexema))
            return nodo, NodoSintactico("Objetivo", valor=tok_obj.lexema)

        elif tok.tipo == 'PARENT_IZQ':
            tok_izq = self.consumir('PARENT_IZQ')
            nodo.agregar_hijo(NodoSintactico("PARENT_IZQ", tok_izq.lexema))
            if self.token_actual.tipo == 'PARENT_DER':
                raise self._error(
                    f"se esperaba un parámetro dentro de '{nombre_accion}(...)' antes de ')'",
                    esperado="NUM / TRUE / FALSE / ID",
                )
            hijo_val, ast_val = self.parse_valor()
            nodo.agregar_hijo(hijo_val)
            if self.token_actual.tipo != 'PARENT_DER':
                raise self._error(
                    f"se esperaba ')' para cerrar los parámetros de la acción '{nombre_accion}'",
                    esperado="PARENT_DER ())",
                )
            tok_der = self.consumir('PARENT_DER')
            nodo.agregar_hijo(NodoSintactico("PARENT_DER", tok_der.lexema))
            return nodo, NodoSintactico("Parametro", hijos=[ast_val])

        else:
            nodo.agregar_hijo(NodoSintactico(EPSILON))
            return nodo, None

    # 16. <clausula_else> -> ELSE <lista_acciones> | ε
    def parse_clausula_else(self) -> Tuple[NodoSintactico, Optional[List[NodoSintactico]]]:
        nodo = NodoSintactico("<clausula_else>")
        if self.token_actual.tipo == 'ELSE':
            tok_else = self.consumir('ELSE')
            nodo.agregar_hijo(NodoSintactico("ELSE", tok_else.lexema))
            hijo_acciones, ast_acciones = self.parse_lista_acciones()
            nodo.agregar_hijo(hijo_acciones)
            return nodo, ast_acciones
        else:
            nodo.agregar_hijo(NodoSintactico(EPSILON))
            return nodo, None


class ParserTablaLL1:
    """
    Analizador Sintáctico Predictivo guiado por la Tabla LL(1) con pila explícita.
    Demuestra la equivalencia exacta entre la tabla formal M[A, a] y el reconocimiento sintáctico.
    """

    def __init__(self) -> None:
        self.first = calcular_first()
        self.follow = calcular_follow(self.first)
        self.tabla, self.conflictos = construir_tabla_ll1(self.first, self.follow)

    def analizar(self, entrada: Union[str, List[Token]]) -> Tuple[NodoSintactico, List[str]]:
        """
        Analiza una entrada empleando una pila explícita y la tabla predictiva M[X, a].
        Retorna (arbol_sintactico, traza_derivaciones).
        """
        tokens = tokenizar_detallado(entrada) if isinstance(entrada, str) else list(entrada)
        if not tokens:
            raise ErrorSintactico(
                "Error sintáctico: la entrada está vacía; se esperaba la palabra reservada WHEN."
            )

        ultima_linea = tokens[-1].linea
        ultima_col = tokens[-1].columna + len(tokens[-1].lexema)
        tokens_eof = tokens + [Token(EOF, EOF, ultima_linea, ultima_col, len(tokens) + 1)]

        raiz = NodoSintactico(SIMBOLO_INICIAL)
        nodo_eof = NodoSintactico(EOF)
        pila: List[Tuple[str, NodoSintactico]] = [(EOF, nodo_eof), (SIMBOLO_INICIAL, raiz)]

        idx = 0
        traza: List[str] = []

        while pila:
            simbolo_tope, nodo_actual = pila.pop()
            tok_actual = tokens_eof[idx]

            if simbolo_tope == EOF:
                if tok_actual.tipo == EOF:
                    break
                raise ErrorSintactico(
                    f"Error sintáctico: símbolo inesperado '{tok_actual.lexema}' cerca de la posición {tok_actual.posicion}."
                )

            if not es_no_terminal(simbolo_tope):
                if simbolo_tope == tok_actual.tipo:
                    nodo_actual.valor = tok_actual.lexema
                    idx += 1
                else:
                    raise ErrorSintactico(
                        f"Error sintáctico: se esperaba {simbolo_tope}, pero se encontró "
                        f"'{tok_actual.lexema}' cerca de la posición {tok_actual.posicion}."
                    )
            else:
                clave = (simbolo_tope, tok_actual.tipo)
                if clave not in self.tabla:
                    esperados = sorted(
                        t for (nt, t) in self.tabla.keys() if nt == simbolo_tope
                    )
                    raise ErrorSintactico(
                        f"Error sintáctico en {simbolo_tope}: símbolo inesperado '{tok_actual.lexema}' "
                        f"cerca de la posición {tok_actual.posicion}. Se esperaba uno de: {', '.join(esperados)}."
                    )

                produccion = self.tabla[clave][0]
                traza.append(f"{simbolo_tope} -> {' '.join(produccion)}")

                if produccion == [EPSILON]:
                    nodo_actual.agregar_hijo(NodoSintactico(EPSILON))
                else:
                    nuevos_hijos = [NodoSintactico(sim) for sim in produccion]
                    for h in nuevos_hijos:
                        nodo_actual.agregar_hijo(h)
                    for sim, h in reversed(list(zip(produccion, nuevos_hijos))):
                        pila.append((sim, h))

        return raiz, traza


def analizar_programa(cadena: str) -> Dict[str, Any]:
    """
    Función de alto nivel para analizar una cadena de entrada con ambos analizadores
    (Descenso Recursivo + Tabla LL(1)) y devolver el resultado estructurado.
    """
    try:
        tokens = tokenizar_detallado(cadena)
        parser_dr = ParserDescensoRecursivo(tokens)
        arbol_sintactico, ast = parser_dr.analizar()

        parser_ll1 = ParserTablaLL1()
        _, traza_ll1 = parser_ll1.analizar(tokens)

        return {
            "valido": True,
            "mensaje": "Entrada sintácticamente válida (Aceptada).",
            "tokens": tokens,
            "arbol_sintactico": arbol_sintactico,
            "ast": ast,
            "traza_ll1": traza_ll1,
        }
    except (ErrorLexico, ErrorSintactico) as err:
        return {
            "valido": False,
            "mensaje": str(err),
            "tokens": [],
            "arbol_sintactico": None,
            "ast": None,
            "traza_ll1": [],
        }
