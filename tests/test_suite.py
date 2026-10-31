"""
Batería Completa de Casos de Prueba para CyberGuard DSL (Sección 6.8 y Rúbrica Criterio 7).
Incluye 30 casos de prueba documentados:
- 12 entradas sintácticamente válidas.
- 12 entradas sintácticamente inválidas.
- 6 casos límite (edge cases).
"""

import os
import sys
from dataclasses import dataclass
from typing import List

_DIR_RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DIR_SRC = os.path.join(_DIR_RAIZ, "src")
if _DIR_SRC not in sys.path:
    sys.path.insert(0, _DIR_SRC)

from parser import analizar_programa

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


@dataclass
class CasoPrueba:
    id_caso: str
    categoria: str  # "Válida", "Inválida", "Caso Límite"
    entrada: str
    esperado_valido: bool
    resultado_esperado: str
    observacion: str


CASOS_DE_PRUEBA: List[CasoPrueba] = [
    # ==========================================
    # 12 ENTRADAS SINTÁCTICAMENTE VÁLIDAS
    # ==========================================
    CasoPrueba(
        "V01", "Válida",
        "WHEN intentos_login > 5 THEN bloquear ip_origen;",
        True, "Aceptada",
        "Regla simple de fuerza bruta con operador '>' y acción verbo-objeto."
    ),
    CasoPrueba(
        "V02", "Válida",
        "WHEN puerto_destino == 22 AND ip_verificada == FALSE THEN cerrar_puerto(22);",
        True, "Aceptada",
        "Condición compuesta con AND, valor booleano FALSE y acción con parámetro numérico."
    ),
    CasoPrueba(
        "V03", "Válida",
        "WHEN trafico_mb >= 1000 OR conexiones_activas >= 500 THEN limitar_ancho_banda(100), alertar soc_admin;",
        True, "Aceptada",
        "Operador OR y múltiples acciones separadas por coma (extensión creativa)."
    ),
    CasoPrueba(
        "V04", "Válida",
        "WHEN NOT firewall_activo == TRUE THEN activar firewall_perimetral, registrar_incidente;",
        True, "Aceptada",
        "Uso del operador unario NOT y combinación de acción con objeto y acción simple."
    ),
    CasoPrueba(
        "V05", "Válida",
        "WHEN (intentos_ssh > 3 OR intentos_rdp > 3) AND ip_interna == FALSE THEN aislar_host(ip_origen) ELSE registrar_acceso;",
        True, "Aceptada",
        "Agrupación con paréntesis, precedencia OR/AND y cláusula condicional ELSE."
    ),
    CasoPrueba(
        "V06", "Válida",
        "WHEN nivel_amenaza != 0 THEN bloquear_ip(ip_atacante), cerrar_puerto(445), notificar_admin(TRUE);",
        True, "Aceptada",
        "Tres acciones encadenadas con parámetros de tipo ID, NUM y booleano TRUE."
    ),
    CasoPrueba(
        "V07", "Válida",
        "WHEN paquetes_syn > 10000 AND NOT (ip_whitelist == TRUE OR modo_mantenimiento == TRUE) THEN activar_mitigacion_ddos;",
        True, "Aceptada",
        "Negación NOT aplicada sobre una agrupación entre paréntesis."
    ),
    CasoPrueba(
        "V08", "Válida",
        "WHEN latencia_ms <= 50 AND perdida_paquetes < 2 THEN mantener_ruta_principal ELSE conmutar_respaldo;",
        True, "Aceptada",
        "Operadores relacionales '<=' y '<' con rama ELSE."
    ),
    CasoPrueba(
        "V09", "Válida",
        "WHEN firma_malware == TRUE THEN poner_cuarentena archivo_sospechoso; WHEN riesgo_fuga >= 80 THEN bloquear_puerto(21);",
        True, "Aceptada",
        "Programa compuesto por múltiples reglas consecutivas en secuencia."
    ),
    CasoPrueba(
        "V10", "Válida",
        "WHEN payload_sql == TRUE OR (cabecera_xss == TRUE AND waf_activo == FALSE) THEN rechazar_peticion, bloquear_ip(cliente_http);",
        True, "Aceptada",
        "Expresión anidada en segundo operando de OR con acciones múltiples."
    ),
    CasoPrueba(
        "V11", "Válida",
        "WHEN certificado_vencido == TRUE THEN redirigir_trafico(443) ELSE permitir_conexion(80);",
        True, "Aceptada",
        "Acciones parametrizadas tanto en la rama THEN como en la rama ELSE."
    ),
    CasoPrueba(
        "V12", "Válida",
        "WHEN temperatura > 28 AND humedad < 40 THEN encender ventilador;",
        True, "Aceptada",
        "Compatibilidad retroactiva con la sentencia de prueba original del notebook base."
    ),

    # ==========================================
    # 12 ENTRADAS SINTÁCTICAMENTE INVÁLIDAS
    # ==========================================
    CasoPrueba(
        "I01", "Inválida",
        "intentos_login > 5 THEN bloquear ip_origen;",
        False, "Rechazada (Falta WHEN)",
        "Error sintáctico al inicio: omisión de la palabra reservada obligatoria WHEN."
    ),
    CasoPrueba(
        "I02", "Inválida",
        "WHEN intentos_login > THEN bloquear ip_origen;",
        False, "Rechazada (Falta valor tras >)",
        "Error sintáctico: se esperaba un valor después del operador relacional '>'."
    ),
    CasoPrueba(
        "I03", "Inválida",
        "WHEN intentos_login > 5 bloquear ip_origen;",
        False, "Rechazada (Falta THEN)",
        "Error sintáctico: se esperaba la palabra reservada THEN después de la condición."
    ),
    CasoPrueba(
        "I04", "Inválida",
        "WHEN intentos_login > 5 THEN bloquear ip_origen",
        False, "Rechazada (Falta ';')",
        "Error sintáctico: falta el delimitador ';' al final de la regla."
    ),
    CasoPrueba(
        "I05", "Inválida",
        "WHEN intentos_login 5 THEN bloquear ip_origen;",
        False, "Rechazada (Falta OP_REL)",
        "Error sintáctico: falta el operador relacional entre el identificador y el valor."
    ),
    CasoPrueba(
        "I06", "Inválida",
        "WHEN (intentos_login > 5 AND puerto == 22 THEN bloquear ip_origen;",
        False, "Rechazada (Paréntesis sin cerrar)",
        "Error sintáctico: paréntesis '(' abierto sin su correspondiente ')'."
    ),
    CasoPrueba(
        "I07", "Inválida",
        "WHEN intentos_login > 5 AND THEN bloquear ip_origen;",
        False, "Rechazada (Operando faltante tras AND)",
        "Error sintáctico: operador lógico AND sin segunda condición."
    ),
    CasoPrueba(
        "I08", "Inválida",
        "WHEN intentos_login > 5 THEN ;",
        False, "Rechazada (Sin acción tras THEN)",
        "Error sintáctico: bloque THEN vacío sin ninguna acción especificada."
    ),
    CasoPrueba(
        "I09", "Inválida",
        "WHEN intentos_login > 5 THEN bloquear_puerto();",
        False, "Rechazada (Parámetro vacío)",
        "Error sintáctico: paréntesis de acción '()' sin argumento interior."
    ),
    CasoPrueba(
        "I10", "Inválida",
        "WHEN intentos_login > 5 THEN bloquear ip_origen, ;",
        False, "Rechazada (Coma colgante en acciones)",
        "Error sintáctico: coma ',' no seguida por otra acción válida."
    ),
    CasoPrueba(
        "I11", "Inválida",
        "WHEN intentos_login > 5 THEN bloquear ip_origen ELSE ;",
        False, "Rechazada (ELSE vacío)",
        "Error sintáctico: palabra reservada ELSE sin acciones asociadas."
    ),
    CasoPrueba(
        "I12", "Inválida",
        "WHEN intentos_login > 5 @ puerto == 22 THEN bloquear ip_origen;",
        False, "Rechazada (Error léxico '@')",
        "Error léxico/sintáctico: carácter '@' fuera del alfabeto del lenguaje."
    ),

    # ==========================================
    # 6 CASOS LÍMITE (EDGE CASES)
    # ==========================================
    CasoPrueba(
        "L01", "Caso Límite",
        "",
        False, "Rechazada (Entrada vacía)",
        "Caso límite: cadena completamente vacía (0 tokens)."
    ),
    CasoPrueba(
        "L02", "Caso Límite",
        "((WHEN ((puerto == 80)) THEN auditar));",
        False, "Rechazada (Paréntesis alrededor de toda la regla)",
        "Caso límite: los paréntesis solo agrupan condiciones, no la sentencia WHEN completa."
    ),
    CasoPrueba(
        "L03", "Caso Límite",
        "WHEN (((NOT NOT alerta_critica == TRUE))) THEN aislar_nodo;",
        True, "Aceptada",
        "Caso límite válido: triple anidamiento de paréntesis y doble negación recursiva NOT NOT."
    ),
    CasoPrueba(
        "L04", "Caso Límite",
        "when trafico_mb > 0 then registrar_log;",
        True, "Aceptada",
        "Caso límite válido: palabras reservadas en minúsculas (insensibilidad a mayúsculas/minúsculas)."
    ),
    CasoPrueba(
        "L05", "Caso Límite",
        "# Regla comentada\nWHEN puerto == 443 THEN permitir_tls; // Comentario final",
        True, "Aceptada",
        "Caso límite válido: programa multilínea con comentarios '#' y '//' intercalados."
    ),
    CasoPrueba(
        "L06", "Caso Límite",
        "WHEN a == b AND c != d AND e >= f OR g <= h THEN acc1, acc2(1), acc3 obj3, acc4(TRUE) ELSE acc5;",
        True, "Aceptada",
        "Caso límite válido: combinación máxima de todos los operadores, tipos de acciones y rama ELSE."
    ),
]


def ejecutar_pruebas(mostrar_tabla: bool = True) -> bool:
    """
    Ejecuta los 30 casos de prueba y verifica que el resultado obtenido coincida con el esperado.
    """
    exitos = 0
    total = len(CASOS_DE_PRUEBA)

    if mostrar_tabla:
        print("=" * 125)
        print(f"{'ID':4s} | {'Categoría':11s} | {'Esperado':10s} | {'Obtenido':10s} | {'Estado':6s} | {'Observación / Mensaje del Analizador'}")
        print("=" * 125)

    for caso in CASOS_DE_PRUEBA:
        res = analizar_programa(caso.entrada)
        obtenido_valido = res["valido"]
        coincide = obtenido_valido == caso.esperado_valido
        if coincide:
            exitos += 1

        estado_str = "OK" if coincide else "FALLO"
        esperado_corto = "Aceptada" if caso.esperado_valido else "Rechazada"
        obtenido_corto = "Aceptada" if obtenido_valido else "Rechazada"
        detalle = caso.observacion if obtenido_valido else res["mensaje"]

        if mostrar_tabla:
            print(
                f"{caso.id_caso:4s} | {caso.categoria:11s} | {esperado_corto:10s} | "
                f"{obtenido_corto:10s} | {estado_str:6s} | {detalle}"
            )

    if mostrar_tabla:
        print("=" * 125)
        print(f"Resumen de pruebas: {exitos}/{total} casos superados exitosamente ({exitos * 100 // total}%).")

    return exitos == total


if __name__ == "__main__":
    exito = ejecutar_pruebas(mostrar_tabla=True)
    sys.exit(0 if exito else 1)
