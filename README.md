# CyberGuard DSL — Analizador Sintáctico LL(1) (INFO1148)

Proyecto de **Teoría de la Computación (INFO1148)**: Diseño e implementación de un analizador sintáctico predictivo **LL(1)** para **CyberGuard DSL**, un Lenguaje de Dominio Específico orientado a **Reglas de Ciberseguridad, Firewall y Respuesta a Incidentes**.

---

## 1. Requisitos y Dependencias

- **Lenguaje:** Python 3.9+ (probado en Python 3.13 y 3.14).
- **Dependencias externas:** **Ninguna obligatoria** (utiliza exclusivamente la biblioteca estándar de Python `re`, `dataclasses`, `typing`, `argparse`, `html`). La exportación gráfica de árboles a `.svg` y `.dot` está implementada de forma nativa sin requerir binarios externos.

---

## 2. Estructura del Proyecto

```text
Analisis-Sintactico-INFO1148/
├── README.md                              # Documentación principal e instrucciones
├── main.py                                # Punto de entrada principal (CLI y demostración)
├── src/                                   # Código fuente modular del analizador
│   ├── __init__.py
│   ├── lexer.py                           # Analizador léxico con rastreo de línea/columna
│   ├── grammar_ll1.py                     # Gramática formal, FIRST, FOLLOW y Tabla LL(1)
│   ├── parser.py                          # Parser por Descenso Recursivo y Tabla LL(1)
│   └── ast_visualizer.py                  # Exportador de árboles (Texto, DOT, Mermaid, SVG)
├── tests/                                 # Batería de casos de prueba
│   └── test_suite.py                      # 30 casos de prueba automatizados (12V, 12I, 6L)
├── notebooks/                             # Notebooks interactivos
│   └── anlizador_lexico1.ipynb            # Notebook con todo el flujo ejecutado
├── docs/                                  # Documentación e informe técnico
│   ├── INFORME_PROYECTO.md                # Informe completo (12 secciones de la pauta)
│   ├── Proyecto Analisis_Sintactico.pdf   # Enunciado oficial del proyecto
│   └── Rubrica_Proyecto.pdf               # Rúbrica oficial de evaluación
└── outputs/                               # Árboles sintácticos y AST generados
    ├── ast_ejemplo.svg
    ├── ast_ejemplo.dot
    ├── arbol_sintactico_ejemplo.svg
    └── arbol_sintactico_ejemplo.dot
```

---

## 3. Instrucciones de Ejecución

### Ejecutar la demostración completa (Gramática + FIRST/FOLLOW + Tabla LL(1) + Árboles + 30 Pruebas)
```bash
python main.py
```

### Analizar una sentencia personalizada desde la terminal
```bash
python main.py -e "WHEN (intentos_ssh > 3 OR puerto == 22) AND NOT ip_interna == TRUE THEN bloquear_ip(ip_origen), alertar soc_admin ELSE registrar_acceso;"
```

### Ejecutar únicamente la batería de 30 casos de prueba
```bash
python tests/test_suite.py
```

### Verificar conjuntos FIRST, FOLLOW y ausencia de conflictos LL(1)
```bash
python src/grammar_ll1.py
```

---

## 4. Formato de Entrada y Sintaxis de CyberGuard DSL

Cada programa consta de una o más reglas terminadas en punto y coma (`;`):

```text
WHEN <condicion> THEN <lista_acciones> [ELSE <lista_acciones>] ;
```

### Características soportadas:
- **Palabras reservadas (8):** `WHEN`, `THEN`, `ELSE`, `AND`, `OR`, `NOT`, `TRUE`, `FALSE`.
- **Operadores relacionales (6):** `>`, `<`, `>=`, `<=`, `==`, `!=`.
- **Operadores lógicos con precedencia formal (3):** `OR` (menor prioridad) $\prec$ `AND` $\prec$ `NOT` $\prec$ `( ... )` (mayor prioridad).
- **Formatos de acción:**
  - Verbo + objeto: `bloquear ip_origen`, `alertar soc_admin`
  - Con parámetro entre paréntesis: `cerrar_puerto(22)`, `aislar_host(ip_remota)`
  - Acción simple: `activar_mitigacion_ddos`
  - Múltiples acciones separadas por coma: `bloquear_ip(ip_atacante), cerrar_puerto(445), notificar_admin(TRUE)`
- **Rama condicional opcional:** `ELSE <lista_acciones>`
- **Comentarios de línea:** `# comentario` o `// comentario`

### Ejemplos de Entrada

**Ejemplo válido:**
```text
WHEN (intentos_ssh > 3 OR intentos_rdp > 3) AND ip_interna == FALSE
THEN aislar_host(ip_origen), alertar soc_admin
ELSE registrar_acceso;
```

**Ejemplo inválido (diagnóstico de error localizado):**
```text
WHEN intentos_login > THEN bloquear ip_origen;
```
Salida del parser:
```text
Error sintáctico: se esperaba un valor (NUM, TRUE, FALSE o ID) después del operador >, pero se encontró 'THEN' [cerca de la posición 4 (línea 1, columna 23)].
```
