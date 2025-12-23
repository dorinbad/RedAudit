#!/usr/bin/env python3
"""Analiza el reporte de cobertura y genera un plan para llegar al 90%."""

import json


def analyze_coverage():
    """Analiza el archivo de cobertura y genera recomendaciones."""
    with open("coverage.json", "r") as f:
        data = json.load(f)

    # Recolectar estadísticas por archivo
    files_coverage = []
    for filepath, filedata in data["files"].items():
        if not filepath.startswith("redaudit/"):
            continue

        summary = filedata["summary"]
        coverage_pct = summary["percent_covered"]
        total_statements = summary["num_statements"]
        missing_lines = summary["missing_lines"]

        files_coverage.append(
            {
                "file": filepath,
                "coverage": coverage_pct,
                "total_statements": total_statements,
                "missing_lines": missing_lines,
                "lines_to_cover": (
                    int((total_statements * (90 - coverage_pct)) / 100) if coverage_pct < 90 else 0
                ),
            }
        )

    # Ordenar por cobertura (menor a mayor)
    files_coverage.sort(key=lambda x: x["coverage"])

    # Estadísticas generales
    total_lines = sum(f["total_statements"] for f in files_coverage)
    total_missing = sum(f["missing_lines"] for f in files_coverage)
    current_coverage = ((total_lines - total_missing) / total_lines) * 100

    print("=" * 80)
    print("ANÁLISIS DE COBERTURA REDAUDIT v3.8.7")
    print("=" * 80)
    print(f"\nCOBERTURA ACTUAL: {current_coverage:.2f}%")
    print("OBJETIVO: 90.00%")
    print(f"BRECHA: {90 - current_coverage:.2f}%")
    print(f"\nTotal de líneas: {total_lines}")
    print(f"Líneas sin cubrir: {total_missing}")
    print(
        f"Líneas adicionales a cubrir para 90%: {int((total_lines * (90 - current_coverage)) / 100)}"
    )

    # Archivos con menos del 90% de cobertura
    low_coverage = [f for f in files_coverage if f["coverage"] < 90]

    print(f"\n{'=' * 80}")
    print(f"ARCHIVOS CON <90% COBERTURA ({len(low_coverage)} archivos)")
    print(f"{'=' * 80}")
    print(f"{'Archivo':<50} {'Cob%':<8} {'Faltante':<10} {'Total'}")
    print("-" * 80)

    for f in low_coverage:
        filename = f["file"].split("/")[-1]
        print(
            f"{filename:<50} {f['coverage']:>6.2f}% {f['missing_lines']:>8} {f['total_statements']:>8}"
        )

    # Top 10 archivos prioritarios (bajo coverage y muchas líneas)
    print(f"\n{'=' * 80}")
    print("TOP 10 ARCHIVOS PRIORITARIOS (bajo coverage + muchas líneas)")
    print(f"{'=' * 80}")

    # Calcular prioridad: (100 - coverage) * total_statements
    for f in low_coverage:
        f["priority"] = (100 - f["coverage"]) * f["total_statements"]

    low_coverage.sort(key=lambda x: x["priority"], reverse=True)

    print(f"{'Archivo':<50} {'Cob%':<8} {'Faltante':<10} {'Prioridad'}")
    print("-" * 80)

    for f in low_coverage[:10]:
        filename = f["file"].split("/")[-1]
        print(
            f"{filename:<50} {f['coverage']:>6.2f}% {f['missing_lines']:>8} {f['priority']:>12.0f}"
        )

    # Archivos con 100% de cobertura (para celebrar 🎉)
    perfect_coverage = [f for f in files_coverage if f["coverage"] == 100.0]
    print(f"\n{'=' * 80}")
    print(f"ARCHIVOS CON 100% COBERTURA ({len(perfect_coverage)} archivos) 🎉")
    print(f"{'=' * 80}")
    for f in perfect_coverage:
        filename = f["file"].split("/")[-1]
        print(f"  ✓ {filename}")


if __name__ == "__main__":
    analyze_coverage()
