/**
 * Check whether a value is a non-array object.
 *
 * @param {unknown} value - Value to inspect.
 * @returns {boolean} Whether the value can be treated as a record.
 * @example
 * isRecord({ target: "127.0.0.1" }); // true
 */
function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Check whether a value is a non-negative integer.
 *
 * @param {unknown} value - Value to inspect.
 * @returns {boolean} Whether the value is an integer greater than or equal to zero.
 * @example
 * isNonNegativeInteger(3); // true
 */
function isNonNegativeInteger(value) {
  return Number.isInteger(value) && value >= 0;
}

/**
 * Parse and validate a PortScanner JSON report before it reaches the UI.
 *
 * @param {string} contents - Raw JSON text selected by the user.
 * @returns {Record<string, unknown>} The validated report data.
 * @throws {Error} If the JSON is malformed or does not match the report schema.
 * @example
 * const report = parseReportJson(await file.text());
 * console.log(report.statistics.total_scanned);
 */
export function parseReportJson(contents) {
  let report;

  try {
    report = JSON.parse(contents);
  } catch {
    throw new Error("El archivo seleccionado no contiene JSON válido.");
  }

  if (!isRecord(report)) {
    throw new Error("El JSON debe contener un objeto de reporte.");
  }

  if (
    !isRecord(report.scan_metadata) ||
    typeof report.scan_metadata.target_ip !== "string"
  ) {
    throw new Error("El reporte no incluye los metadatos del destino.");
  }

  if (
    report.scan_metadata.scan_timestamp !== undefined &&
    typeof report.scan_metadata.scan_timestamp !== "string"
  ) {
    throw new Error("La fecha del escaneo no es válida.");
  }

  if (!isRecord(report.statistics)) {
    throw new Error("El reporte no incluye estadísticas.");
  }

  for (const field of [
    "total_scanned",
    "open_count",
    "closed_count",
    "filtered_count",
  ]) {
    if (!isNonNegativeInteger(report.statistics[field])) {
      throw new Error(`La estadística "${field}" no es válida.`);
    }
  }

  if (
    report.statistics.error_count !== undefined &&
    !isNonNegativeInteger(report.statistics.error_count)
  ) {
    throw new Error('La estadística "error_count" no es válida.');
  }

  if (
    !isRecord(report.security_analysis) ||
    !Array.isArray(report.security_analysis.alerts)
  ) {
    throw new Error("El reporte no incluye un análisis de seguridad válido.");
  }

  if (
    report.security_analysis.risk_level !== undefined &&
    typeof report.security_analysis.risk_level !== "string"
  ) {
    throw new Error("El nivel de riesgo no es válido.");
  }

  for (const alert of report.security_analysis.alerts) {
    if (!isRecord(alert)) {
      throw new Error("El reporte contiene una alerta no válida.");
    }

    if (
      alert.port !== undefined &&
      typeof alert.port !== "string" &&
      !Number.isInteger(alert.port)
    ) {
      throw new Error("El reporte contiene un puerto de alerta no válido.");
    }

    for (const field of ["service", "risk", "message", "recommendation"]) {
      if (alert[field] !== undefined && typeof alert[field] !== "string") {
        throw new Error(`El campo "${field}" de una alerta no es válido.`);
      }
    }
  }

  return report;
}