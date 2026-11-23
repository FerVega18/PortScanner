import { useState } from "react";

import { parseReportJson } from "../js/report.js";
import "./App.css";

const statistics = [
  { key: "total_scanned", label: "Puertos revisados" },
  { key: "open_count", label: "Abiertos" },
  { key: "closed_count", label: "Cerrados" },
  { key: "filtered_count", label: "Filtrados" },
  { key: "error_count", label: "Errores" },
];

/**
 * Format a report timestamp for display in the user's locale.
 *
 * @param {string | undefined} value - ISO timestamp from the report metadata.
 * @returns {string} Localized timestamp or a fallback label.
 * @example
 * formatTimestamp("2026-04-01T13:18:54.815201");
 */
function formatTimestamp(value) {
  if (!value) {
    return "Fecha no disponible";
  }

  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : new Intl.DateTimeFormat("es", {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(date);
}

/**
 * Render the report picker, scan summary, and security alerts.
 *
 * @returns {import("react").ReactElement} The report viewer interface.
 * @remarks This root component does not receive props; its view is driven by
 * local React state.
 * @example
 * <App />
 */
function App() {
  const [report, setReport] = useState(null);
  const [filename, setFilename] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  /**
   * Read the selected file and update the view from validated React state.
   *
   * @param {import("react").ChangeEvent<HTMLInputElement>} event - File input event.
   * @returns {Promise<void>} Resolves after the file has been read and handled.
   * @example
   * <input type="file" onChange={handleFileChange} />
   */
  async function handleFileChange(event) {
    const input = event.currentTarget;
    const file = input.files?.[0];

    if (!file) {
      return;
    }

    setReport(null);
    setFilename(file.name);
    setError("");
    setIsLoading(true);

    try {
      setReport(parseReportJson(await file.text()));
    } catch (caughtError) {
      setError(
        caughtError instanceof Error
          ? caughtError.message
          : "No se pudo leer el reporte.",
      );
    } finally {
      setIsLoading(false);
      input.value = "";
    }
  }

  const alertCount = report?.security_analysis.alerts.length ?? 0;
  const riskLevel = report?.security_analysis.risk_level ?? "SIN DATOS";
  const riskModifier = riskLevel.toLowerCase().replace(/[^a-z0-9-]+/g, "-");

  return (
    <main className="report-viewer">
      <header className="report-viewer__header">
        <p className="report-viewer__eyebrow">PORTSCANNER / VISOR LOCAL</p>
        <h1 className="report-viewer__title">Reportes de escaneo</h1>
        <p className="report-viewer__intro">
          Seleccioná un archivo JSON para consultar el resumen del escaneo y sus
          alertas.
        </p>
      </header>

      <section
        className="report-viewer__upload"
        aria-labelledby="upload-title"
      >
        <div className="report-viewer__upload-copy">
          <p className="report-viewer__eyebrow">ARCHIVO JSON</p>
          <h2 className="report-viewer__section-title" id="upload-title">
            Cargar un reporte
          </h2>
          <p className="report-viewer__muted">
            El archivo se procesa localmente en tu navegador.
          </p>
        </div>
        <label className="report-viewer__file-picker">
          <span className="report-viewer__file-picker-label">
            {isLoading ? "Leyendo reporte..." : "Seleccionar archivo"}
          </span>
          <input
            className="report-viewer__file-input"
            type="file"
            accept=".json,application/json"
            onChange={handleFileChange}
            disabled={isLoading}
          />
        </label>
        {filename && (
          <p className="report-viewer__filename">{filename}</p>
        )}
      </section>

      {error && (
        <p
          className="report-viewer__message report-viewer__message--error"
          role="alert"
        >
          {error}
        </p>
      )}

      {report && (
        <section className="report-viewer__report" aria-live="polite">
          <div className="report-viewer__report-heading">
            <div>
              <p className="report-viewer__eyebrow">RESUMEN DEL ESCANEO</p>
              <h2 className="report-viewer__target">
                {report.scan_metadata.target_ip}
              </h2>
              <p className="report-viewer__timestamp report-viewer__muted">
                {formatTimestamp(report.scan_metadata.scan_timestamp)}
              </p>
            </div>
            <span
              className={`report-viewer__risk-badge report-viewer__risk-badge--${riskModifier}`}
            >
              Riesgo: {riskLevel}
            </span>
          </div>

          <div className="report-viewer__stats">
            {statistics.map(({ key, label }) => (
              <article className="report-viewer__stat" key={key}>
                <p className="report-viewer__stat-label">{label}</p>
                <strong className="report-viewer__stat-value">
                  {key === "error_count"
                    ? report.statistics[key] ?? 0
                    : report.statistics[key]}
                </strong>
              </article>
            ))}
          </div>

          <section
            className="report-viewer__alerts"
            aria-labelledby="alerts-title"
          >
            <div className="report-viewer__alerts-heading">
              <h3
                className="report-viewer__section-title"
                id="alerts-title"
              >
                Alertas de seguridad
              </h3>
              <span className="report-viewer__alert-count">{alertCount}</span>
            </div>
            {alertCount === 0 ? (
              <p className="report-viewer__muted">
                No hay alertas en este reporte.
              </p>
            ) : (
              <ul className="report-viewer__alert-list">
                {report.security_analysis.alerts.map((alert, index) => (
                  <li
                    className="report-viewer__alert"
                    key={`${alert.port ?? "alerta"}-${index}`}
                  >
                    <div className="report-viewer__alert-heading">
                      <strong className="report-viewer__alert-title">
                        Puerto {alert.port ?? "desconocido"} ·{" "}
                        {alert.service ?? "Servicio desconocido"}
                      </strong>
                      <span className="report-viewer__alert-risk">
                        {alert.risk ?? "Riesgo sin clasificar"}
                      </span>
                    </div>
                    {alert.message && (
                      <p className="report-viewer__alert-description">
                        {alert.message}
                      </p>
                    )}
                    {alert.recommendation && (
                      <p className="report-viewer__alert-recommendation">
                        {alert.recommendation}
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </section>
        </section>
      )}
    </main>
  );
}

export default App;
