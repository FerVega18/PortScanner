import assert from "node:assert/strict";
import test from "node:test";

import { parseReportJson } from "./report.js";

const validReport = {
  scan_metadata: { target_ip: "127.0.0.1" },
  statistics: {
    total_scanned: 2,
    open_count: 1,
    closed_count: 1,
    filtered_count: 0,
    error_count: 0,
  },
  security_analysis: { alerts: [] },
};

/**
 * Verify that valid scanner JSON is returned as report data.
 *
 * @returns {void}
 * @example
 * test("parses a valid scanner report", parsesValidScannerReport);
 */
function parsesValidScannerReport() {
  assert.deepEqual(parseReportJson(JSON.stringify(validReport)), validReport);
}
test("parses a valid scanner report", parsesValidScannerReport);

/**
 * Verify that malformed JSON produces a clear parser error.
 *
 * @returns {void}
 * @example
 * test("rejects malformed JSON", rejectsMalformedJson);
 */
function rejectsMalformedJson() {
  assert.throws(
    () => parseReportJson("{"),
    /no contiene JSON válido/,
  );
}
test("rejects malformed JSON", rejectsMalformedJson);

/**
 * Verify that JSON without required scan statistics is rejected.
 *
 * @returns {void}
 * @example
 * test("rejects JSON without scanner statistics", rejectsMissingStatistics);
 */
function rejectsMissingStatistics() {
  assert.throws(
    () =>
      parseReportJson(
        JSON.stringify({ scan_metadata: validReport.scan_metadata }),
      ),
    /no incluye estadísticas/,
  );
}
test("rejects JSON without scanner statistics", rejectsMissingStatistics);

/**
 * Verify that malformed alert entries do not reach the React view.
 *
 * @returns {void}
 * @example
 * test("rejects malformed security alerts", rejectsMalformedAlerts);
 */
function rejectsMalformedAlerts() {
  const report = {
    ...validReport,
    security_analysis: { alerts: [null] },
  };

  assert.throws(
    () => parseReportJson(JSON.stringify(report)),
    /alerta no válida/,
  );
}
test("rejects malformed security alerts", rejectsMalformedAlerts);
