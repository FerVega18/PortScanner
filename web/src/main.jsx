/**
 * Mount the report viewer React tree into the page root.
 *
 * @example
 * npm run dev
 */
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import App from "./App.jsx";

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
