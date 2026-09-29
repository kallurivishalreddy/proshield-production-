"""ProShield desktop application (native Windows shell).

Thin shell around the **existing authoritative React UI**
(``frontend/soc/index.html``, built from ``frontend/src_upgraded_gemini``).

    Double-click ProShield.exe
        -> native Windows window (WinForms host + Edge WebView2 control)
        -> connect to the ProShield Service / backend
        -> show real application state
        -> navigate to the SOC UI served by the analyst plane

What this shell deliberately does NOT do:

* it does not contain any security logic;
* it does not duplicate backend logic in JavaScript;
* it does not connect to MongoDB (``include_secrets=False`` - it never even
  reads the signing-key / database configuration file);
* it does not bypass SecureProxy - the React UI talks to ``/api/proxy`` over
  the analyst plane exactly as it does in development.

The UI is loaded from ``http://127.0.0.1:8088/static/soc/index.html`` so it is
**same-origin with the wire boundary**; the shell only supplies the window.
"""
from __future__ import annotations

from desktop.main import main

__all__ = ["main"]
