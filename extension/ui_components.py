# -*- coding: utf-8 -*-
"""
Shared UI components for AI Security Analyzer Burp Extension.
Jython 2.7 compatible (Python 2.7 syntax).
"""

from javax.swing import (
    JPanel, JLabel, JTextField, JComboBox,
    JButton, JTextPane, JScrollPane, BorderFactory, Box,
    BoxLayout, SwingUtilities, JOptionPane
)
from javax.swing.text import SimpleAttributeSet, StyleConstants
from java.awt import BorderLayout, FlowLayout, GridBagLayout, GridBagConstraints
from java.awt import Color, Font, Dimension, Insets
from java.lang import Runnable
import json


# ── Constants ────────────────────────────────────────────────
DEFAULT_SERVER_URL = "http://127.0.0.1:8089"

PROVIDERS = ["openai", "anthropic", "google"]

DEFAULT_MODELS = {
    "openai": "gpt-4o",
    "anthropic": "claude-sonnet-4-5-20250929",
    "google": "gemini-2.0-flash",
}

PROVIDER_MODELS = {
    "openai": [
        "gpt-4o",
        "gpt-4o-mini",
        "gpt-4-turbo",
        "o1",
        "o1-mini",
        "o3-mini",
    ],
    "anthropic": [
        "claude-opus-4-6",
        "claude-sonnet-4-5-20250929",
        "claude-haiku-4-5-20251001",
    ],
    "google": [
        "gemini-2.0-flash",
        "gemini-2.0-pro",
        "gemini-1.5-pro",
        "gemini-1.5-flash",
    ],
}

SEVERITY_COLORS = {
    "Critical": Color(204, 0, 0),
    "High": Color(255, 102, 0),
    "Medium": Color(255, 204, 0),
    "Low": Color(0, 153, 0),
    "Info": Color(0, 102, 204),
}


# ── UI Thread Safety ─────────────────────────────────────────

class UIUpdater(Runnable):
    """Wraps a callable to run on the Swing EDT."""

    def __init__(self, fn):
        self._fn = fn

    def run(self):
        self._fn()


def run_on_edt(fn):
    """Execute a function on the Event Dispatch Thread."""
    SwingUtilities.invokeLater(UIUpdater(fn))


# ── Text Pane Utilities ──────────────────────────────────────

def append_to_pane(text_pane, text, color=None, bold=False, size=12):
    """Append styled text to a JTextPane."""
    doc = text_pane.getStyledDocument()
    attrs = SimpleAttributeSet()
    if color:
        StyleConstants.setForeground(attrs, color)
    if bold:
        StyleConstants.setBold(attrs, True)
    StyleConstants.setFontSize(attrs, size)
    StyleConstants.setFontFamily(attrs, "Monospaced")
    doc.insertString(doc.getLength(), text, attrs)
    # Auto-scroll to bottom
    text_pane.setCaretPosition(doc.getLength())


def clear_pane(text_pane):
    """Clear all text from a JTextPane."""
    text_pane.setText("")


# ── Server Communication ─────────────────────────────────────

def server_request(path, method="GET", data=None, server_url=DEFAULT_SERVER_URL):
    """Make HTTP request to the middleware server.
    Uses java.net.HttpURLConnection for Jython compatibility.
    """
    from java.net import URL, HttpURLConnection
    from java.io import BufferedReader, InputStreamReader, OutputStreamWriter

    url = URL(server_url + path)
    conn = url.openConnection()
    conn.setRequestMethod(method)
    conn.setRequestProperty("Content-Type", "application/json")
    conn.setRequestProperty("Accept", "application/json")
    conn.setConnectTimeout(10000)   # 10s connect timeout
    conn.setReadTimeout(330000)     # 330s read timeout (must exceed server-side 300s AI timeout)

    if data and method in ("POST", "PUT"):
        conn.setDoOutput(True)
        writer = OutputStreamWriter(conn.getOutputStream(), "UTF-8")
        writer.write(json.dumps(data))
        writer.flush()
        writer.close()

    response_code = conn.getResponseCode()

    # Read response
    if response_code >= 200 and response_code < 300:
        stream = conn.getInputStream()
    else:
        stream = conn.getErrorStream()

    if stream is None:
        return {"error": "No response stream", "status": response_code}

    reader = BufferedReader(InputStreamReader(stream, "UTF-8"))
    response_body = []
    line = reader.readLine()
    while line is not None:
        response_body.append(line)
        line = reader.readLine()
    reader.close()
    conn.disconnect()

    body_str = "\n".join(response_body)

    try:
        result = json.loads(body_str)
    except:
        result = {"raw": body_str}

    if response_code >= 400:
        result["_http_status"] = response_code
        if "error" not in result:
            result["error"] = "HTTP %d" % response_code

    return result


# ── API Config Panel ─────────────────────────────────────────

class APIConfigPanel(JPanel):
    """Reusable API configuration panel for each component.
    API keys are managed server-side in config.py.
    This panel only selects provider and model.
    """

    def __init__(self, component_name, callbacks=None):
        JPanel.__init__(self)
        self.component_name = component_name
        self._callbacks = callbacks
        self._server_url = DEFAULT_SERVER_URL

        self.setLayout(BorderLayout())
        self.setBorder(BorderFactory.createTitledBorder(
            "AI Configuration - %s" % component_name.title()
        ))

        # Row panel using FlowLayout for compact horizontal layout
        row_panel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))

        row_panel.add(JLabel("Provider:"))
        self.provider_combo = JComboBox(PROVIDERS)
        self.provider_combo.setPreferredSize(Dimension(120, 24))
        self.provider_combo.addActionListener(lambda e: self._on_provider_change())
        row_panel.add(self.provider_combo)

        row_panel.add(Box.createHorizontalStrut(8))

        row_panel.add(JLabel("Model:"))
        self.model_combo = JComboBox(PROVIDER_MODELS.get("openai", []))
        self.model_combo.setPreferredSize(Dimension(250, 24))
        self.model_combo.setEditable(True)
        row_panel.add(self.model_combo)

        row_panel.add(Box.createHorizontalStrut(8))

        self.apply_btn = JButton("Apply", actionPerformed=self._on_apply)
        row_panel.add(self.apply_btn)

        self.refresh_btn = JButton("Refresh", actionPerformed=self._on_refresh)
        row_panel.add(self.refresh_btn)

        row_panel.add(Box.createHorizontalStrut(4))

        self.status_label = JLabel("API keys managed in server/config.py")
        self.status_label.setForeground(Color.GRAY)
        self.status_label.setFont(Font("SansSerif", Font.PLAIN, 11))
        row_panel.add(self.status_label)

        self.add(row_panel, BorderLayout.CENTER)

        # Load saved config from Burp settings
        self._load_config()

    def _on_provider_change(self):
        """Update model dropdown when provider changes."""
        provider = str(self.provider_combo.getSelectedItem())
        models = PROVIDER_MODELS.get(provider, [])
        self.model_combo.removeAllItems()
        for m in models:
            self.model_combo.addItem(m)
        if models:
            self.model_combo.setSelectedIndex(0)

    def _on_apply(self, event=None):
        """Apply provider/model selection to server."""
        provider = str(self.provider_combo.getSelectedItem())
        model = str(self.model_combo.getSelectedItem()).strip()

        self.status_label.setText("Applying...")
        self.status_label.setForeground(Color.BLUE)
        self.apply_btn.setEnabled(False)

        import threading
        def do_apply():
            try:
                result = server_request(
                    "/config/%s" % self.component_name,
                    method="POST",
                    data={"provider": provider, "model": model},
                    server_url=self._server_url,
                )

                if "error" in result:
                    def update_error():
                        self.status_label.setText("Error: %s" % result["error"][:60])
                        self.status_label.setForeground(Color.RED)
                        self.apply_btn.setEnabled(True)
                    run_on_edt(update_error)
                else:
                    self._save_config(provider, model)
                    def update_success():
                        self.status_label.setText("Active: %s / %s" % (provider, model))
                        self.status_label.setForeground(Color(0, 128, 0))
                        self.apply_btn.setEnabled(True)
                    run_on_edt(update_success)
            except Exception as e:
                def update_exc():
                    self.status_label.setText("Server unreachable: %s" % str(e)[:50])
                    self.status_label.setForeground(Color.RED)
                    self.apply_btn.setEnabled(True)
                run_on_edt(update_exc)

        t = threading.Thread(target=do_apply)
        t.setDaemon(True)
        t.start()

    def _on_refresh(self, event=None):
        """Fetch current config from server."""
        import threading
        def do_refresh():
            try:
                result = server_request(
                    "/config/%s" % self.component_name,
                    method="GET",
                    server_url=self._server_url,
                )
                if "error" not in result:
                    provider = result.get("provider", "")
                    model = result.get("model", "")
                    configured = result.get("configured", False)
                    def update_ui():
                        if provider:
                            self.provider_combo.setSelectedItem(provider)
                        if model:
                            self.model_combo.setSelectedItem(model)
                        if configured:
                            self.status_label.setText("Active: %s / %s" % (provider, model))
                            self.status_label.setForeground(Color(0, 128, 0))
                        else:
                            self.status_label.setText("Server has no key for: %s" % provider)
                            self.status_label.setForeground(Color(255, 102, 0))
                    run_on_edt(update_ui)
                else:
                    def show_err():
                        self.status_label.setText("Error: %s" % result["error"][:50])
                        self.status_label.setForeground(Color.RED)
                    run_on_edt(show_err)
            except Exception as e:
                def show_exc():
                    self.status_label.setText("Server unreachable")
                    self.status_label.setForeground(Color.RED)
                run_on_edt(show_exc)

        t = threading.Thread(target=do_refresh)
        t.setDaemon(True)
        t.start()

    def _save_config(self, provider, model):
        """Save provider/model to Burp settings."""
        if self._callbacks:
            prefix = "aianalyzer.%s." % self.component_name
            self._callbacks.saveExtensionSetting(prefix + "provider", provider)
            self._callbacks.saveExtensionSetting(prefix + "model", model)

    def _load_config(self):
        """Load config from Burp settings."""
        if self._callbacks:
            prefix = "aianalyzer.%s." % self.component_name
            provider = self._callbacks.loadExtensionSetting(prefix + "provider")
            model = self._callbacks.loadExtensionSetting(prefix + "model")

            if provider:
                self.provider_combo.setSelectedItem(provider)
            if model:
                self.model_combo.setSelectedItem(model)
                self.status_label.setText("Saved: %s / %s (click Apply)" % (provider, model))
                self.status_label.setForeground(Color(180, 140, 0))

    def get_server_url(self):
        """Get current server URL."""
        return self._server_url

    def is_configured(self):
        """Check if provider is selected."""
        return bool(str(self.provider_combo.getSelectedItem()))


# ── Loading Indicator ────────────────────────────────────────

class LoadingIndicator(JPanel):
    """Simple loading/status indicator."""

    def __init__(self):
        JPanel.__init__(self, FlowLayout(FlowLayout.LEFT))
        self.label = JLabel("")
        self.label.setFont(Font("SansSerif", Font.ITALIC, 11))
        self.add(self.label)

    def show_loading(self, text="Analyzing..."):
        """Show loading state."""
        def update():
            self.label.setText(text)
            self.label.setForeground(Color.BLUE)
            self.setVisible(True)
        run_on_edt(update)

    def show_success(self, text="Complete"):
        """Show success state."""
        def update():
            self.label.setText(text)
            self.label.setForeground(Color(0, 128, 0))
        run_on_edt(update)

    def show_error(self, text="Error"):
        """Show error state."""
        def update():
            self.label.setText(text)
            self.label.setForeground(Color.RED)
        run_on_edt(update)

    def hide(self):
        """Hide the indicator."""
        def update():
            self.label.setText("")
        run_on_edt(update)
