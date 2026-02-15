# -*- coding: utf-8 -*-
"""
AI Security Analyzer - Burp Suite Extension
Main entry point. Registers tabs, context menu, and manages cross-panel communication.
Jython 2.7 compatible (Python 2.7 syntax).

Usage:
  1. Start the middleware server: python server/server.py
  2. In Burp Suite: Extender > Add > Python > select this file
"""

import sys
import os

# Add extension directory to sys.path so sibling modules can be imported
# __file__ is not defined when Burp loads the script via Jython,
# so we inspect the call stack to find the actual script path.
try:
    _ext_dir = os.path.dirname(os.path.abspath(__file__))
except NameError:
    # Fallback: extract path from the Java stack / inspection
    import inspect
    _frame_info = inspect.getfile(lambda: None)
    _ext_dir = os.path.dirname(os.path.abspath(_frame_info))
if _ext_dir not in sys.path:
    sys.path.insert(0, _ext_dir)

from burp import IBurpExtender, ITab, IContextMenuFactory
from javax.swing import JTabbedPane, JMenuItem, SwingUtilities
from java.lang import Runnable
from java.util import ArrayList

from scanner_panel import ScannerPanel
from cve_panel import CVEAnalyzerPanel
from critical_panel import CriticalAnalyzerPanel
from ui_components import UIUpdater


EXTENSION_NAME = "AI Security Analyzer"


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    """Main Burp Suite extension entry point."""

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName(EXTENSION_NAME)
        callbacks.registerContextMenuFactory(self)

        # Build UI on EDT
        SwingUtilities.invokeLater(UIUpdater(self._build_ui))

        callbacks.issueAlert("%s loaded successfully. Start the middleware server on port 8089." % EXTENSION_NAME)

    def _build_ui(self):
        """Build the main tabbed UI."""
        self._main_tabs = JTabbedPane()

        # Tab 1: Scanner
        self._scanner_panel = ScannerPanel(self._callbacks, self)
        self._main_tabs.addTab("Scanner", self._scanner_panel)

        # Tab 2: Analyze (sub-tabs)
        self._analyze_tabs = JTabbedPane()

        self._cve_panel = CVEAnalyzerPanel(self._callbacks, self)
        self._analyze_tabs.addTab("CVE Analyzer", self._cve_panel)

        self._critical_panel = CriticalAnalyzerPanel(self._callbacks, self)
        self._analyze_tabs.addTab("Critical Analyzer", self._critical_panel)

        self._main_tabs.addTab("Analyze", self._analyze_tabs)

        # Register as Burp tab
        self._callbacks.addSuiteTab(self)

    # ── ITab ──────────────────────────────────────────────────

    def getTabCaption(self):
        return EXTENSION_NAME

    def getUiComponent(self):
        return self._main_tabs

    # ── IContextMenuFactory ───────────────────────────────────

    def createMenuItems(self, invocation):
        """Create right-click context menu items."""
        menu_list = ArrayList()

        ctx = invocation.getInvocationContext()
        # Only show in proxy history, site map, or message viewer
        valid_contexts = [
            invocation.CONTEXT_PROXY_HISTORY,
            invocation.CONTEXT_TARGET_SITE_MAP_TABLE,
            invocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
            invocation.CONTEXT_MESSAGE_VIEWER_RESPONSE,
        ]
        if ctx not in valid_contexts:
            return menu_list

        # "Send to CVE Analyzer"
        item_cve = JMenuItem(
            "Send to AI CVE Analyzer",
            actionPerformed=lambda e: self._context_send_to_cve(invocation)
        )
        menu_list.add(item_cve)

        # "Send to Critical Analyzer"
        item_critical = JMenuItem(
            "Send to AI Critical Analyzer",
            actionPerformed=lambda e: self._context_send_to_critical(invocation)
        )
        menu_list.add(item_critical)

        return menu_list

    def _context_send_to_cve(self, invocation):
        """Handle context menu: Send to CVE Analyzer."""
        items = self._extract_http_items(invocation)
        if items:
            self.send_to_cve_analyzer(items)

    def _context_send_to_critical(self, invocation):
        """Handle context menu: Send to Critical Analyzer."""
        items = self._extract_http_items(invocation)
        if items:
            self.send_to_critical_analyzer(items)

    def _extract_http_items(self, invocation):
        """Extract HttpItem objects from context menu invocation."""
        from models import HttpItem

        messages = invocation.getSelectedMessages()
        if not messages:
            return []

        items = []
        for i, msg in enumerate(messages):
            try:
                req_info = self._helpers.analyzeRequest(msg)
                url = str(req_info.getUrl())
                method = str(req_info.getMethod())

                req_bytes = msg.getRequest()
                req_str = self._helpers.bytesToString(req_bytes) if req_bytes else ""

                resp_bytes = msg.getResponse()
                resp_str = ""
                status_code = 0
                content_type = ""
                length = 0

                if resp_bytes:
                    resp_str = self._helpers.bytesToString(resp_bytes)
                    resp_info = self._helpers.analyzeResponse(resp_bytes)
                    status_code = resp_info.getStatusCode()
                    for header in resp_info.getHeaders():
                        header_str = str(header)
                        if header_str.lower().startswith("content-type:"):
                            content_type = header_str.split(":", 1)[1].strip()
                            break
                    length = len(resp_bytes)

                url_obj = req_info.getUrl()
                host = str(url_obj.getHost())
                port = url_obj.getPort()
                protocol = str(url_obj.getProtocol())
                path = str(url_obj.getPath())

                items.append(HttpItem(
                    index=i + 1,
                    method=method,
                    url=url,
                    status_code=status_code,
                    content_type=content_type,
                    request_str=req_str,
                    response_str=resp_str,
                    host=host,
                    port=port,
                    protocol=protocol,
                    path=path,
                    length=length,
                ))
            except Exception:
                pass
        return items

    # ── Cross-panel communication ─────────────────────────────

    def send_to_cve_analyzer(self, items):
        """Send items to CVE Analyzer and switch tab."""
        def do_switch():
            self._cve_panel.receive_items(items)
            self._main_tabs.setSelectedIndex(1)       # Analyze tab
            self._analyze_tabs.setSelectedIndex(0)     # CVE Analyzer sub-tab
        SwingUtilities.invokeLater(UIUpdater(do_switch))

    def send_to_critical_analyzer(self, items):
        """Send items to Critical Analyzer and switch tab."""
        def do_switch():
            self._critical_panel.receive_items(items)
            self._main_tabs.setSelectedIndex(1)       # Analyze tab
            self._analyze_tabs.setSelectedIndex(1)     # Critical Analyzer sub-tab
        SwingUtilities.invokeLater(UIUpdater(do_switch))
