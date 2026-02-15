# -*- coding: utf-8 -*-
"""
Scanner Panel for AI Security Analyzer Burp Extension.
Loads proxy history, analyzes versions/weaknesses, sends items to other tabs.
Jython 2.7 compatible.
"""

from javax.swing import (
    JPanel, JButton, JTable, JScrollPane, JSplitPane,
    JTextPane, JLabel, JOptionPane, BorderFactory,
    ListSelectionModel, BoxLayout, Box
)
from javax.swing.table import TableRowSorter
from java.awt import BorderLayout, FlowLayout, Color, Font, Dimension
import json
import threading

from models import HttpItem, FindingEntry
from ui_components import (
    APIConfigPanel, LoadingIndicator, run_on_edt,
    append_to_pane, clear_pane, server_request
)
from table_models import ScannerTableModel, FindingsTableModel


class ScannerPanel(JPanel):
    """Main Scanner tab panel."""

    def __init__(self, callbacks, extender):
        JPanel.__init__(self)
        self._callbacks = callbacks
        self._extender = extender
        self._helpers = callbacks.getHelpers()

        self.setLayout(BorderLayout())
        self._build_ui()

    def _build_ui(self):
        """Build the complete Scanner UI."""
        # ── Top: API Config ──
        self.api_config = APIConfigPanel("scanner", self._callbacks)
        self.api_config.setPreferredSize(Dimension(0, 58))

        # ── Center: Main split ──
        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        main_split.setResizeWeight(0.5)

        # Upper: Proxy history table
        upper_panel = JPanel(BorderLayout())

        # Button bar
        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT, 5, 5))

        self.refresh_btn = JButton("Refresh History", actionPerformed=self._on_refresh)
        btn_panel.add(self.refresh_btn)

        self.clear_history_btn = JButton("Clear History", actionPerformed=self._on_clear_history)
        btn_panel.add(self.clear_history_btn)

        btn_panel.add(Box.createHorizontalStrut(10))

        self.analyze_ver_btn = JButton("Analyze Versions", actionPerformed=self._on_analyze_versions)
        btn_panel.add(self.analyze_ver_btn)

        self.analyze_weak_btn = JButton("Analyze Weaknesses", actionPerformed=self._on_analyze_weaknesses)
        btn_panel.add(self.analyze_weak_btn)

        btn_panel.add(Box.createHorizontalStrut(10))

        self.send_cve_btn = JButton("Send to CVE Analyzer", actionPerformed=self._on_send_to_cve)
        btn_panel.add(self.send_cve_btn)

        self.send_critical_btn = JButton("Send to Critical Analyzer", actionPerformed=self._on_send_to_critical)
        btn_panel.add(self.send_critical_btn)

        self.loading = LoadingIndicator()
        btn_panel.add(self.loading)

        upper_panel.add(btn_panel, BorderLayout.NORTH)

        # History table
        self.scanner_model = ScannerTableModel()
        self.history_table = JTable(self.scanner_model)
        self.history_table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self.history_table.setAutoCreateRowSorter(True)
        self.history_table.getTableHeader().setReorderingAllowed(False)

        # Set column widths
        col_model = self.history_table.getColumnModel()
        col_model.getColumn(0).setPreferredWidth(50)   # #
        col_model.getColumn(1).setPreferredWidth(60)   # Method
        col_model.getColumn(2).setPreferredWidth(400)  # URL
        col_model.getColumn(3).setPreferredWidth(50)   # Status
        col_model.getColumn(4).setPreferredWidth(150)  # Content-Type
        col_model.getColumn(5).setPreferredWidth(70)   # Length

        history_scroll = JScrollPane(self.history_table)
        upper_panel.add(history_scroll, BorderLayout.CENTER)

        # Item count label
        self.count_label = JLabel("  0 items loaded")
        self.count_label.setFont(Font("SansSerif", Font.PLAIN, 11))
        upper_panel.add(self.count_label, BorderLayout.SOUTH)

        main_split.setTopComponent(upper_panel)

        # Lower: Results split (findings table + detail)
        lower_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        lower_split.setResizeWeight(0.5)

        # Findings table
        findings_panel = JPanel(BorderLayout())
        findings_panel.setBorder(BorderFactory.createTitledBorder("Findings"))
        self.findings_model = FindingsTableModel()
        self.findings_table = JTable(self.findings_model)
        self.findings_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.findings_table.getSelectionModel().addListSelectionListener(
            lambda e: self._on_finding_selected(e)
        )
        findings_panel.add(JScrollPane(self.findings_table), BorderLayout.CENTER)

        clear_findings_btn = JButton("Clear", actionPerformed=lambda e: self._clear_findings())
        findings_btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        findings_btn_panel.add(clear_findings_btn)
        findings_panel.add(findings_btn_panel, BorderLayout.SOUTH)

        lower_split.setLeftComponent(findings_panel)

        # Detail pane
        detail_panel = JPanel(BorderLayout())
        detail_panel.setBorder(BorderFactory.createTitledBorder("Detail / Raw Response"))
        self.detail_pane = JTextPane()
        self.detail_pane.setEditable(False)
        self.detail_pane.setFont(Font("Monospaced", Font.PLAIN, 12))
        detail_panel.add(JScrollPane(self.detail_pane), BorderLayout.CENTER)

        lower_split.setRightComponent(detail_panel)

        main_split.setBottomComponent(lower_split)

        # Assemble
        top_wrapper = JPanel(BorderLayout())
        top_wrapper.add(self.api_config, BorderLayout.NORTH)
        top_wrapper.add(main_split, BorderLayout.CENTER)

        self.add(top_wrapper, BorderLayout.CENTER)

    def _on_refresh(self, event=None):
        """Load proxy history from Burp."""
        self.loading.show_loading("Loading proxy history...")
        self.refresh_btn.setEnabled(False)

        def do_load():
            try:
                proxy_history = self._callbacks.getProxyHistory()
                items = []
                for i, entry in enumerate(proxy_history):
                    try:
                        req_info = self._helpers.analyzeRequest(entry)
                        url = str(req_info.getUrl())
                        method = str(req_info.getMethod())

                        # Get request string
                        req_bytes = entry.getRequest()
                        req_str = self._helpers.bytesToString(req_bytes) if req_bytes else ""

                        # Get response info
                        resp_bytes = entry.getResponse()
                        resp_str = ""
                        status_code = 0
                        content_type = ""
                        length = 0

                        if resp_bytes:
                            resp_str = self._helpers.bytesToString(resp_bytes)
                            resp_info = self._helpers.analyzeResponse(resp_bytes)
                            status_code = resp_info.getStatusCode()
                            # Extract content-type from headers
                            for header in resp_info.getHeaders():
                                header_str = str(header)
                                if header_str.lower().startswith("content-type:"):
                                    content_type = header_str.split(":", 1)[1].strip()
                                    break
                            length = len(resp_bytes)

                        # Parse host/port/protocol from URL
                        url_obj = req_info.getUrl()
                        host = str(url_obj.getHost())
                        port = url_obj.getPort()
                        protocol = str(url_obj.getProtocol())
                        path = str(url_obj.getPath())

                        item = HttpItem(
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
                        )
                        items.append(item)
                    except Exception:
                        pass  # Skip malformed entries

                def update_ui():
                    self.scanner_model.set_items(items)
                    self.count_label.setText("  %d items loaded" % len(items))
                    self.loading.show_success("Loaded %d items" % len(items))
                    self.refresh_btn.setEnabled(True)
                run_on_edt(update_ui)

            except Exception as e:
                def show_error():
                    self.loading.show_error("Load failed: %s" % str(e))
                    self.refresh_btn.setEnabled(True)
                run_on_edt(show_error)

        t = threading.Thread(target=do_load)
        t.setDaemon(True)
        t.start()

    def _on_clear_history(self, event=None):
        """Clear all loaded proxy history items from the table."""
        self.scanner_model.clear()
        self.count_label.setText("  0 items loaded")
        self.loading.hide()

    def _get_selected_items(self):
        """Get selected HttpItems from the history table."""
        rows = self.history_table.getSelectedRows()
        if not rows:
            JOptionPane.showMessageDialog(self, "Please select one or more items first.")
            return []
        # Convert view indices to model indices (for sorted table)
        model_rows = [self.history_table.convertRowIndexToModel(r) for r in rows]
        return self.scanner_model.get_items_at_rows(model_rows)

    def _on_analyze_versions(self, event=None):
        """Analyze selected items for version exposure."""
        items = self._get_selected_items()
        if not items:
            return

        self.loading.show_loading("Analyzing versions (%d items)..." % len(items))
        self.analyze_ver_btn.setEnabled(False)

        def do_analyze():
            try:
                data = {"items": [item.to_dict() for item in items]}
                result = server_request(
                    "/analyze/versions", method="POST", data=data,
                    server_url=self.api_config.get_server_url()
                )

                if "error" in result:
                    def show_err():
                        self.loading.show_error(result["error"][:80])
                        self.analyze_ver_btn.setEnabled(True)
                    run_on_edt(show_err)
                    return

                # Use server-parsed JSON if available, fallback to client parsing
                content = result.get("content", "")
                parsed = result.get("parsed")
                findings = self._parse_version_findings(content, parsed=parsed)
                elapsed = result.get("elapsed", 0)

                def update_ui():
                    self.findings_model.add_entries(findings)
                    clear_pane(self.detail_pane)
                    append_to_pane(self.detail_pane, "=== Version Analysis Result ===\n", bold=True)
                    append_to_pane(self.detail_pane, "Items analyzed: %d\n" % len(items))
                    append_to_pane(self.detail_pane, "Time: %.1fs\n" % elapsed)
                    append_to_pane(self.detail_pane, "Findings: %d\n\n" % len(findings))
                    append_to_pane(self.detail_pane, content)
                    self.loading.show_success("Found %d issues (%.1fs)" % (len(findings), elapsed))
                    self.analyze_ver_btn.setEnabled(True)
                run_on_edt(update_ui)

            except Exception as e:
                def show_err():
                    self.loading.show_error("Error: %s" % str(e)[:60])
                    self.analyze_ver_btn.setEnabled(True)
                run_on_edt(show_err)

        t = threading.Thread(target=do_analyze)
        t.setDaemon(True)
        t.start()

    def _on_analyze_weaknesses(self, event=None):
        """Analyze selected items for security weaknesses."""
        items = self._get_selected_items()
        if not items:
            return

        self.loading.show_loading("Analyzing weaknesses (%d items)..." % len(items))
        self.analyze_weak_btn.setEnabled(False)

        def do_analyze():
            try:
                data = {"items": [item.to_dict() for item in items]}
                result = server_request(
                    "/analyze/weaknesses", method="POST", data=data,
                    server_url=self.api_config.get_server_url()
                )

                if "error" in result:
                    def show_err():
                        self.loading.show_error(result["error"][:80])
                        self.analyze_weak_btn.setEnabled(True)
                    run_on_edt(show_err)
                    return

                content = result.get("content", "")
                parsed = result.get("parsed")
                findings = self._parse_weakness_findings(content, parsed=parsed)
                elapsed = result.get("elapsed", 0)

                def update_ui():
                    self.findings_model.add_entries(findings)
                    clear_pane(self.detail_pane)
                    append_to_pane(self.detail_pane, "=== Weakness Analysis Result ===\n", bold=True)
                    append_to_pane(self.detail_pane, "Items analyzed: %d\n" % len(items))
                    append_to_pane(self.detail_pane, "Time: %.1fs\n" % elapsed)
                    append_to_pane(self.detail_pane, "Findings: %d\n\n" % len(findings))
                    append_to_pane(self.detail_pane, content)
                    self.loading.show_success("Found %d issues (%.1fs)" % (len(findings), elapsed))
                    self.analyze_weak_btn.setEnabled(True)
                run_on_edt(update_ui)

            except Exception as e:
                def show_err():
                    self.loading.show_error("Error: %s" % str(e)[:60])
                    self.analyze_weak_btn.setEnabled(True)
                run_on_edt(show_err)

        t = threading.Thread(target=do_analyze)
        t.setDaemon(True)
        t.start()

    def _on_send_to_cve(self, event=None):
        """Send selected items to CVE Analyzer tab."""
        items = self._get_selected_items()
        if not items:
            return
        self._extender.send_to_cve_analyzer(items)

    def _on_send_to_critical(self, event=None):
        """Send selected items to Critical Analyzer tab."""
        items = self._get_selected_items()
        if not items:
            return
        self._extender.send_to_critical_analyzer(items)

    def _on_finding_selected(self, event):
        """Show finding detail when a row is selected."""
        if event.getValueIsAdjusting():
            return
        row = self.findings_table.getSelectedRow()
        if row < 0:
            return
        entry = self.findings_model.get_entry(row)
        if entry:
            clear_pane(self.detail_pane)
            append_to_pane(self.detail_pane, "%s: %s\n" % (entry.finding_type, entry.finding_id), bold=True)
            append_to_pane(self.detail_pane, "Name: %s\n" % entry.name)
            append_to_pane(self.detail_pane, "Severity: %s\n" % entry.severity)
            append_to_pane(self.detail_pane, "\nDescription:\n%s\n" % entry.description)
            if entry.evidence:
                append_to_pane(self.detail_pane, "\nEvidence:\n%s\n" % entry.evidence)
            if entry.remediation:
                append_to_pane(self.detail_pane, "\nRemediation:\n%s\n" % entry.remediation)

    def _clear_findings(self):
        """Clear all findings."""
        self.findings_model.clear()
        clear_pane(self.detail_pane)

    def _parse_version_findings(self, content, parsed=None):
        """Parse version analysis AI response into FindingEntry list.

        Args:
            content: Raw AI response text (fallback).
            parsed: Server-parsed JSON dict (preferred if available).
        """
        findings = []
        try:
            data = parsed if parsed else json.loads(self._extract_json(content) or "{}")
            for f in data.get("findings", []):
                software = f.get("software", "Unknown")
                version = f.get("version", "?")
                source = f.get("source", "")
                for vuln in f.get("vulnerabilities", []):
                    findings.append(FindingEntry(
                        finding_type=vuln.get("id", "").split("-")[0] if "-" in vuln.get("id", "") else "Info",
                        finding_id=vuln.get("id", "N/A"),
                        name="%s %s" % (software, version),
                        severity=vuln.get("severity", "Info"),
                        description=vuln.get("description", ""),
                        source=source,
                    ))
        except Exception:
            # If JSON parsing fails, create a single finding with raw content
            findings.append(FindingEntry(
                finding_type="Info",
                finding_id="RAW",
                name="Version Analysis (raw)",
                severity="Info",
                description=content[:500],
            ))
        return findings

    def _parse_weakness_findings(self, content, parsed=None):
        """Parse weakness analysis AI response into FindingEntry list.

        Args:
            content: Raw AI response text (fallback).
            parsed: Server-parsed JSON dict (preferred if available).
        """
        findings = []
        try:
            data = parsed if parsed else json.loads(self._extract_json(content) or "{}")
            for f in data.get("findings", []):
                findings.append(FindingEntry(
                    finding_type=f.get("type", "CWE"),
                    finding_id=f.get("id", "N/A"),
                    name=f.get("name", "Unknown"),
                    severity=f.get("severity", "Info"),
                    description=f.get("description", ""),
                    evidence=f.get("evidence", ""),
                    remediation=f.get("remediation", ""),
                ))
        except Exception:
            findings.append(FindingEntry(
                finding_type="Info",
                finding_id="RAW",
                name="Weakness Analysis (raw)",
                severity="Info",
                description=content[:500],
            ))
        return findings

    def _extract_json(self, text):
        """Extract JSON object from text that may contain markdown code blocks."""
        # Try direct parse first
        text = text.strip()
        if text.startswith("{"):
            return text

        # Try to find JSON in code blocks
        import re
        patterns = [
            r'```json\s*\n(.*?)\n```',
            r'```\s*\n(\{.*?\})\n```',
            r'(\{[^{}]*"findings"[^{}]*\{.*\}[^{}]*\})',
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                return match.group(1)

        # Last resort: find first { to last }
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return text[start:end + 1]

        return None
