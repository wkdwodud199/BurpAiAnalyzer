# -*- coding: utf-8 -*-
"""
CVE Analyzer Panel for AI Security Analyzer Burp Extension.
Analyzes HTTP items for CVEs, generates PoC code, checks responses.
Jython 2.7 compatible.
"""

from javax.swing import (
    JPanel, JButton, JTable, JScrollPane, JSplitPane,
    JTextPane, JTextArea, JLabel, JOptionPane, BorderFactory,
    ListSelectionModel, BoxLayout, Box
)
from java.awt import BorderLayout, FlowLayout, Color, Font, Dimension
import json
import threading

from models import HttpItem, CVEEntry
from ui_components import (
    APIConfigPanel, LoadingIndicator, run_on_edt,
    append_to_pane, clear_pane, server_request
)
from table_models import CVETableModel


class CVEAnalyzerPanel(JPanel):
    """CVE Analyzer tab panel."""

    def __init__(self, callbacks, extender):
        JPanel.__init__(self)
        self._callbacks = callbacks
        self._extender = extender
        self._received_items = []
        self._session_id = None
        self._current_poc = ""
        self._current_cve_info = ""

        self.setLayout(BorderLayout())
        self._build_ui()

    def _build_ui(self):
        """Build the CVE Analyzer UI."""
        # ── Top: Config + Info ──
        top_panel = JPanel()
        top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))

        self.api_config = APIConfigPanel("cve", self._callbacks)
        self.api_config.setMaximumSize(Dimension(99999, 58))
        top_panel.add(self.api_config)

        # Items info + buttons
        info_panel = JPanel(FlowLayout(FlowLayout.LEFT, 5, 5))
        self.items_label = JLabel("No items received. Use 'Send to CVE Analyzer' from Scanner tab.")
        self.items_label.setFont(Font("SansSerif", Font.BOLD, 12))
        info_panel.add(self.items_label)

        info_panel.add(Box.createHorizontalStrut(15))

        self.analyze_btn = JButton("Analyze CVEs", actionPerformed=self._on_analyze)
        self.analyze_btn.setEnabled(False)
        info_panel.add(self.analyze_btn)

        self.clear_btn = JButton("Clear", actionPerformed=self._on_clear)
        info_panel.add(self.clear_btn)

        self.loading = LoadingIndicator()
        info_panel.add(self.loading)

        info_panel.setMaximumSize(Dimension(99999, 45))
        top_panel.add(info_panel)

        self.add(top_panel, BorderLayout.NORTH)

        # ── Center: Main vertical split ──
        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        main_split.setResizeWeight(0.4)

        # Upper: CVE table
        table_panel = JPanel(BorderLayout())
        table_panel.setBorder(BorderFactory.createTitledBorder("CVE Findings"))
        self.cve_model = CVETableModel()
        self.cve_table = JTable(self.cve_model)
        self.cve_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.cve_table.getSelectionModel().addListSelectionListener(
            lambda e: self._on_cve_selected(e)
        )

        # Column widths
        col_model = self.cve_table.getColumnModel()
        col_model.getColumn(0).setPreferredWidth(120)  # CVE ID
        col_model.getColumn(1).setPreferredWidth(50)   # CVSS
        col_model.getColumn(2).setPreferredWidth(70)   # Severity
        col_model.getColumn(3).setPreferredWidth(350)  # Description
        col_model.getColumn(4).setPreferredWidth(100)  # Affected

        table_panel.add(JScrollPane(self.cve_table), BorderLayout.CENTER)
        main_split.setTopComponent(table_panel)

        # Lower: Horizontal split (PoC code + Response Checker)
        lower_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        lower_split.setResizeWeight(0.5)

        # Left: PoC Code viewer
        poc_panel = JPanel(BorderLayout())
        poc_panel.setBorder(BorderFactory.createTitledBorder("PoC Code"))

        self.poc_pane = JTextPane()
        self.poc_pane.setEditable(False)
        self.poc_pane.setFont(Font("Monospaced", Font.PLAIN, 12))
        poc_panel.add(JScrollPane(self.poc_pane), BorderLayout.CENTER)

        poc_btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.copy_poc_btn = JButton("Copy PoC", actionPerformed=self._on_copy_poc)
        poc_btn_panel.add(self.copy_poc_btn)
        poc_panel.add(poc_btn_panel, BorderLayout.SOUTH)

        lower_split.setLeftComponent(poc_panel)

        # Right: Response Checker
        checker_panel = JPanel(BorderLayout())
        checker_panel.setBorder(BorderFactory.createTitledBorder("Response Checker"))

        # Input area
        input_panel = JPanel(BorderLayout())
        input_label = JLabel("  Paste PoC execution output below:")
        input_label.setFont(Font("SansSerif", Font.PLAIN, 11))
        input_panel.add(input_label, BorderLayout.NORTH)

        self.response_input = JTextArea(8, 40)
        self.response_input.setFont(Font("Monospaced", Font.PLAIN, 11))
        self.response_input.setLineWrap(True)
        input_panel.add(JScrollPane(self.response_input), BorderLayout.CENTER)

        check_btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.check_btn = JButton("Check Response", actionPerformed=self._on_check_response)
        self.check_btn.setEnabled(False)
        check_btn_panel.add(self.check_btn)
        self.check_loading = LoadingIndicator()
        check_btn_panel.add(self.check_loading)
        input_panel.add(check_btn_panel, BorderLayout.SOUTH)

        # Result area
        result_panel = JPanel(BorderLayout())
        result_label = JLabel("  Analysis Result:")
        result_label.setFont(Font("SansSerif", Font.PLAIN, 11))
        result_panel.add(result_label, BorderLayout.NORTH)

        self.check_result_pane = JTextPane()
        self.check_result_pane.setEditable(False)
        self.check_result_pane.setFont(Font("Monospaced", Font.PLAIN, 11))
        result_panel.add(JScrollPane(self.check_result_pane), BorderLayout.CENTER)

        checker_inner = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        checker_inner.setResizeWeight(0.5)
        checker_inner.setTopComponent(input_panel)
        checker_inner.setBottomComponent(result_panel)

        checker_panel.add(checker_inner, BorderLayout.CENTER)
        lower_split.setRightComponent(checker_panel)

        main_split.setBottomComponent(lower_split)
        self.add(main_split, BorderLayout.CENTER)

    def receive_items(self, items):
        """Receive HTTP items from Scanner or context menu."""
        self._received_items = list(items)
        self._session_id = None

        def update():
            self.items_label.setText("%d items received for CVE analysis" % len(items))
            self.analyze_btn.setEnabled(True)
            self.cve_model.clear()
            clear_pane(self.poc_pane)
            clear_pane(self.check_result_pane)
            self.response_input.setText("")
        run_on_edt(update)

    def _on_analyze(self, event=None):
        """Run CVE analysis on received items."""
        if not self._received_items:
            JOptionPane.showMessageDialog(self, "No items to analyze.")
            return

        self.loading.show_loading("Analyzing CVEs...")
        self.analyze_btn.setEnabled(False)

        def do_analyze():
            try:
                data = {
                    "items": [item.to_dict() for item in self._received_items],
                }
                if self._session_id:
                    data["session_id"] = self._session_id

                result = server_request(
                    "/analyze/cve", method="POST", data=data,
                    server_url=self.api_config.get_server_url()
                )

                if "error" in result:
                    def show_err():
                        self.loading.show_error(result["error"][:80])
                        self.analyze_btn.setEnabled(True)
                    run_on_edt(show_err)
                    return

                self._session_id = result.get("session_id")
                content = result.get("content", "")
                elapsed = result.get("elapsed", 0)
                parsed = result.get("parsed")
                cve_entries = self._parse_cve_response(content, parsed=parsed)

                def update_ui():
                    self.cve_model.set_entries(cve_entries)
                    self.check_btn.setEnabled(len(cve_entries) > 0)
                    self.loading.show_success("Found %d CVEs (%.1fs)" % (len(cve_entries), elapsed))
                    self.analyze_btn.setEnabled(True)

                    # Show raw response in PoC pane if no CVEs parsed
                    if not cve_entries:
                        clear_pane(self.poc_pane)
                        append_to_pane(self.poc_pane, "=== Raw AI Response ===\n\n", bold=True)
                        append_to_pane(self.poc_pane, content)
                run_on_edt(update_ui)

            except Exception as e:
                def show_err():
                    self.loading.show_error("Error: %s" % str(e)[:60])
                    self.analyze_btn.setEnabled(True)
                run_on_edt(show_err)

        t = threading.Thread(target=do_analyze)
        t.setDaemon(True)
        t.start()

    def _on_cve_selected(self, event):
        """Show PoC code when a CVE is selected."""
        if event.getValueIsAdjusting():
            return
        row = self.cve_table.getSelectedRow()
        if row < 0:
            return
        entry = self.cve_model.get_entry(row)
        if entry:
            self._current_poc = entry.poc_code or ""
            self._current_cve_info = "%s - %s (CVSS: %s)\n%s" % (
                entry.cve_id, entry.severity, entry.cvss, entry.description
            )

            clear_pane(self.poc_pane)
            append_to_pane(self.poc_pane, "# %s\n" % entry.cve_id, bold=True, color=Color(0, 102, 204))
            append_to_pane(self.poc_pane, "# Severity: %s | CVSS: %s\n" % (entry.severity, entry.cvss))
            append_to_pane(self.poc_pane, "# %s\n\n" % entry.description)

            if entry.poc_code:
                append_to_pane(self.poc_pane, entry.poc_code)
            else:
                append_to_pane(self.poc_pane, "# No PoC code generated for this CVE", color=Color.GRAY)

            if entry.poc_usage:
                append_to_pane(self.poc_pane, "\n\n# Usage:\n# %s" % entry.poc_usage, color=Color(0, 128, 0))

            self.check_btn.setEnabled(True)

    def _on_copy_poc(self, event=None):
        """Copy PoC code to clipboard."""
        if self._current_poc:
            from java.awt import Toolkit
            from java.awt.datatransfer import StringSelection
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(StringSelection(self._current_poc), None)
            self.loading.show_success("PoC copied to clipboard")
        else:
            self.loading.show_error("No PoC code to copy")

    def _on_check_response(self, event=None):
        """Check PoC execution output with AI."""
        execution_output = self.response_input.getText().strip()
        if not execution_output:
            JOptionPane.showMessageDialog(self, "Please paste the PoC execution output first.")
            return

        self.check_loading.show_loading("Checking response...")
        self.check_btn.setEnabled(False)

        def do_check():
            try:
                data = {
                    "cve_info": self._current_cve_info,
                    "poc_code": self._current_poc,
                    "execution_output": execution_output,
                }
                if self._session_id:
                    data["session_id"] = self._session_id

                result = server_request(
                    "/analyze/response-check", method="POST", data=data,
                    server_url=self.api_config.get_server_url()
                )

                if "error" in result:
                    def show_err():
                        self.check_loading.show_error(result["error"][:60])
                        self.check_btn.setEnabled(True)
                    run_on_edt(show_err)
                    return

                content = result.get("content", "")
                elapsed = result.get("elapsed", 0)
                parsed = result.get("parsed")

                def update_ui():
                    clear_pane(self.check_result_pane)

                    # Use server-parsed JSON if available, fallback to client parsing
                    check_data = parsed if parsed else self._parse_check_response(content)
                    if check_data:
                        confirmed = check_data.get("confirmed", False)
                        confidence = check_data.get("confidence", "Unknown")

                        if confirmed:
                            append_to_pane(self.check_result_pane,
                                "VULNERABILITY CONFIRMED\n", bold=True, color=Color(204, 0, 0))
                        else:
                            append_to_pane(self.check_result_pane,
                                "NOT CONFIRMED\n", bold=True, color=Color(0, 128, 0))

                        append_to_pane(self.check_result_pane,
                            "Confidence: %s\n\n" % confidence, bold=True)
                        append_to_pane(self.check_result_pane,
                            check_data.get("analysis", ""))

                        # If modified PoC provided, show it
                        modified = check_data.get("modified_poc")
                        if modified:
                            append_to_pane(self.check_result_pane,
                                "\n\n=== Modified PoC ===\n", bold=True, color=Color(0, 102, 204))
                            append_to_pane(self.check_result_pane, modified)
                            # Also update the PoC pane
                            self._current_poc = modified
                            clear_pane(self.poc_pane)
                            append_to_pane(self.poc_pane, "# MODIFIED PoC\n\n",
                                bold=True, color=Color(255, 102, 0))
                            append_to_pane(self.poc_pane, modified)

                        if check_data.get("recommendations"):
                            append_to_pane(self.check_result_pane,
                                "\n\nRecommendations:\n%s" % check_data["recommendations"])
                    else:
                        append_to_pane(self.check_result_pane, content)

                    self.check_loading.show_success("Check complete (%.1fs)" % elapsed)
                    self.check_btn.setEnabled(True)
                run_on_edt(update_ui)

            except Exception as e:
                def show_err():
                    self.check_loading.show_error("Error: %s" % str(e)[:60])
                    self.check_btn.setEnabled(True)
                run_on_edt(show_err)

        t = threading.Thread(target=do_check)
        t.setDaemon(True)
        t.start()

    def _on_clear(self, event=None):
        """Clear all data."""
        self._received_items = []
        self._session_id = None
        self._current_poc = ""
        self._current_cve_info = ""
        self.cve_model.clear()
        clear_pane(self.poc_pane)
        clear_pane(self.check_result_pane)
        self.response_input.setText("")
        self.items_label.setText("No items received. Use 'Send to CVE Analyzer' from Scanner tab.")
        self.analyze_btn.setEnabled(False)
        self.check_btn.setEnabled(False)
        self.loading.hide()
        self.check_loading.hide()

    def _parse_cve_response(self, content, parsed=None):
        """Parse CVE analysis response into CVEEntry list.

        Args:
            content: Raw AI response text (fallback).
            parsed: Server-parsed JSON dict (preferred if available).
        """
        entries = []
        try:
            data = parsed if parsed else json.loads(self._extract_json(content) or "{}")
            for cve in data.get("cves", []):
                entries.append(CVEEntry(
                    cve_id=cve.get("id", "N/A"),
                    cvss=cve.get("cvss", "N/A"),
                    severity=cve.get("severity", "Unknown"),
                    description=cve.get("description", ""),
                    affected_versions=cve.get("affected_versions", ""),
                    poc_code=cve.get("poc_code", ""),
                    poc_usage=cve.get("poc_usage", ""),
                ))
        except Exception:
            pass
        return entries

    def _parse_check_response(self, content):
        """Parse response check result."""
        try:
            json_str = self._extract_json(content)
            if json_str:
                return json.loads(json_str)
        except Exception:
            pass
        return None

    def _extract_json(self, text):
        """Extract JSON from text (may have markdown code blocks)."""
        text = text.strip()
        if text.startswith("{"):
            return text

        import re
        patterns = [
            r'```json\s*\n(.*?)\n```',
            r'```\s*\n(\{.*?\})\n```',
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                return match.group(1)

        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return text[start:end + 1]
        return None
