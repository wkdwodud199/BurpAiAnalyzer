# -*- coding: utf-8 -*-
"""
Critical Analyzer Panel for AI Security Analyzer Burp Extension.
Performs deep, recursive vulnerability analysis with AI.
Jython 2.7 compatible.
"""

from javax.swing import (
    JPanel, JButton, JTable, JScrollPane, JSplitPane,
    JTextPane, JTextArea, JTextField, JLabel, JComboBox,
    JOptionPane, BorderFactory, ListSelectionModel,
    BoxLayout, Box
)
from java.awt import BorderLayout, FlowLayout, Color, Font, Dimension
import json
import threading
import time

from models import HttpItem, ChatMessage
from ui_components import (
    APIConfigPanel, LoadingIndicator, run_on_edt,
    append_to_pane, clear_pane, server_request, SEVERITY_COLORS
)
from table_models import CriticalTableModel


# Fallback list used only if server is unreachable during init
_FALLBACK_VULN_TYPES = [
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Command Injection",
    "Path Traversal",
    "Server-Side Request Forgery (SSRF)",
    "XML External Entity (XXE)",
    "Insecure Deserialization",
    "Authentication Bypass",
    "Broken Access Control",
    "Security Misconfiguration",
]


def _fetch_vulnerability_types(server_url="http://127.0.0.1:8089"):
    """Fetch vulnerability types from server. Falls back to hardcoded list."""
    try:
        result = server_request("/vulnerability-types", server_url=server_url)
        types = result.get("types", [])
        if types:
            return types
    except Exception:
        pass
    return list(_FALLBACK_VULN_TYPES)


class CriticalAnalyzerPanel(JPanel):
    """Critical Analyzer tab panel."""

    def __init__(self, callbacks, extender):
        JPanel.__init__(self)
        self._callbacks = callbacks
        self._extender = extender
        self._received_items = []
        self._session_id = None
        self._chat_session_id = None
        self._analysis_thread = None
        self._stop_flag = False
        self._chat_messages = []

        self.setLayout(BorderLayout())
        self._build_ui()

    def _build_ui(self):
        """Build the Critical Analyzer UI."""
        # ── Top: Config + Controls ──
        top_panel = JPanel()
        top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))

        self.api_config = APIConfigPanel("critical", self._callbacks)
        self.api_config.setMaximumSize(Dimension(99999, 58))
        top_panel.add(self.api_config)

        # Control bar
        control_panel = JPanel(FlowLayout(FlowLayout.LEFT, 5, 5))

        self.items_label = JLabel("No items received")
        self.items_label.setFont(Font("SansSerif", Font.BOLD, 12))
        control_panel.add(self.items_label)

        control_panel.add(Box.createHorizontalStrut(10))

        control_panel.add(JLabel("Vulnerability Type:"))
        self.vuln_combo = JComboBox(_fetch_vulnerability_types())
        self.vuln_combo.setPreferredSize(Dimension(250, 25))
        control_panel.add(self.vuln_combo)

        control_panel.add(Box.createHorizontalStrut(10))

        self.start_btn = JButton("Start Analysis", actionPerformed=self._on_start)
        self.start_btn.setEnabled(False)
        control_panel.add(self.start_btn)

        self.stop_btn = JButton("Stop", actionPerformed=self._on_stop)
        self.stop_btn.setEnabled(False)
        control_panel.add(self.stop_btn)

        self.clear_btn = JButton("Clear", actionPerformed=self._on_clear)
        control_panel.add(self.clear_btn)

        self.loading = LoadingIndicator()
        control_panel.add(self.loading)

        control_panel.setMaximumSize(Dimension(99999, 45))
        top_panel.add(control_panel)

        self.add(top_panel, BorderLayout.NORTH)

        # ── Center: Main horizontal split (Work Log + Chat) ──
        main_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        main_split.setResizeWeight(0.6)

        # Left: Work Log
        log_panel = JPanel(BorderLayout())
        log_panel.setBorder(BorderFactory.createTitledBorder("Work Log"))

        self.log_pane = JTextPane()
        self.log_pane.setEditable(False)
        self.log_pane.setFont(Font("Monospaced", Font.PLAIN, 11))
        log_panel.add(JScrollPane(self.log_pane), BorderLayout.CENTER)

        # PoC display at bottom of log
        poc_panel = JPanel(BorderLayout())
        poc_panel.setBorder(BorderFactory.createTitledBorder("Current PoC"))
        self.poc_pane = JTextPane()
        self.poc_pane.setEditable(False)
        self.poc_pane.setFont(Font("Monospaced", Font.PLAIN, 11))
        poc_scroll = JScrollPane(self.poc_pane)
        poc_scroll.setPreferredSize(Dimension(0, 200))
        poc_panel.add(poc_scroll, BorderLayout.CENTER)

        poc_btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.copy_poc_btn = JButton("Copy PoC", actionPerformed=self._on_copy_poc)
        poc_btn_panel.add(self.copy_poc_btn)
        poc_panel.add(poc_btn_panel, BorderLayout.SOUTH)

        log_split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        log_split.setResizeWeight(0.6)
        log_split.setTopComponent(log_panel)
        log_split.setBottomComponent(poc_panel)

        main_split.setLeftComponent(log_split)

        # Right: Chat interface
        chat_panel = JPanel(BorderLayout())
        chat_panel.setBorder(BorderFactory.createTitledBorder("Communication"))

        # Chat display
        self.chat_pane = JTextPane()
        self.chat_pane.setEditable(False)
        self.chat_pane.setFont(Font("Monospaced", Font.PLAIN, 11))
        chat_panel.add(JScrollPane(self.chat_pane), BorderLayout.CENTER)

        # Chat input
        input_panel = JPanel(BorderLayout())
        input_panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))

        self.chat_input = JTextField()
        self.chat_input.setFont(Font("SansSerif", Font.PLAIN, 12))
        self.chat_input.addActionListener(lambda e: self._on_send_chat())
        input_panel.add(self.chat_input, BorderLayout.CENTER)

        self.send_btn = JButton("Send", actionPerformed=lambda e: self._on_send_chat())
        input_panel.add(self.send_btn, BorderLayout.EAST)

        chat_panel.add(input_panel, BorderLayout.SOUTH)

        main_split.setRightComponent(chat_panel)

        self.add(main_split, BorderLayout.CENTER)

    def receive_items(self, items):
        """Receive HTTP items from Scanner or context menu."""
        self._received_items = list(items)
        self._session_id = None
        self._chat_session_id = None

        def update():
            self.items_label.setText("%d items received for critical analysis" % len(items))
            self.start_btn.setEnabled(True)
        run_on_edt(update)

    def _on_start(self, event=None):
        """Start recursive critical analysis."""
        if not self._received_items:
            JOptionPane.showMessageDialog(self, "No items to analyze.")
            return

        self._stop_flag = False
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.vuln_combo.setEnabled(False)
        self.loading.show_loading("Analysis in progress...")

        vuln_type = str(self.vuln_combo.getSelectedItem())

        def log_entry(text, color=None, bold=False):
            """Add timestamped entry to work log."""
            timestamp = time.strftime("%H:%M:%S")
            def update():
                append_to_pane(self.log_pane, "[%s] " % timestamp, color=Color.GRAY, size=10)
                append_to_pane(self.log_pane, text + "\n", color=color, bold=bold)
            run_on_edt(update)

        def update_poc(code):
            """Update the PoC display."""
            def update():
                clear_pane(self.poc_pane)
                append_to_pane(self.poc_pane, code)
            run_on_edt(update)

        def do_analysis():
            try:
                log_entry("Starting %s analysis..." % vuln_type, bold=True, color=Color(0, 102, 204))
                log_entry("Analyzing %d HTTP items" % len(self._received_items))

                # Initial analysis
                data = {
                    "items": [item.to_dict() for item in self._received_items],
                    "vuln_type": vuln_type,
                }

                result = server_request(
                    "/analyze/critical/start", method="POST", data=data,
                    server_url=self.api_config.get_server_url()
                )

                if "error" in result:
                    log_entry("ERROR: %s" % result["error"], color=Color.RED, bold=True)
                    self._finish_analysis()
                    return

                self._session_id = result.get("session_id")
                self._chat_session_id = self._session_id  # Share session for chat context
                content = result.get("content", "")
                elapsed = result.get("elapsed", 0)
                server_parsed = result.get("parsed")

                log_entry("Initial analysis complete (%.1fs)" % elapsed, color=Color(0, 128, 0))

                # Process the response
                iteration = 0
                max_iterations = 10

                while not self._stop_flag and iteration < max_iterations:
                    iteration += 1

                    # Use server-parsed JSON if available, fallback to client parsing
                    parsed = server_parsed if server_parsed else self._parse_critical_response(content)
                    stage = parsed.get("stage", "unknown")
                    findings = parsed.get("findings", "")
                    poc_code = parsed.get("poc_code", "")
                    status = parsed.get("status", "")

                    log_entry("--- Iteration %d (stage: %s) ---" % (iteration, stage), bold=True)

                    if findings:
                        log_entry("Findings: %s" % findings[:300])

                    if poc_code:
                        log_entry("PoC code generated (%d chars)" % len(poc_code), color=Color(0, 102, 204))
                        update_poc(poc_code)

                    # Show input points if present
                    input_points = parsed.get("input_points", [])
                    if input_points:
                        visible = [p for p in input_points if p.get("source") == "visible"]
                        inferred = [p for p in input_points if p.get("source") == "inferred"]
                        if visible:
                            log_entry("Visible params: %s" % ", ".join(p.get("name", "?") for p in visible),
                                     color=Color(0, 102, 204))
                        if inferred:
                            log_entry("Inferred params: %s" % ", ".join(p.get("name", "?") for p in inferred),
                                     color=Color(180, 100, 0))

                    # Check if analysis is complete (only allow after phase 3+)
                    if iteration >= 4 and ("ANALYSIS_COMPLETE" in status or "ANALYSIS_COMPLETE" in content):
                        conclusion = parsed.get("conclusion", "Analysis completed")
                        log_entry("ANALYSIS COMPLETE", bold=True, color=Color(0, 128, 0))
                        log_entry("Conclusion: %s" % conclusion)
                        break

                    next_steps = parsed.get("next_steps", "")
                    if next_steps:
                        log_entry("Next steps: %s" % next_steps[:200])

                    if self._stop_flag:
                        log_entry("Analysis stopped by user", color=Color(255, 102, 0))
                        break

                    log_entry("Continuing analysis...", color=Color.GRAY)

                    # Server handles follow-up generation (centralized prompt logic)
                    cont_result = server_request(
                        "/analyze/critical/continue",
                        method="POST",
                        data={
                            "session_id": self._session_id,
                            "iteration": iteration,
                            "poc_code": poc_code if poc_code else "",
                        },
                        server_url=self.api_config.get_server_url()
                    )

                    if "error" in cont_result:
                        log_entry("ERROR: %s" % cont_result["error"], color=Color.RED)
                        break

                    content = cont_result.get("content", "")
                    server_parsed = cont_result.get("parsed")
                    elapsed = cont_result.get("elapsed", 0)
                    log_entry("Response received (%.1fs)" % elapsed)

                    # Show phase violation if server detected premature completion
                    if cont_result.get("phase_violation"):
                        log_entry("Phase violation: %s" % cont_result["phase_violation"],
                                 color=Color(255, 102, 0))

                    if cont_result.get("is_complete") and iteration >= 4:
                        log_entry("ANALYSIS COMPLETE (signaled by AI)", bold=True, color=Color(0, 128, 0))
                        # Parse final response for conclusion
                        final = self._parse_critical_response(content)
                        if final.get("conclusion"):
                            log_entry("Conclusion: %s" % final["conclusion"])
                        if final.get("poc_code"):
                            update_poc(final["poc_code"])
                        break

                if iteration >= max_iterations and not self._stop_flag:
                    log_entry("Max iterations reached (%d)" % max_iterations,
                             color=Color(255, 102, 0), bold=True)

                log_entry("Analysis session ended", bold=True)

            except Exception as e:
                log_entry("EXCEPTION: %s" % str(e), color=Color.RED, bold=True)
            finally:
                self._finish_analysis()

        self._analysis_thread = threading.Thread(target=do_analysis)
        self._analysis_thread.setDaemon(True)
        self._analysis_thread.start()

    def _on_stop(self, event=None):
        """Stop the running analysis."""
        self._stop_flag = True
        self.loading.show_loading("Stopping...")

    def _finish_analysis(self):
        """Clean up after analysis completes."""
        def update():
            self.start_btn.setEnabled(bool(self._received_items))
            self.stop_btn.setEnabled(False)
            self.vuln_combo.setEnabled(True)
            self.loading.show_success("Analysis finished")
        run_on_edt(update)

    def _on_send_chat(self):
        """Send a chat message to AI."""
        message = self.chat_input.getText().strip()
        if not message:
            return

        self.chat_input.setText("")

        # Show user message
        timestamp = time.strftime("%H:%M:%S")
        def show_user_msg():
            append_to_pane(self.chat_pane, "[%s] " % timestamp, color=Color.GRAY, size=10)
            append_to_pane(self.chat_pane, "You: ", bold=True, color=Color(0, 102, 204))
            append_to_pane(self.chat_pane, message + "\n\n")
        run_on_edt(show_user_msg)

        self.send_btn.setEnabled(False)

        def do_chat():
            try:
                session = self._chat_session_id or self._session_id
                data = {"message": message}
                if session:
                    data["session_id"] = session

                result = server_request(
                    "/analyze/critical/chat", method="POST", data=data,
                    server_url=self.api_config.get_server_url()
                )

                if not self._chat_session_id:
                    self._chat_session_id = result.get("session_id")

                if "error" in result:
                    def show_err():
                        append_to_pane(self.chat_pane, "Error: %s\n\n" % result["error"],
                                      color=Color.RED)
                        self.send_btn.setEnabled(True)
                    run_on_edt(show_err)
                    return

                content = result.get("content", "")
                display_content = self._unescape_for_display(content)
                elapsed = result.get("elapsed", 0)
                ts = time.strftime("%H:%M:%S")

                def show_response():
                    append_to_pane(self.chat_pane, "[%s] " % ts, color=Color.GRAY, size=10)
                    append_to_pane(self.chat_pane, "AI: ", bold=True, color=Color(0, 128, 0))
                    append_to_pane(self.chat_pane, display_content + "\n")
                    append_to_pane(self.chat_pane, "(%.1fs)\n\n" % elapsed, color=Color.GRAY, size=10)
                    self.send_btn.setEnabled(True)
                run_on_edt(show_response)

            except Exception as e:
                def show_err():
                    append_to_pane(self.chat_pane, "Error: %s\n\n" % str(e), color=Color.RED)
                    self.send_btn.setEnabled(True)
                run_on_edt(show_err)

        t = threading.Thread(target=do_chat)
        t.setDaemon(True)
        t.start()

    def _on_copy_poc(self, event=None):
        """Copy current PoC to clipboard."""
        doc = self.poc_pane.getStyledDocument()
        text = doc.getText(0, doc.getLength())
        if text.strip():
            from java.awt import Toolkit
            from java.awt.datatransfer import StringSelection
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(StringSelection(text), None)
            self.loading.show_success("PoC copied to clipboard")

    def _on_clear(self, event=None):
        """Clear all state."""
        self._stop_flag = True
        self._received_items = []
        self._session_id = None
        self._chat_session_id = None
        self._chat_messages = []

        def update():
            clear_pane(self.log_pane)
            clear_pane(self.poc_pane)
            clear_pane(self.chat_pane)
            self.chat_input.setText("")
            self.items_label.setText("No items received")
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(False)
            self.vuln_combo.setEnabled(True)
            self.loading.hide()
        run_on_edt(update)

    @staticmethod
    def _unescape_for_display(text):
        """Unescape JSON escape sequences for readable display.

        When AI includes JSON blocks in responses, string values contain
        literal \\n, \\t, \\\" which should render as actual newlines/tabs/quotes.
        """
        if not text:
            return text
        text = text.replace('\\n', '\n')
        text = text.replace('\\t', '\t')
        text = text.replace('\\"', '"')
        return text

    def _parse_critical_response(self, content):
        """Parse critical analysis response."""
        try:
            json_str = self._extract_json(content)
            if json_str:
                return json.loads(json_str)
        except Exception:
            pass
        # Return basic structure from raw content
        return {
            "stage": "unknown",
            "findings": content[:500] if content else "",
            "poc_code": "",
            "status": "ANALYSIS_COMPLETE" if "ANALYSIS_COMPLETE" in (content or "") else "CONTINUE",
        }

    def _extract_json(self, text):
        """Extract JSON from text."""
        if not text:
            return None
        text = text.strip()
        if text.startswith("{"):
            # Find matching closing brace
            depth = 0
            for i, c in enumerate(text):
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        return text[:i + 1]
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
