# -*- coding: utf-8 -*-
"""
Table models for AI Security Analyzer Burp Extension.
Jython 2.7 compatible (Python 2.7 syntax).
"""

from javax.swing.table import AbstractTableModel


class ScannerTableModel(AbstractTableModel):
    """Table model for Scanner tab - displays proxy history items."""

    COLUMNS = ["#", "Method", "URL", "Status", "Content-Type", "Length"]

    def __init__(self):
        AbstractTableModel.__init__(self)
        self._items = []  # list of HttpItem

    def getRowCount(self):
        return len(self._items)

    def getColumnCount(self):
        return len(self.COLUMNS)

    def getColumnName(self, col):
        return self.COLUMNS[col]

    def getValueAt(self, row, col):
        if row >= len(self._items):
            return ""
        item = self._items[row]
        if col == 0:
            return item.index
        elif col == 1:
            return item.method
        elif col == 2:
            return item.url
        elif col == 3:
            return item.status_code
        elif col == 4:
            return item.content_type or ""
        elif col == 5:
            return item.length
        return ""

    def getColumnClass(self, col):
        from java.lang import Integer, String
        if col in (0, 3, 5):
            return Integer
        return String

    def isCellEditable(self, row, col):
        return False

    def set_items(self, items):
        """Replace all items and refresh table."""
        self._items = list(items)
        self.fireTableDataChanged()

    def get_item(self, row):
        """Get HttpItem at row index."""
        if 0 <= row < len(self._items):
            return self._items[row]
        return None

    def get_items_at_rows(self, rows):
        """Get HttpItems at multiple row indices."""
        return [self._items[r] for r in rows if 0 <= r < len(self._items)]

    def clear(self):
        """Remove all items."""
        self._items = []
        self.fireTableDataChanged()


class CVETableModel(AbstractTableModel):
    """Table model for CVE Analyzer tab - displays CVE findings."""

    COLUMNS = ["CVE ID", "CVSS", "Severity", "Description", "Affected Versions"]

    def __init__(self):
        AbstractTableModel.__init__(self)
        self._entries = []  # list of CVEEntry

    def getRowCount(self):
        return len(self._entries)

    def getColumnCount(self):
        return len(self.COLUMNS)

    def getColumnName(self, col):
        return self.COLUMNS[col]

    def getValueAt(self, row, col):
        if row >= len(self._entries):
            return ""
        entry = self._entries[row]
        if col == 0:
            return entry.cve_id
        elif col == 1:
            return entry.cvss
        elif col == 2:
            return entry.severity
        elif col == 3:
            return entry.description
        elif col == 4:
            return entry.affected_versions
        return ""

    def isCellEditable(self, row, col):
        return False

    def set_entries(self, entries):
        """Replace all entries."""
        self._entries = list(entries)
        self.fireTableDataChanged()

    def add_entries(self, entries):
        """Add entries to existing list."""
        start = len(self._entries)
        self._entries.extend(entries)
        self.fireTableRowsInserted(start, start + len(entries) - 1)

    def get_entry(self, row):
        """Get CVEEntry at row index."""
        if 0 <= row < len(self._entries):
            return self._entries[row]
        return None

    def clear(self):
        """Remove all entries."""
        self._entries = []
        self.fireTableDataChanged()


class CriticalTableModel(AbstractTableModel):
    """Table model for Critical Analyzer - displays received HTTP items."""

    COLUMNS = ["#", "Method", "URL", "Status"]

    def __init__(self):
        AbstractTableModel.__init__(self)
        self._items = []

    def getRowCount(self):
        return len(self._items)

    def getColumnCount(self):
        return len(self.COLUMNS)

    def getColumnName(self, col):
        return self.COLUMNS[col]

    def getValueAt(self, row, col):
        if row >= len(self._items):
            return ""
        item = self._items[row]
        if col == 0:
            return item.index
        elif col == 1:
            return item.method
        elif col == 2:
            return item.url
        elif col == 3:
            return item.status_code
        return ""

    def isCellEditable(self, row, col):
        return False

    def set_items(self, items):
        self._items = list(items)
        self.fireTableDataChanged()

    def add_items(self, items):
        start = len(self._items)
        self._items.extend(items)
        if items:
            self.fireTableRowsInserted(start, start + len(items) - 1)

    def get_items(self):
        return list(self._items)

    def clear(self):
        self._items = []
        self.fireTableDataChanged()


class FindingsTableModel(AbstractTableModel):
    """Table model for displaying security findings (version/weakness analysis)."""

    COLUMNS = ["Type", "ID", "Name", "Severity", "Description"]

    def __init__(self):
        AbstractTableModel.__init__(self)
        self._entries = []  # list of FindingEntry

    def getRowCount(self):
        return len(self._entries)

    def getColumnCount(self):
        return len(self.COLUMNS)

    def getColumnName(self, col):
        return self.COLUMNS[col]

    def getValueAt(self, row, col):
        if row >= len(self._entries):
            return ""
        entry = self._entries[row]
        if col == 0:
            return entry.finding_type
        elif col == 1:
            return entry.finding_id
        elif col == 2:
            return entry.name
        elif col == 3:
            return entry.severity
        elif col == 4:
            return entry.description
        return ""

    def isCellEditable(self, row, col):
        return False

    def set_entries(self, entries):
        self._entries = list(entries)
        self.fireTableDataChanged()

    def add_entries(self, entries):
        start = len(self._entries)
        self._entries.extend(entries)
        if entries:
            self.fireTableRowsInserted(start, start + len(entries) - 1)

    def get_entry(self, row):
        if 0 <= row < len(self._entries):
            return self._entries[row]
        return None

    def clear(self):
        self._entries = []
        self.fireTableDataChanged()
