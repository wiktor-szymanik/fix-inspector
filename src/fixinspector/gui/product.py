"""Final desktop affordances. No session/transport objects are created here."""
from PySide6.QtCore import Qt
from PySide6.QtGui import QKeySequence, QShortcut

from .dictionaries.management import DictionaryManagement


class ProductPresentation:
    def __init__(self, window):
        self.window = window
        old_box = window.transport_dict.parentWidget()
        self.dictionaries = DictionaryManagement(window)
        old_box.hide()
        window.dictionary_browser.layout().insertWidget(0, self.dictionaries)
        self.shortcuts = []
        for sequence, callback in (("Ctrl+F", self.search), ("Ctrl+R", self.send_repeater)):
            shortcut = QShortcut(QKeySequence(sequence), window)
            shortcut.setContext(Qt.ShortcutContext.WindowShortcut)
            shortcut.activated.connect(callback)
            self.shortcuts.append(shortcut)

    def search(self):
        w = self.window
        route = w.workspace_tabs.tabText(w.workspace_tabs.currentIndex())
        target = w.composer_panel.search if route == "Composer" else w.dictionary_browser.search if route == "Dictionaries" else None
        if route == "Proxy":
            w._navigate("History")
            target = w.proxy_workspace.filters.search
        if target is not None:
            target.setFocus()
            target.selectAll()

    def send_repeater(self):
        w = self.window
        if w.workspace_tabs.tabText(w.workspace_tabs.currentIndex()) == "Sender":
            editor = w.repeater_panel.tabs.currentWidget()
            if hasattr(editor, "queue_button") and editor.queue_button.isEnabled():
                editor.queue_button.click()
