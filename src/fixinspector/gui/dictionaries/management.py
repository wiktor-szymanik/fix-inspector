"""One dictionary-management surface over MainWindow's existing load pathway."""
from pathlib import Path
from PySide6.QtWidgets import QFileDialog, QGridLayout, QGroupBox, QLabel, QPushButton


class DictionaryManagement(QGroupBox):
    def __init__(self, window):
        super().__init__("FIX dictionaries")
        self.window = window
        layout = QGridLayout(self)
        self.states = []
        for row, (title, control) in enumerate((("Transport dictionary", window.transport_dict),
                                               ("Application dictionary", window.app_dict))):
            state = QLabel()
            self.states.append(state)
            replace = QPushButton("Load / Replace…")
            remove = QPushButton("Remove")
            replace.clicked.connect(lambda _checked=False, current=control: self.choose(current))
            remove.clicked.connect(lambda _checked=False, current=control: self.remove(current))
            layout.addWidget(QLabel(title), row, 0)
            layout.addWidget(control, row, 1)
            layout.addWidget(state, row, 2)
            layout.addWidget(replace, row, 3)
            layout.addWidget(remove, row, 4)
            control.textChanged.connect(self.refresh)
        load = QPushButton("Load dictionaries")
        load.clicked.connect(self.load)
        layout.addWidget(load, 2, 3, 1, 2)
        layout.addWidget(window.dictionary_state, 2, 0, 1, 3)
        if not hasattr(window, "_loaded_dictionary_paths"):
            window._loaded_dictionary_paths = self.paths() if window.dictionary.fields_by_tag else ("", "")
        self.refresh()

    def paths(self):
        return tuple(control.text().strip() for control in (self.window.transport_dict, self.window.app_dict))

    def refresh(self, *_):
        loaded = getattr(self.window, "_loaded_dictionary_paths", ("", ""))
        for index, (state, path) in enumerate(zip(self.states, self.paths())):
            state.setText("Loaded" if path and path == loaded[index] else "Not loaded")
            state.setToolTip(Path(path).name if path else "Optional metadata - forwarding works without dictionaries")

    def load(self):
        self.window._load_dictionaries()
        self.refresh()

    def choose(self, control):
        path, _ = QFileDialog.getOpenFileName(self, "Load / replace FIX dictionary", control.text(), "FIX dictionaries (*.xml);;All files (*)")
        if path:
            control.setText(path)
            self.load()

    def remove(self, control):
        previous = control.text()
        control.clear()
        if not self.window._load_dictionaries():
            control.setText(previous)
        self.refresh()
