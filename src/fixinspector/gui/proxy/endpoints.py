"""Compact endpoint settings; transport choice does not interpret FIX payloads."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QGridLayout,
    QGroupBox,
    QLabel,
    QLineEdit,
    QPushButton,
)


class ProxyEndpointsPanel(QGroupBox):
    def __init__(self, parent=None) -> None:
        super().__init__("Proxy endpoints", parent)
        self._running = False
        layout = QGridLayout(self)
        self.listen_host = QLineEdit("127.0.0.1")
        self.listen_port = QLineEdit("4582")
        self.upstream_host = QLineEdit()
        self.upstream_port = QLineEdit("4581")
        self.upstream_transport = QComboBox()
        self.upstream_transport.addItem("Plain TCP", "plain_tcp")
        self.upstream_transport.addItem("TLS", "tls")
        self.upstream_transport.setCurrentIndex(1)
        self.upstream_sni = QLineEdit()
        self.verify_tls = QCheckBox("Verify upstream certificate")
        self.verify_tls.setChecked(True)
        self.ca_file = QLineEdit()
        self.ca_browse = QPushButton("Browse…")
        self.route_summary = QLabel()
        self.route_summary.setTextFormat(Qt.TextFormat.PlainText)
        self.route_summary.setWordWrap(True)
        self.route_summary.setObjectName("mutedLabel")

        layout.addWidget(QLabel("Listener"), 0, 0, 1, 4)
        layout.addWidget(QLabel("Listen host"), 1, 0)
        layout.addWidget(self.listen_host, 1, 1)
        layout.addWidget(QLabel("Listen port"), 1, 2)
        layout.addWidget(self.listen_port, 1, 3)
        layout.addWidget(QLabel("Upstream"), 2, 0, 1, 4)
        layout.addWidget(QLabel("Host"), 3, 0)
        layout.addWidget(self.upstream_host, 3, 1)
        layout.addWidget(QLabel("Port"), 3, 2)
        layout.addWidget(self.upstream_port, 3, 3)
        layout.addWidget(QLabel("Transport"), 4, 0)
        layout.addWidget(self.upstream_transport, 4, 1)
        layout.addWidget(QLabel("SNI / hostname"), 5, 0)
        layout.addWidget(self.upstream_sni, 5, 1)
        layout.addWidget(self.verify_tls, 5, 2, 1, 2)
        layout.addWidget(QLabel("CA file"), 6, 0)
        layout.addWidget(self.ca_file, 6, 1, 1, 2)
        layout.addWidget(self.ca_browse, 6, 3)
        layout.addWidget(self.route_summary, 7, 0, 1, 4)
        layout.setColumnStretch(1, 1)
        layout.setColumnStretch(3, 1)

        for control in (self.listen_host, self.listen_port, self.upstream_host, self.upstream_port):
            control.textChanged.connect(self._update_route)
        self.verify_tls.toggled.connect(self._update_route)
        self.upstream_transport.currentIndexChanged.connect(self._update_transport)
        self._update_transport()

    def set_running(self, running: bool) -> None:
        self._running = running
        for control in (
            self.listen_host, self.listen_port, self.upstream_host,
            self.upstream_port, self.upstream_transport,
        ):
            control.setEnabled(not running)
        self._update_transport()

    def _update_transport(self) -> None:
        tls_enabled = not self._running and self.upstream_transport.currentData() == "tls"
        for control in (self.upstream_sni, self.verify_tls, self.ca_file, self.ca_browse):
            control.setEnabled(tls_enabled)
        for row in (5, 6):
            for column in range(4):
                item = self.layout().itemAtPosition(row, column)
                if item is not None and item.widget() is not None:
                    item.widget().setVisible(self.upstream_transport.currentData() == "tls")
        self._update_route()

    @staticmethod
    def _endpoint(host: str, port: str) -> str:
        host = host.strip() or "-"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"{host}:{port.strip() or '-'}"

    def _update_route(self) -> None:
        transport = self.upstream_transport.currentText()
        if self.upstream_transport.currentData() == "tls" and not self.verify_tls.isChecked():
            transport += " (certificate verification disabled)"
        listener = self._endpoint(self.listen_host.text(), self.listen_port.text())
        upstream = self._endpoint(self.upstream_host.text(), self.upstream_port.text())
        self.route_summary.setText(f"Current route: {listener} → {transport} → {upstream}")
