import sys
import ipaddress
from datetime import datetime, timedelta
from pathlib import Path

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QFormLayout, QHBoxLayout,
    QLineEdit, QLabel, QPushButton, QFileDialog, QMessageBox,
    QRadioButton, QButtonGroup, QSpinBox
)

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives.serialization import pkcs12


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def build_name(c, st, l, o, ou, cn):
    attrs = []
    if c: attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, c))
    if st: attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, st))
    if l: attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, l))
    if o: attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, o))
    if ou: attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    if cn: attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    return x509.Name(attrs)


def write_pem_key(path: Path, key):
    with open(path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )


def write_pem_cert(path: Path, cert):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def write_der_cert(path: Path, cert):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.DER))


def write_csr(path: Path, csr):
    with open(path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))


class CertMakerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CertMaker WINDOWS")
        self.resize(540, 540)

        self.defaults = {
            "CN": "localhost",
            "BASE": "server",
            "O": "VMachine",
            "OU": "Dev",
            "C": "MX",
            "ST": "CDMX",
            "L": "Local",
            "SAN": "",
            "DAYS": 825
        }

        main = QVBoxLayout(self)
        main.setSpacing(6)
        main.setContentsMargins(10, 10, 10, 10)

        # ----- Modo -----
        self.rb_quick = QRadioButton("TLS rápido (localhost)")
        self.rb_manual = QRadioButton("TLS manual")
        self.rb_quick.setChecked(True)

        mode_group = QButtonGroup(self)
        mode_group.addButton(self.rb_quick)
        mode_group.addButton(self.rb_manual)

        main.addWidget(self.rb_quick)
        main.addWidget(self.rb_manual)

        # ----- Formulario -----
        form = QFormLayout()

        self.txt_cn = QLineEdit(self.defaults["CN"])
        self.txt_base = QLineEdit(self.defaults["BASE"])
        self.txt_o = QLineEdit(self.defaults["O"])
        self.txt_ou = QLineEdit(self.defaults["OU"])
        self.txt_c = QLineEdit(self.defaults["C"])
        self.txt_st = QLineEdit(self.defaults["ST"])
        self.txt_l = QLineEdit(self.defaults["L"])
        self.txt_san = QLineEdit(self.defaults["SAN"])
        self.txt_san.setPlaceholderText("SANs separados por coma o espacio")

        self.spin_days = QSpinBox()
        self.spin_days.setRange(1, 3650)
        self.spin_days.setValue(self.defaults["DAYS"])
        self.spin_days.setSuffix(" días")

        self.txt_ca_status = QLineEdit()
        self.txt_ca_status.setReadOnly(True)

        form.addRow("CN:", self.txt_cn)
        form.addRow("Nombre base:", self.txt_base)
        form.addRow("Organización (O):", self.txt_o)
        form.addRow("Unidad (OU):", self.txt_ou)
        form.addRow("País (C):", self.txt_c)
        form.addRow("Estado (ST):", self.txt_st)
        form.addRow("Ciudad (L):", self.txt_l)
        form.addRow("SANs:", self.txt_san)
        form.addRow("Duración servidor:", self.spin_days)
        form.addRow("Estado CA:", self.txt_ca_status)

        # Carpeta salida
        self.lbl_out = QLineEdit(str(Path.cwd()))
        btn_browse = QPushButton("Elegir carpeta…")
        btn_browse.clicked.connect(self.choose_dir)

        folder_layout = QHBoxLayout()
        folder_layout.addWidget(self.lbl_out)
        folder_layout.addWidget(btn_browse)

        form.addRow("Carpeta salida:", folder_layout)

        main.addLayout(form)

        # Botón generar
        btn_gen = QPushButton("Generar certificados")
        btn_gen.clicked.connect(self.generate)
        main.addWidget(btn_gen)

        self.toggle_manual_fields(False)
        self.rb_quick.toggled.connect(
            lambda _: self.toggle_manual_fields(self.rb_manual.isChecked())
        )

        self.update_ca_status()

    def toggle_manual_fields(self, enabled: bool):
        for w in (
            self.txt_cn, self.txt_base, self.txt_o, self.txt_ou,
            self.txt_c, self.txt_st, self.txt_l,
            self.txt_san, self.spin_days
        ):
            w.setEnabled(enabled)

    def choose_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Elegir carpeta", self.lbl_out.text())
        if d:
            self.lbl_out.setText(d)
            self.update_ca_status()

    def update_ca_status(self):
        ca_path = Path(self.lbl_out.text()) / "ca.crt"
        if ca_path.exists():
            self.txt_ca_status.setText("CA detectada")
            self.txt_ca_status.setStyleSheet("color: green;")
        else:
            self.txt_ca_status.setText("No existe (se creará)")
            self.txt_ca_status.setStyleSheet("color: orange;")

    def generate(self):
        try:
            if self.rb_quick.isChecked():
                cn = self.defaults["CN"]
                base = self.defaults["BASE"]
                o = self.defaults["O"]
                ou = self.defaults["OU"]
                c = self.defaults["C"]
                st = self.defaults["ST"]
                l = self.defaults["L"]
                san_input = self.defaults["SAN"]
                days = self.defaults["DAYS"]
            else:
                cn = self.txt_cn.text().strip()
                base = self.txt_base.text().strip()
                o = self.txt_o.text().strip()
                ou = self.txt_ou.text().strip()
                c = self.txt_c.text().strip()
                st = self.txt_st.text().strip()
                l = self.txt_l.text().strip()
                san_input = self.txt_san.text().strip()
                days = self.spin_days.value()

            if not cn or not base:
                QMessageBox.warning(self, "Error", "CN y Nombre base son obligatorios.")
                return

            out_base = Path(self.lbl_out.text()).expanduser().resolve()
            out_base.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_dir = out_base / f"{base}_{timestamp}"
            out_dir.mkdir(parents=True, exist_ok=True)

            now = datetime.utcnow()
            ca_key_path = out_base / "ca.key"
            ca_cert_path = out_base / "ca.crt"

            # ----- CA -----
            if ca_key_path.exists() and ca_cert_path.exists():
                with open(ca_key_path, "rb") as f:
                    ca_key = serialization.load_pem_private_key(f.read(), password=None)
                with open(ca_cert_path, "rb") as f:
                    ca_cert = x509.load_pem_x509_certificate(f.read())
                ca_name = ca_cert.subject
            else:
                ca_key = rsa.generate_private_key(65537, 4096)
                ca_name = build_name(c, st, l, o, ou, f"{o}-Root-CA")
                ca_cert = (
                    x509.CertificateBuilder()
                    .subject_name(ca_name)
                    .issuer_name(ca_name)
                    .public_key(ca_key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(days=1))
                    .not_valid_after(now + timedelta(days=3650))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
                    .sign(ca_key, hashes.SHA256())
                )
                write_pem_key(ca_key_path, ca_key)
                write_pem_cert(ca_cert_path, ca_cert)

            self.update_ca_status()

            # ----- Server Key -----
            srv_key = rsa.generate_private_key(65537, 2048)
            write_pem_key(out_dir / f"{base}.key", srv_key)

            srv_name = build_name(c, st, l, o, ou, cn)

            tokens = [t.strip() for t in san_input.replace(",", " ").split() if t.strip()] if san_input else [cn]
            san_list = [
                x509.IPAddress(ipaddress.ip_address(t)) if is_ip(t)
                else x509.DNSName(t)
                for t in tokens
            ]

            # ----- CSR -----
            csr = (
                x509.CertificateSigningRequestBuilder()
                .subject_name(srv_name)
                .add_extension(x509.SubjectAlternativeName(san_list), False)
                .sign(srv_key, hashes.SHA256())
            )

            write_csr(out_dir / f"{base}.csr", csr)

            # ----- Cert firmado -----
            cert = (
                x509.CertificateBuilder()
                .subject_name(srv_name)
                .issuer_name(ca_name)
                .public_key(srv_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=days))
                .add_extension(x509.SubjectAlternativeName(san_list), False)
                .add_extension(x509.BasicConstraints(False, None), True)
                .add_extension(
                    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                    False
                )
                .sign(ca_key, hashes.SHA256())
            )

            write_pem_cert(out_dir / f"{base}.crt", cert)
            write_der_cert(out_dir / f"{base}.cer", cert)

            # ----- PFX sin contraseña ----- 
            pfx = pkcs12.serialize_key_and_certificates(
                name=b"server",
                key=srv_key,
                cert=cert,
                cas=[ca_cert],
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(out_dir / "server.pfx", "wb") as f:
                f.write(pfx)

            QMessageBox.information(
                self,
                "Éxito",
                f"Archivos generados en:\n{out_dir}"
            )

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CertMakerGUI()
    window.show()
    sys.exit(app.exec_())
