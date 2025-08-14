import sys, os, ipaddress
from datetime import datetime, timedelta
from pathlib import Path

from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QFormLayout, QHBoxLayout,
    QLineEdit, QLabel, QPushButton, QFileDialog, QMessageBox,
    QRadioButton, QButtonGroup, QDesktopWidget
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
    name_attrs = []
    if c:  name_attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, c))
    if st: name_attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, st))
    if l:  name_attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, l))
    if o:  name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, o))
    if ou: name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    if cn: name_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    return x509.Name(name_attrs)


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
        f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))


def write_der_cert(path: Path, cert):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(encoding=serialization.Encoding.DER))


class CertMakerGUI(QWidget):
    def __init__(self):
        super().__init__()
        cp = QDesktopWidget().availableGeometry().center()
        self.setWindowIcon(QIcon("ico.ico"))
        self.setWindowTitle("CertMaker")
        self.resize(560, 520)

        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

        

        self.defaults = {
            "CN": "localhost",
            "O": "infernocore",
            "OU": "Dev",
            "C": "MX",
            "ST": "EDMX",
            "L": "Local",
            "SAN": ""  # vacío = usará CN por defecto
        }

        main = QVBoxLayout(self)

        # ----- Modo -----
        self.rb_quick = QRadioButton("TLS rápido (predeterminado: localhost)")
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
        self.txt_o  = QLineEdit(self.defaults["O"])
        self.txt_ou = QLineEdit(self.defaults["OU"])
        self.txt_c  = QLineEdit(self.defaults["C"])
        self.txt_st = QLineEdit(self.defaults["ST"])
        self.txt_l  = QLineEdit(self.defaults["L"])
        self.txt_san = QLineEdit(self.defaults["SAN"])
        self.txt_san.setPlaceholderText("Opcional: SANs separados por coma o espacio (ej: api.local, 127.0.0.1)")

        form.addRow("CN (IP o dominio):", self.txt_cn)
        form.addRow("Organización (O):", self.txt_o)
        form.addRow("Unidad (OU):", self.txt_ou)
        form.addRow("País (C):", self.txt_c)
        form.addRow("Estado/Provincia (ST):", self.txt_st)
        form.addRow("Ciudad/Localidad (L):", self.txt_l)
        form.addRow("SANs:", self.txt_san)
        main.addLayout(form)

        # Por defecto, deshabilitar en modo rápido
        self.toggle_manual_fields(enabled=False)
        self.rb_quick.toggled.connect(lambda _: self.toggle_manual_fields(self.rb_manual.isChecked()))

        # ----- Carpeta de salida -----
        out_row = QHBoxLayout()
        self.lbl_out = QLineEdit(str(Path.cwd()))
        btn_browse = QPushButton("Elegir carpeta…")
        btn_browse.clicked.connect(self.choose_dir)
        out_row.addWidget(QLabel("Carpeta de salida:"))
        out_row.addWidget(self.lbl_out)
        out_row.addWidget(btn_browse)
        main.addLayout(out_row)

        # ----- Botón generar -----
        btn_gen = QPushButton("Generar certificados")
        btn_gen.clicked.connect(self.generate)
        main.addWidget(btn_gen)

        # Nota corta
        note = QLabel("Genera CA (raíz) y un certificado de servidor firmado por esa CA.\n"
                      "Salida: ca.crt/ca.key, server.crt/server.key, server.pem, server.cer")
        note.setStyleSheet("color: gray;")
        main.addWidget(note)

    def toggle_manual_fields(self, enabled: bool):
        for w in (self.txt_cn, self.txt_o, self.txt_ou, self.txt_c, self.txt_st, self.txt_l, self.txt_san):
            w.setEnabled(enabled)

    def choose_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Elegir carpeta de salida", self.lbl_out.text())
        if d:
            self.lbl_out.setText(d)

    def generate(self):
        try:
            if self.rb_quick.isChecked():
                cn = self.defaults["CN"]
                o  = self.defaults["O"]
                ou = self.defaults["OU"]
                c  = self.defaults["C"]
                st = self.defaults["ST"]
                l  = self.defaults["L"]
                san_input = self.defaults["SAN"]
            else:
                cn = self.txt_cn.text().strip()
                o  = self.txt_o.text().strip()
                ou = self.txt_ou.text().strip()
                c  = self.txt_c.text().strip()
                st = self.txt_st.text().strip()
                l  = self.txt_l.text().strip()
                san_input = self.txt_san.text().strip()

            if not cn:
                QMessageBox.warning(self, "Datos incompletos", "CN (IP o dominio) es obligatorio.")
                return

            out_base = Path(self.lbl_out.text()).expanduser().resolve()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_dir = out_base / f"certs_{cn}_{timestamp}"
            out_dir.mkdir(parents=True, exist_ok=True)

            # ----- Generar CA -----
            ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
            ca_name = build_name(c, st, l, o, ou, "SoySH-CA")
            now = datetime.utcnow()

            ca_builder = (
                x509.CertificateBuilder()
                .subject_name(ca_name)
                .issuer_name(ca_name)
                .public_key(ca_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=False,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=True,
                        crl_sign=True,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
            )
            ca_cert = ca_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

            # Guardar CA
            write_pem_key(out_dir / "ca.key", ca_key)
            write_pem_cert(out_dir / "ca.crt", ca_cert)

            # ----- Generar servidor -----
            srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            srv_name = build_name(c, st, l, o, ou, cn)

            # SANs
            tokens = []
            if san_input:
                tokens = [t.strip() for t in san_input.replace(",", " ").split() if t.strip()]
            if not tokens:
                tokens = [cn]
            san_objs = []
            for t in tokens:
                if is_ip(t):
                    san_objs.append(x509.IPAddress(ipaddress.ip_address(t)))
                else:
                    san_objs.append(x509.DNSName(t))

            srv_builder = (
                x509.CertificateBuilder()
                .subject_name(srv_name)
                .issuer_name(ca_name)
                .public_key(srv_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=825))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName(san_objs), critical=False)
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=True,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .add_extension(
                    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                    critical=False,
                )
            )

            srv_cert = srv_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

            # Guardar servidor
            write_pem_key(out_dir / "server.key", srv_key)
            write_pem_cert(out_dir / "server.crt", srv_cert)
            # PEM combinado
            with open(out_dir / "server.pem", "wb") as f:
                f.write((out_dir / "server.crt").read_bytes())
                f.write(b"\n")
                f.write((out_dir / "server.key").read_bytes())
            # CER (DER)
            write_der_cert(out_dir / "server.cer", srv_cert)

            # (Opcional) PFX sin contraseña; comenta si no lo quieres
            pfx = pkcs12.serialize_key_and_certificates(
                name=b"server",
                key=srv_key,
                cert=srv_cert,
                cas=[ca_cert],
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(out_dir / "server.pfx", "wb") as f:
                f.write(pfx)

            QMessageBox.information(
                self,
                "Éxito",
                f"Certificados generados en:\n{out_dir}\n\n"
                f"- ca.crt / ca.key\n- server.crt / server.key\n- server.pem / server.cer\n- server.pfx"
            )

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Ocurrió un error:\n{e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon("ico.ico"))
    w = CertMakerGUI()
    w.show()
    sys.exit(app.exec_())
