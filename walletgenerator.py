"""Create encrypted Electrum wallets with configurable passwords."""
import asyncio
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import secrets
import sys
from tempfile import TemporaryDirectory
from threading import Event, Thread
import time

from PyQt6.QtCore import QLockFile, QObject, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication, QComboBox, QCompleter, QFileDialog, QFormLayout, QHBoxLayout,
    QFrame, QLabel, QLineEdit, QMessageBox, QProgressBar, QPushButton, QSpinBox,
    QVBoxLayout, QWidget,
)

from electrum import util
from electrum.mnemonic import Mnemonic
from electrum.simple_config import SimpleConfig
from electrum.storage import WalletStorage
from electrum.wallet import create_new_wallet
from electrum.wallet_db import WalletDB


def verify_wallet(path, pin):
    storage = WalletStorage(str(path))
    if not storage.is_encrypted_with_user_pw():
        raise ValueError(f"Keine passwortverschlüsselte Wallet: {path.name}")
    storage.decrypt(pin)
    db = WalletDB(storage.read(), storage=storage, upgrade=True)
    address = db.get("addresses")["receiving"][0]
    if not address.startswith("bc1"):
        raise ValueError(
            "Der Zielordner enthält Wallets aus der früheren Regtest-Version. "
            "Wähle für reguläre Bitcoin-Wallets einen neuen leeren Ordner."
        )


LOGICAL_CPUS = max(1, os.cpu_count() or 1)
APP_VERSION = "2.2"
SEED_WORDS = tuple(Mnemonic("en").wordlist)
SEED_WORD_SET = frozenset(SEED_WORDS)
PAUSE_FILE = ".walletgenerator.pause"
CANCEL_FILE = ".walletgenerator.cancel"
DATASET_FILE = ".walletgenerator-password-mode-v2"

APP_STYLESHEET = """
QWidget {
    color: #dceaf1;
    font-family: "Segoe UI";
    font-size: 10pt;
}
QWidget#Root {
    background-color: #081018;
}
QLabel#Eyebrow {
    color: #43d7d0;
    font-family: "Consolas";
    font-size: 9pt;
    font-weight: 700;
    letter-spacing: 2px;
}
QLabel#Title {
    color: #f2f8fb;
    font-size: 24pt;
    font-weight: 650;
}
QLabel#VersionBadge {
    color: #7fe8e3;
    background-color: #123139;
    border: 1px solid #24545c;
    border-radius: 11px;
    padding: 4px 10px;
    font-family: "Consolas";
    font-weight: 700;
}
QLabel#Subtitle {
    color: #839aa8;
    font-size: 10pt;
}
QFrame#Card {
    background-color: #0f1a24;
    border: 1px solid #1d3342;
    border-radius: 10px;
}
QLabel#SectionTag {
    color: #43d7d0;
    background-color: #112c32;
    border-radius: 4px;
    padding: 3px 7px;
    font-family: "Consolas";
    font-size: 8pt;
    font-weight: 700;
}
QLabel#SectionTitle {
    color: #bcd0da;
    font-size: 9pt;
    font-weight: 650;
    letter-spacing: 1px;
}
QLabel#FieldLabel {
    color: #91a6b2;
}
QLabel#Notice {
    color: #9db2bd;
    background-color: #0b151e;
    border-left: 3px solid #43d7d0;
    border-radius: 4px;
    padding: 9px 11px;
}
QLabel#Capacity {
    color: #75d6ed;
    font-family: "Consolas";
    font-size: 9pt;
}
QLabel#Status {
    background-color: #0b151e;
    border: 1px solid #1d3342;
    border-radius: 6px;
    padding: 9px 11px;
    font-family: "Consolas";
    font-size: 9pt;
}
QLabel#Status[state="ready"] { color: #93a9b5; }
QLabel#Status[state="running"] { color: #69e6df; border-color: #24545c; }
QLabel#Status[state="paused"] { color: #f1c86a; border-color: #5a4b25; }
QLabel#Status[state="success"] { color: #78e6a4; border-color: #265b3c; }
QLabel#Status[state="warning"] { color: #f1c86a; border-color: #5a4b25; }
QLabel#Status[state="error"] { color: #ff8f9b; border-color: #64333c; }
QLineEdit, QComboBox, QSpinBox {
    color: #e5f0f5;
    background-color: #09131c;
    border: 1px solid #284050;
    border-radius: 6px;
    padding: 7px 9px;
    min-height: 18px;
    selection-background-color: #267f85;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    border: 1px solid #43d7d0;
    background-color: #0b1821;
}
QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled {
    color: #607480;
    background-color: #0b131a;
    border-color: #1a2a34;
}
QComboBox::drop-down {
    border: 0;
    width: 28px;
}
QComboBox QAbstractItemView {
    color: #dceaf1;
    background-color: #0f1a24;
    border: 1px solid #284050;
    selection-color: #ffffff;
    selection-background-color: #236e74;
    padding: 4px;
}
QSpinBox::up-button, QSpinBox::down-button {
    background-color: #132431;
    border: 0;
    width: 22px;
}
QProgressBar {
    color: #c9dae2;
    background-color: #09131c;
    border: 1px solid #1d3342;
    border-radius: 7px;
    min-height: 25px;
    text-align: center;
    font-family: "Consolas";
    font-size: 9pt;
    font-weight: 700;
}
QProgressBar::chunk {
    background-color: #258e91;
    border-radius: 6px;
}
QPushButton {
    color: #bfd0d8;
    background-color: #152431;
    border: 1px solid #2b4352;
    border-radius: 6px;
    padding: 8px 14px;
    min-height: 20px;
    font-weight: 600;
}
QPushButton:hover {
    color: #eef8fb;
    background-color: #1b3040;
    border-color: #406276;
}
QPushButton:pressed { background-color: #0f202c; }
QPushButton:disabled {
    color: #526671;
    background-color: #0d1720;
    border-color: #1b2a34;
}
QPushButton#PrimaryButton {
    color: #061316;
    background-color: #43d7d0;
    border-color: #65ece5;
    padding-left: 18px;
    padding-right: 18px;
}
QPushButton#PrimaryButton:hover { background-color: #65e5df; }
QPushButton#PauseButton:enabled {
    color: #f1d48b;
    border-color: #5d4f2e;
}
QPushButton#DangerButton:enabled {
    color: #ff9ca6;
    border-color: #653640;
}
QToolTip {
    color: #e4eff4;
    background-color: #13212b;
    border: 1px solid #2d4655;
    padding: 5px;
}
"""


def calculate_worker_count(logical_cpus, cpu_percent, process_limit):
    percentage_limit = max(1, (logical_cpus * cpu_percent + 99) // 100)
    return max(1, min(process_limit, percentage_limit))


def create_password(mode, value):
    if mode == "random_pin":
        length = int(value)
        if not 6 <= length <= 20:
            raise ValueError("Die PIN-Länge muss zwischen 6 und 20 liegen.")
        return "".join(secrets.choice("0123456789") for _ in range(length))
    if mode == "random_seed_word":
        return secrets.choice(SEED_WORDS)
    if mode == "seed_word":
        if value not in SEED_WORD_SET:
            raise ValueError("Wähle ein gültiges Wort aus der Electrum-Seed-Wortliste.")
        return value
    raise ValueError("Unbekannter Passwortmodus.")


def dataset_config(mode, value):
    if mode == "random_pin":
        return {"version": 2, "mode": mode, "pin_length": int(value)}
    if mode == "random_seed_word":
        return {"version": 2, "mode": mode}
    if mode == "seed_word":
        return {
            "version": 2,
            "mode": mode,
            "password_fingerprint": hashlib.sha256(
                value.encode("utf-8")
            ).hexdigest(),
        }
    raise ValueError("Unbekannter Passwortmodus.")


def generate_batch(job):
    root, start, stop, password_mode, password_value = job
    pause_flag = root / PAUSE_FILE
    cancel_flag = root / CANCEL_FILE

    async def run():
        util.AS_LIB_USER_I_WANT_TO_MANAGE_MY_OWN_ASYNCIO_LOOP = True
        folder = root / f"{start // 1000:04d}"
        folder.mkdir(exist_ok=True)
        with TemporaryDirectory(prefix=".wallet-", dir=folder) as staging:
            config = SimpleConfig({"electrum_path": staging})
            temporary = Path(staging) / "wallet"
            processed = 0
            for index in range(start, stop):
                while pause_flag.exists() and not cancel_flag.exists():
                    time.sleep(0.1)
                if cancel_flag.exists():
                    return processed
                destination = folder / f"wallet_{index:07d}"
                if destination.exists():
                    processed += 1
                    continue
                password = create_password(password_mode, password_value)
                create_new_wallet(
                    path=str(temporary), config=config, password=password,
                    encrypt_file=True, seed_type="segwit",
                    gap_limit=1, gap_limit_for_change=1,
                )
                storage = WalletStorage(str(temporary))
                if not storage.is_encrypted_with_user_pw():
                    raise RuntimeError(f"Wallet {index} wurde nicht verschlüsselt.")
                os.rename(temporary, destination)
                processed += 1
        return processed

    return asyncio.run(run())


def generate(
    root, count, cancelled, progress, worker_count, password_mode,
    password_value,
):
    root.mkdir(parents=True, exist_ok=True)
    pause_flag = root / PAUSE_FILE
    cancel_flag = root / CANCEL_FILE
    lock = QLockFile(str(root / ".walletgenerator.lock"))
    lock.setStaleLockTime(0)
    if not lock.tryLock():
        raise ValueError("Dieser Zielordner ist bereits in Benutzung oder schreibgeschützt.")

    try:
        marker = root / DATASET_FILE
        expected_config = dataset_config(password_mode, password_value)
        existing_items = [item for item in root.iterdir()
                          if item.name != ".walletgenerator.lock"]
        if not marker.exists() and existing_items:
            raise ValueError(
                "Wähle einen neuen leeren Ordner. Datensätze aus einer älteren "
                "Version oder mit anderen Passworteinstellungen können nicht "
                "übernommen werden."
            )
        if not marker.exists():
            marker.write_text(json.dumps(expected_config, sort_keys=True), encoding="utf-8")
        else:
            try:
                stored_config = json.loads(marker.read_text(encoding="utf-8"))
            except (OSError, ValueError) as error:
                raise ValueError("Die Datensatzkonfiguration ist beschädigt.") from error
            if stored_config != expected_config:
                raise ValueError(
                    "Dieser Datensatz wurde mit anderen Passworteinstellungen "
                    "erstellt. Verwende die ursprünglichen Einstellungen oder "
                    "wähle einen neuen leeren Ordner."
                )

        batch_size = 100
        jobs = iter(
            (
                root, start, min(start + batch_size, count), password_mode,
                password_value,
            )
            for start in range(0, count, batch_size)
        )
        completed = 0
        with ProcessPoolExecutor(max_workers=worker_count) as pool:
            pending = set()
            for _ in range(worker_count):
                try:
                    pending.add(pool.submit(generate_batch, next(jobs)))
                except StopIteration:
                    break

            while pending:
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    completed += future.result()
                    progress(min(completed, count))
                    if not cancelled.is_set():
                        try:
                            pending.add(pool.submit(generate_batch, next(jobs)))
                        except StopIteration:
                            pass
                if cancelled.is_set():
                    for future in pending:
                        future.cancel()
                    return completed
        return completed
    finally:
        pause_flag.unlink(missing_ok=True)
        cancel_flag.unlink(missing_ok=True)
        lock.unlock()


class WalletJob(QObject):
    finished = pyqtSignal()
    progress = pyqtSignal(int)
    completed = pyqtSignal(int)
    failed = pyqtSignal(str)

    def __init__(
        self, root, count, worker_count, password_mode, password_value, parent,
    ):
        super().__init__(parent)
        self.root = root
        self.count = count
        self.worker_count = worker_count
        self.password_mode = password_mode
        self.password_value = password_value
        self.cancelled = Event()
        self.pause_flag = root / PAUSE_FILE
        self.cancel_flag = root / CANCEL_FILE

    def start(self):
        self.root.mkdir(parents=True, exist_ok=True)
        self.pause_flag.unlink(missing_ok=True)
        self.cancel_flag.unlink(missing_ok=True)
        Thread(target=self.run, daemon=False).start()

    def pause(self):
        self.pause_flag.write_text("paused\n", encoding="utf-8")

    def resume(self):
        self.pause_flag.unlink(missing_ok=True)

    def cancel(self):
        self.cancelled.set()
        self.pause_flag.unlink(missing_ok=True)
        self.cancel_flag.write_text("cancelled\n", encoding="utf-8")

    def run(self):
        try:
            done = generate(
                self.root, self.count, self.cancelled, self.progress.emit,
                self.worker_count, self.password_mode, self.password_value,
            )
            self.completed.emit(done)
        except Exception as error:
            self.failed.emit(str(error))
        finally:
            self.finished.emit()


class WalletWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"Walletgenerator {APP_VERSION}")
        self.setObjectName("Root")
        self.setMinimumSize(680, 760)
        self.resize(760, 820)
        self.job = None
        self.is_paused = False

        def field_label(text):
            label = QLabel(text)
            label.setObjectName("FieldLabel")
            return label

        def make_card(code, title):
            frame = QFrame()
            frame.setObjectName("Card")
            body = QVBoxLayout(frame)
            body.setContentsMargins(18, 15, 18, 17)
            body.setSpacing(12)
            heading = QHBoxLayout()
            heading.setSpacing(9)
            tag = QLabel(code)
            tag.setObjectName("SectionTag")
            section_title = QLabel(title)
            section_title.setObjectName("SectionTitle")
            heading.addWidget(tag)
            heading.addWidget(section_title)
            heading.addStretch()
            body.addLayout(heading)
            return frame, body

        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 22, 26, 24)
        layout.setSpacing(12)

        eyebrow = QLabel("ELECTRUM DATASET LAB")
        eyebrow.setObjectName("Eyebrow")
        layout.addWidget(eyebrow)
        title_row = QHBoxLayout()
        title_row.setSpacing(12)
        title = QLabel("Walletgenerator")
        title.setObjectName("Title")
        version = QLabel(f"v{APP_VERSION}")
        version.setObjectName("VersionBadge")
        title_row.addWidget(title)
        title_row.addStretch()
        title_row.addWidget(version)
        layout.addLayout(title_row)
        subtitle = QLabel(
            "Parallele Synthese verschlüsselter Electrum-Wallets  •  Bitcoin Mainnet / bc1"
        )
        subtitle.setObjectName("Subtitle")
        layout.addWidget(subtitle)

        dataset_card, dataset_body = make_card("01", "DATASET-KONFIGURATION")

        self.folder = QLineEdit()
        self.folder.setPlaceholderText("Leeren oder bestehenden Datensatzordner wählen")
        self.folder.setToolTip("Speicherort für die erzeugten Wallet-Dateien")
        self.browse = QPushButton("Ordner wählen")
        self.browse.clicked.connect(self.pick_folder)
        folder_row = QHBoxLayout()
        folder_row.setSpacing(8)
        folder_row.addWidget(self.folder)
        folder_row.addWidget(self.browse)

        self.count = QSpinBox()
        self.count.setRange(1, 1_000_000)
        self.count.setValue(1_000_000)
        self.count.setGroupSeparatorShown(True)
        self.count.setToolTip("Anzahl der zu erzeugenden Wallet-Dateien")
        dataset_form = QFormLayout()
        dataset_form.setContentsMargins(0, 0, 0, 0)
        dataset_form.setHorizontalSpacing(18)
        dataset_form.setVerticalSpacing(10)
        dataset_form.addRow(field_label("Zielordner"), folder_row)
        dataset_form.addRow(field_label("Wallet-Anzahl"), self.count)
        dataset_body.addLayout(dataset_form)
        layout.addWidget(dataset_card)

        security_card, security_body = make_card("02", "VERSCHLÜSSELUNGSPROFIL")
        self.password_mode = QComboBox()
        self.password_mode.addItem("Zufällige PIN pro Wallet", "random_pin")
        self.password_mode.addItem(
            "Zufälliges Seed-Wort pro Wallet", "random_seed_word"
        )
        self.password_mode.addItem("Festes Seed-Wort", "seed_word")
        self.password_mode.setToolTip("Methode zur Verschlüsselung der Wallet-Dateien")
        self.pin_length = QSpinBox()
        self.pin_length.setRange(6, 20)
        self.pin_length.setValue(6)
        self.pin_length.setSuffix(" Stellen")
        self.pin_length_label = QLabel("PIN-Länge")
        self.pin_length_label.setObjectName("FieldLabel")
        self.seed_word = QComboBox()
        self.seed_word.setEditable(True)
        self.seed_word.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.seed_word.setMaxVisibleItems(20)
        self.seed_word.addItems(SEED_WORDS)
        self.seed_word.setCurrentText("abandon")
        self.seed_word_label = QLabel("Seed-Wort")
        self.seed_word_label.setObjectName("FieldLabel")
        word_completer = self.seed_word.completer()
        word_completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
        word_completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        word_completer.setFilterMode(Qt.MatchFlag.MatchContains)
        self.password_mode.currentIndexChanged.connect(self.update_password_controls)
        security_form = QFormLayout()
        security_form.setContentsMargins(0, 0, 0, 0)
        security_form.setHorizontalSpacing(18)
        security_form.setVerticalSpacing(10)
        security_form.addRow(field_label("Passwortmodus"), self.password_mode)
        security_form.addRow(self.pin_length_label, self.pin_length)
        security_form.addRow(self.seed_word_label, self.seed_word)
        security_body.addLayout(security_form)
        self.notice = QLabel()
        self.notice.setObjectName("Notice")
        self.notice.setWordWrap(True)
        self.notice.setMinimumHeight(48)
        security_body.addWidget(self.notice)
        layout.addWidget(security_card)

        compute_card, compute_body = make_card("03", "RECHENBUDGET")
        self.cpu_percent = QSpinBox()
        self.cpu_percent.setRange(1, 100)
        self.cpu_percent.setValue(50)
        self.cpu_percent.setSuffix(" %")
        self.cpu_percent.setToolTip("Näherungsweise CPU-Auslastung über Worker-Prozesse")
        self.process_limit = QSpinBox()
        self.process_limit.setRange(1, LOGICAL_CPUS)
        self.process_limit.setValue(LOGICAL_CPUS)
        self.process_limit.setToolTip("Maximale Anzahl parallel arbeitender Prozesse")
        self.capacity = QLabel()
        self.capacity.setObjectName("Capacity")
        self.cpu_percent.valueChanged.connect(self.update_capacity)
        self.process_limit.valueChanged.connect(self.update_capacity)
        compute_form = QFormLayout()
        compute_form.setContentsMargins(0, 0, 0, 0)
        compute_form.setHorizontalSpacing(18)
        compute_form.setVerticalSpacing(10)
        compute_form.addRow(field_label("CPU-Zielauslastung"), self.cpu_percent)
        compute_form.addRow(field_label("Maximale Prozesse"), self.process_limit)
        compute_form.addRow(field_label("Systemanalyse"), self.capacity)
        compute_body.addLayout(compute_form)
        layout.addWidget(compute_card)
        self.update_password_controls()
        self.update_capacity()

        run_card, run_body = make_card("04", "GENERIERUNGSKONTROLLE")
        self.progress = QProgressBar()
        self.progress.setRange(0, self.count.value())
        self.progress.setValue(0)
        self.progress.setFormat("%p%   •   %v / %m WALLET-DATEIEN")
        run_body.addWidget(self.progress)
        self.status = QLabel()
        self.status.setObjectName("Status")
        self.status.setProperty("state", "ready")
        self.status.setWordWrap(True)
        self.status.setMinimumHeight(38)
        run_body.addWidget(self.status)

        self.start = QPushButton("▶  Starten / Fortsetzen")
        self.start.setObjectName("PrimaryButton")
        self.start.clicked.connect(self.start_job)
        self.pause = QPushButton("Ⅱ  Pause")
        self.pause.setObjectName("PauseButton")
        self.pause.setEnabled(False)
        self.pause.clicked.connect(self.toggle_pause)
        self.cancel = QPushButton("■  Abbrechen")
        self.cancel.setObjectName("DangerButton")
        self.cancel.setEnabled(False)
        self.cancel.clicked.connect(self.stop_job)
        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        buttons.addStretch()
        buttons.addWidget(self.cancel)
        buttons.addWidget(self.pause)
        buttons.addWidget(self.start)
        run_body.addLayout(buttons)
        layout.addWidget(run_card)
        self.set_status("BEREIT  •  System wartet auf Konfiguration", "ready")

    def pick_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Zielordner wählen", self.folder.text())
        if folder:
            self.folder.setText(folder)

    def set_status(self, text, state):
        self.status.setText(text)
        self.status.setProperty("state", state)
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)

    def active_worker_count(self):
        return calculate_worker_count(
            LOGICAL_CPUS, self.cpu_percent.value(), self.process_limit.value(),
        )

    def update_capacity(self):
        active = self.active_worker_count()
        self.capacity.setText(
            f"{LOGICAL_CPUS} logische Prozessoren erkannt, {active} Prozesse aktiv"
        )

    def update_password_controls(self):
        mode = self.password_mode.currentData()
        pin_mode = mode == "random_pin"
        fixed_word_mode = mode == "seed_word"
        self.pin_length_label.setVisible(pin_mode)
        self.pin_length.setVisible(pin_mode)
        self.seed_word_label.setVisible(fixed_word_mode)
        self.seed_word.setVisible(fixed_word_mode)
        if pin_mode:
            self.notice.setText(
                "Jede Wallet erhält eine eigene zufällige Zahlen-PIN. Die PINs "
                "werden nicht angezeigt oder gespeichert. Prozessoranzahl und "
                "Auslastung werden an diesen Rechner angepasst."
            )
        elif mode == "random_seed_word":
            self.notice.setText(
                "Jede Wallet erhält ein eigenes zufälliges englisches Seed-Wort. "
                "Die Wörter werden nicht angezeigt oder gespeichert. "
                "Prozessoranzahl und Auslastung werden an diesen Rechner angepasst."
            )
        else:
            self.notice.setText(
                "Alle Wallets werden mit dem ausgewählten englischen Seed-Wort "
                "verschlüsselt. Prozessoranzahl und Auslastung werden an diesen "
                "Rechner angepasst."
            )

    def password_settings(self):
        mode = self.password_mode.currentData()
        if mode == "random_pin":
            return mode, str(self.pin_length.value())
        if mode == "random_seed_word":
            return mode, ""
        word = self.seed_word.currentText().strip().lower()
        if word not in SEED_WORD_SET:
            raise ValueError(
                "Wähle ein gültiges englisches Wort aus der Seed-Wortliste."
            )
        return mode, word

    def start_job(self):
        folder = self.folder.text().strip()
        if not folder:
            QMessageBox.information(self, "Eingabe prüfen", "Wähle einen Zielordner.")
            return
        try:
            password_mode, password_value = self.password_settings()
        except ValueError as error:
            QMessageBox.information(self, "Eingabe prüfen", str(error))
            return
        worker_count = self.active_worker_count()
        self.job = WalletJob(
            Path(folder).resolve(), self.count.value(), worker_count,
            password_mode, password_value, self,
        )
        self.job.progress.connect(self.progress.setValue)
        self.job.completed.connect(self.job_completed)
        self.job.failed.connect(self.job_failed)
        self.job.finished.connect(self.job_finished)
        self.progress.setRange(0, self.job.count)
        self.progress.setValue(0)
        self.set_status(
            f"AKTIV  •  Generierung mit {worker_count} Prozessen läuft …",
            "running",
        )
        for widget in (
            self.folder, self.browse, self.count, self.password_mode,
            self.pin_length, self.seed_word, self.cpu_percent, self.process_limit,
            self.start,
        ):
            widget.setEnabled(False)
        self.is_paused = False
        self.pause.setText("Ⅱ  Pause")
        self.pause.setEnabled(True)
        self.cancel.setEnabled(True)
        self.job.start()

    def toggle_pause(self):
        if self.job is None:
            return
        if self.is_paused:
            self.job.resume()
            self.is_paused = False
            self.pause.setText("Ⅱ  Pause")
            self.set_status("AKTIV  •  Generierung wird fortgesetzt …", "running")
        else:
            self.job.pause()
            self.is_paused = True
            self.pause.setText("▶  Fortsetzen")
            self.set_status(
                "PAUSIERT  •  Fortsetzen arbeitet an derselben Stelle weiter",
                "paused",
            )

    def stop_job(self):
        self.job.cancel()
        self.is_paused = False
        self.pause.setText("Ⅱ  Pause")
        self.pause.setEnabled(False)
        self.cancel.setEnabled(False)
        self.set_status("STOPP  •  Lauf wird kontrolliert beendet …", "warning")

    def job_completed(self, done):
        self.progress.setValue(done)
        if done == self.job.count:
            self.set_status(
                "FERTIG  •  Datensatz vollständig im Zielordner gespeichert",
                "success",
            )
        else:
            self.set_status(
                "GESTOPPT  •  Datensatz kann später fortgesetzt werden",
                "warning",
            )

    def job_failed(self, message):
        self.set_status("FEHLER  •  Erzeugung wurde abgebrochen", "error")
        QMessageBox.critical(self, "Walletgenerator", message)

    def job_finished(self):
        self.job.deleteLater()
        self.job = None
        for widget in (
            self.folder, self.browse, self.count, self.password_mode,
            self.pin_length, self.seed_word, self.cpu_percent, self.process_limit,
            self.start,
        ):
            widget.setEnabled(True)
        self.update_password_controls()
        self.is_paused = False
        self.pause.setText("Ⅱ  Pause")
        self.pause.setEnabled(False)
        self.cancel.setEnabled(False)

    def closeEvent(self, event):
        if self.job is not None:
            self.stop_job()
            event.ignore()
        else:
            event.accept()


def main():
    multiprocessing.freeze_support()
    app = QApplication(sys.argv)
    app.setApplicationName("Walletgenerator")
    app.setApplicationDisplayName(f"Walletgenerator {APP_VERSION}")
    app.setStyle("Fusion")
    app.setStyleSheet(APP_STYLESHEET)
    window = WalletWindow()
    if len(sys.argv) == 3 and sys.argv[1] == "--ui-screenshot":
        window.show()
        app.processEvents()
        saved = window.grab().save(sys.argv[2], "PNG")
        return 0 if saved else 1
    if len(sys.argv) == 3 and sys.argv[1] == "--smoke-test":
        root = Path(sys.argv[2])
        window.password_mode.setCurrentIndex(
            window.password_mode.findData("seed_word")
        )
        window.seed_word.setCurrentText("abandon")
        if window.password_settings() != ("seed_word", "abandon"):
            return 1
        if generate_batch((root, 0, 2, "seed_word", "abandon")) != 2:
            return 1
        verify_wallet(root / "0000" / "wallet_0000001", "abandon")
        random_pins = {create_password("random_pin", "20") for _ in range(25)}
        if len(random_pins) != 25 or not all(
            len(pin) == 20 and pin.isdigit() for pin in random_pins
        ):
            return 1
        random_words = [
            create_password("random_seed_word", "") for _ in range(100)
        ]
        if not all(word in SEED_WORD_SET for word in random_words):
            return 1
        (root / "smoke-ok.txt").write_text("OK", encoding="utf-8")
        return 0
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
