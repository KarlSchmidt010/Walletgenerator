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
    QLabel, QLineEdit, QMessageBox, QProgressBar, QPushButton, QSpinBox,
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
APP_VERSION = "2.1"
SEED_WORDS = tuple(Mnemonic("en").wordlist)
SEED_WORD_SET = frozenset(SEED_WORDS)
PAUSE_FILE = ".walletgenerator.pause"
CANCEL_FILE = ".walletgenerator.cancel"
DATASET_FILE = ".walletgenerator-password-mode-v2"


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
        self.setMinimumWidth(510)
        self.job = None
        self.is_paused = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)
        subtitle = QLabel("Verschlüsselte Electrum-Wallets mit regulären bc1-Adressen")
        layout.addWidget(subtitle)
        self.notice = QLabel()
        self.notice.setWordWrap(True)
        layout.addWidget(self.notice)

        self.folder = QLineEdit()
        self.folder.setPlaceholderText("Leeren oder bestehenden Datensatzordner wählen")
        self.browse = QPushButton("Auswählen …")
        self.browse.clicked.connect(self.pick_folder)
        folder_row = QHBoxLayout()
        folder_row.addWidget(self.folder)
        folder_row.addWidget(self.browse)

        self.count = QSpinBox()
        self.count.setRange(1, 1_000_000)
        self.count.setValue(1_000_000)
        self.count.setGroupSeparatorShown(True)
        self.password_mode = QComboBox()
        self.password_mode.addItem("Zufällige PIN pro Wallet", "random_pin")
        self.password_mode.addItem(
            "Zufälliges Seed-Wort pro Wallet", "random_seed_word"
        )
        self.password_mode.addItem("Festes Seed-Wort", "seed_word")
        self.pin_length = QSpinBox()
        self.pin_length.setRange(6, 20)
        self.pin_length.setValue(6)
        self.pin_length.setSuffix(" Stellen")
        self.pin_length_label = QLabel("PIN-Länge")
        self.seed_word = QComboBox()
        self.seed_word.setEditable(True)
        self.seed_word.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.seed_word.setMaxVisibleItems(20)
        self.seed_word.addItems(SEED_WORDS)
        self.seed_word.setCurrentText("abandon")
        self.seed_word_label = QLabel("Seed-Wort")
        word_completer = self.seed_word.completer()
        word_completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
        word_completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        word_completer.setFilterMode(Qt.MatchFlag.MatchContains)
        self.password_mode.currentIndexChanged.connect(self.update_password_controls)
        self.cpu_percent = QSpinBox()
        self.cpu_percent.setRange(1, 100)
        self.cpu_percent.setValue(50)
        self.cpu_percent.setSuffix(" %")
        self.process_limit = QSpinBox()
        self.process_limit.setRange(1, LOGICAL_CPUS)
        self.process_limit.setValue(LOGICAL_CPUS)
        self.capacity = QLabel()
        self.cpu_percent.valueChanged.connect(self.update_capacity)
        self.process_limit.valueChanged.connect(self.update_capacity)
        form = QFormLayout()
        form.addRow("Zielordner", folder_row)
        form.addRow("Wallet-Anzahl", self.count)
        form.addRow("Passwortmodus", self.password_mode)
        form.addRow(self.pin_length_label, self.pin_length)
        form.addRow(self.seed_word_label, self.seed_word)
        form.addRow("CPU-Zielauslastung", self.cpu_percent)
        form.addRow("Maximale Prozesse", self.process_limit)
        form.addRow("Erkannte Leistung", self.capacity)
        layout.addLayout(form)
        self.update_password_controls()
        self.update_capacity()

        self.progress = QProgressBar()
        self.progress.setRange(0, self.count.value())
        self.progress.setValue(0)
        self.progress.setFormat("%v / %m")
        layout.addWidget(self.progress)
        self.status = QLabel("Bereit")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        self.start = QPushButton("Starten / Fortsetzen")
        self.start.clicked.connect(self.start_job)
        self.pause = QPushButton("Pause")
        self.pause.setEnabled(False)
        self.pause.clicked.connect(self.toggle_pause)
        self.cancel = QPushButton("Abbrechen")
        self.cancel.setEnabled(False)
        self.cancel.clicked.connect(self.stop_job)
        buttons = QHBoxLayout()
        buttons.addStretch()
        buttons.addWidget(self.cancel)
        buttons.addWidget(self.pause)
        buttons.addWidget(self.start)
        layout.addLayout(buttons)

    def pick_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Zielordner wählen", self.folder.text())
        if folder:
            self.folder.setText(folder)

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
        self.status.setText(
            f"Wallets werden mit {worker_count} Prozessen geprüft und erstellt …"
        )
        for widget in (
            self.folder, self.browse, self.count, self.password_mode,
            self.pin_length, self.seed_word, self.cpu_percent, self.process_limit,
            self.start,
        ):
            widget.setEnabled(False)
        self.is_paused = False
        self.pause.setText("Pause")
        self.pause.setEnabled(True)
        self.cancel.setEnabled(True)
        self.job.start()

    def toggle_pause(self):
        if self.job is None:
            return
        if self.is_paused:
            self.job.resume()
            self.is_paused = False
            self.pause.setText("Pause")
            self.status.setText("Wallets werden weiter erstellt …")
        else:
            self.job.pause()
            self.is_paused = True
            self.pause.setText("Fortsetzen")
            self.status.setText("Pausiert. Mit Fortsetzen geht es an derselben Stelle weiter.")

    def stop_job(self):
        self.job.cancel()
        self.is_paused = False
        self.pause.setText("Pause")
        self.pause.setEnabled(False)
        self.cancel.setEnabled(False)
        self.status.setText("Wird abgebrochen …")

    def job_completed(self, done):
        self.progress.setValue(done)
        if done == self.job.count:
            self.status.setText("Fertig. Der Datensatz liegt im Zielordner.")
        else:
            self.status.setText("Gestoppt. Du kannst den Datensatz später fortsetzen.")

    def job_failed(self, message):
        self.status.setText("Erzeugung abgebrochen.")
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
        self.pause.setText("Pause")
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
    window = WalletWindow()
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
