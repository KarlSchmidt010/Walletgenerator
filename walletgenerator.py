"""Create encrypted Electrum wallets protected by one fixed PIN."""
import asyncio
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
import multiprocessing
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from threading import Event, Thread
import time

from PyQt6.QtCore import QLockFile, QObject, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit,
    QMessageBox, QProgressBar, QPushButton, QSpinBox, QVBoxLayout, QWidget,
)

from electrum import util
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


WALLET_PIN = "120577"
LOGICAL_CPUS = max(1, os.cpu_count() or 1)
PAUSE_FILE = ".walletgenerator.pause"
CANCEL_FILE = ".walletgenerator.cancel"


def calculate_worker_count(logical_cpus, cpu_percent, process_limit):
    percentage_limit = max(1, (logical_cpus * cpu_percent + 99) // 100)
    return max(1, min(process_limit, percentage_limit))


def generate_batch(job):
    root, start, stop = job
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
                create_new_wallet(
                    path=str(temporary), config=config, password=WALLET_PIN,
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


def generate(root, count, cancelled, progress, worker_count):
    root.mkdir(parents=True, exist_ok=True)
    pause_flag = root / PAUSE_FILE
    cancel_flag = root / CANCEL_FILE
    lock = QLockFile(str(root / ".walletgenerator.lock"))
    lock.setStaleLockTime(0)
    if not lock.tryLock():
        raise ValueError("Dieser Zielordner ist bereits in Benutzung oder schreibgeschützt.")

    try:
        marker = root / ".walletgenerator-fixed-pin-120577-v1"
        existing_items = [item for item in root.iterdir()
                          if item.name != ".walletgenerator.lock"]
        if not marker.exists() and existing_items:
            raise ValueError(
                "Wähle einen neuen leeren Ordner. Bestehende Datensätze mit anderen "
                "PIN-Einstellungen können nicht übernommen werden."
            )
        if not marker.exists():
            marker.write_text(
                "Walletgenerator fixed PIN dataset v1\nPIN: 120577\n",
                encoding="utf-8",
            )

        batch_size = 100
        jobs = iter(
            (root, start, min(start + batch_size, count))
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

    def __init__(self, root, count, worker_count, parent):
        super().__init__(parent)
        self.root = root
        self.count = count
        self.worker_count = worker_count
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
                self.worker_count,
            )
            self.completed.emit(done)
        except Exception as error:
            self.failed.emit(str(error))
        finally:
            self.finished.emit()


class WalletWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Walletgenerator")
        self.setMinimumWidth(510)
        self.job = None
        self.is_paused = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)
        subtitle = QLabel("Verschlüsselte Electrum-Wallets mit regulären bc1-Adressen")
        layout.addWidget(subtitle)
        notice = QLabel(
            "Jede Wallet wird mit der festen PIN 120577 verschlüsselt. "
            "Prozessoranzahl und Auslastung werden an diesen Rechner angepasst."
        )
        notice.setWordWrap(True)
        layout.addWidget(notice)

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
        form.addRow("CPU-Zielauslastung", self.cpu_percent)
        form.addRow("Maximale Prozesse", self.process_limit)
        form.addRow("Erkannte Leistung", self.capacity)
        layout.addLayout(form)
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

    def start_job(self):
        folder = self.folder.text().strip()
        if not folder:
            QMessageBox.information(self, "Eingabe prüfen", "Wähle einen Zielordner.")
            return
        worker_count = self.active_worker_count()
        self.job = WalletJob(
            Path(folder).resolve(), self.count.value(), worker_count, self,
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
            self.folder, self.browse, self.count, self.cpu_percent,
            self.process_limit, self.start,
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
            self.folder, self.browse, self.count, self.cpu_percent,
            self.process_limit, self.start,
        ):
            widget.setEnabled(True)
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
    window.show()
    if len(sys.argv) == 3 and sys.argv[1] == "--smoke-test":
        root = Path(sys.argv[2])
        window.folder.setText(str(root))
        window.count.setValue(2)
        window.start.click()
        window.job.finished.connect(app.quit)
        QTimer.singleShot(15000, app.quit)
        app.exec()
        if window.progress.value() != 2 or not window.status.text().startswith("Fertig."):
            return 1
        verify_wallet(root / "0000" / "wallet_0000001", WALLET_PIN)
        (root / "smoke-ok.txt").write_text("OK", encoding="utf-8")
        return 0
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
