import logging

from .process import Process


class ProcessManager:
    def __init__(self):
        self.processes: list[Process] = []
        self.logger = logging.getLogger("Manager")

    def add(self, process: Process):
        self.processes.append(process)

    def get_statues(self):
        statuses = []
        for p in self.processes:
            statuses.append((p.__class__.__name__, p.get_status()))

        return statuses

    def start(self):
        for p in self.processes:
            p.start()

    def stop(self):
        for process in reversed(self.processes):
            process.stop()

    def __del__(self):
        self.logger.info("Cleaning up processes...")
        for process in reversed(self.processes):
            try:
                process.stop()
            except Exception as e:
                self.logger.error("Error stopping process: %s", e)
        self.processes.clear()
