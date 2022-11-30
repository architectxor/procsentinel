from pathlib import Path
from AnalyzedProcess import *


class ProcessesContext:
    current_pids = {}
    def __init__(self, store_path_str):
        self.store_path = Path(store_path_str)
        self.init_store_dir()
        self.main_log_path = self.store_path / "main_log"
        self.update()


    def init_store_dir(self):
        if not self.store_path.exists():
            self.store_path.mkdir()


    def get_all_pids(self):
        proc_path = Path('/proc/')
        glob_string = '[0-9]*'
        return [path for path in proc_path.glob(glob_string)]


    def update(self):
        relevant_pids_list = self.get_all_pids()
        for rp in relevant_pids_list:
            if not (rp.parts[-1] in self.current_pids.keys()):
                an_p = AnalyzedProcess(rp, self.store_path)
                an_p.write()
                self.current_pids[an_p.get_pid()] = an_p

        terminated_pids = []
        for current_proc in self.current_pids.keys():
            if not (current_proc in [pid.parts[-1] for pid in relevant_pids_list]):
                self.current_pids[current_proc].terminate()
                terminated_pids.append(current_proc)
        for tp in terminated_pids:
            self.current_pids.pop(tp)

