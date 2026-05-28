#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com

from typing import Optional, Dict, Any
from datetime import datetime


class USSJobState:
    def __init__(self, conversation_id: str, network_uid: str, dry_run: bool = False):
        self.conversation_id = conversation_id
        self.network_uid = network_uid
        self.dry_run = dry_run
        self.started_at = datetime.now()
        self.completed_at = None  # type: Optional[datetime]
        self.status = 'running'  # running, completed, failed
        self.result = None  # type: Optional[Dict[str, Any]]

    def mark_completed(self, result: Optional[Dict[str, Any]] = None):
        self.status = 'completed'
        self.completed_at = datetime.now()
        self.result = result

    def mark_failed(self, error: Optional[str] = None):
        self.status = 'failed'
        self.completed_at = datetime.now()
        if error:
            self.result = {'error': error}

    def to_dict(self) -> Dict[str, Any]:
        return {
            'conversation_id': self.conversation_id,
            'network_uid': self.network_uid,
            'dry_run': self.dry_run,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'status': self.status,
            'result': self.result
        }


class USSState:
    def __init__(self):
        self.jobs = {}  # type: Dict[str, USSJobState]  # conversation_id -> job

    def start_job(self, conversation_id: str, network_uid: str, dry_run: bool = False) -> USSJobState:
        job = USSJobState(conversation_id, network_uid, dry_run)
        self.jobs[conversation_id] = job
        return job

    def complete_job(self, conversation_id: str, result: Optional[Dict[str, Any]] = None):
        if conversation_id in self.jobs:
            self.jobs[conversation_id].mark_completed(result)

    def fail_job(self, conversation_id: str, error: Optional[str] = None):
        if conversation_id in self.jobs:
            self.jobs[conversation_id].mark_failed(error)

    def get_job(self, conversation_id: str) -> Optional[USSJobState]:
        return self.jobs.get(conversation_id)

    def get_job_info(self, conversation_id: str) -> Optional[Dict[str, Any]]:
        job = self.jobs.get(conversation_id)
        if job:
            return job.to_dict()
        return None

    def get_all_jobs(self) -> Dict[str, USSJobState]:
        return self.jobs.copy()

    def get_dry_run_jobs(self) -> Dict[str, USSJobState]:
        return {cid: job for cid, job in self.jobs.items() if job.dry_run}

    def clear_job(self, conversation_id: str):
        if conversation_id in self.jobs:
            del self.jobs[conversation_id]

    def clear_all(self):
        self.jobs.clear()
