"""Secure recovery: restore an earlier version only if it is cryptographically verified."""
from dataclasses import dataclass

from file_service import check_version, create_version
from models import File, db
from security import add_risk_event, evaluate_risk, log_incident


@dataclass
class RecoveryResult:
    ok: bool
    message: str
    new_version: int = None
    restricted: bool = False


def restore_version(file: File, version_number: int, user) -> RecoveryResult:
    """Restore `version_number` of `file` for `user` (ownership is verified here as well)."""
    if file.owner_id != user.id:
        add_risk_event(user, "unauthorized_file_access", f"Recovery attempt on file {file.public_id}")
        log_incident("unauthorized_access", "critical", f"Recovery attempted on a file owned by someone else ({file.public_id}).",
                     user=user, file_public_id=file.public_id, commit=False)
        return RecoveryResult(False, "You do not have access to this file.", restricted=evaluate_risk(user))

    source = file.version(version_number)
    if source is None:
        add_risk_event(user, "invalid_recovery_request", f"Version {version_number} of {file.public_id} does not exist")
        log_incident("recovery_rejected", "warning", f"Invalid recovery request: version {version_number} does not exist.",
                     user=user, file_public_id=file.public_id, commit=False)
        return RecoveryResult(False, "That version does not exist.", restricted=evaluate_risk(user))

    if source.version_number == file.current_version:
        return RecoveryResult(False, "That version is already the current version.")

    # AES-GCM authentication + SHA-256 (ciphertext and plaintext) must all pass
    result = check_version(source, user, action="recovery")
    if not result.ok:
        log_incident("recovery_rejected", "critical",
                     f"Recovery of {file.original_name} v{source.version_number} rejected: version is corrupted or tampered.",
                     user=user, file_public_id=file.public_id)
        return RecoveryResult(False, "Recovery rejected: this version failed integrity verification and was not restored.",
                              restricted=(user.status == "restricted"))

    new = create_version(file, result.plaintext, restored_from=source.version_number)
    log_incident("version_restored", "ok",
                 f"{file.original_name}: v{source.version_number} restored as new version v{new.version_number}.",
                 user=user, file_public_id=file.public_id, commit=False)
    db.session.commit()
    return RecoveryResult(True, f"Version {source.version_number} restored as version {new.version_number}. History preserved.",
                          new_version=new.version_number)
