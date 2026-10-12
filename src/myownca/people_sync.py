"""Mirror login accounts into the People holder registry.

Every login ``User`` (any role) gets a matching ``Person`` (keyed by email) so the
superuser can issue/assign certificates to operators. The mirror is one-time and
idempotent: a ``Person`` is created only when no person shares the user's email
(case-insensitive). The created ``Person`` is editable afterward and is not kept in
sync with the user.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from myownca.domain import Person, User
from myownca.storage.repositories import PKIRepository, RepositoryError


def person_fields_from_user(user: User) -> dict[str, str]:
    """Derive a Person's name/surname/email from a login user (no name stored)."""
    local_part = user.email.split("@", 1)[0]
    return {"name": local_part or user.email, "surname": "", "email": user.email}


def ensure_person_for_user(repository: PKIRepository, user: User) -> bool:
    """Create a Person mirroring ``user`` if none shares its email. Returns True if created."""
    target = user.email.casefold()
    if any(person.email.casefold() == target for person in repository.list_people()):
        return False
    fields = person_fields_from_user(user)
    person = Person(
        id=str(uuid4()),
        name=fields["name"],
        surname=fields["surname"],
        email=fields["email"],
        created_at=datetime.now(timezone.utc),
    )
    try:
        repository.add_person(person)
    except RepositoryError:
        # Lost a race against another writer that inserted the same email — fine.
        return False
    return True


def ensure_people_for_all_users(repository: PKIRepository) -> int:
    """Backfill a Person for every login user that lacks one. Returns the count created."""
    return sum(ensure_person_for_user(repository, user) for user in repository.list_users())
