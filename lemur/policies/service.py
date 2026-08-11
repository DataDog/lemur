"""
.. module: lemur.policies.service
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""

from lemur import database
from lemur.policies.models import RotationPolicy


def get(policy_id):
    """
    Retrieves policy by its ID.
    :param policy_id:
    :return:
    """
    return database.get(RotationPolicy, policy_id)


def get_by_name(policy_name):
    """
    Retrieves policy by its name.
    :param policy_name:
    :return:
    """
    return database.get_all(RotationPolicy, policy_name, field="name").all()


def delete(policy_id):
    """
    Delete a rotation policy.
    :param policy_id:
    :return:
    """
    database.delete(get(policy_id))


def get_all_policies():
    """
    Retrieves all rotation policies.
    :return:
    """
    return RotationPolicy.query.all()


def create(**kwargs):
    """
    Creates a new rotation policy.

    :param kwargs:
    :return:
    """
    policy = RotationPolicy(**kwargs)
    database.create(policy)
    return policy


def sync_default_rotation_policy():
    """
    Ensure the named ``"default"`` RotationPolicy exists and matches
    ``LEMUR_DEFAULT_ROTATION_INTERVAL`` (via ``_default_rotation_days``).

    Used by ``lemur init`` (InitializeApp) so the seeded default policy and the
    runtime NULL-policy fallback can never diverge. Creates the policy if missing,
    otherwise updates ``days`` in place if it differs from the configured default.

    :return: the ``"default"`` RotationPolicy
    """
    from lemur.certificates.models import _default_rotation_days

    days = _default_rotation_days()
    existing = get_by_name("default")
    if existing:
        policy = existing[0]
        if policy.days != days:
            policy.days = days
            database.commit()
        return policy
    return create(days=days, name="default")


def update(policy_id, **kwargs):
    """
    Updates a policy.
    :param policy_id:
    :param kwargs:
    :return:
    """
    policy = get(policy_id)

    for key, value in kwargs.items():
        setattr(policy, key, value)

    return database.update(policy)
