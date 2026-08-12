"""
.. module: lemur.policies.service
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""

from flask import current_app

from lemur import database
from lemur.policies.models import RotationPolicy


def sync_default_rotation_policy():
    """
    Create or update the named "default" RotationPolicy so its ``days`` matches
    the LEMUR_DEFAULT_ROTATION_INTERVAL config.

    Called at the start of the rotation-candidate query
    (``certificates.service.get_all_pending_reissue``) so the row is always in
    sync with config before it is used — a config change takes effect on the
    next rotation pass, regardless of whether any cert is created.
    """
    days = current_app.config.get("LEMUR_DEFAULT_ROTATION_INTERVAL", 60)
    policies = get_by_name("default")
    if not policies:
        return create(days=days, name="default")
    policy = policies[0]
    if policy.days != days:
        update(policy.id, days=days)
    return policy


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
