"""DRF permission classes for the django-waf API.

See the module docstring in ``api/serializers.py`` for why a plain
``rest_framework`` import is safe here.
"""

from __future__ import annotations

from rest_framework.permissions import BasePermission


class IsWafAdmin(BasePermission):
    """Grants access to superusers, or staff users with rule-management rights.

    Matches the existing staff-dashboard access model in ``django_waf.views``
    (superuser or staff), narrowed for write endpoints by requiring the
    ``django_waf.change_blockrule`` permission on non-superuser staff.
    """

    def has_permission(self, request, view) -> bool:
        user = request.user
        if not (user and user.is_authenticated):
            return False
        if user.is_superuser:
            return True
        return bool(user.is_staff and user.has_perm("django_waf.change_blockrule"))
