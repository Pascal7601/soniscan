from django import forms

from . import services


class SignupForm(forms.Form):
    """Extra sign-up fields. allauth merges these into the sign-up API (ACCOUNT_SIGNUP_FORM_CLASS)
    and calls signup() once the user row exists."""

    organisation_name = forms.CharField(min_length=2, max_length=200, strip=True)
    display_name = forms.CharField(max_length=200, required=False, strip=True)

    def signup(self, request, user) -> None:
        display_name = self.cleaned_data.get("display_name", "")
        if display_name:
            user.display_name = display_name
            user.save(update_fields=["display_name"])
        services.ensure_organisation(user=user, name=self.cleaned_data["organisation_name"])