from django import forms
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import password_validation
from django.contrib.auth.models import User

class UserProfileForm(forms.Form):
    phone_number = forms.CharField(max_length=20)  # You can adjust the max_length as needed
    auth_option = forms.ChoiceField(choices=[('otp', 'OTP'), ('qr', 'QR Code')])  # Add the auth_option field


class UpdatePasswordForm(PasswordChangeForm):
    confirm_new_password = forms.CharField(
        label="Confirmer le nouveau mot de passe",
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
    )

    def clean_confirm_new_password(self):
        new_password1 = self.cleaned_data.get('new_password1')
        confirm_new_password = self.cleaned_data.get('confirm_new_password')
        if new_password1 and confirm_new_password and new_password1 != confirm_new_password:
            raise forms.ValidationError("Les nouveaux mots de passe ne correspondent pas.")
        return confirm_new_password

    def __init__(self, user, *args, **kwargs):
        super().__init__(user, *args, **kwargs)
        # Ajouter ici des validations personnalisées pour le nouveau mot de passe si nécessaire

        # Par exemple, pour appliquer les règles de validation de Django pour les mots de passe :
        self.fields['new_password1'].validators = password_validation.password_validators_help_texts()

    class Meta:
        model = User
        fields = []