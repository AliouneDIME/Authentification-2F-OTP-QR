from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from listings.forms import UserProfileForm
from listings.models import UserProfile
from pyotp import OTP
from twilio.rest import Client
from pyotp import TOTP
import pyotp
import qrcode 
from io import BytesIO
import base64
from django.contrib import messages
from .forms import UpdatePasswordForm
from django.http import JsonResponse
from django.contrib.auth.forms import SetPasswordForm
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm

# Create your views here.

@login_required
def HomePage(request):
    return render(request, 'welcome.html', {})

def Register(request):
    if request.method == 'POST':
        fname = request.POST.get('fname')
        lname = request.POST.get('sname') 
        name = request.POST.get('uname')
        email = request.POST.get('email')
        password = request.POST.get('pass')
        phone_number = request.POST.get('phone_number')
        formatted_phone_number = f"{phone_number}"

        new_user = User.objects.create_user(username=name, email=email, password=password)
        new_user.first_name = fname
        new_user.last_name = lname
        new_user.save()
        
        # Stockez l'OTP associé à l'utilisateur
        UserProfile.objects.create(user=new_user, phone_number=formatted_phone_number)
        
        return redirect('login-page') 
        
    return render(request, 'register.html', {})

def validate_otp(request):
    if request.method == 'POST':
        otp_entered = request.POST.get('otp')
        user = request.user

        profile = UserProfile.objects.get(user=user)
        stored_otp = profile.stored_otp

        if otp_entered == stored_otp:
            # L'OTP est valide, continuez avec la logique appropriée
            return redirect('home-page')
        else:
            return HttpResponse('Invalid OTP')

    return render(request, 'validate_otp_page.html', {})

def generate_otp():
    # Générez une clé secrète aléatoire (base32)
    otp_secret = pyotp.random_base32()
    
    # Créez une instance TOTP avec la clé secrète
    totp = TOTP(otp_secret)
    
    # Générez le code OTP à six chiffres
    otp_code = totp.now()
    
    return otp_code


def send_otp_sms(phone_number, otp):
    # Configurez votre client Twilio avec vos clés d'authentification
    account_sid = ""
    auth_token = ""
    client = Client(account_sid, auth_token)

    message = client.messages.create(
        body=f"Votre OTP est : {otp}",
        from_="",
        to=phone_number
    )
    return message.sid

def Login(request):
    if request.method == 'POST':
        name = request.POST.get('uname')
        password = request.POST.get('pass')
        auth_option = request.POST.get('auth_option')  # Récupérez l'option d'authentification

        user = authenticate(request, username=name, password=password)
        if user is not None:
            # L'utilisateur est authentifié avec succès
            login(request, user)
            
            if auth_option == 'otp':
                # Générez l'OTP
                otp = generate_otp()
                
                # Enregistrez l'OTP dans le profil de l'utilisateur
                try:
                    profile = UserProfile.objects.get(user=user)
                    profile.auth_option = auth_option
                    profile.stored_otp = otp
                    profile.save()
                except UserProfile.DoesNotExist:
                    # Gérez le cas où le profil n'existe pas encore
                    pass
                
                # Envoyez l'OTP par SMS
                phone_number = profile.phone_number if hasattr(profile, 'phone_number') else None
                if phone_number:
                    send_otp_sms(phone_number, otp)
                
                return redirect('validate_otp_page')  # Redirigez vers la page de validation OTP
            
            elif auth_option == 'qr':
                # Générer les données spécifiques à l'utilisateur pour le QR code (par exemple, un jeton d'authentification)
                user_data = f"{user.username}-{user.email}"  # Personnalisez les données comme nécessaire

                # Créer un objet QRCode
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_L,
                    box_size=10,
                    border=4,
                )

                # Ajouter les données à l'objet QRCode
                qr.add_data(user_data)
                qr.make(fit=True)

                # Créer une image QRCode (PIL Image object)
                img = qr.make_image(fill_color="black", back_color="white")

                # Convertir l'image en base64
                buffer = BytesIO()
                img.save(buffer, format="PNG")
                image_data = buffer.getvalue()

                image_base64 = base64.b64encode(image_data).decode('utf-8')

                return render(request, 'QrCodePage.html', {'image_base64': image_base64})
            
            else:
                return HttpResponse('Option d\'authentification invalide')       
        
        else:
            return HttpResponse('Error, user does not exist')

    return render(request, 'login.html', {})


#Fonction de l'Authentfication par code QR
def QRCodePage(request):
    user = request.user
    try:
        profile = UserProfile.objects.get(user=user)
        otp_secret = profile.otp_secret  # Supposons que vous stockez la clé secrète OTP dans le profil

        # Générez le code QR en utilisant la clé secrète
        totp_uri = pyotp.TOTP(otp_secret).provisioning_uri(user.email, issuer_name="")
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(totp_uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        image_data = buffer.getvalue()
        
         # Stocker le code QR dans le profil de l'utilisateur
        profile.qr_code = image_data
        profile.save()

        return HttpResponse(image_data, content_type="image/png")
    except UserProfile.DoesNotExist:
        return HttpResponse("Votre profil n'existe pas encore.")


@login_required
def verify_qr_code(request):
    if request.method == 'POST' and request.is_ajax():
        provided_qr_code = request.POST.get('qrcode')

        user_profile = UserProfile.objects.filter(qr_code=provided_qr_code).first()

        if user_profile:
            return JsonResponse({'status': 'success', 'message': 'QR code is valid.'})
        else:
            return JsonResponse({'status': 'error', 'message': 'QR code is not authorized.'})

    return JsonResponse({'status': 'error', 'message': 'Invalid request.'})


@login_required
def validate_qr_code(request):

        return render(request, 'validate_qr_code.html')

@login_required
def compare_qr_codes(request):
    if request.method == 'POST' and request.is_ajax():
        provided_qr_code = request.POST.get('qrcode')

        user_profile = UserProfile.objects.get(user=request.user)
        expected_qr_code = user_profile.qr_code

        if provided_qr_code == expected_qr_code:
            return JsonResponse({'status': 'success', 'message': 'QR codes match!'})
        else:
            return JsonResponse({'status': 'error', 'message': 'QR codes do not match.'})
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request.'})

@login_required
def update_password(request):
    if request.method == 'POST':
        password = request.POST.get("pass")
        repassword = request.POST.get("repass")
        
        if repassword != password:
             messages.error(request, "Les deux mots de passe ne correspondent pas.")
        else:
            # Mettre à jour le mot de passe de l'utilisateur ici
            user = request.user
            user.set_password(password)
            user.save()

            # Vous pouvez ajouter un message de succès ici si vous le souhaitez
            messages.success(request, "Votre mot de passe a été changer avec succes!")
            
            return redirect('login-page')  # Rediriger vers la page de profil de l'utilisateur

    return render(request, 'update_password.html')

def forgot_password(request):
    if request.method == "POST":
        email = request.POST.get("email")
        user = User.objects.filter(email=email).first()

        if user:
            return redirect('update_password')
        else:
            return HttpResponse("Votre email n'existe pas! Veuillez vous inscrire.")

    return render(request, 'forgot_password.html')
    

def logoutuser(request):
    logout(request)
    return redirect('login-page')

def test(request):
    return render(request, 'welcome.html', {})