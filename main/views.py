from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from sympy import *


def loginView(request):
    context = {
        'page_title': 'Login',
    }
    if request.method == 'GET':
        if request.user.is_authenticated == True:
            return redirect('index')
        else:
            return render(request, 'login.html', context)
    elif request.method == "POST":
        username_login = request.POST['username']
        password_login = request.POST['password']

        user = authenticate(request, username=username_login, password=password_login)
        if user is not None:
            login(request, user)
            return redirect('index')
        else:
            messages.add_message(request, messages.ERROR,
                                 'Username atau password anda salah, silahkan masukkan dengan benar!')
            return redirect('login')


def logoutView(request):
    username_login = request.user.username
    context = {
        'page_title': 'Logout',
    }
    if request.method == "POST":
        if request.POST["logout"] == "Iya, Saya ingin logout":
            if ssim.objects.filter(username=username_login).exists() and crypto.objects.filter(
                    username=username_login).exists():
                ssim.objects.filter(username=username_login).delete()
                crypto.objects.filter(username=username_login).delete()
                logout(request)
                return redirect('login')
            elif ssim.objects.filter(username=username_login).exists():
                ssim.objects.filter(username=username_login).delete()
                logout(request)
                return redirect('login')
            elif crypto.objects.filter(username=username_login).exists():
                crypto.objects.filter(username=username_login).delete()
                logout(request)
                return redirect('login')
            else:
                logout(request)
                return redirect('login')
        elif request.POST["logout"] == "Tidak, Batalkan logout":
            return redirect('index')
    elif request.method == 'GET':
        if request.user.is_authenticated == True:
            return render(request, 'logout.html', context)
        else:
            return redirect('login')


def registerView(request):
    context = {
        'page_title': 'Register',
    }
    if request.method == "POST":
        username_register = request.POST['username']
        email_register = request.POST['email']
        password_register = request.POST['password']
        if User.objects.filter(username=username_register).exists():
            messages.add_message(request, messages.ERROR,
                                 'Username telah digunakan, silahkan menggunakan Username yang lain!')
            return redirect('register')
        elif User.objects.filter(email=email_register).exists():
            messages.add_message(request, messages.ERROR,
                                 'Email telah digunakan, silahkan menggunakan Email yang lain!')
            return redirect('register')
        else:
            messages.add_message(request, messages.ERROR, 'Akun berhasil dibuat, silahkan login menggunakan akun anda!')
            user = User.objects.create_user(username=username_register, email=email_register,
                                            password=password_register)
            return redirect('login')

    return render(request, 'register.html', context)


def pageimage(request):
    return render(request, 'image.html')


def index(request):
    context = {
        'judul': 'ini Judul',
        'content': 'ini content',

    }
    user = None
    if request.method == 'POST':
        if request.POST['fungsi'] == 'enkripsi':
            if request.POST['algoritma'] == 'cc':
                context['pesan'] = request.POST['pesan']
                context['kunciangka'] = request.POST['kunciangka']
                x = request.POST['pesan']
                n = int(request.POST['kunciangka'])
                c = ''
                t = len(x)
                for i in range(0, t):
                    if ord(x[i]) >= 65 and ord(x[i]) <= 90:
                        p = (ord(x[i]) - 65 + n) % 26
                        y = p + 65
                        ct = chr(y)
                    elif ord(x[i]) >= 97 and ord(x[i]) <= 122:
                        p = (ord(x[i]) - 97 + n) % 26
                        y = p + 97
                        ct = chr(y)
                    elif x[i] == ' ':
                        ct = ' '
                    c = c + ct
                context['hasil'] = c
            elif request.POST['algoritma'] == 'vc':
                teks = request.POST['pesan']
                kunciteks = request.POST['kunciteks']
                context['pesan'] = request.POST['pesan']
                context['kunciteks'] = request.POST['kunciteks']
                HURUF = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                ubah = []
                kunciIndex = 0
                kunciteks = kunciteks.upper()

                for symbol in teks:
                    # akan dilakukan pada seluruh karakter dalam pesan
                    nomor = HURUF.find(symbol.upper())
                    if nomor != -1:  # -1 berarti symbol.upper() tidak ditemukan didalam HURUF
                        nomor += HURUF.find(kunciteks[kunciIndex])  # tambahkan jika dienkripsi
                        nomor %= len(HURUF)

                        # tambahkan pada hasil symbol enkrip/dekrip yang sudah diubahkan
                        if symbol.isupper():
                            ubah.append(HURUF[nomor])
                        elif symbol.islower():
                            ubah.append(HURUF[nomor].lower())

                        kunciIndex += 1
                        # ubah kunci yang akan dipakai selanjutnya
                        if kunciIndex == len(kunciteks):
                            kunciIndex = 0

                    else:
                        # symbol tidak berada pada HURUF, maka tambahkan hal tersebut dan ubahkan
                        ubah.append(symbol)
                context['hasil'] = ''.join(ubah)
            elif request.POST['algoritma'] == 'tc':
                context['pesan'] = request.POST['pesan']
                context['kunciangka'] = request.POST['kunciangka']
                teks = request.POST['pesan']
                kunci = int(request.POST['kunciangka'])
                c = ''
                p = len(teks)
                while p % kunci > 0:
                    teks = teks + 'x'
                    p = len(teks)
                n = p // kunci
                for i in range(kunci):
                    for j in range(n):
                        c = c + teks[i + j * kunci]
                context['hasil'] = c
            elif request.POST['algoritma'] == 'se':
                context['pesan'] = request.POST['pesan']
                context['kunciangka'] = request.POST['kunciangka']
                context['kuncikedua'] = request.POST['kuncikedua']
                teks = request.POST['pesan']
                n = int(request.POST['kunciangka'])
                kunci = int(request.POST['kuncikedua'])
                c = ''
                p = len(teks)
                while p % kunci > 0:
                    teks = teks + 'x'
                    p = len(teks)
                s = p // kunci
                for i in range(kunci):
                    for j in range(s):
                        c = c + teks[i + j * kunci]
                t = len(c)
                x = c
                q = ''
                for r in range(0, t):
                    if ord(x[r]) >= 65 and ord(x[r]) <= 90:
                        z = (ord(x[r]) - 65 + n) % 26
                        y = z + 65
                        ct = chr(y)
                    elif ord(x[r]) >= 97 and ord(x[r]) <= 122:
                        z = (ord(x[r]) - 97 + n) % 26
                        y = z + 97
                        ct = chr(y)
                    elif x[r] == ' ':
                        ct = ' '
                    q = q + ct
                context['hasil'] = q
            elif request.POST['algoritma'] == 'hc':
                context['pesan'] = request.POST['pesan']
                p = request.POST['pesan']
                c = ''
                i = 0
                t = Matrix(([2, 1], [5, 3]))
                n = 0
                q = ''
                while i < len(p):
                    if ord(p[i]) != 32:
                        i = i + 1
                        n = n + 1
                        q = q + p[i - 1]
                    else:
                        if n % 2 == 0:
                            i = i + 1
                            q = q + p[i - 1]
                        else:
                            n = 0
                            i = i + 1
                            q = q + 'x' + p[i - 1]
                i = 0
                p = q
                n = 0
                while i < len(p):
                    if ord(p[i]) != 32:
                        i = i + 1
                        n = n + 1
                    else:
                        i = i + 1
                if n % 2 == 0:
                    p = p
                else:
                    p = p + 'x'
                i = 0
                while i < len(p):
                    if ord(p[i]) >= 65 and ord(p[i]) <= 90:
                        P = Matrix((ord(p[i]) - 65, ord(p[i + 1]) - 65))
                        C = t * P
                        c = c + chr(((C[0]) % 26) + 65) + chr(((C[1]) % 26) + 65)
                        i = i + 2
                    elif ord(p[i]) >= 97 and ord(p[i]) <= 122:
                        P = Matrix((ord(p[i]) - 97, ord(p[i + 1]) - 97))
                        C = t * P
                        c = c + chr(((C[0]) % 26) + 97) + chr(((C[1]) % 26) + 97)
                        i = i + 2
                    elif ord(p[i]) == 32:
                        c = c + ' '
                        i = i + 1
                context['hasil'] = c
        elif request.POST['fungsi'] == 'deskripsi':
            if request.POST['algoritma'] == 'cc':
                context['pesan'] = request.POST['pesan']
                context['kunciangka'] = request.POST['kunciangka']
                c = request.POST['pesan']
                k = int(request.POST['kunciangka'])
                p = ''
                t = len(c)
                for i in range(0, t):
                    if ord(c[i]) >= 65 and ord(c[i]) <= 90:
                        q = (ord(c[i]) - 65 - k) % 26
                        y = q + 65
                        ct = chr(y)
                    elif ord(c[i]) >= 97 and ord(c[i]) <= 122:
                        q = (ord(c[i]) - 97 - k) % 26
                        y = q + 97
                        ct = chr(y)
                    elif c[i] == ' ':
                        ct = ' '
                    p = p + ct
                context['hasil'] = p
            elif request.POST['algoritma'] == 'vc':
                teks = request.POST['pesan']
                kunciteks = request.POST['kunciteks']
                context['pesan'] = request.POST['pesan']
                context['kunciteks'] = request.POST['kunciteks']
                HURUF = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                ubah = []
                kunciIndex = 0
                kunciteks = kunciteks.upper()

                for symbol in teks:
                    # akan dilakukan pada seluruh karakter dalam pesan
                    nomor = HURUF.find(symbol.upper())
                    if nomor != -1:  # -1 berarti symbol.upper() tidak ditemukan didalam HURUF
                        nomor -= HURUF.find(kunciteks[kunciIndex])  # tambahkan jika dienkripsi
                        nomor %= len(HURUF)

                        # tambahkan pada hasil symbol enkrip/dekrip yang sudah diubahkan
                        if symbol.isupper():
                            ubah.append(HURUF[nomor])
                        elif symbol.islower():
                            ubah.append(HURUF[nomor].lower())

                        kunciIndex += 1
                        # ubah kunci yang akan dipakai selanjutnya
                        if kunciIndex == len(kunciteks):
                            kunciIndex = 0

                    else:
                        # symbol tidak berada pada HURUF, maka tambahkan hal tersebut dan ubahkan
                        ubah.append(symbol)
                context['hasil'] = ''.join(ubah)
            elif request.POST['algoritma'] == 'tc':
                context['pesan'] = request.POST['pesan']
                context['kunciangka'] = request.POST['kunciangka']
                enc = request.POST['pesan']
                kunci = int(request.POST['kunciangka'])
                c = ''
                p = len(enc)
                kunci = p // kunci
                p = len(enc)
                n = p // kunci
                for i in range(kunci):
                    for j in range(n):
                        c = c + enc[i + j * kunci]
                context['hasil'] = c
            elif request.POST['algoritma'] == 'se':
                context['pesan'] = request.POST['pesan']
                context['kunciangka'] = request.POST['kunciangka']
                context['kuncikedua'] = request.POST['kuncikedua']
                enc = request.POST['pesan']
                k = int(request.POST['kunciangka'])
                kunci = int(request.POST['kuncikedua'])
                p = ''
                c = enc
                t = len(enc)
                for i in range(0, t):
                    if ord(c[i]) >= 65 and ord(c[i]) <= 90:
                        q = (ord(c[i]) - 65 - k) % 26
                        y = q + 65
                        ct = chr(y)
                    elif ord(c[i]) >= 97 and ord(c[i]) <= 122:
                        q = (ord(c[i]) - 97 - k) % 26
                        y = q + 97
                        ct = chr(y)
                    elif c[i] == ' ':
                        ct = ' '
                    p = p + ct
                c = ''
                x = len(p)
                kunci = x // kunci
                x = len(p)
                n = x // kunci
                for i in range(kunci):
                    for j in range(n):
                        c = c + p[i + j * kunci]
                context['hasil'] = c
            elif request.POST['algoritma'] == 'hc':
                context['pesan'] = request.POST['pesan']
                p = request.POST['pesan']
                c = ''
                i = 0
                t = Matrix(([2, 1], [5, 3]))
                n = 0
                q = ''
                while i < len(p):
                    if ord(p[i]) != 32:
                        i = i + 1
                        n = n + 1
                        q = q + p[i - 1]
                    else:
                        if n % 2 == 0:
                            i = i + 1
                            q = q + p[i - 1]
                        else:
                            n = 0
                            i = i + 1
                            q = q + 'x' + p[i - 1]
                i = 0
                p = q
                n = 0
                while i < len(p):
                    if ord(p[i]) != 32:
                        i = i + 1
                        n = n + 1
                    else:
                        i = i + 1
                if n % 2 == 0:
                    p = p
                else:
                    p = p + 'x'
                i = 0
                while i < len(p):
                    if ord(p[i]) >= 65 and ord(p[i]) <= 90:
                        P = Matrix((ord(p[i]) - 65, ord(p[i + 1]) - 65))
                        C = t.inv() * P
                        c = c + chr(((C[0]) % 26) + 65) + chr(((C[1]) % 26) + 65)
                        i = i + 2
                    elif ord(p[i]) >= 97 and ord(p[i]) <= 122:
                        P = Matrix((ord(p[i]) - 97, ord(p[i + 1]) - 97))
                        C = t.inv() * P
                        c = c + chr(((C[0]) % 26) + 97) + chr(((C[1]) % 26) + 97)
                        i = i + 2
                    elif ord(p[i]) == 32:
                        c = c + ' '
                        i = i + 1
                context['hasil'] = c
        return render(request, 'index2.html', context)
    elif request.method == 'GET':
        return render(request, 'index2.html', context)





