
pwqualitylista = open("/etc/security/pwquality.conf").readlines()

passwordlista = open("/etc/pam.d/password-auth").readlines()
passwordstring = open("/etc/pam.d/password-auth").read()

systemlista = open("/etc/pam.d/system-auth").readlines()
systemstring = open("/etc/pam.d/system-auth").read()


def pwquality(pwquality):
    listapw = []
    for i in pwquality:
        if "minlen =" in i:
            add = "minlen = 14 \n"
            listapw.append(add)
        elif "ocredit =" in i:
            add = "ocredit = -1 \n"
            listapw.append(add)
        elif "lcredit =" in i:
            add = "lcredit = -1 \n"
            listapw.append(add)
        elif "ucredit = " in i:
            add = "ucredit = -1 \n"
            listapw.append(add)
        elif "dcredit = " in i:
            add = "dcredit = -1 \n"
            listapw.append(add)
        elif "minclass = " in i:
            add = "minclass = 4 \n"
            listapw.append(add)
        else:
            listapw.append(i)
    return listapw


def constructor(lista):
    string = ""
    for i in lista:
        string += i
    return string


def verificar(lista, string, comprobar, agregar):
    lista2 = []
    if comprobar.replace(" ", "") in string.replace(" ",""):
        lista2 = lista
    else:
        for i in lista:
            if agregar.replace(" ", "") in i.replace(" ", ""):
                lista2.append(i)
                comprobar = comprobar + "\n"
                lista2.append(comprobar)
            else:
                lista2.append(i)
    return lista2


def sha5(lista):
    lista2 = []
    x = False
    sha512 = "password    sufficient    pam_unix.so"
    iter = 0
    for i in lista:
        if sha512.replace(" ", "") and "sha512" in i.replace(" ", ""):
            x = True
            break
        elif sha512.replace(" ", "") and "md5" in i.replace(" ",""):
            lista[iter] = lista[iter].replace("md5", "sha512")
            x = True
            break
        elif sha512.replace(" ", "") in i.replace(" ", ""):
            lista[iter] = lista[iter].replace("\n", "") + " sha512\n"
            x = True
            break
        iter += 1
    if not x:
        for i in lista:
            if "passwordrequisitepam_pwquality.so" in i.replace(" ", ""):
                lista2.append(i)
                lista2.append("password    sufficient    pam_unix.so try_first_pass use_authtok nullok sha512 shadow\n")
            else:
                lista2.append(i)
        lista = lista2
    return lista


def history(lista, string):
    lista2 = []
    hist = "password    required      pam_pwhistory.so"
    if hist.replace(" ", "") in string:
        if "remember=5" in string:
            pass
        else:
            for i in lista:
                if hist.replace(" ", "") in i.replace(" ", ""):
                    linea = i.replace("\n", "") + "remember=5\n"
                    lista2.append(linea)
                else:
                    lista2.append(i)
    else:
        for i in lista:
            if "passwordrequisite" in i.replace(" ",""):
                lista2.append(i)
                lista2.append("password    required      pam_pwhistory.so remember=5\n")
            else:
                lista2.append(i)
    return lista2


paso1 = verificar(passwordlista, passwordstring,
                  "auth        required      pam_faillock.so preauth silent audit deny=5 unlock_time=900",
                  "auth        required      pam_env.so")

paso2 = verificar(paso1, constructor(paso1),
                  "auth        [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900",
                  "auth        sufficient    pam_unix.so")

paso3 = verificar(paso2, constructor(paso2),
                  "account     required      pam_faillock.so",
                  "account     required      pam_unix.so")

paso5 = verificar(systemlista, systemstring,
                  "auth        required      pam_faillock.so preauth silent audit deny=5 unlock_time=900",
                  "auth        required      pam_env.so")

paso6 = verificar(paso5, constructor(paso5),
                  "auth        [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900",
                  "auth        sufficient    pam_unix.so")

paso7 = verificar(paso6, constructor(paso6),
                  "account     required      pam_faillock.so",
                  "account     required      pam_unix.so")

paso4 = history(sha5(paso7), constructor(sha5(paso7)))

paso8 = history(sha5(paso3), constructor(sha5(paso3)))

pw = constructor(pwquality(pwqualitylista))

system = constructor(paso8)

passwor = constructor(paso4)

with open("/etc/pam.d/password-auth", "w") as myfile:
    myfile.write(passwor)

with open("/etc/pam.d/system-auth", "w") as myfile:
    myfile.write(system)

with open("/etc/security/pwquality.conf", "w") as myfile:
    myfile.write(pw)