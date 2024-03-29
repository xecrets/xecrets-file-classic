;//
;//	Xecrets File Classic - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
;//	Server or Web Storage of Document Files.
;//
;//	Copyright (C) 2006-2023 Svante Seleborg/Axantum Software AB, All rights reserved.
;//
;// *** NOTE TO TRANSLATORS: You must be aware that by translating texts here, you are
;// transferring the copyright to the above copyright holder, and allowing the results
;// to be published under the GNU General Public License. You should also
;// acknowledge the fact that the result of the translation may be used in other contexts,
;// including commercial licensed software, in addition to the GNU GPL release.
;//
;// *** TRANSLATION INSTRUCTIONS - READ CAREFULLY ***
;//
;// Try to keep the texts of the approximate same lengths as the other languages.
;// Try to use 'Windows' vocabulary for words like 'Cancel', 'OK', 'File' etc.
;// Please do not do any reorganization, clean-up or changes to the format - it'll make it harder to merge.
;// There are some texts referring to 'activation' and 'license' etc. Xecrets File Classic is free software, but
;// it is also used to demonstrate a digital signuature based licensing scheme. Xecrets File Classic will stay free.
;// Only use a raw text editor that fully supports Unicode UTF-16 encoding, such as Notepad or Visual Studio.
;//
;//	This program is free software; you can redistribute it and/or modify it under the terms
;//	of the GNU General Public License as published by the Free Software Foundation;
;//	either version 2 of the License, or (at your option) any later version.
;//
;//	This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
;//	without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
;//	See the GNU General Public License for more details.
;//
;//	You should have received a copy of the GNU General Public License along with this program;
;//	if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
;//	Boston, MA 02111-1307 USA
;//
;//	The author may be reached at mailto:support@axantum.com and http://www.axantum.com
;//----
;//	XecretsFileTexts.mc				Messages in all languages
;//
;//	E-mail							YYYY-MM-DD				Reason
;//	support@axantum.com			2001					Initial
;//                                 2002-04-17				German Version - Juergen Nieveler, Thomas Schmidt
;//									2002-07-23				Spanish Version - Carlos Fuentes
;//									2002-08-11				Rel 1.2
;//									2002-09-22				Italian Version - Stefano Paganini
;//                                 2004-03-30              Spanish new version - Jacobo Fortuny Ayuso
;//	                                2010-03-03              Brazilian Portuguese - Wagner Bellato
;//                                 2010-03-26              Polish - Piotr Drozdowski
;//                                 2010-11-23              Russian - Sergey Stenin, stenser funnya mail.ru
;//                                 2012-01-31              New Dutch version - Ron van de Crommert
;//                                 2012-09-22              Czech - Miroslav Geisselreiter
;//
;// Note to self: A good reg-exp is: Language=ENU\n(^.*\n)@^\.
;// Other note to self: AddLanguage.vb is good for adding languages.
;// More: You must define a new entry, INF_MENU_language, with the name of the language itself.
;// Also: Update the shell extension with the appropriate menu selection choice for the new language.
;// And: http://l10n.kde.org/ is a great site for localization info.
;// See: http://msdn.microsoft.com/en-us/library/dd318693(VS.85).aspx for Language Identifier Constants and Strings
;//

;// Chinese (PRC) (2052)
LanguageNames=(CHI=0x804:MSG00804)

;// Norwegian (Nynorsk) (2068, NSIS "Norwegian")
;// LanguageNames=(NON=0x814:MSG00814)

;// Danish (1030, NSIS "Danish")
LanguageNames=(DNK=0x406:MSG00406)

;// Finnish (1035, NSIS "Finnish")
LanguageNames=(FIN=0x40b:MSG0040B)

;// Polish (1045, NSIS "Polish")
LanguageNames=(POL=0x415:MSG00415)

;// German (Standard) (1031, NSIS "German")
LanguageNames=(DEU=0x407:MSG00407)

;// Dutch (Netherlands) (1043, NSIS "Dutch")
LanguageNames=(NLD=0x413:MSG00413)

;// Portugese (Portugal) (2070, NSIS "Portuguese")
LanguageNames=(PTG=0x816:MSG00816)

;// Portugese (Brazil)
LanguageNames=(PTB=0x416:MSG00416)

;// Hungarian (1038, NSIS "Hungarian")
LanguageNames=(HUN=0x40e:MSG0040E)

;// English (USA) (1033, NSIS "English")
LanguageNames=(ENU=0x409:MSG00409)

;// Spanish (Spain, Traditional Sort) (Use 40a to harmonize with Nsis-installer.) (1034, NSIS "Spanish")
LanguageNames=(ESN=0x40A:MSG0040A)

;// French (Standard) (1036, NSIS "French")
LanguageNames=(FRA=0x40C:MSG0040C)

;// Italian (Standard) (1040, NSIS "Italian")
LanguageNames=(ITA=0x410:MSG00410)

;// Norwegian (Bokmal) (1044, NSIS "Norwegian" (Is 1044, not 2068 as per comment in Norwegian.nsh))
LanguageNames=(NOR=0x414:MSG00414)

;// Swedish (1053, NSIS "Swedish")
LanguageNames=(SVE=0x41D:MSG0041D)

;// Russian (1049, NSIS "Russian")
LanguageNames=(RUS=0x419:MSG00419)

;// Czech (1029, NSIS "?")
LanguageNames=(CZH=0x405:MSG00405)

;//
;//
;//	%2 will be the system generated error.
;//	%3 should be output file name or other context related info given in the call
;//	%4 is the previously stored message that can be included in this message.
;//

MessageId=10
Severity=Informational
Facility=Application
SymbolicName=INF_FILE_TYPE_NAME
Language=ENU
%1 Security Wrapped
.
Language=SVE
%1 Skyddat
.
Language=DEU
%1 verschlüsselte Datei
.
Language=FRA
Fichier scellé %1
.
Language=ESN
Fichero cifrado %1
.
Language=ITA
File cifrato %1
.
Language=HUN
%1 Titkosított Fájl
.
Language=NOR
%1 Security Wrapped
.
Language=NLD
Door %1 versleuteld
.
Language=DNK
%1 Krypteret
.
Language=POL
%1 Zabezpieczanie danych
.
Language=CHI
%1 Security Wrapped
.
Language=PTG
%1 Security Wrapped
.
Language=PTB
%1 Arquivo encriptado
.
Language=RUS
Зашифровано %1
.
Language=CZH
%1 Bezpečně zašifrováno
.
Language=FIN
%1 salakoodattu tiedosto
.

MessageId=20
Severity=Error
Facility=Application
SymbolicName=MSG_SHELL_EXECUTE
Language=ENU
Failed to launch application for '%3', %2
.
Language=SVE
Kunde inte starta applikationen för '%3', %2
.
Language=DEU
Fehler beim Starten der Applikation für '%3', %2
.
Language=FRA
Erreur lors du lancement de l'application pour '%3', %2
.
Language=ESN
Error al lanzar la aplicación para '%3', %2
.
Language=ITA
Errore nel lanciare l'applicazione per '%3', %2
.
Language=HUN
Az alkalmazás indítása nem sikerült a(z) '%3' részére, %2
.
Language=NOR
Failed to launch application for '%3', %2
.
Language=NLD
Kan toepassing niet starten voor '%3'. %2
.
Language=DNK
Kunne ikke starte applikationen for '%3', %2
.
Language=POL
Nie można uruchomić aplikacji dla '%3', %2
.
Language=CHI
Failed to launch application for '%3', %2
.
Language=PTG
Failed to launch application for '%3', %2
.
Language=PTB
Erro ao executar aplicação para '%3', %2
.
Language=RUS
Не удалось запустить приложение для '%3', %2
.
Language=CZH
Chyba spuštění aplikace pro '%3', %2
.
Language=FIN
Sovellus tiedostoa '%3' varten ei käynnistynyt, %2
.

MessageId=30
Severity=Error
Facility=Application
SymbolicName=MSG_OPEN_LAUNCH
Language=ENU
Decrypt and launch of '%3' failed, %4
.
Language=SVE
Dekryptera och köra '%3' misslyckades, %4
.
Language=DEU
Entschlüsseln von '%3' fehlgeschlagen, %4
.
Language=FRA
Erreur lors du descellement et de l'ouverture de '%3', %4
.
Language=ESN
Fallo en el descifrado y ejecución de '%3', %4
.
Language=ITA
Decifratura e avvio di '%3' fallite, %4
.
Language=HUN
'%3' visszafejtése és indítása sikertelen, %4
.
Language=NOR
Decrypt and launch of '%3' failed, %4
.
Language=NLD
Ontsleutelen en starten van '%3' mislukt. %4
.
Language=DNK
Dekryptering og start af '%3' mislykkedes, %4
.
Language=POL
Błąd odszyfrowania i uruchomienia '%3', %4
.
Language=CHI
Decrypt and launch of '%3' failed, %4
.
Language=PTG
Decrypt and launch of '%3' failed, %4
.
Language=PTB
Falha ao decriptar e executar '%3', %4
.
Language=RUS
Не удалось расшифровать и запустить '%3', %4
.
Language=CZH
Dešifrování a spuštění '%3' selhalo, %4
.
Language=FIN
'%3':n purkaminen ja käynnistys epäonnistui, %4
.

MessageId=40
Severity=Error
Facility=Application
SymbolicName=MSG_OPEN
Language=ENU
Error opening file '%3', %2
.
Language=SVE
Fel vid öppnande av '%3', %2
.
Language=DEU
Fehler beim Öffnen der Datei '%3', %2
.
Language=FRA
Erreur lors de l'ouverture de '%3', %2
.
Language=ESN
Error abriendo el fichero '%3', %2
.
Language=ITA
Errore in apertura del file '%3', %2
.
Language=HUN
A(z) '%3' fájl megnyitása sikertelen, %2
.
Language=NOR
Error opening file '%3', %2
.
Language=NLD
Fout bij openen van bestand '%3'. %2
.
Language=DNK
Fejl ved åbning af '%3', %2
.
Language=POL
Błąd podczas otwierania pliku '%3', %2
.
Language=CHI
Error opening file '%3', %2
.
Language=PTG
Error opening file '%3', %2
.
Language=PTB
Erro ao abrir o arquivo '%3', %2
.
Language=RUS
Ошибка при открытии файла '%3', %2
.
Language=CZH
Chyba při otevírání souboru '%3', %2
.
Language=FIN
Virhe avattaessa tiedostoa '%3', %2
.

MessageId=50
Severity=Error
Facility=Application
SymbolicName=MSG_FILE_VERSION
Language=ENU
File saved in newer, unsupported, version. Please upgrade.
.
Language=SVE
Datat sparat med nyare version, uppgradera ditt program.
.
Language=DEU
Datei wurde mit aktuellerer, nicht unterstützter Version erstellt. Bitte upgraden.
.
Language=FRA
Les données ont été enregistrées dans une version postérieure non compatible. Vous devriez mettre à jour %1.
.
Language=ESN
La versión del fichero es posterior a la actual y no está soportada. Por favor, actualice el programa.
.
Language=ITA
Il file e' stato salvato con una nuova versione non supportata. Per favore, aggiornare il programma.
.
Language=HUN
A fájl újabb, nem támogatott verzióban készült. Kérem frissítse a programot.
.
Language=NOR
File saved in newer, unsupported, version. Please upgrade.
.
Language=NLD
Bestand opgeslagen met een nieuwere, niet-ondersteunde versie. Installeer de nieuwste softwareversie.
.
Language=DNK
Filen er gemt med en nyere udgave som ikke er understøttet. Opgrader venligst.
.
Language=POL
Plik zapisany jest w nowszej, nieobsługiwanej wersji. Przeprowadź aktualizację.
.
Language=CHI
File saved in newer, unsupported, version. Please upgrade.
.
Language=PTG
File saved in newer, unsupported, version. Please upgrade.
.
Language=PTB
A versão do arquivo está desatualizada e não é suportada. Por favor, atualize o programa.
.
Language=RUS
Файл сохранен более новой, неподдерживаемой версией. Пожалуйста, обновите.
.
Language=CZH
Soubor uložen v novější, nepodporované verzi. Prosím upgradujte.
.
Language=FIN
Tämä tiedosto on tallennettu uudemmalla versiolla. Päivitä ohjelma.
.

MessageId=60
Severity=Error
Facility=Application
SymbolicName=MSG_FILE_LENGTH
Language=ENU
Wrapped file format error or file may be damaged. The file is shorter or longer than indicated internally.
.
Language=SVE
Fel i filformat i den krypterade filen, eller så är den skadad. Filen är kortare eller längre än vad som indikeras internt.
.
Language=DEU
Dateiformatfehler oder beschädigte Datei. Datei ist kürzer oder länger als erwartet.
.
Language=FRA
Le fichier scellé est erroné ou endommagé : le fichier n'a pas la taille indiquée dans l'en-tête.
.
Language=ESN
Error en el formato o fichero dañado. El tamaño del archivo no coincide con el indicado internamente.
.
Language=ITA
Errore interno o file danneggiato. La dimensione del file non corrisponde a quanto indicato internamente.
.
Language=HUN
Titkosított fájl formátuma hibás, vagy a fájl sérült. A fájl rövidebb vagy hosszabb mint a belsõ bejegyzés szerint.
.
Language=NOR
Wrapped file format error or file may be damaged. The file is shorter or longer than indicated internally.
.
Language=NLD
Fout in bestandsformaat van wrapper of bestand beschadigd. Het bestand is korter of langer dan intern aangegeven.
.
Language=DNK
Formatet på den krypterede fil er forkert eller den er beskadiget. Filen er kortere eller længere end forventet.
.
Language=POL
Plik jest uszkodzony lub błędnie zaszyfrowany. Jego rzeczywista wielkość jest inna, niż na to wskazuje.
.
Language=CHI
Wrapped file format error or file may be damaged. The file is shorter or longer than indicated internally.
.
Language=PTG
Wrapped file format error or file may be damaged. The file is shorter or longer than indicated internally.
.
Language=PTB
Erro no formato do arquivo ou o arquivo está corrompido. O tamanho do arquivo não coincide com o indicado internamente.
.
Language=RUS
Ошибка формата упакованного файла или файл может быть поврежден. Файл короче или длиннее, чем указано внутри.
.
Language=CZH
Chyba zabaleného souboru nebo je soubor poškozen. Soubor je kratší nebo delší než je interně indikováno.
.
Language=FIN
Virhe tiedoston suojausmuodossa tai vahingoittunut tiedosto. Tiedosto on lyhempi tai pidempi kuin pitäisi.
.

MessageId=70
Severity=Error
Facility=Application
SymbolicName=MSG_MAKE_TMP
Language=ENU
Could not open %3 as temporary, %2
.
Language=SVE
Fel vid skapande av %3 som temporärfil, %2
.
Language=DEU
Fehler beim Öffnen von %3 als temporäre Datei, %2
.
Language=FRA
Le fichier '%3' n'a pas pu être ouvert comme fichier temporaire, %2
.
Language=ESN
No se puede abrir %3 como temporal, %2
.
Language=ITA
Non e' possibile aprire %3 come temporaneo, %2
.
Language=HUN
A %3 ideiglenes fájlként történõ megnyitása nem sikerült, %2
.
Language=NOR
Could not open %3 as temporary, %2
.
Language=NLD
Fout bij openen van '%3' als tijdelijk bestand. %2
.
Language=DNK
Kunne ikke åbne %3 som midlertidig fil, %2
.
Language=POL
Nie można utworzyć pliku tymczasowego z %3, %2
.
Language=CHI
Could not open %3 as temporary, %2
.
Language=PTG
Could not open %3 as temporary, %2
.
Language=PTB
Impossível abrir %3 como temporário, %2
.
Language=RUS
Не удалось открыть %3 как временный файл, %2
.
Language=CZH
Nelze otevřít %3 jako dočasný, %2
.
Language=FIN
%3 ei avautunut väliaikaistiedostona, %2
.

MessageId=80
Severity=Error
Facility=Application
SymbolicName=MSG_GET_TEMP
Language=ENU
Could not create temporary file in %3, %2
.
Language=SVE
Fel vid försök att skapa temporärfil %3, %2
.
Language=DEU
Konnte temporäre Datei nicht erstellen in %3, %2
.
Language=FRA
Erreur lors de la création d'un fichier temporaire dans %3, %2
.
Language=ESN
No se puede crear un fichero temporal en %3, %2
.
Language=ITA
Non e' possibile creare un file temporaneo in %3, %2
.
Language=HUN
Ideiglenes fájl létrehozása %3-ban sikertelen, %2
.
Language=NOR
Could not create temporary file in %3, %2
.
Language=NLD
Kan geen tijdelijk bestand maken in %3. %2
.
Language=DNK
Fejl ved forsøg på at skabe midlertidig fil i %3, %2
.
Language=POL
Nie można utworzyć pliku tymczasowego w %3, %2
.
Language=CHI
Could not create temporary file in %3, %2
.
Language=PTG
Could not create temporary file in %3, %2
.
Language=PTB
Impossível criar um arquivo temporário em %3, %2
.
Language=RUS
Не удалось создать временный файл в %3, %2
.
Language=CZH
Nelze vytvořit dočasný soubor v %3, %2
.
Language=FIN
Ei kyetty luomaan väliaikaistiedostoa kohteessa %3, %2
.

MessageId=90
Severity=Error
Facility=Application
SymbolicName=MSG_PAD_ERROR
Language=ENU
Decryption error in padding integrity check.
.
Language=SVE
Fel vid dekryptering - utfyllnadsinnehållet felaktigt.
.
Language=DEU
Entschlüsselungsfehler, Integritätsprüfung der Datei fehlgeschlagen.
.
Language=FRA
Erreur de décryptage : les données de remplissage sont erronées.
.
Language=ESN
Error de descifrado en la comprobación de los datos de relleno.
.
Language=ITA
Errore di decifratura nella verifica di integrità.
.
Language=HUN
Visszafejtési hiba a belsõ integritás ellenõrzés során.
.
Language=NOR
Decryption error in padding integrity check.
.
Language=NLD
Ontsleutelingsfout: bestandsintegriteit niet correct.
.
Language=DNK
Fejl under dekryptering -  udfyldningsindholdet er forkert.
.
Language=POL
Problem z odszyfrowaniem - podczas sprawdzania integralności pliku wystąpił błąd.
.
Language=CHI
Decryption error in padding integrity check.
.
Language=PTG
Decryption error in padding integrity check.
.
Language=PTB
Erro de decodificação: Falha na verificação de integridade dos dados.
.
Language=RUS
Ошибка расшифровки в проверке целостности заполнения.
.
Language=CZH
Chyba dešifrování během kontroly integrity.
.
Language=FIN
Purkuvirhe - täytesisältö virheellinen.
.

MessageId=100
Severity=Error
Facility=Application
SymbolicName=MSG_INVALID_GUID
Language=ENU
The file does not appear to be produced by %1. GUID mismatch.
.
Language=SVE
Filen verkar inte vara skapad av %1. Fel GUID.
.
Language=DEU
Die Datei wurden anscheinend nicht mit %1 erstellt. GUID ist falsch.
.
Language=FRA
Le fichier ne semble pas avoir été créé par %1 : le GUID est incohérent.
.
Language=ESN
El fichero no parece haber sido creado por %1. El GUID no coincide.
.
Language=ITA
Il file non pare essere stato creato da %1. Il GUID non coincide.
.
Language=HUN
Úgy tûnik, ezt a fájlt nem a %1 készítette. GUID eltérés.
.
Language=NOR
The file does not appear to be produced by %1. GUID mismatch.
.
Language=NLD
Het bestand lijkt niet gemaakt te zijn door %1. De GUID klopt niet.
.
Language=DNK
Filen ser ikke ud til at være skabt af %1. GUID uoverensstemmelse.
.
Language=POL
Plik nie wygląda na utworzony przez %1. Niezgodność identyfikatora GUID.
.
Language=CHI
The file does not appear to be produced by %1. GUID mismatch.
.
Language=PTG
The file does not appear to be produced by %1. GUID mismatch.
.
Language=PTB
O arquivo parece não ter sido criado por %1. GUID não coincide.
.
Language=RUS
Кажется, файл не был создан %1. Несоответствие GUID.
.
Language=CZH
Soubor nejspíš nebyl vytvořen %1. GUID nesouhlasí.
.
Language=FIN
Vaikuttaa siltä, että tiedostoa ei ole luotu %1-ohjelmalla. Väärä GUID.
.

MessageId=110
Severity=Error
Facility=Application
SymbolicName=MSG_FILE_FORMAT
Language=ENU
File format error - probably damaged or too large version difference.
.
Language=SVE
Filformatsfel - antagligen är den skadad, eller så är det för stor skillnad i versioner.
.
Language=DEU
Dateiformatfehler - möglicherweise beschädigt oder zu große Versionsunterschiede.
.
Language=FRA
Erreur de format de fichier : il est endommagé, ou la différence de versions est trop importante.
.
Language=ESN
Error en el formato del fichero - Puede estar dañado o existir una diferencia de versión muy grande.
.
Language=ITA
Errore nel formato del file - Probabilmente e' danneggiato o la differenza di versione e' troppo grande.
.
Language=HUN
Fájl formátum hiba - valószínû megsérült vagy túl nagy a verzió különbség.
.
Language=NOR
File format error - probably damaged or too large version difference.
.
Language=NLD
Fout in bestandsformaat. Het bestand is waarschijnlijk beschadigd of het versieverschil is te groot.
.
Language=DNK
Fejl i filformatet - sandsynligvis er den beskadiget eller der er for stort et spring mellem udgaverne.
.
Language=POL
Błąd formatu - plik jest prawdopodobnie uszkodzony lub istnieje zbyt duża różnica wersji.
.
Language=CHI
File format error - probably damaged or too large version difference.
.
Language=PTG
File format error - probably damaged or too large version difference.
.
Language=PTB
Erro no formato do arquivo - Provavelmente corrompido ou existe uma diferença de versão muito grande.
.
Language=RUS
Ошибка формата файла, возможно, поврежден или слишком большое отличие версии.
.
Language=CZH
Chyba formátu souboru - pravděpodobně poškozen nebo příliš rozdílné verze.
.
Language=FIN
Tiedoston muotovirhe - vahingoittunut tiedosto tai liian erilainen versio.
.

MessageId=120
Severity=Error
Facility=Application
SymbolicName=MSG_INVALID_HMAC
Language=ENU
File damaged or manipulated, integrity checksum (HMAC) error.
.
Language=SVE
Filformatsfel eller manipulerad fil. Kontrollsummefel (HMAC).
.
Language=DEU
Datei beschädigt oder manipuliert. Prüfsummenfehler (HMAC).
.
Language=FRA
Le fichier est endommagé ou a été modifié intentionnellement : le contrôle d'intégrité (HMAC) a échoué.
.
Language=ESN
Fichero dañado o manipulado. Error en la comprobación de la integridad (HMAC).
.
Language=ITA
File danneggiato o manipolato, errore nel controllo di integrità (HMAC).
.
Language=HUN
A fájl megsérült vagy szándékosan módosították, belsõ integritás (checksum - HMAC) hiba.
.
Language=NOR
File damaged or manipulated, integrity checksum (HMAC) error.
.
Language=NLD
Bestand beschadigd of aangepast. Fout in integriteitscontrolesom (HMAC).
.
Language=DNK
Filen er beskadiget eller manipuleret, fejl i kontrolsum (HMAC).
.
Language=POL
Plik jest uszkodzony, błąd sumy kontrolnej (HMAC).
.
Language=CHI
File damaged or manipulated, integrity checksum (HMAC) error.
.
Language=PTG
File damaged or manipulated, integrity checksum (HMAC) error.
.
Language=PTB
Arquivo corrompido ou em uso. Erro na integridade dos dados (HMAC).
.
Language=RUS
Файл поврежден или модифицирован, ошибка целостности контрольной суммы (HMAC).
.
Language=CZH
Soubor poškozen nebo změněn, chyba kontroly integrity (HMAC).
.
Language=FIN
Tiedosto on vahingoittunut tai sitä on sorkittu, ehjyystarkistussumma (HMAC) ei täsmää.
.

MessageId=130
Severity=Error
Facility=Application
SymbolicName=MSG_WRAP_ERROR
Language=ENU
An error occurred when security wrapping %3.
%4
.
Language=SVE
Ett fel uppstod under kryptering av %3.
%4
.
Language=DEU
Fehler beim Verschlüsseln von %3.
%4
.
Language=FRA
Une erreur est survenue lors du scellage de %3.
%4
.
Language=ESN
Error durante el cifrado de %3.
%4
.
Language=ITA
Si e' verificato un errore nella cifratura di %3.
%4
.
Language=HUN
Hiba történt a %3 titkosítása során.
%4
.
Language=NOR
An error occurred when security wrapping %3.
%4
.
Language=NLD
Er is een fout opgetreden bij het versleutelen van '%3'.
%4
.
Language=DNK
Der opstod en fejl under kryptering af %3.
%4
.
Language=POL
Wystąpił błąd podczas szyfrowania %3.
%4
.
Language=CHI
An error occurred when security wrapping %3.
%4
.
Language=PTG
An error occurred when security wrapping %3.
%4
.
Language=PTB
Erro durante a encriptação %3.
%4
.
Language=RUS
Произошла ошибка в процессе шифрования %3.
%4
.
Language=CZH
Došlo k chybě během procesu šifrování %3.
%4
.
Language=FIN
Virhe tiedostoa %3 salakoodattaessa.
%4
.

MessageId=140
Severity=Error
Facility=Application
SymbolicName=MSG_UNWRAP_ERROR
Language=ENU
An error occurred when unwrappping %3.
%4
.
Language=SVE
Ett fel uppstod under dekryptering av %3.
%4
.
Language=DEU
Fehler beim Entschlüsseln von %3.
%4
.
Language=FRA
Une erreur est survenue lors du déscellement de %3.
%4
.
Language=ESN
Error durante el descifrado de %3.
%4
.
Language=ITA
Si e' verificato un errore nella decifratura di %3.
%4
.
Language=HUN
Hiba történt a(z) %3 visszafejtése során.
%4
.
Language=NOR
An error occurred when unwrappping %3.
%4
.
Language=NLD
Er is een fout opgetreden bij het ontsleutelen van '%3'.
%4
.
Language=DNK
Der opstod en fejl under dekryptering af %3.
%4
.
Language=POL
Wystąpił błąd podczas odszyfrowywania %3.
%4
.
Language=CHI
An error occurred when unwrappping %3.
%4
.
Language=PTG
An error occurred when unwrappping %3.
%4
.
Language=PTB
Ocorreu um erro durante a decriptação %3.
%4
.
Language=RUS
Произошла ошибка во время распаковки %3.
%4
.
Language=CZH
Došlo k chybě při dešifrování %3.
%4
.
Language=FIN
Virhe tapahtui tiedoston %3 salakoodausta purettaessa.
%4
.

MessageId=160
Severity=Error
Facility=Application
SymbolicName=MSG_CREATE_REG_KEY
Language=ENU
Failed to add key '%3' to the registry, %2
.
Language=SVE
Fel vid uppdatering av registry-nyckel '%3', %2
.
Language=DEU
Konnte Schlüssel '%3' nicht in die Registry eintragen, %2
.
Language=FRA
Erreur lors de l'enregistrement de la clé '%3' dans le Registre, %2
.
Language=ESN
Error al guardar la clave '%3' en el registro, %2
.
Language=ITA
Errore nell'aggiungere la chiave '%3' al Registry, %2
.
Language=HUN
'%3' hozzáadása a registry-hez nem sikerült, %2
.
Language=NOR
Failed to add key '%3' to the registry, %2
.
Language=NLD
Sleutel '%3' kan niet aan het register worden toegevoegd. %2
.
Language=DNK
Fejl under indføring af nøglen '%3' i registret, %2
.
Language=POL
Nie można dodać klucza '%3' do rejestru, %2
.
Language=CHI
Failed to add key '%3' to the registry, %2
.
Language=PTG
Failed to add key '%3' to the registry, %2
.
Language=PTB
Erro ao criar a chave '%3' ao registro, %2
.
Language=RUS
Не удалось добавить в реестр ключ '%3', %2
.
Language=CZH
Selhalo přidání klíče '%3' do registru, %2
.
Language=FIN
Avainta '%3' ei saatu kirjoitettua rekisteriin, %2
.

MessageId=170
Severity=Error
Facility=Application
SymbolicName=MSG_INSTALL_ERROR
Language=ENU
Registry installation error, %4
(You must be an Administrator and have sufficient access to the registry to install)
.
Language=SVE
Fel vid installation i systemregistret, %4
(Du måste vara inloggad som Administratör och ha tillräckliga rättigheter vid installationen)
.
Language=DEU
Registry-Zugriffsfehler, %4
(Sie müssen Administrator-Rechte haben, um auf die Registry zuzugreifen)
.
Language=FRA
Erreur d'accès au Registre lors de l'installation, %4
(Vous devez être administrateur pour pouvoir modifier le Registre et installer %1).
.
Language=ESN
Error en la actualización del registro tras la instalación, %4
(Debe ser un Administrador y tener suficientes derechos de acceso al registro para realizar la instalación)
.
Language=ITA
Errore di installazione nel Registry, %4
(E' necessario essere Amministratore ed avere sufficienti permessi di accesso al Registry per installare)
.
Language=HUN
Registry telepítési hiba, %4
(Administratori jogokkal kell rendelkeznie a registry-hez a telepítéshez)
.
Language=NOR
Registry installation error, %4
(You must be an Administrator and have sufficient access to the registry to install)
.
Language=NLD
Fout bij installatie in register. %4
(U moet beheerder zijn en voldoende toegang tot het register hebben om de software te installeren.)
.
Language=DNK
Fejl under forsøg på at skrive i registret, %4
(Du skal være administrator og have tilstrækkelig rettigheder til registret for at installere)
.
Language=POL
Błąd instalacji, %4
(Musisz posiadać uprawnienia administratora oraz wystarczający dostęp do rejestru)
.
Language=CHI
Registry installation error, %4
(You must be an Administrator and have sufficient access to the registry to install)
.
Language=PTG
Registry installation error, %4
(You must be an Administrator and have sufficient access to the registry to install)
.
Language=PTB
Erro ao atualizar o registro, %4
(Você deve ter privilégios de administrador e direitos de acesso ao registro para realizar a instalação)
.
Language=RUS
Ошибка установки при доступе к реестру, %4
(Вы должны быть Администратором и иметь достаточно прав доступа к реестру для инсталляции)
.
Language=CZH
Chyba při zápisu do registru, %4
(Je nutné být Administrator a mít pro instalaci dostatečná práva k registru)
.
Language=FIN
Rekisterivirhe asennettaessa, %4
(Asentamiseen tarvitaan järjestelmänvalvojan oikeudet ja pääsy rekisteriin)
.

MessageId=180
Severity=Error
Facility=Application
SymbolicName=MSG_UNINSTALL_ERROR
Language=ENU
Un-installation error, %4
(You must be an Administrator and have sufficient access to the registry to un-install)
.
Language=SVE
Fel vid avinstallation, %4
(Du måste vara inloggad som Administratör och ha tillräckliga rättigheter vid avinstallationen)
.
Language=DEU
Deinstallationsfehler, %4
(Sie müssen Administrator-Rechte haben, um zum Deinstallieren auf die Registry zuzugreifen)
.
Language=FRA
Erreur d'accès au Registre lors de la désinstallation, %4
(Vous devez être administrateur pour pouvoir modifier le Registre et désinstaller %1).
.
Language=ESN
Error en la actualización del registro tras la desinstalación, %4
(Debe ser un Administrador y tener suficientes derechos de acceso al registro para realizar la desinstalación)
.
Language=ITA
Errore di disinstallazione, %4
(E' necessario essere Amministratore ed avere sufficienti permessi di accesso al Registry per disinstallare)
.
Language=HUN
Telepítés eltávolítási hiba, %4
(Adminisztrátori jogokkal kell rendelkeznie a registry-hez a telepítés eltávolításához)
.
Language=NOR
Un-installation error, %4
(You must be an Administrator and have sufficient access to the registry to un-install)
.
Language=NLD
Fout bij het verwijderen van de software. %4
(U moet beheerder zijn en voldoende toegang tot het register hebben om de software te verwijderen.)
.
Language=DNK
Afinstalleringsfejl, %4
(Du skal være administrator og have tilstrækkelige rettigheder til registret for at fjerne programmet)
.
Language=POL
Błąd deinstalacji, %4
(Musisz posiadać uprawnienia administratora i wystarczający dostęp do rejestru)
.
Language=CHI
Un-installation error, %4
(You must be an Administrator and have sufficient access to the registry to un-install)
.
Language=PTG
Un-installation error, %4
(You must be an Administrator and have sufficient access to the registry to un-install)
.
Language=PTB
Erro ao desinstalar, %4
(Você deve ter privilégios de administrador e direitos de acesso ao registro para realizar a desinstalação)
.
Language=RUS
Ошибка деинсталляции, %4
(Вы должны быть Администратором и иметь достаточно прав доступа к реестру для деинсталляции)
.
Language=CZH
Chyba odinstalace, %4
(Je nutné být Administrator a mít pro odinstalaci dostatečná práva k registru)
.
Language=FIN
Asennuksen purkuvirhe, %4
(Asennuksen purkamiseen tarvitaan järjestelmänvalvojan oikeudet ja pääsy rekisteriin)
.

MessageId=190
Severity=Error
Facility=Application
SymbolicName=MSG_UNKNOWN_OPT
Language=ENU
Unrecognized option switch '%2'.
.
Language=SVE
Okänt startval '%2'.
.
Language=DEU
Unbekannte Option '%2'.
.
Language=FRA
Paramètre de démarrage '%2' inconnu.
.
Language=ESN
Opción '%2' no reconocida.
.
Language=ITA
Opzione '%2' non riconosciuta.
.
Language=HUN
Ismeretlen opció kód '%2'.
.
Language=NOR
Unrecognized option switch '%2'.
.
Language=NLD
Onbekende optie '%2'.
.
Language=DNK
Ukendt parameter '%2'.
.
Language=POL
Nieznana opcja '%2'.
.
Language=CHI
Unrecognized option switch '%2'.
.
Language=PTG
Unrecognized option switch '%2'.
.
Language=PTB
Opção '%2' desconhecida.
.
Language=RUS
Нераспознанный параметр '%2'.
.
Language=CZH
Neznámý přepínač '%2'.
.
Language=FIN
Tuntematon komentokytkin '%2'.
.

MessageId=200
Severity=Error
Facility=Application
SymbolicName=MSG_CMD_LINE_OPEN
Language=ENU
Error executing request with file '%3', %4
.
Language=SVE
Fel vid programstart med filnamn '%3', %4
.
Language=DEU
Fehler beim Ausführen von '%3', %4
.
Language=FRA
Erreur de lancement du programme avec le fichier '%3', %4
.
Language=ESN
Error en una solicitud al archivo '%3', %4
.
Language=ITA
Errore nell'eseguire il file '%3', '%4'
.
Language=HUN
Hiba a kérés teljesítése során a(z) '%3' fájlnál, %4
.
Language=NOR
Error executing request with file '%3', %4
.
Language=NLD
Fout bij uitvoeren van verzoek met bestand '%3'. %4
.
Language=DNK
Fejl under start med filnavn '%3', %4
.
Language=POL
Błąd podczas wykonywania żądania do pliku '%3', %4
.
Language=CHI
Error executing request with file '%3', %4
.
Language=PTG
Error executing request with file '%3', %4
.
Language=PTB
Erro na solicitação do arquivo '%3', %4
.
Language=RUS
Ошибка выполнения запроса для файла '%3', %4
.
Language=CZH
Chyba při práci se souborem '%3', %4
.
Language=FIN
Virhe käynnistettäessä ohjelmaa tiedostolla '%3', %4
.

MessageId=210
Severity=Error
Facility=Application
SymbolicName=MSG_SYSTEM_CALL
Language=ENU
Error in system call to %3, %2
.
Language=SVE
Fel vid systemanrop %3, %2
.
Language=DEU
Fehler in Systemaufruf %3, %2
.
Language=FRA
Erreur lors de l'appel système %3, %2
.
Language=ESN
Error en la llamada al sistema a %3, %2
.
Language=ITA
Errore nella chiamata di sistema a %3, %2
.
Language=HUN
Hiba a rendszerhívás során %3 felé, %2
.
Language=NOR
Error in system call to %3, %2
.
Language=NLD
Fout in systeemaanroep naar %3. %2
.
Language=DNK
Fejl under systemkald til %3, %2
.
Language=POL
Błąd odwołania systemowego do %3, %2
.
Language=CHI
Error in system call to %3, %2
.
Language=PTG
Error in system call to %3, %2
.
Language=PTB
Erro na chamada ao sistema para %3, %2
.
Language=RUS
Ошибка в системном запросе к %3, %2
.
Language=CZH
Chyba systémového volání %3, %2
.
Language=FIN
Virhe %3-järjestelmäkutsussa, %2
.

MessageId=220
Severity=Error
Facility=Application
SymbolicName=MSG_WINMAIN
Language=ENU
Failed to startup %1.
%4
.
Language=SVE
Kan inte starta %1.
%4
.
Language=DEU
Fehler beim Starten von %1.
%4
.
Language=FRA
Erreur lors du démarrage d'%1.
%4
.
Language=ESN
Error al arrancar %1.
%4
.
Language=ITA
Errore nel lanciare %1.
%4
.
Language=HUN
A(z) %1 indítása nem sikerült.
%4
.
Language=NOR
Failed to startup %1.
%4
.
Language=NLD
Fout bij starten van %1.
%4
.
Language=DNK
Kan ikke starte %1.
%4
.
Language=POL
Nie można uruchomić %1.
%4
.
Language=CHI
Failed to startup %1.
%4
.
Language=PTG
Failed to startup %1.
%4
.
Language=PTB
Falha na inicialização %1.
%4
.
Language=RUS
Неудалось запустить %1.
%4
.
Language=CZH
Chyba spuštění %1.
%4
.
Language=FIN
1%:n käynnistäminen epäonnistui.
%4
.

MessageId=230
Severity=Error
Facility=Application
SymbolicName=MSG_NOTSAME
Language=ENU
The passphrases do not match. Please try again.
.
Language=SVE
Lösenorden är olika. Försök igen.
.
Language=DEU
Die Passwörter stimmen nicht überein. Bitte versuchen sie es noch einmal.
.
Language=FRA
Les clés ne correspondent pas. Veuillez réessayer.
.
Language=ESN
Las contraseñas no coinciden. Por favor, inténtelo otra vez.
.
Language=ITA
Le password non corrispondono. Per favore, ritentare.
.
Language=HUN
A kulcsmondatok nem azonosak. Próbálja újra.
.
Language=NOR
The passphrases do not match. Please try again.
.
Language=NLD
De wachtwoorden zijn niet gelijk. Probeer het nog eens.
.
Language=DNK
Kodeordene er ikke ens. Prøv igen.
.
Language=POL
Hasła nie zgadzają się. Spróbuj ponownie.
.
Language=CHI
The passphrases do not match. Please try again.
.
Language=PTG
The passphrases do not match. Please try again.
.
Language=PTB
As senhas não correspondem. Por favor, tente novamente.
.
Language=RUS
Пароли не совпадают. Попытайтесь снова.
.
Language=CZH
Hesla se neshodují. Prosím zkuste znovu.
.
Language=FIN
Salasanat eivät täsmää. Yritä uudelleen.
.

MessageId=240
Severity=Informational
Facility=Application
SymbolicName=INF_ENC_LEAD
Language=ENU
Encryption:
.
Language=SVE
Kryptering:
.
Language=DEU
Verschüsselung:
.
Language=FRA
Cryptage:
.
Language=ESN
Cifrado:
.
Language=ITA
Cifratura:
.
Language=HUN
Titkosítás:
.
Language=NOR
Encryption:
.
Language=NLD
Versleuteling:
.
Language=DNK
Kryptering:
.
Language=POL
Szyfrowanie:
.
Language=CHI
Encryption:
.
Language=PTG
Encryption:
.
Language=PTB
Encriptação:
.
Language=RUS
Шифрование:
.
Language=CZH
Šifrování:
.
Language=FIN
Salakoodaus:
.

MessageId=250
Severity=Informational
Facility=Application
SymbolicName=INF_COMP_LEAD
Language=ENU
Compression:
.
Language=SVE
Komprimering:
.
Language=DEU
Komprimierung:
.
Language=FRA
Compression:
.
Language=ESN
Compresión:
.
Language=ITA
Compressione:
.
Language=HUN
Tömörítés:
.
Language=NOR
Compression:
.
Language=NLD
Compressie:
.
Language=DNK
Komprimering:
.
Language=POL
Kompresja:
.
Language=CHI
Compression:
.
Language=PTG
Compression:
.
Language=PTB
Compressão:
.
Language=RUS
Сжатие:
.
Language=CZH
Komprese:
.
Language=FIN
Tiivistys:
.

MessageId=260
Severity=Informational
Facility=Application
SymbolicName=INF_AUTH_LEAD
Language=ENU
Integrity:
.
Language=SVE
Integritet:
.
Language=DEU
Integrität:
.
Language=FRA
Intégrité:
.
Language=ESN
Integridad:
.
Language=ITA
Integrità:
.
Language=HUN
Integritás:
.
Language=NOR
Integrity:
.
Language=NLD
Integriteit:
.
Language=DNK
Integritet:
.
Language=POL
Integralność:
.
Language=CHI
Integrity:
.
Language=PTG
Integrity:
.
Language=PTB
Integridade:
.
Language=RUS
Целостность:
.
Language=CZH
Integrita:
.
Language=FIN
Ehjyys:
.

MessageId=270
Severity=Informational
Facility=Application
SymbolicName=INF_RAND_LEAD
Language=ENU
PRNG:
.
Language=SVE
PRNG:
.
Language=DEU
PRNG:
.
Language=FRA
PRNG:
.
Language=ESN
PRNG:
.
Language=ITA
PRNG:
.
Language=HUN
PRNG:
.
Language=NOR
PRNG:
.
Language=NLD
PRNG:
.
Language=DNK
PRNG:
.
Language=POL
PRNG:
.
Language=CHI
PRNG:
.
Language=PTG
PRNG:
.
Language=PTB
PRNG:
.
Language=RUS
PRNG:
.
Language=CZH
PRNG:
.
Language=FIN
PRNG:
.

MessageId=280
Severity=Informational
Facility=Application
SymbolicName=INF_ENC
Language=ENU
FIPS 197 AES-128 CBC.
.
Language=SVE
FIPS 197 AES-128 CBC.
.
Language=DEU
FIPS 197 AES-128 CBC.
.
Language=FRA
FIPS 197 AES-128 CBC.
.
Language=ESN
FIPS 197 AES-128 CBC.
.
Language=ITA
FIPS 197 AES-128 CBC.
.
Language=HUN
FIPS 197 AES-128 CBC.
.
Language=NOR
FIPS 197 AES-128 CBC.
.
Language=NLD
FIPS 197 AES-128 CBC.
.
Language=DNK
FIPS 197 AES-128 CBC.
.
Language=POL
FIPS 197 AES-128 CBC.
.
Language=CHI
FIPS 197 AES-128 CBC.
.
Language=PTG
FIPS 197 AES-128 CBC.
.
Language=PTB
FIPS 197 AES-128 CBC.
.
Language=RUS
FIPS 197 AES-128 CBC.
.
Language=CZH
FIPS 197 AES-128 CBC.
.
Language=FIN
FIPS 197 AES-128 CBC.
.

MessageId=290
Severity=Informational
Facility=Application
SymbolicName=INF_COMP
Language=ENU
Zlib/Deflate, RFC1950 and RFC1951.
.
Language=SVE
Zlib/Deflate, RFC1950 och RFC1951.
.
Language=DEU
Zlib/Deflate, RFC1950 und RFC1951.
.
Language=FRA
Zlib/Deflate, RFC1950 et RFC1951.
.
Language=ESN
Zlib/Deflate, RFC1950 y RFC1951.
.
Language=ITA
Zlib/Deflate, RFC1950 e RFC1951.
.
Language=HUN
Zlib/Deflate, RFC1950 and RFC1951.
.
Language=NOR
Zlib/Deflate, RFC1950 and RFC1951.
.
Language=NLD
Zlib/Deflate, RFC1950 en RFC1951.
.
Language=DNK
Zlib/Deflate, RFC1950 og RFC1951.
.
Language=POL
Zlib/Deflate, RFC1950 oraz RFC1951.
.
Language=CHI
Zlib/Deflate, RFC1950 and RFC1951.
.
Language=PTG
Zlib/Deflate, RFC1950 and RFC1951.
.
Language=PTB
Zlib/Deflate, RFC1950 e RFC1951.
.
Language=RUS
Zlib/Deflate, RFC1950 e RFC1951.
.
Language=CZH
Zlib/Deflate, RFC1950 and RFC1951.
.
Language=FIN
Zlib/Deflate, RFC1950 and RFC1951.
.

MessageId=300
Severity=Informational
Facility=Application
SymbolicName=INF_AUTH
Language=ENU
HMAC-SHA1-128, RFC2104.
.
Language=SVE
HMAC-SHA1-128, RFC2104.
.
Language=DEU
HMAC-SHA1-128, RFC2104.
.
Language=FRA
HMAC-SHA1-128, RFC2104.
.
Language=ESN
HMAC-SHA1-128, RFC2104.
.
Language=ITA
HMAC-SHA1-128, RFC2104.
.
Language=HUN
HMAC-SHA1-128, RFC2104.
.
Language=NOR
HMAC-SHA1-128, RFC2104.
.
Language=NLD
HMAC-SHA1-128, RFC2104.
.
Language=DNK
HMAC-SHA1-128, RFC2104.
.
Language=POL
HMAC-SHA1-128, RFC2104.
.
Language=CHI
HMAC-SHA1-128, RFC2104.
.
Language=PTG
HMAC-SHA1-128, RFC2104.
.
Language=PTB
HMAC-SHA1-128, RFC2104.
.
Language=RUS
HMAC-SHA1-128, RFC2104.
.
Language=CZH
HMAC-SHA1-128, RFC2104.
.
Language=FIN
HMAC-SHA1-128, RFC2104.
.

MessageId=310
Severity=Informational
Facility=Application
SymbolicName=INF_RAND
Language=ENU
FIPS 186-2/SHA-1.
.
Language=SVE
FIPS 186-2/SHA-1.
.
Language=DEU
FIPS 186-2/SHA-1.
.
Language=FRA
FIPS 186-2/SHA-1.
.
Language=ESN
FIPS 186-2/SHA-1.
.
Language=ITA
FIPS 186-2/SHA-1.
.
Language=HUN
FIPS 186-2/SHA-1.
.
Language=NOR
FIPS 186-2/SHA-1.
.
Language=NLD
FIPS 186-2/SHA-1.
.
Language=DNK
FIPS 186-2/SHA-1.
.
Language=POL
FIPS 186-2/SHA-1.
.
Language=CHI
FIPS 186-2/SHA-1.
.
Language=PTG
FIPS 186-2/SHA-1.
.
Language=PTB
FIPS 186-2/SHA-1.
.
Language=RUS
FIPS 186-2/SHA-1.
.
Language=CZH
FIPS 186-2/SHA-1.
.
Language=FIN
FIPS 186-2/SHA-1.
.

MessageId=320
Severity=Informational
Facility=Application
SymbolicName=INF_ABOUT
Language=ENU
Compressing and Encrypting Wrapper and Application Launcher for Secure Local, Server or Web Storage of Document Files.
This program is licensed according to the agreement.
%n%n%2
%n%nAcknowledgements:
%nAES code by Vincent Rijmen, Antoon Bosselaers and Paulo Barreto.
%nSHA-1 code by Steve Reid, James H. Brown and Saul Kravitz.
%nZlib code by Jean-loup Gailly and Mark Adler.
.
Language=SVE
Kryptering, komprimering och applikationsstart i ett paket för säker lokal, central och webblagring av dokument.
Detta program är licensierat i enlighet med avtalet.
%n%n%2
%n%nBidrag:
%nAES kod av Vincent Rijmen, Antoon Bosselaers och Paulo Barreto.
%nSHA-1 kod av Steve Reid, James H. Brown och Saul Kravitz.
%nZlib kod av Jean-loup Gailly och Mark Adler.
.
Language=DEU
Komprimierungs- und Verschüsselungstool und Applikationsstarter für die sichere Speicherung von lokalen, serverbasierten oder webbasierten Dateien.
Dieses Programm wird entsprechend der Vereinbarung genehmigt.
%n%n%2
%n%nBeitrag:
%nAES Code von Vincent Rijmen, Antoon Bosselaers und Paulo Barreto.
%nSHA-1 Code von Steve Reid, James H. Brown und Saul Kravitz.
%nZlib Code von Jean-loup Gailly und Mark Adler.
.
Language=FRA
Outil de compression, cryptage et ouverture de fichiers pour stockage et partage sécurisés de documents électroniques.
Ce logiciel est livré d'après la licence.
%n%n%2
%n%nContributions:
%nCode AES par Vincent Rijmen, Antoon Bosselears et Paulo Barreto.
%nCode SHA-1 par Steve Reid, James H. Brown et Saul Kravitz.
%nCode Zlib par Jean-loup Gailly et Mark Adler.
.
Language=ESN
Cifrador, Compresor y Lanzador de Aplicaciones para el Almacenamiento Seguro de Archivos Locales, en Servidores o Alojamiento Web.
Este programa se licencia según el acuerdo.
%n%n%2
%nContribuciones:
%nCódigo AES por Vincent Rijmen, Antoon Bosselaers y Paulo Barreto.
%nCódigo SHA-1 por Steve Reid, James H. Brown y Saul Kravitz.
%nCódigo Zlib por Jean-loup Gailly y Mark Adler.
.
Language=ITA
Software di cifratura, compressione e lancio di applicazioni per la per la memorizzazione sicura di file e documenti locali, su server o siti Web.
Questo programma è autorizzato secondo l'accordo.
%n%n%2
%n%nRiconoscimenti:
%nCodice AES a cura di Vincent Rijmen, Antoon Bosselaers e Paulo Barreto.
%nCodice SHA-1 a cura di Steve Reid, James H. Brown e Saul Kravitz.
%nCodice Zlib a cura di Jean-loup Gailly e Mark Adler.
.
Language=HUN
Fájlok tömörítésére, titkosítására és visszafejtésére alkalmas eszköz, elektronikus dokumentumok biztonságos tárolásához és megosztásához.
A program a licenszmegállapodás alapján használható fel.
%n%n%2
%n%nAcknowledgements:
%nAES code by Vincent Rijmen, Antoon Bosselaers and Paulo Barreto.
%nSHA-1 code by Steve Reid, James H. Brown and Saul Kravitz.
%nZlib code by Jean-loup Gailly and Mark Adler.
.
Language=NOR
Compressing and Encrypting Wrapper and Application Launcher for Secure Local, Server or Web Storage of Document Files.
This program is licensed according to the agreement.
%n%n%2
%n%nAcknowledgements:
%nAES code by Vincent Rijmen, Antoon Bosselaers and Paulo Barreto.
%nSHA-1 code by Steve Reid, James H. Brown and Saul Kravitz.
%nZlib code by Jean-loup Gailly and Mark Adler.
.
Language=NLD
Compressie- en versleutelingswrapper en toepassingsstarter voor beveiligde opslag van gegevensbestanden op locale computers, servers of online.
De licentie voor dit programma is conform de overeenkomst.
%n%n%2
%n%nMet dank aan:
%nAES-code door Vincent Rijmen, Antoon Bosselaers en Paulo Barreto.
%nSHA-1-code door Steve Reid, James H. Brown en Saul Kravitz.
%nZlib-code door Jean-loup Gailly en Mark Adler.
.
Language=DNK
Komprimering og kryptering og programstarter i en pakke for sikker lokal-, server- og weblagring af dokumenter.
Dette program er licensieret i henhold til aftalen.
%n%n%2
%n%nBidrag:
%nAES kode af Vincent Rijmen, Antoon Bosselaers og Paulo Barreto.
%nSHA-1 kode af Steve Reid, James H. Brown og Saul Kravitz.
%nZlib kode af Jean-loup Gailly og Mark Adler.
.
Language=POL
Compressing and Encrypting Wrapper and Application Launcher for Secure Local, Server or Web Storage of Document Files.
Ten program jest licencjonowany zgodnie z umową.
%n%n%2
%n%nPodziękowania:
%nkod AES dla Vincent Rijmen, Antoon Bosselaers i Paulo Barreto.
%nkod SHA-1 dla Steve Reid, James H. Brown i Saul Kravitz.
%nkod Zlib dla Jean-loup Gailly i Mark Adler.
.
Language=CHI
Compressing and Encrypting Wrapper and Application Launcher for Secure Local, Server or Web Storage of Document Files.
This program is licensed according to the agreement.
%n%n%2
%n%nAcknowledgements:
%nAES code by Vincent Rijmen, Antoon Bosselaers and Paulo Barreto.
%nSHA-1 code by Steve Reid, James H. Brown and Saul Kravitz.
%nZlib code by Jean-loup Gailly and Mark Adler.
.
Language=PTG
Compressing and Encrypting Wrapper and Application Launcher for Secure Local, Server or Web Storage of Document Files.
This program is licensed according to the agreement.
%n%n%2
%n%nAcknowledgements:
%nAES code by Vincent Rijmen, Antoon Bosselaers and Paulo Barreto.
%nSHA-1 code by Steve Reid, James H. Brown and Saul Kravitz.
%nZlib code by Jean-loup Gailly and Mark Adler.
.
Language=PTB
Software de encriptação, compactação e armazenamento seguro de arquivos locais, em servidores ou web hosting.
Este programa é licenciado de acordo com a licença.
%n%n%2
%n%nAgradecimentos:
%nCódigo AES por Vincent Rijmen, Antoon Bosselaers e Paulo Barreto.
%nCódigo SHA-1 por Steve Reid, James H. Brown e Saul Kravitz.
%nCódigo Zlib por Jean-loup Gailly e Mark Adler.
.
Language=RUS
Сжатие, шифрование и запуск приложений для локальной безопасности, сервера или веб-хранения файлов документов.
Эта программа лицензируется в соответствии с соглашением.
%n%n%2
%n%nБлагодарности:
%nКод AES Vincent Rijmen, Antoon Bosselaers and Paulo Barreto.
%nКод SHA-1 Steve Reid, James H. Brown and Saul Kravitz.
%nКод Zlib Jean-loup Gailly and Mark Adler.
.
Language=CZH
Kompresní a šifrovací software pro bezpečné lokální, serverové nebo webové ukládání dokumentů.
Tento program je licencován na základě dohody.
%n%n%2
%n%nPoděkování:
%nAES kód Vincent Rijmen, Antoon Bosselaers a Paulo Barreto.
%nSHA-1 kód Steve Reid, James H. Brown a Saul Kravitz.
%nZlib kód Jean-loup Gailly a Mark Adler.
.
Language=FIN
Tiedontiivistys-, salakoodaus- sekä paketointisovellus tiedostojen turvalliseen tallentamiseen omalle koneelle, verkkopalvelimelle tai nettiin.
Tämä ohjelma lisensoidaan sopimuksen mukaan.
%n%n%2
%n%nKiitämme seuraavia:
%nAES-koodin osalta: Vincent Rijmen, Antoon Bosselaers ja Paulo Barreto.
%nSHA-1-koodin osalta: Steve Reidi, James H. Brown ja Saul Kravitz.
%nZlib-koodin osalta: Jean-loup Gailly ja Mark Adler.
.

MessageId=330
Severity=Informational
Facility=Application
SymbolicName=INF_PROP_SHEET_PAGE
Language=ENU
%1
.
Language=SVE
%1
.
Language=DEU
%1
.
Language=FRA
%1
.
Language=ESN
%1
.
Language=ITA
%1
.
Language=HUN
%1
.
Language=NOR
%1
.
Language=NLD
%1
.
Language=DNK
%1
.
Language=POL
%1
.
Language=CHI
%1
.
Language=PTG
%1
.
Language=PTB
%1
.
Language=RUS
%1
.
Language=CZH
%1
.
Language=FIN
%1
.

MessageId=340
Severity=Informational
Facility=Application
SymbolicName=INF_ENTER_PASS
Language=ENU
Enter passphrase
.
Language=SVE
Ange lösenord
.
Language=DEU
Passwort eingeben
.
Language=FRA
Entrez la clé
.
Language=ESN
Introduzca la contraseña
.
Language=ITA
Inserire la password
.
Language=HUN
Írja be a kulcsmondatot
.
Language=NOR
Enter passphrase
.
Language=NLD
Voer wachtwoord in
.
Language=DNK
Indtast kodeord
.
Language=POL
Podaj hasło
.
Language=CHI
Enter passphrase
.
Language=PTG
Enter passphrase
.
Language=PTB
Digite a senha
.
Language=RUS
Введите пароль
.
Language=CZH
Zadejte heslo
.
Language=FIN
Syötä salasana
.

MessageId=350
Severity=Informational
Facility=Application
SymbolicName=INF_REENTER_PASS
Language=ENU
Invalid passphrase! Please re-enter
.
Language=SVE
Fel lösenord! Försök igen
.
Language=DEU
Ungültiges Passwort! Bitte nochmal eingeben
.
Language=FRA
Clé incorrecte. Veuillez réessayer
.
Language=ESN
¡Contraseña inválida!. Introdúzcala de nuevo
.
Language=ITA
Password non valida! Per favore re-inserirla
.
Language=HUN
Nem megfelelõ kulcsmondat! Próbálja újra
.
Language=NOR
Invalid passphrase! Please re-enter
.
Language=NLD
Ongeldig wachtwoord! Voer het opnieuw in.
.
Language=DNK
Forkert kodeord! Prøv igen
.
Language=POL
Błędne hasło! Wprowadź ponownie
.
Language=CHI
Invalid passphrase! Please re-enter
.
Language=PTG
Invalid passphrase! Please re-enter
.
Language=PTB
Senha inválida! Por favor digite-a novamente
.
Language=RUS
Неверный пароль! Пожалуйста, повторите
.
Language=CZH
Chybné heslo či klíč! Prosím zadejte znovu
.
Language=FIN
Väärä salasana! Yritä uudelleen
.

MessageId=360
Severity=Informational
Facility=Application
SymbolicName=INF_ENTER_VERIFY
Language=ENU
Verify passphrase
.
Language=SVE
Bekräfta lösenord
.
Language=DEU
Passwort bestätigen
.
Language=FRA
Confirmez la clé
.
Language=ESN
Verifique la contraseña
.
Language=ITA
Verificare la password
.
Language=HUN
Kulcsmondat ellenõrzése
.
Language=NOR
Verify passphrase
.
Language=NLD
Bevestig wachtwoord
.
Language=DNK
Bekræft kodeord
.
Language=POL
Sprawdź hasło
.
Language=CHI
Verify passphrase
.
Language=PTG
Verify passphrase
.
Language=PTB
Confirmar senha
.
Language=RUS
Подтверждение пароля
.
Language=CZH
Potvrzení hesla
.
Language=FIN
Toista salasana
.

MessageId=370
Severity=Informational
Facility=Application
SymbolicName=INF_IDOK
Language=ENU
OK
.
Language=SVE
OK
.
Language=DEU
OK
.
Language=FRA
OK
.
Language=ESN
Aceptar
.
Language=ITA
OK
.
Language=HUN
Rendben
.
Language=NOR
OK
.
Language=NLD
OK
.
Language=DNK
OK
.
Language=POL
OK
.
Language=CHI
OK
.
Language=PTG
OK
.
Language=PTB
OK
.
Language=RUS
OK
.
Language=CZH
OK
.
Language=FIN
OK
.

MessageId=380
Severity=Informational
Facility=Application
SymbolicName=INF_IDCANCEL
Language=ENU
Cancel
.
Language=SVE
Avbryt
.
Language=DEU
Abbrechen
.
Language=FRA
Annuler
.
Language=ESN
Cancelar
.
Language=ITA
Annulla
.
Language=HUN
Mégsem
.
Language=NOR
Cancel
.
Language=NLD
Annuleren
.
Language=DNK
Annuller
.
Language=POL
Anuluj
.
Language=CHI
Cancel
.
Language=PTG
Cancel
.
Language=PTB
Cancelar
.
Language=RUS
Отмена
.
Language=CZH
Zrušit
.
Language=FIN
Peruuta
.

MessageId=390
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_OPEN
Language=ENU
Open
.
Language=SVE
Öppna
.
Language=DEU
Öffnen
.
Language=FRA
Ouvrir
.
Language=ESN
Abrir
.
Language=ITA
Apri
.
Language=HUN
Megnyitás
.
Language=NOR
Open
.
Language=NLD
Openen
.
Language=DNK
Åben
.
Language=POL
Otwórz
.
Language=CHI
Open
.
Language=PTG
Open
.
Language=PTB
Abrir
.
Language=RUS
Открыть
.
Language=CZH
Otevřít
.
Language=FIN
Avaa
.

MessageId=400
Severity=Informational
Facility=Application
SymbolicName=HLP_MENU_OPEN
Language=ENU
Decrypt and open document with associated application.
.
Language=SVE
Dekryptera och öppna dokumentet i sin applikation.
.
Language=DEU
Datei entschlüsseln und mit zugehöriger Anwendung öffnen.
.
Language=FRA
Décrypter et ouvrir avec l'application associée.
.
Language=ESN
Descifrar y abrir el documento con la aplicación asociada.
.
Language=ITA
Decifra e apri il documento con l'applicazione associata.
.
Language=HUN
Dokumentum visszafejtése és megnyitása a társított alkalmazással.
.
Language=NOR
Decrypt and open document with associated application.
.
Language=NLD
Bestand ontsleutelen en openen met bijbehorende toepassing.
.
Language=DNK
Dekrypter og åben med det tilknyttede program.
.
Language=POL
Odszyfruj i otwórz dokument za pomocą skojarzonej aplikacji.
.
Language=CHI
Decrypt and open document with associated application.
.
Language=PTG
Decrypt and open document with associated application.
.
Language=PTB
Decriptar e abrir o documento com o aplicativo associado.
.
Language=RUS
Расшифровать и открыть документ в ассоциированном приложении.
.
Language=CZH
Dešifrovat a otevřít dokument přidruženou aplikací.
.
Language=FIN
Purkaa salakoodauksen ja avaa asiakirjan siihen liitetyllä sovelluksella.
.

MessageId=410
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_WRAPZ
Language=ENU
Encrypt
.
Language=SVE
Kryptera
.
Language=DEU
Verschlüsseln
.
Language=FRA
Crypter
.
Language=ESN
Cifrar
.
Language=ITA
Cifrare
.
Language=HUN
Titkosítás
.
Language=NOR
Encrypt
.
Language=NLD
Versleutelen
.
Language=DNK
Krypter
.
Language=POL
Zaszyfruj
.
Language=CHI
Encrypt
.
Language=PTG
Encrypt
.
Language=PTB
Encriptar
.
Language=RUS
Шифровать
.
Language=CZH
Zašifrovat
.
Language=FIN
Salakoodaa
.

MessageId=420
Severity=Informational
Facility=Application
SymbolicName=HLP_MENU_WRAPZ
Language=ENU
First compress, then encrypt the document.
.
Language=SVE
Komprimera dokumentet först, kryptera det sedan.
.
Language=DEU
Datei zuerst komprimieren, dann verschlüsseln.
.
Language=FRA
Comprimer d'abord, puis crypter.
.
Language=ESN
Comprimir antes de cifrar el documento.
.
Language=ITA
Prima comprime poi cifra il documento.
.
Language=HUN
Elõször tömöríti, majd titkosítja a dokumentumot.
.
Language=NOR
First compress, then encrypt the document.
.
Language=NLD
Het bestand eerst comprimeren en daarna versleutelen.
.
Language=DNK
Komprimer dokumentet først og krypter bagefter.
.
Language=POL
Skompresuj, a następnie zaszyfruj dokument.
.
Language=CHI
First compress, then encrypt the document.
.
Language=PTG
First compress, then encrypt the document.
.
Language=PTB
Compactar antes de encriptar o documento.
.
Language=RUS
Сначала сжатие, затем шифрование документа.
.
Language=CZH
Nejdřív komprese, potom zašifrování dokumentu.
.
Language=FIN
Tiivistää asiakirjan ensin ja salakoodaa sen vasta sitten.
.

MessageId=427
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_WRAPZC
Language=ENU
Encrypt a copy
.
Language=SVE
Kryptera en kopia
.
Language=DEU
Kopie verschlüsseln
.
Language=FRA
Crypter et copier
.
Language=ESN
Cifrar y copiar
.
Language=ITA
Cifrare e copiare
.
Language=HUN
Titkosít és másol
.
Language=NOR
Encrypt a copy
.
Language=NLD
Kopie versleutelen
.
Language=DNK
Krypter en kopi
.
Language=POL
Zaszyfruj kopię
.
Language=CHI
Encrypt a copy
.
Language=PTG
Encrypt a copy
.
Language=PTB
Encriptar e copiar
.
Language=RUS
Шифровать копию
.
Language=CZH
Zašifrovat kopii
.
Language=FIN
Salakoodaa kopio
.

MessageId=428
Severity=Informational
Facility=Application
SymbolicName=HLP_MENU_WRAPZC
Language=ENU
First compress, then encrypt the document. Keep the original.
.
Language=SVE
Komprimera dokumentet först, kryptera det sedan. Behåll orginalet.
.
Language=DEU
Datei zuerst komprimieren, dann als kopie verschlüsseln.
.
Language=FRA
Comprimer d'abord, puis crypter et copier.
.
Language=ESN
Comprimir antes de cifrar y copiar el documento.
.
Language=ITA
Prima comprime poi cifra e copia il documento.
.
Language=HUN
Elõször tömöríti, majd titkosítja a dokumentumot. Eredetit megtartja.
.
Language=NOR
First compress, then encrypt the document. Keep the original.
.
Language=NLD
Het bestand eerst comprimeren en daarna versleutelen. Het origineel blijft behouden.
.
Language=DNK
Komprimer dokumentet først og krypter bagefter. Bevar originalen.
.
Language=POL
Skompresuj, następnie zaszyfruj dokument. Zachowaj oryginał.
.
Language=CHI
First compress, then encrypt the document. Keep the original.
.
Language=PTG
First compress, then encrypt the document. Keep the original.
.
Language=PTB
Compactar antes de encriptar o documento e manter o original.
.
Language=RUS
Сначала сжатие, затем шифрование документа. Оригинал сохраняется.
.
Language=CZH
Nejdřív komprese, potom zašifrování dokumentu. Zachovat originál.
.
Language=FIN
Tiivistää asiakirjan ensin ja vasta sitten salakoodaa sen. Säilyttää alkuperäisen.
.

MessageId=430
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_WRAP
Language=ENU
Encrypt only
.
Language=SVE
Kryptera endast
.
Language=DEU
Datei nur verschlüsseln
.
Language=FRA
Crypter uniquement
.
Language=ESN
Cifrar solamente
.
Language=ITA
Cifrare soltanto
.
Language=HUN
Csak titkosít
.
Language=NOR
Encrypt only
.
Language=NLD
Alleen versleutelen
.
Language=DNK
Kun kryptering
.
Language=POL
Tylko zaszyfruj
.
Language=CHI
Encrypt only
.
Language=PTG
Encrypt only
.
Language=PTB
Somente encriptar
.
Language=RUS
Только Шифровать
.
Language=CZH
Pouze zašifrování
.
Language=FIN
Ainoastaan salakoodaa
.

MessageId=440
Severity=Informational
Facility=Application
SymbolicName=HLP_MENU_WRAP
Language=ENU
Encrypt the document without compression.
.
Language=SVE
Kryptera dokumentet utan komprimering.
.
Language=DEU
Datei ohne Komprimierung verschlüsseln.
.
Language=FRA
Crypter sans compression.
.
Language=ESN
Cifrar el documento sin compresión.
.
Language=ITA
Cifrare il documento senza compressione.
.
Language=HUN
Titkosítja a dokumentumot tömörítés nélkül.
.
Language=NOR
Encrypt the document without compression.
.
Language=NLD
Het bestand zonder compressie versleutelen.
.
Language=DNK
Krypter dokumentet uden komprimering.
.
Language=POL
Zaszyfruj dokument bez użycia kompresji.
.
Language=CHI
Encrypt the document without compression.
.
Language=PTG
Encrypt the document without compression.
.
Language=PTB
Encriptar o documento sem compactar.
.
Language=RUS
Шифровать документ без сжатия.
.
Language=CZH
Zašifrovat dokument bez komprese.
.
Language=FIN
Salakoodaa asiakirjan sitä tiivistämättä.
.

MessageId=450
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_UNWRAP
Language=ENU
Decrypt
.
Language=SVE
Dekryptera
.
Language=DEU
Entschlüsseln
.
Language=FRA
Décrypter
.
Language=ESN
Descifrar
.
Language=ITA
Decifrare
.
Language=HUN
Visszafejt
.
Language=NOR
Decrypt
.
Language=NLD
Ontsleutelen
.
Language=DNK
Dekrypter
.
Language=POL
Odszyfruj
.
Language=CHI
Decrypt
.
Language=PTG
Decrypt
.
Language=PTB
Decriptar
.
Language=RUS
Расшифровать
.
Language=CZH
Dešifrovat
.
Language=FIN
Pura salakoodaus
.

MessageId=460
Severity=Informational
Facility=Application
SymbolicName=HLP_MENU_UNWRAP
Language=ENU
Decrypt the document and restore name and modification time.
.
Language=SVE
Dekryptera dokumentet och återställ namn och modifieringstid.
.
Language=DEU
Dokument entschlüsseln und Name sowie letzte Zugriffszeit wiederherstellen.
.
Language=FRA
Décrypter et restaurer nom et date de modification.
.
Language=ESN
Descifrar el documento y restaurar el nombre y la hora de modificación.
.
Language=ITA
Decifra il documento e ripristina il nome e l'ora di modifica.
.
Language=HUN
Visszafejti a dokumentumot majd visszaállítja a nevét és a módosítás dátumát.
.
Language=NOR
Decrypt the document and restore name and modification time.
.
Language=NLD
Het bestand ontsleutelen en de bestandsnaam en tijd van laatste wijziging herstellen.
.
Language=DNK
Dekrypter dokumentet og gendan ændringtidspunktet.
.
Language=POL
Odszyfruj dokument i odtwórz jego nazwę oraz datę modyfikacji.
.
Language=CHI
Decrypt the document and restore name and modification time.
.
Language=PTG
Decrypt the document and restore name and modification time.
.
Language=PTB
Decriptar o documento e restaurar o nome e a hora de modificação.
.
Language=RUS
Расшифровка документа, восстановление его имени и времени модификации.
.
Language=CZH
Dešifrovat dokument a obnovit jméno a čas změny.
.
Language=FIN
Purkaa asiakirjan salakoodauksen ja palauttaa sen nimen ja muokkausajankohdon.
.

MessageId=470
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_WIPE
Language=ENU
Shred and Delete
.
Language=SVE
Strimla och Ta Bort
.
Language=DEU
Datei löschen und vernichten
.
Language=FRA
Brouiller et supprimer
.
Language=ESN
Destruir datos y Borrar
.
Language=ITA
Cancella e rimuove completamente
.
Language=HUN
Megsemmisít
.
Language=NOR
Shred and Delete
.
Language=NLD
Vernietigen en verwijderen
.
Language=DNK
Overskriv og slet
.
Language=POL
Zniszcz i usuń
.
Language=CHI
Shred and Delete
.
Language=PTG
Shred and Delete
.
Language=PTB
Destruir e Deletar
.
Language=RUS
Уничтожить
.
Language=CZH
Bezpečně vymazat
.
Language=FIN
Tuhoa ja poista
.

MessageId=480
Severity=Informational
Facility=Application
SymbolicName=HLP_MENU_WIPE
Language=ENU
Overwrite the entire file with random data and then delete permanently.
.
Language=SVE
Skriv över hela filen med slumpmässigt data och ta sedan bort permanent.
.
Language=DEU
Datei mit Zufallsdaten überschreiben und anschließend endgültig löschen.
.
Language=FRA
Réécrire le fichier avec des données aléatoires puis supprimer définitivement.
.
Language=ESN
Sobreescribir todo el fichero con datos aleatorios y borrar permanentemente.
.
Language=ITA
Sovrascrive l'intero file con dati casuali e cancella in modo permanente.
.
Language=HUN
A teljes fájlt véletlenszerû adatokkal felülírja, majd véglegesen törli.
.
Language=NOR
Overwrite the entire file with random data and then delete permanently.
.
Language=NLD
Het gehele bestand met willekeurige gegevens overschrijven en vervolgens definitief verwijderen.
.
Language=DNK
Overskriv hele filen med tilfældige data og slet den permanent.
.
Language=POL
Nadpisz cały plik z użyciem losowych danych, a nastepnie trwale go usuń.
.
Language=CHI
Overwrite the entire file with random data and then delete permanently.
.
Language=PTG
Overwrite the entire file with random data and then delete permanently.
.
Language=PTB
Substituir o arquivo com dados aleatórios e então deletá-lo permanentemente.
.
Language=RUS
Перезапись всего файла случайными данными, затем окончательное его удаление.
.
Language=CZH
Přepsat celý soubor náhodnými daty a následně nenávratně odstranit.
.
Language=FIN
Kirjoittaa koko tiedoston päälle satunnaista tietoa ja poistaa sen sitten lopullisesti.
.

MessageId=490
Severity=Warning
Facility=Application
SymbolicName=WRN_DIR_NOT_EMPTY
Language=ENU
Error deleting directory '%2', %4 Please check and remove manually. It will be removed on next %1 start-up.
.
Language=SVE
Fel vid borttagning av filmapp '%2', %4 Vänligen kontrollera och rensa manuellt. Bortrensning sker automatiskt vid nästa start av %1.
.
Language=DEU
Fehler beim Löschen von Verzeichnis '%2', %4 Bitte prüfen und manuell löschen. Es wird dann beim nächsten Start von %1 gelöscht.
.
Language=FRA
Erreur lors de la suppression du répertoire '%2', %4 Vous devrez le supprimer manuellement. Sinon, il sera supprimé lors du prochain lancement d'%1.
.
Language=ESN
Error borrando el directorio '%2', %4 Por favor, bórrelo manualmente. Si no, será borrado en la siguiente ejecución de %1.
.
Language=ITA
Errore nel cancellare la directory '%2', %4 Per favore controllare e rimuovere manualmente. Verra' rimossa al prossimo avvio di %1.
.
Language=HUN
Hiba a '%2' könyvtár törlése során, %4 Kérem ellenõrizze és kézzel törölje. Ha nem, a legközelebbi %1 indításnál törlõdik.
.
Language=NOR
Error deleting directory '%2', %4 Please check and remove manually. It will be removed on next %1 start-up.
.
Language=NLD
Fout bij verwijderen van map '%2'. %4 Controleer de map en verwijder die handmatig. De map wordt verwijderd zodra %1 opnieuw wordt gestart.
.
Language=DNK
Fejl under sletning af mappen '%2', %4 Kontroller venligst og slet den manuelt. Den vil blive fjernet automatisk under næste start af %1.
.
Language=POL
Wystąpił błąd podczas usuwania katalogu '%2', %4 Sprawdź i usuń katalog ręcznie. Zostanie usunięty przy następnym uruchomieniu %1.
.
Language=CHI
Error deleting directory '%2', %4 Please check and remove manually. It will be removed on next %1 start-up.
.
Language=PTG
Error deleting directory '%2', %4 Please check and remove manually. It will be removed on next %1 start-up.
.
Language=PTB
Erro ao deletar o diretório '%2', %4 Por favor delete-o manualmente ou então ele será excluído na próxima %1 inicialização.
.
Language=RUS
Ошибка удаления каталога '%2', %4 Пожалуйста проверьте и удалите вручную. Он будет удален при следующем запуске %1.
.
Language=CZH
Chyba při mazání adresáře '%2', %4 Prosím zkontrolujte a odstraňte ručně. Bude odstraněno při příštím startu %1.
.
Language=FIN
Hakemistoa '%2', %4 ei saatu poistettua. Tarkista ja poista käsin. Se poistetaan seuraavalla %1:n käynnistyskerralla.
.

MessageId=500
Severity=Error
Facility=Application
SymbolicName=MSG_OPEN_WITH
Language=ENU
Failed to start 'Open With...' dialog for file '%3'.
.
Language=SVE
Kan inte starta 'Öppna med...'-dialogen för '%3'.
.
Language=DEU
Konnte 'Öffnen mit...' Dialog nicht starten für Datei '%3'.
.
Language=FRA
Erreur lors de la création de la fenêtre 'Ouvrir avec...' pour le fichier '%3'.
.
Language=ESN
Error abriendo el diálogo 'Abrir con...' para el fichero '%3'.
.
Language=ITA
Errore nell'aprire la finestra di dialogo 'Apri con...' per il file '%3'.
.
Language=HUN
A 'Társítás...' ablak megnyitása a '%3' fájlhoz nem sikerült.
.
Language=NOR
Failed to start 'Open With...' dialog for file '%3'.
.
Language=NLD
Fout bij starten van dialoogvenster 'Openen met...' voor bestand '%3'.
.
Language=DNK
Kan ikke starte 'Åben med...' dialog for filen '%3'.
.
Language=POL
Nie można uruchomić okna dialogowego 'Otwórz za pomocą...' dla pliku '%3'.
.
Language=CHI
Failed to start 'Open With...' dialog for file '%3'.
.
Language=PTG
Failed to start 'Open With...' dialog for file '%3'.
.
Language=PTB
Falha ao executar o diálogo 'Abrir com...' para o arquivo '%3'.
.
Language=RUS
Неудалось запустить диалог 'Открыть с помощью' для файла '%3'.
.
Language=CZH
Selhalo spuštění dialogu 'Otevřít v...' pro soubor '%3'.
.
Language=FIN
Tiedoston '%3' 'Avaa sovelluksessa' -dialogi ei käynnistynyt.
.

MessageId=510
Severity=Warning
Facility=Application
SymbolicName=WRN_CANT_TELL_DONE
Language=ENU
Unable to determine when the application launched for '%2' is done with the document.
You must do this manually, by clicking 'Ok' when you are done. If you do this
incorrectly you will not lose data, but the plain text will be left 'orphaned'
in your temporary directory and
visible on your harddisk, and the encrypted file will not be updated.
.
Language=SVE
Kan inte avgöra när applikationen som startats för '%2' är klar med dokumentet.
Du måste göra detta manuellt genom att klicka 'Ok' när du är klar med det. Om du
gör detta för tidigt förlorar du inget data, men klartexten ligger kvar 'övergiven'
i temporärbiblioteket, och det krypterade dokumentet kommer inte att uppdateras med
eventuella redigeringar.
.
Language=DEU
Kann nicht feststellen, wann die Anwendung mit Datei '%2' fertig ist.
Bitte klicken Sie auf 'Ok', wenn Sie fertig sind. Sollten Sie dies
irrtümlich falsch machen (z.B. zu früh), verlieren sie keine Daten,
aber die unverschlüsselte Datei bleibt in Ihrem TEMP-Verzeichnis
und die verschlüsselte Datei wird nicht aktualisiert.
.
Language=FRA
Impossible de déterminer quand l'application pour '%2' en aura fini avec le document.
Vous devrez l'indiquer manuellement en cliquant sur 'OK' lorsque vous aurez fini de
travailler dessus. Si vous le faites trop tôt, vous ne perdrez aucune donnée mais le
contenu décrypté restera dans le répertoire temporaire, et le fichier scellé ne sera
pas mis à jour avec les éventuelles modifications que vous aurez effectuées.
.
Language=ESN
No es posible determinar cuándo finalizará la aplicación ejecutada para '%2'.
Cuando la aplicación haya finalizado, pulse 'Aceptar'. Si hace ésto antes de tiempo
no perderá los datos, pero el fichero quedará 'huérfano' en su directorio temporal y
visible en su disco duro, y el archivo cifrado no se actualizará.
.
Language=ITA
Impossibile determinare quando l'applicazione lanciata da '%2' ha finito con il documento.
E' necessario intervenire manualmente cliccando su 'Ok' quando hai finito.
Se intervieni in modo non corretto i dati non andranno persi, ma il testo rimarra' 'orfano'
nella directory temporanea e visibile in chiaro sull'hard disk ed il file cifrato non verra' aggiornato.
.
Language=HUN
Lehetetlen megállapítani, hogy a '%2' feldolgozását végzõ alkalmazás mikor végez a dokumentummal.
Ezt önnek kézzel kell megtennie az 'Ok' gombra kattintással, amikor elkészült. Ha nem teszi,
nem veszt adatot, de a visszafejtett nyers tartalom titkosítás nélkül marad
az ideiglenes könyvtárban az ön merevlemezén,
illetve a titkosított fájl sem kerül frissítésre.
.
Language=NOR
Unable to determine when the application launched for '%2' is done with the document.
You must do this manually, by clicking 'Ok' when you are done. If you do this
incorrectly you will not lose data, but the plain text will be left 'orphaned'
in your temporary directory and
visible on your harddisk, and the encrypted file will not be updated.
.
Language=NLD
Kan niet bepalen wanneer de voor '%2' gestarte toepassing klaar is met het bestand.
U moet dit handmatig doen door op 'OK' te klikken als u klaar bent. Als u dit verkeerd doet,
verliest u geen gegevens, maar de kale tekst blijft in uw tijdelijke map staan en blijft zichtbaar
op uw harde schijf. Het versleutelde bestand wordt niet bijgewerkt.
.
Language=DNK
Kan ikke afgøre, hvornår programmet startet for '%2' er færdig med dokumentet.
Du må gøre dette manuelt ved at klikke 'Ok' når du er færdig.
Hvis du gør dette for tidligt, vil du ikke miste data, men klarteksten vil blive efterladt synligt i den midlertidige mappe på din harddisk, og ændringerne kommer ikke i den krypterede fil.
.
Language=POL
Nie można określić kiedy aplikacja, uruchomiona dla '%2', zakończy swoje działanie.
Musisz to zrobić ręcznie - kiedy zakończysz - kliknij przycisk 'Ok'. Jeżeli tej operacji
nie uda Ci się wykonać prawidłowo, na szczęście nie stracisz danych. Jednak musisz pamiętać, że
plik zawierający oryginalny tekst pozostanie w katalogu tymczasowym, a zaszyfrowany plik nie zostanie zaktualizowany.
.
Language=CHI
Unable to determine when the application launched for '%2' is done with the document.
You must do this manually, by clicking 'Ok' when you are done. If you do this
incorrectly you will not lose data, but the plain text will be left 'orphaned'
in your temporary directory and
visible on your harddisk, and the encrypted file will not be updated.
.
Language=PTG
Unable to determine when the application launched for '%2' is done with the document.
You must do this manually, by clicking 'Ok' when you are done. If you do this
incorrectly you will not lose data, but the plain text will be left 'orphaned'
in your temporary directory and
visible on your harddisk, and the encrypted file will not be updated.
.
Language=PTB
Impossível determinar quando o processo terminará para o documento '%2'.
Você deve fazê-lo manualmente, pressionando "Ok" quando estiver pronto.
Caso o faça antes da finalização, você não perderá os dados, mas o arquivo
se tornará 'órfão' na pasta temporária e estará acessível no disco rígido.
O arquivo encriptado não será atualizado.
.
Language=RUS
Невозможно определить, когда приложение, запущенное для '%2', закончит свою
работу. Вы должны сделать это вручную, нажав "Ok", когда закончите вносить
изменения в документ. Если вы сделаете это некорректно, вы не потеряете данные,
просто оставшийся во временном каталоге на вашем жестком диске незашифрованный
текст будет виден и останется незащищённым, а зашифрованный файл не будет обновлен.
.
Language=CZH
Nelze určit, kdy aplikace spuštěna pro '%2' s dokumentem skončila.
Po skončení je nutno potvrdit kliknutím na 'Ok'. Pokud to neuděláte správně,
nepřijdete o data, ale prostý text zůstane přístupný v dočasné složce a viditelný
na disku a zašifrovaný soubor nebude aktualizován.
.
Language=FIN
Ei pystytä määrittelemään, milloin '%2':ta varten käynnistetty sovellus lopettaa
asiakirjan käsittelyn. Joudut tekemään tämän itse napsauttamalla 'Ok', kun olet valmis.
Jos teet virheen, et menetä tietoja, mutta selkokielinen teksti jää erikseen
väliaikaishakemistoosi ja näkyviin kovalevyllesi ja salakoodattu tiedosto ei päivity.
.

MessageId=520
Severity=Warning
Facility=Application
SymbolicName=WRN_INPUT_IDLE_TIMEOUT
Language=ENU
The application associated with '%2' is taking too long to start. Please click 'Ok' when
it has started, and opened the document.
.
Language=SVE
Applikationsprogrammet för '%2' tar för lång tid att starta. Klicka 'Ok' när den har startat
och öppnat dokumentet.
.
Language=DEU
Die zur Datei '%2' gehörende Anwendung braucht zu lange zum Starten. Klicken sie 'Ok',
wenn die Applikation gestartet ist und das Dokument geöffnet hat.
.
Language=FRA
L'application associée à '%2' prend trop de temps pour démarrer. Veuillez cliquer sur 'OK'
lorsqu'elle sera démarrée et que le document sera ouvert.
.
Language=ESN
La aplicación asociada con '%2' está tardando demasiado en empezar. Por favor, pulse 'Aceptar'
cuando haya abierto el documento.
.
Language=ITA
L'applicazione associata con '%2' sta impiegando troppo tempo per partire. Per favore cliccare su
'Ok' quando e' avviata ed ha aperto il documento.
.
Language=HUN
A '%2' fájlhoz rendelt alkalmazás indítása a vártnál hosszabb idõt vesz igénybe. Nyomja meg az 'Ok'-t
amikor elindult és a dokumentumot megnyitotta.
.
Language=NOR
The application associated with '%2' is taking too long to start. Please click 'Ok' when
it has started, and opened the document.
.
Language=NLD
De bij '%2' behorende toepassing neemt te veel tijd in beslag om te starten. Klik op 'OK' als
die toepassing is gestart en het bestand is geopend.
.
Language=DNK
Applikationen tilknyttet '%2' tager for lang tid om at starte. Klik venligst på 'Ok' når den har startet og åbnet dokumentet.
.
Language=POL
Uruchomienie aplikacji powiązanej z '%2' trwa zbyt długo. Kiedy aplikacja już się uruchomi,
a dokument zostanie otwarty, kliknij przycisk 'Ok'.
.
Language=CHI
The application associated with '%2' is taking too long to start. Please click 'Ok' when
it has started, and opened the document.
.
Language=PTG
The application associated with '%2' is taking too long to start. Please click 'Ok' when
it has started, and opened the document.
.
Language=PTB
A aplicação associada com '%2' está demorando para iniciar.
Por favor pressione 'Ok' quando o documento for aberto.
.
Language=RUS
Приложение, связанное с '%2', слишком долго запускается для его открытия.
Пожалуйста, нажмите 'Ok' когда оно запустится и откроет его.
.
Language=CZH
Aplikace přidružená k '%2' startuje příliš dlouho. Prosím klikněte na 'OK' až nastartuje
a dokument je otevřen.
.
Language=FIN
'%2':een liitetyn sovelluksen käynnistäminen kestää liian kauan. Napsauta 'Ok', kun se on
käynnistynyt ja avannut asiakirjan.
.

MessageId=530
Severity=Warning
Facility=Application
SymbolicName=WRN_ACTIVE_APPS
Language=ENU
%1 is about to exit, but you still have applications with encrypted content open.
If these are not terminated automatically by the system, please EXIT these, and then click 'Ok'.
.
Language=SVE
%1 håller på att avslutas, men du har fortfarande öppna dokument som
behöver stängas och eventuellt återkrypteras. Om dessa inte avslutas automatiskt av systemet, AVSLUTA dessa applikationer och
klicka sedan 'Ok'.
.
Language=DEU
%1 soll beendet werden, aber es sind immer noch Anwendungen mit verschlüsselten Daten geöffnet.
Wenn sie nicht automatisch geschlossen werden, beenden Sie diese bitte manuell und klicken Sie 'Ok'.
.
Language=FRA
%1 est sur le point de se terminer, mais vous avez encore des documents cryptés ouverts qui
devront être fermés et eventuellement recryptés manuellement. Si les applications concernées ne sont
pas fermées automatiquement par le système, veuillez les fermer manuellement puis cliquer sur 'OK'.
.
Language=ESN
%1 está a punto de cerrarse, pero usted todavía tiene aplicaciones abiertas con contenido cifrado.
Si el sistema no las cierra automáticamente, por favor, ciérrelas manualmente y pulse 'Aceptar'.
.
Language=ITA
%1 sta per terminare, ma hai ancora applicationi con dati cifrati aperti.
Se questi non venissero terminati automaticamente dal sistema, chiuderli manualmente e cliccare su 'Ok'.
.
Language=HUN
%1 éppen kilépne, de még nyitva vannak titkosított tartalommal rendelkezõ alkalmazások.
Ha a rendszer automatikusan nem tette meg volna, kérem ZÁRJA BE ezeket, majd nyomja meg az 'Ok'-t.
.
Language=NOR
%1 is about to exit, but you still have applications with encrypted content open.
If these are not terminated automatically by the system, please EXIT these, and then click 'Ok'.
.
Language=NLD
%1 staat op het punt te sluiten, maar u hebt nog steeds toepassingen met versleutelde gegevens open.
Als het systeem deze bestanden niet automatisch sluit, kunt u ze zelf afsluiten en op 'OK' klikken.
.
Language=DNK
%1 skal til at lukke, men har stadig applikationer med krypteret indhold åbnet. Hvis ikke disse lukkes automatisk af systemet, så LUK venligst disse og klik 'Ok'.
.
Language=POL
%1 kończy działanie, a nadal czynne jest okno z zaszyfrowaną zawartością.
Jeżeli nie zostanie automatycznie zamknięte przez system, zamknij je, a następnie kliknij 'Ok'.
.
Language=CHI
%1 is about to exit, but you still have applications with encrypted content open.
If these are not terminated automatically by the system, please EXIT these, and then click 'Ok'.
.
Language=PTG
%1 is about to exit, but you still have applications with encrypted content open.
If these are not terminated automatically by the system, please EXIT these, and then click 'Ok'.
.
Language=PTB
%1 será encerrado, mas ainda há aplicações abertas com conteúdo encriptado.
Caso o sistema não as feche automaticamente, por favor feche-as manualmente, e então pressione 'Ok'.
.
Language=RUS
%1 собирается выйти, но у вас все еще открыты приложения с зашифрованным содержимым.
Если они не будут завершены автоматически системой, пожалуйста, выйдите из них, а затем нажмите 'Ok'.
.
Language=CZH
%1 se chystá ukončit, ale máte stále otevřené aplikace se zašifrovaným obsahem.
Pokud nebudou automaticky ukončeny systémem, prosím ukončete je a pak klikněte na 'OK'.
.
Language=FIN
%1 on sulkeutumassa, mutta sinulla on vielä sovelluksia, joissa on salakoodattua sisältö auki.
Jollei järjestelmä sulje näitä automaattisesti, SULJE ne itse ja paina sitten 'Ok'.
.

MessageId=540
Severity=Error
Facility=Application
SymbolicName=ERR_CANT_STOP
Language=ENU
The system is shutting down or logging off, but you still have encrypted content open. Please click 'Ok', CLOSE
all your applications, and then retry the attempted operation.
.
Language=SVE
Systemet håller på att avslutas, men du har krypterade dokument öppna. Klicka 'Ok', AVSLUTA
sedan dessa applikationer, och pröva sedan på nytt.
.
Language=DEU
Das System wird heruntergefahren oder abgemeldet, aber es sind noch verschlüsselte Dateien geöffnet.
Bitte klicken sie auf 'OK' und schließen sie alle Anwendungen.
.
Language=FRA
Le système ou la session est en cours d'arrêt, mais vous avez encore des documents cryptés ouverts.
Veuillez fermer toutes vos applications, puis réessayer l'opération.
.
Language=ESN
El sistema esta cerrándose pero usted todavía tiene contenido cifrado abierto. Por favor,
pulse 'Aceptar', CIERRE todas las aplicaciones e inténtelo de nuevo.
.
Language=ITA
Il sistema si sta arrestando o sta disconnettendo l'utente, ma hai ancora dati cifrati aperti.
Per favore cliccare su 'Ok' per chiudere tutte le applicazioni e tentare di nuovo l'operazione richiesta.
.
Language=HUN
A rendszer leáll vagy kijelentkezik, de még mindig van titkosított dokumentum nyitva. Kérem nyomja meg az 'Ok-t' ZÁRJA
BE az összes alkalmazást, majd próbálja újra ezt a funkciót.
.
Language=NOR
The system is shutting down or logging off, but you still have encrypted content open. Please click 'Ok', CLOSE
all your applications, and then retry the attempted operation.
.
Language=NLD
Het systeem is bezig met afsluiten of uitloggen, maar u hebt nog steeds versleutelde gegevens open.
Klik op 'OK', sluit alle toepassingen af en probeer de handeling nog eens.
.
Language=DNK
Systemet er ved at lukke ned eller logge af, men du har stadig krypteret indhold åben. Klik venligst 'Ok', LUK alle dine applikationer og prøv igen.
.
Language=POL
System jest w trakcie zamykania lub wylogowywania, a nadal czynne jest okno z zaszyfrowaną zawartością. Kliknij przycisk 'Ok', CLOSE
wszystkich aplikacji i spróbuj ponownie powtórzyć operację.
.
Language=CHI
The system is shutting down or logging off, but you still have encrypted content open. Please click 'Ok', CLOSE
all your applications, and then retry the attempted operation.
.
Language=PTG
The system is shutting down or logging off, but you still have encrypted content open. Please click 'Ok', CLOSE
all your applications, and then retry the attempted operation.
.
Language=PTB
O sistema está sendo encerrado, mas ainda existem conteúdos encriptados abertos. Por favor pressione 'Ok', FECHE
todas as aplicações e tente novamente.
.
Language=RUS
Система производит выход или завершает свою работу, но у вас все еще открыто зашифрованное содержимое.
Пожалуйста, нажмите 'Ok' и ЗАКРОЙТЕ все ваши приложения, затем вновь повторите неудавшуюся операцию.
.
Language=CZH
Systém se vypíná nebo probíhá odhlášení, ale máte stále otevřen šifrovaný obsah. Prosím klikněte na 'OK',
ukončete všechny aplikace a poté zkuste operaci znovu.
.
Language=FIN
Järjestelmä on sulkeutumassa tai kirjautumassa ulos, mutta sinulla on vielä salakoodattua sisältöä auki. Paina 'Ok' ja
SULJE kaikki sovelluksesi ja yritä uudelleen.
.

MessageId=550
Severity=Warning
Facility=Application
SymbolicName=WRN_SHUT_DOWN
Language=ENU
The system is definitely shutting down or logging off, but you still have encrypted content open.
WARNING: There may be encrypted content in plain text form left in the temporary directory! If so, It will be removed on restart.
.
Language=SVE
Systemet kommer att avslutas, eller logga av, men det finns fortfarande krypterade dokument
öppna. VARNING: Det kan alltså finnas krypterade dokument i klartext kvar i temporärbiblioteket! Isåfall, kommer det att tas bort vid omstart.
.
Language=DEU
Das System wird heruntergefahren oder abgemeldet, aber es sind noch verschlüsselte Dateien geöffnet.
WARNUNG: Es können noch unverschlüsselte Dateien im TEMP-Verzeichnis stehen! Diese werden beim nächsten Neustart automatisch gelöscht.
.
Language=FRA
Le système ou la session va être arrêté, mais vous avez encore des documents cryptés ouverts.
ATTENTION: il se peut que des données non-cryptées restent dans le répertoire temporaire de votre disque dur. Dans ce cas,
elles seront supprimées lors du prochain redémarrage.
.
Language=ESN
El sistema esta cerrándose definitivamente pero usted todavía tiene contenido cifrado abierto.
ATENCIÓN: ¡Puede haber contenido cifrado en forma de texto plano en el directorio temporal!. En ese caso se borrará en el siguiente inicio de sesión.
.
Language=ITA
Il sistema si sta definitivamente arrestando o sta disconnettendo, ma hai ancora dati cifrati aperti.
Attenzione potrebbero essere rimasti dati in chiaro nella directory temporanea! Se cosi' fosse, saranno rimossi al riavvio.
.
Language=HUN
A rendszer leáll vagy kijelentkezik, de még mindig van titkosított dokumentum nyitva.
FIGYELEM: Hátramaradhattak visszafejtett dokumentumok sima szöveges formában az ideiglenes könyvtárban! Ha igen, újraindításnál ezek törlõdnek..
.
Language=NOR
The system is definitely shutting down or logging off, but you still have encrypted content open.
WARNING: There may be encrypted content in plain text form left in the temporary directory! If so, It will be removed on restart.
.
Language=NLD
Het systeem sluit definitief af of logt uit, maar u hebt nog steeds versleutelde gegevens open.
WAARSCHUWING: Er zijn mogelijk versleutelde gegevens als leesbare tekst achtergebleven in de tijdelijke map! Als dat zo is, worden die verwijderd zodra de computer opnieuw wordt gestart.
.
Language=DNK
Systemet er ved at lukke ned eller logge af, men du har stadig krypteret indhold åben.
ADVARSEL: Der kan være klartekst efterladt i den midlertidige mappe! I så fald vil det blive slettet ved næste start.
.
Language=POL
System jest w trakcie zamykania lub wylogowywania, a nadal czynne jest okno z szyfrowaną zawartością.
OSTRZEŻENIE: W katalogu tymczasowym może pozostać niezaszyfrowana treść! Zostanie usunięta dopiero po restarcie.
.
Language=CHI
The system is definitely shutting down or logging off, but you still have encrypted content open.
WARNING: There may be encrypted content in plain text form left in the temporary directory! If so, It will be removed on restart.
.
Language=PTG
The system is definitely shutting down or logging off, but you still have encrypted content open.
WARNING: There may be encrypted content in plain text form left in the temporary directory! If so, It will be removed on restart.
.
Language=PTB
O sistema está sendo encerrado definitivamente, mas ainda existem dados encriptados abertos.
ATENÇÃO: Pode haver conteúdo encriptado em forma de texto pleno no diretório temporário! Neste caso, ele será removido ao reiniciar o sistema.
.
Language=RUS
Система явно производит выход или завершает свою работу, но у вас все еще открыто зашифрованное содержимое.
ВНИМАНИЕ: Во временном каталоге может находиться зашифрованное содержимое в открытом виде. Если это так, то оно будет удалено при перезагрузке.
.
Language=CZH
Systém se zcela určitě vypíná nebo probíhá odhlášení, ale máte stále otevřen šifrovaný obsah.
VAROVÁNÍ: Šifrovaný obsah v otevřené podobě může zůstat v dočasné složce! Pokud k tomu dojde,
bude odstaněn po restartu.
.
Language=FIN
Järjestelmä on lopullisesti sulkeutumassa tai kirjautumassa ulos, mutta sinulla on vielä salakoodattua sisältöä auki.
VAROITUS: Salakoodattua sisältöä voi olla vielä jäljellä väliaikaishakemistossa! Jos näin on, se poistetaan konetta uudelleen käynnistettäessä.
.

MessageId=560
Severity=Error
Facility=Application
SymbolicName=ERR_VERSION_RESOURCE
Language=ENU
System error reading version resource.
.
Language=SVE
Systemfel under läsning av versionsresurs.
.
Language=DEU
Systemfehler beim Prüfen der Versionsnummer.
.
Language=FRA
Erreur systeme lors de la lecture de la resource de version.
.
Language=ESN
Error de sistema leyendo el recurso de versión.
.
Language=ITA
Errore di sistema leggendo la risorsa di versione.
.
Language=HUN
Rendszerhiba a forrás verzió olvasásakor.
.
Language=NOR
System error reading version resource.
.
Language=NLD
Systeemfout bij lezen van versienummer.
.
Language=DNK
Systemfejl under læsning af udgavenummer.
.
Language=POL
Wystąpił błąd systemowy podczas odczytu wersji.
.
Language=CHI
System error reading version resource.
.
Language=PTG
System error reading version resource.
.
Language=PTB
Erro de sistema lendo o recurso de versão.
.
Language=RUS
Системная ошибка чтения версии ресурса.
.
Language=CZH
Systémová chyba při čtení verze zdroje.
.
Language=FIN
Järjestelmävirhe versioresurssia luettaessa.
.

MessageId=570
Severity=Error
Facility=Application
SymbolicName=ERR_TEMP_DIR
Language=ENU
Failed to create temporary directory in %3, try cleaning up.
.
Language=SVE
Misslyckades skapa temporärbibliotek i %3, försök med att rensa gamla temporärbibliotek.
.
Language=DEU
Konnte kein temporäres Verzeichnis in  %3 erstellen, bitte aufräumen.
.
Language=FRA
Erreur lors de la création d'un répertoire temporaire dans %3.
Vous pouvez essayer de nettoyer le répertoire temporaire, puis recommencer.
.
Language=ESN
Error al crear un directorio temporal  en '%3'.
Pruebe a limpiar el directorio temporal e inténtelo de nuevo.
.
Language=ITA
Errore nel creare la directory temporanea in %3, tentare manualmente.
.
Language=HUN
Az ideiglenes könyvtár létrehozása %3-ban nem sikerült, próbálja törölni az
ideiglenes könyvtár tartalmát, majd kezdje újra.
.
Language=NOR
Failed to create temporary directory in %3, try cleaning up.
.
Language=NLD
Fout bij aanmaken van tijdelijke map in %3. Probeer deze op te ruimen.
.
Language=DNK
Kunne ikke skabe midlertidig mappe i %3, prøv at fjerne den gamle midlertidige mappe.
.
Language=POL
Nie można utworzyć tymczasowego katalogu w '%3', spróbuj go oczyścić.
.
Language=CHI
Failed to create temporary directory in %3, try cleaning up.
.
Language=PTG
Failed to create temporary directory in %3, try cleaning up.
.
Language=PTB
Falha ao criar diretório temporário em %3, tente novamente.
.
Language=RUS
Не удалось создать временный каталог в %3, попробуйте сделать очистку.
.
Language=CZH
Chyba při vytváření dočasné složky v %3, zkuste pročištění.
.
Language=FIN
Ei kyetty luomaan väliaikaishakemistoa kohteessa %3, poista vanhoja väliaikaistiedostoja.
.

MessageId=580
Severity=Warning
Facility=Application
SymbolicName=WRN_REALLY_WIPE
Language=ENU
Do you want to overwrite %2 with random data and then permanently delete it?
.
Language=SVE
Vill skriva över %2 med slumpässigt data och sedan permanent ta bort den?
.
Language=DEU
Möchten Sie %2 mit Zufallswerten überschreiben und anschließend endgültig löschen?
.
Language=FRA
Souhaitez-vous réécrire %2 avec des données aléatoires, puis le supprimer définitivement?
.
Language=ESN
¿Quiere sobreescribir %2 con datos aleatorios y borrarlo permanentemente?
.
Language=ITA
Vuoi sovrascrivere %2 con dati casuali e poi rimuoverlo permanentemente?
.
Language=HUN
Szeretné a %2 fájlt véletlenszerû adatokkal felülírni majd véglegesen törölni?
.
Language=NOR
Do you want to overwrite %2 with random data and then permanently delete it?
.
Language=NLD
Wilt u '%2' overschrijven met willekeurige gegevens en vervolgens definitief verwijderen?
.
Language=DNK
Ønsker du at overskrive %2 med tilfældige data og derefter slette den permanent?
.
Language=POL
Czy chcesz nadpisać plik %2 losowymi danymi i na stałe go usunąć?
.
Language=CHI
Do you want to overwrite %2 with random data and then permanently delete it?
.
Language=PTG
Do you want to overwrite %2 with random data and then permanently delete it?
.
Language=PTB
Deseja sobrescrever %2 com dados aleatórios e excluí-lo permanentemente?
.
Language=RUS
Вы действительно хотите перезаписать %2 случайными данными, а затем окончательно его удалить?
.
Language=CZH
Chcete přepsat %2 náhodnými daty a poté nenávratně odstranit?
.
Language=FIN
Haluatko kirjoittaa tiedoston %2 päälle satunnaista tietoa ja poistaa tiedoston sitten lopullisesti?
.

MessageId=590
Severity=Error
Facility=Application
SymbolicName=ERR_REG_VALUE_TYPE
Language=ENU
Registry key %3 is of the wrong type.
.
Language=SVE
Registernyckel %3 har fel typ.
.
Language=DEU
Registry-Schlüssel %3 hat den falschen Typ.
.
Language=FRA
La clé de Registre %3 est du mauvais type.
.
Language=ESN
La clave de registro %3 es del tipo incorrecto.
.
Language=ITA
La chiave %3 del registry e' di tipo errato.
.
Language=HUN
A %3 regisztrációs kulcs típusa nem megfelelõ.
.
Language=NOR
Registry key %3 is of the wrong type.
.
Language=NLD
Register sleutel %3 is van het verkeerde type.
.
Language=DNK
Registernøglen %3 er af en forkert type.
.
Language=POL
Błędny klucz rejestru %3.
.
Language=CHI
Registry key %3 is of the wrong type.
.
Language=PTG
Registry key %3 is of the wrong type.
.
Language=PTB
A chave de registro %3 é incorreta.
.
Language=RUS
Ключ реестра %3 имеет неверный тип.
.
Language=CZH
Klíč registru %3 je chybného typu.
.
Language=FIN
Rekisteriavain %3 on väärää tyyppiä.
.

MessageId=600
Severity=Error
Facility=Application
SymbolicName=ERR_LOG_LEVEL
Language=ENU
Error '%2' reading event log level (%3) from the registry.
.
Language=SVE
Fel '%2' vid läsning av loggningsnivå (%3) från registret.
.
Language=DEU
Fehler '%2' beim Lesen des Event Log Level (%3) aus der Registry.
.
Language=FRA
Erreur '%2' lors de la lecture du niveau de log (%3) dans le Regitre.
.
Language=ESN
Error '%2' leyendo el nivel del registro de eventos (%3) del registro.
.
Language=ITA
Errore '%2' nel leggere il livello (%3) dell'Event Log dal registry.
.
Language=HUN
Hiba '%2' a logfájl szintjének (%3) olvasásakor a registry-bõl.
.
Language=NOR
Error '%2' reading event log level (%3) from the registry.
.
Language=NLD
Fout '%2' bij lezen van niveau van gebeurtenislogboek (%3) in het register.
.
Language=DNK
Fejl '%2' under læsning af logningsniveau (%3) fra registret.
.
Language=POL
Podczas odczytu z rejestru dziennika zdarzeń poziomu (%3), wystąpił błąd '%2'.
.
Language=CHI
Error '%2' reading event log level (%3) from the registry.
.
Language=PTG
Error '%2' reading event log level (%3) from the registry.
.
Language=PTB
Erro '%2' lendo o registro de eventos nível (%3) do registro.
.
Language=RUS
Ошибка '%2' чтения уровня журнала событий (%3) из реестра.
.
Language=CZH
Chyba '%2' při čtení protokolu událostí úrovně (%3) z registru.
.
Language=FIN
Virhe '%2' luettaessa tapahtumalokitasoa (%3) rekisteristä.
.

MessageId=610
Severity=Warning
Facility=Application
SymbolicName=WRN_CLEAN_UP
Language=ENU
Warning, error during clean-up of temporaries: %4
.
Language=SVE
Varning, fel vid rensning av temporärfiler: %4
.
Language=DEU
Warnung, Fehler beim Beseitigen der temporären Dateien: %4
.
Language=FRA
Alerte, erreur lors du nettoyage de données temporaire: %4
.
Language=ESN
Atención, error durante la limpieza de temporales: %4
.
Language=ITA
Attenzione, errore durante la rimozione dei file temporanei: %4
.
Language=HUN
Figyelem, a következõ fájl(ok) törlése az ideiglenes könyvtárból nem sikerült: %4
.
Language=NOR
Warning, error during clean-up of temporaries: %4
.
Language=NLD
Waarschuwing: fout bij opruimen van tijdelijke bestanden. %4
.
Language=DNK
Advarsel, fejl under oprydning af midlertidige filer: %4
.
Language=POL
Uwaga, wystąpił błąd podczas usuwania danych tymczasowych: %4
.
Language=CHI
Warning, error during clean-up of temporaries: %4
.
Language=PTG
Warning, error during clean-up of temporaries: %4
.
Language=PTB
Atenção, erro durante a limpeza de arquivos temporários: %4
.
Language=RUS
Предупреждение: ошибка во время очистки временных файлов: %4
.
Language=CZH
Varování, chyba během čištění dočasných souborů: %4
.
Language=FIN
Varoitus, virhe väliaikaistiedostoja poistettaessa: %4
.

;//
;//	Rel 1.2 - Used to display the name of the current operation in the
;//	progress window, which the progress bar indicates.
;//
MessageId=620
Severity=Informational
Facility=Application
SymbolicName=INF_OPNAME_ENCRYPT
Language=ENU
Encrypting
.
Language=SVE
Krypterar
.
Language=DEU
Verschlüsseln
.
Language=FRA
Cryptage
.
Language=ESN
Cifrando
.
Language=ITA
Cifratura in corso
.
Language=HUN
Titkosítás
.
Language=NOR
Encrypting
.
Language=NLD
Versleutelen...
.
Language=DNK
Krypterer
.
Language=POL
Szyfrowanie
.
Language=CHI
Encrypting
.
Language=PTG
Encrypting
.
Language=PTB
Encriptando
.
Language=RUS
Шифрование
.
Language=CZH
Probíhá šifrování
.
Language=FIN
Salakoodataan
.

;//
;//	Rel 1.2 - Used to display the name of the current operation in the
;//	progress window, which the progress bar indicates.
;//
MessageId=630
Severity=Informational
Facility=Application
SymbolicName=INF_OPNAME_DECRYPT
Language=ENU
Decrypting
.
Language=SVE
Dekrypterar
.
Language=DEU
Entschlüsseln
.
Language=FRA
Décryptage
.
Language=ESN
Descifrando
.
Language=ITA
Decifratura in corso
.
Language=HUN
Visszafejtés
.
Language=NOR
Decrypting
.
Language=NLD
Ontsleutelen
.
Language=DNK
Dekrypterer
.
Language=POL
Odszyfrowywanie
.
Language=CHI
Decrypting
.
Language=PTG
Decrypting
.
Language=PTB
Decriptando
.
Language=RUS
Расшифровка
.
Language=CZH
Probíhá dešifrování
.
Language=FIN
Puretaan salakoodaus
.

;//
;//	Rel 1.2 - Used to display the name of the current operation in the
;//	progress window, which the progress bar indicates.
;//
MessageId=640
Severity=Informational
Facility=Application
SymbolicName=INF_OPNAME_COMPRESS
Language=ENU
Compressing
.
Language=SVE
Komprimerar
.
Language=DEU
Komprimieren
.
Language=FRA
Compression
.
Language=ESN
Comprimiendo
.
Language=ITA
Compressione in corso
.
Language=HUN
Tömörítés
.
Language=NOR
Compressing
.
Language=NLD
Comprimeren
.
Language=DNK
Komprimerer
.
Language=POL
Kompresowanie
.
Language=CHI
Compressing
.
Language=PTG
Compressing
.
Language=PTB
Compactando
.
Language=RUS
Сжатие
.
Language=CZH
Probíhá komprese
.
Language=FIN
Tiivistetään
.

;//
;//	Rel 1.2 - Used to display the name of the current operation in the
;//	progress window, which the progress bar indicates.
;//
MessageId=650
Severity=Informational
Facility=Application
SymbolicName=INF_OPNAME_DECOMPRESS
Language=ENU
Decompressing
.
Language=SVE
Dekomprimerar
.
Language=DEU
Dekomprimieren
.
Language=FRA
Décompression
.
Language=ESN
Descomprimiendo
.
Language=ITA
Decompressione in corso
.
Language=HUN
Kibontás
.
Language=NOR
Decompressing
.
Language=NLD
Decomprimeren
.
Language=DNK
Pakker ud
.
Language=POL
Dekompresowanie
.
Language=CHI
Decompressing
.
Language=PTG
Decompressing
.
Language=PTB
Descompactando
.
Language=RUS
Распаковка
.
Language=CZH
Probíhá dekomprese
.
Language=FIN
Puretaan tiivistys
.

;//
;//	Rel 1.2 - Used to display the name of the current operation in the
;//	progress window, which the progress bar indicates.
;//
MessageId=660
Severity=Informational
Facility=Application
SymbolicName=INF_OPNAME_WIPETEMP
Language=ENU
Shredding temporaries
.
Language=SVE
Skriver över temporärfiler
.
Language=DEU
Datei löschen
.
Language=FRA
Brouillage des fichiers temporaires
.
Language=ESN
Limpiando temporales
.
Language=ITA
Sto rimuovendo completamente i file temporanei
.
Language=HUN
Ideiglenes fájlok megsemmisítése
.
Language=NOR
Shredding temporaries
.
Language=NLD
Vernietigen van tijdelijke bestanden
.
Language=DNK
Sletter midlertidige filer
.
Language=POL
Niszczenie danych tymczasowych
.
Language=CHI
Shredding temporaries
.
Language=PTG
Shredding temporaries
.
Language=PTB
Destruindo temporários
.
Language=RUS
Уничтожение временных файлов
.
Language=CZH
Probíhá likvidace dočasných souborů
.
Language=FIN
Tuhotaan väliaikaistiedostot
.

;//
;//	Rel 1.2 - Used to display the name of the current operation in the
;//	progress window, which the progress bar indicates.
;//
MessageId=670
Severity=Informational
Facility=Application
SymbolicName=INF_OPNAME_WIPEDATA
Language=ENU
Shredding
.
Language=SVE
Skriver över
.
Language=DEU
Löschen
.
Language=FRA
Brouillage
.
Language=ESN
Limpiando
.
Language=ITA
Sto rimuovendo completamente i file.
.
Language=HUN
Megsemmisítés
.
Language=NOR
Shredding
.
Language=NLD
Vernietigen
.
Language=DNK
Overskriver
.
Language=POL
Niszczenie
.
Language=CHI
Shredding
.
Language=PTG
Shredding
.
Language=PTB
Destruindo
.
Language=RUS
Уничтожение
.
Language=CZH
Probíhá skartace
.
Language=FIN
Päällekirjoitetaan
.

;//
;//	Rel 1.2 - Used to display the name of the current operation in the
;//	progress window, which the progress bar indicates.
;//
MessageId=680
Severity=Informational
Facility=Application
SymbolicName=INF_OPNAME_HMAC
Language=ENU
Calculating integrity checksum (HMAC)
.
Language=SVE
Beräknar kontrollsumma (HMAC)
.
Language=DEU
Erstelle Prüfsummen (HMAC)
.
Language=FRA
Contrôle d'intégrité (HMAC)
.
Language=ESN
Comprobando la integridad (HMAC)
.
Language=ITA
Sto verificando il checksum d'integrità(HMAC)
.
Language=HUN
Integritás ellenõrzése (checksum - HMAC)
.
Language=NOR
Calculating integrity checksum (HMAC)
.
Language=NLD
Berekenen van integriteitscontrolesom (HMAC)
.
Language=DNK
Beregner kontrolsum (HMAC)
.
Language=POL
Obliczanie sumy kontrolnej (HMAC)
.
Language=CHI
Calculating integrity checksum (HMAC)
.
Language=PTG
Calculating integrity checksum (HMAC)
.
Language=PTB
Verificando a integridade dos dados (HMAC)
.
Language=RUS
Расчет целостности контрольной суммы (HMAC)
.
Language=CZH
Probíhá výpočet kontrolního součtu (HMAC)
.
Language=FIN
Lasketaan ehjyystarkistussumma (HMAC)
.

;//
;//	Rel 1.2 - This message is displayed, when the user clicks the 'cancel' button
;// in the progress dialogue. It is also used without display in other cases when
;// the user cancels, such as pressing cancel in an 'enter key' dialogue.
;//
MessageId=690
Severity=Warning
Facility=Application
SymbolicName=WRN_CANCEL
Language=ENU
Operation cancelled.
.
Language=SVE
Handlingen avbruten.
.
Language=DEU
Operation abgebrochen.
.
Language=FRA
Opération annulée.
.
Language=ESN
Operación cancelada.
.
Language=ITA
Operazione annullata.
.
Language=HUN
A mûvelet megszakadt.
.
Language=NOR
Operation cancelled.
.
Language=NLD
Actie geannuleerd.
.
Language=DNK
Handlingen blev afbrudt.
.
Language=POL
Operacja została anulowana.
.
Language=CHI
Operation cancelled.
.
Language=PTG
Operation cancelled.
.
Language=PTB
Operação cancelada.
.
Language=RUS
Операция отменена
.
Language=CZH
Operace zrušena.
.
Language=FIN
Toiminto peruutettu.
.

;//
;//	Rel 1.4.2 - This message is displayed, when the user clicks the 'Yes' button
;// in the file wipe question in batched mode for example, when there are three
;// choices 'Yes', 'No', 'Cancel'.
;//
MessageId=700
Severity=Informational
Facility=Application
SymbolicName=INF_YESALL
Language=ENU
Yes To All.
.
Language=SVE
Ja till Alla.
.
Language=DEU
Ja, Alle.
.
Language=FRA
Oui pour tous.
.
Language=ESN
Sí a todo.
.
Language=ITA
Si a tutti.
.
Language=HUN
Igen, mindet.
.
Language=NOR
Yes To All.
.
Language=NLD
Ja op alles.
.
Language=DNK
Ja til alle.
.
Language=POL
Tak dla wszystkich.
.
Language=CHI
Yes To All.
.
Language=PTG
Yes To All.
.
Language=PTB
Sim para todos.
.
Language=RUS
Да для всех.
.
Language=CZH
Ano na vše.
.
Language=FIN
Kyllä kaikkiin
.

;//
;//	Rel 1.2
;//
;// This is used for the 'save passphrase' checkbox in the enter
;// encryption key dialogue. The context is such that the word
;// 'passphrase' is not necessary to prompt with.
;// The prompt should indicate that the usage is for 'encryption'.
;//
MessageId=710
Severity=Informational
Facility=Application
SymbolicName=INF_SAVE_ENCKEY
Language=ENU
Use as default for encryption
.
Language=SVE
Lägg i minne som standard för kryptering
.
Language=DEU
Als Standard-Passwort benutzen und speichern
.
Language=FRA
Retenir et utiliser en tant que défaut
.
Language=ESN
Recordar y usar como contraseña por defecto
.
Language=ITA
Ricorda e usa come password di default
.
Language=HUN
Legyen alapértelmezett titkosításnál
.
Language=NOR
Use as default for encryption
.
Language=NLD
Als standaard voor versleuteling gebruiken
.
Language=DNK
Husk som standard for kryptering
.
Language=POL
Użyj jako domyślne dla szyfrowania
.
Language=CHI
Use as default for encryption
.
Language=PTG
Use as default for encryption
.
Language=PTB
Tornar padrão para encriptar
.
Language=RUS
Как пароль по умолчанию для шифрования
.
Language=CZH
Použít jako výchozí pro šifrování
.
Language=FIN
Käytä oletuksena salakoodauksessa
.

;//
;//	Rel 1.2
;//
;// This is used for the 'save passphrase' checkbox in the enter
;// decryption key dialogue. The context is such that the word
;// 'passphrase' is not necessary to prompt with.
;//
MessageId=720
Severity=Informational
Facility=Application
SymbolicName=INF_SAVE_DECKEY
Language=ENU
Remember this for decryption
.
Language=SVE
Lägg i minne för dekryptering
.
Language=DEU
Dieses Passwort speichern
.
Language=FRA
Retenir cette clé
.
Language=ESN
Recordar esta contraseña
.
Language=ITA
Memorizza questa password
.
Language=HUN
Jegyezze meg a visszafejtéshez
.
Language=NOR
Remember this for decryption
.
Language=NLD
Dit wachtwoord onthouden voor ontsleuteling
.
Language=DNK
Husk til brug for dekryptering
.
Language=POL
Zapamiętaj dla odszyfrowywania
.
Language=CHI
Remember this for decryption
.
Language=PTG
Remember this for decryption
.
Language=PTB
Lembrar esta senha para decriptar
.
Language=RUS
Помнить для расшифровки
.
Language=CZH
Zapamatovat pro dešifrování
.
Language=FIN
Muista tämä salakoodauksen purkua varten
.

;//
;//	Rel 1.2
;//
;//	This message is shown when it is detected that a file was encrypted
;// with a previous version, to give a strong hint to the user that this
;// file should be decrypted and re-encrypted for enhanced security.
;//
MessageId=730
Severity=Warning
Facility=Application
SymbolicName=WRN_REENCRYPT
Language=ENU
The file '%3' is encrypted in an earlier format. For full security, please decrypt and re-encrypt using this version.
.
Language=SVE
Filen '%3' är krypterad med en äldre version. Dekryptera och kryptera om med denna version för full säkerhet.
.
Language=DEU
Die Datei '%3' wurde in einem früheren Format verschlüsselt.  Bitte entschlüsseln und verschlüsseln Sie die Datei mit dieser Version, um höhere Sicherheit zu gewährleisten.
.
Language=FRA
Le fichier '%3' a été scellé dans un ancien format. Pour obtenir une meilleur sécurité, vous devriez désceller puis resceller le fichier avec cette version-ci d'%1.
.
Language=ESN
El fichero '%3' está cifrado con un formato anterior.  Para una completa seguridad, descifre y vuelva a cifrar con esta versión.
.
Language=ITA
Il file '%3' e' cifrato in un formato piu' vecchio. Per una maggiore sicurezza, e' consigliabile decifrare e ri-cifrare utilizzando questa versione.
.
Language=HUN
A '%3' fájlt egy korábbi formátumban titkosították. A teljes biztonság érdekében kérjük fejtse vissza majd titkosítsa újra ezzel a verzióval.
.
Language=NOR
The file '%3' is encrypted in an earlier format. For full security, please decrypt and re-encrypt using this version.
.
Language=NLD
Het bestand '%3' is versleuteld in een ouder formaat. Voor optimale beveiliging dient u het te ontsleutelen en opnieuw te versleutelen met deze versie.
.
Language=DNK
Filen '%3' er krypteret med en tidligere udgave. For bedre sikkerhed, dekrypter venligst og krypter med denne udgave.
.
Language=POL
Plik '%3' zaszyfrowany jest w starszym formacie. Dla pełnego bezpieczeństwa odszyfruj i zaszyfruj ponownie używając aktualnej wersji.
.
Language=CHI
The file '%3' is encrypted in an earlier format. For full security, please decrypt and re-encrypt using this version.
.
Language=PTG
The file '%3' is encrypted in an earlier format. For full security, please decrypt and re-encrypt using this version.
.
Language=PTB
O arquivo '%3' está encriptado numa versão anterior. Para maior segurança, por favor decripte-o e volte a encriptá-lo novamente usando esta versão.
.
Language=RUS
Файл '%3' зашифрован более ранней версией формата. Для полной безопасности, пожалуйста, расшифруйте и повторно зашифруйте в текущей версии.
.
Language=CZH
Soubor '%3' je zašifrován ve starším formátu. Pro zajištění bezpečnosti prosím dešifrujte a znovu zašifrujte touto verzí.
.
Language=FIN
Tiedosto '%3' salakoodattu aiemmassa muodossa. Turvallisuuden vuoksi pura salakoodaus ja salakoodaa uudelleen tätä versiota käyttäen.
.

;//
;//	Rel 1.2
;//
;// The context menu prompt to clear the passphrase memory.
;//
MessageId=740
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_CLEARKEYS
Language=ENU
Clear Passphrase Memory
.
Language=SVE
Rensa lösenordsminne
.
Language=DEU
Gespeicherte Passwörter löschen
.
Language=FRA
Effacer toutes les clés
.
Language=ESN
Eliminar contraseñas memorizadas
.
Language=ITA
Elimina la memoria delle password
.
Language=HUN
Törölje a kulcsmondatokat a memóriából
.
Language=NOR
Clear Passphrase Memory
.
Language=NLD
Wachtwoord uit geheugen verwijderen
.
Language=DNK
Slet kodeords hukommelse
.
Language=POL
Oczyść pamięć hasła
.
Language=CHI
Clear Passphrase Memory
.
Language=PTG
Clear Passphrase Memory
.
Language=PTB
Excluir senhas memorizadas
.
Language=RUS
Очистить память паролей
.
Language=CZH
Odstranit heslo z paměti
.
Language=FIN
Tyhjennä salasanamuisti
.

;//
;//	Rel 1.2
;//
MessageId=750
Severity=Informational
Facility=Application
SymbolicName=HLP_MENU_CLEARKEYS
Language=ENU
Remove all passphrases from active memory.
.
Language=SVE
Rensa alla lösenord från minnet.
.
Language=DEU
Passwörter aus dem Arbeitsspeicher entfernen.
.
Language=FRA
Supprimer toutes les clés de la mémoire.
.
Language=ESN
Elimina todas las contraseñas de la memoria activa.
.
Language=ITA
Rimuovo tutte le password dalla memoria.
.
Language=HUN
Törölje az összes kulcsmondatot az aktív memóriából.
.
Language=NOR
Remove all passphrases from active memory.
.
Language=NLD
Alle wachtwoorden uit het actieve geheugen verwijderen.
.
Language=DNK
Slet alle kodeord fra arbejdshukommelsen.
.
Language=POL
Usuń wszystkie hasła z pamięci.
.
Language=CHI
Remove all passphrases from active memory.
.
Language=PTG
Remove all passphrases from active memory.
.
Language=PTB
Remover todas as senhas da memória.
.
Language=RUS
Удалить все пароли по умолчанию из памяти.
.
Language=CZH
Odstranit všechna hesla z paměti.
.
Language=FIN
Poistaa kaikki salasanat käyttömuistista.
.

;//
;//	Rel 1.2
;//
MessageId=760
Severity=Warning
Facility=Application
SymbolicName=WRN_INSECURE_WIPE
Language=ENU
'%3' cannot be shredded in a secure way by %1.
The file is compressed or encrypted by the file system,
this requires low level routines not provided in %1.
Please either change the file or directory attributes,
or install a special purpose utility for this task.
.
Language=SVE
'%3' kan inte säkert skrivas över av %1.
Filen är endera komprimerad eller krypterad av filsystemet.
%1 kan därför ej göra detta säkert.
Ändra fil- eller katalogattributen,
alternativt installera annan specialprogramvara för ändamålet.
.
Language=DEU
'%3' kann nicht in einer sicheren Weise von %1 gelöscht werden.
Die Datei ist durch das Betriebssystem komprimiert oder verschlüsselt
und erfordert Funktionen, die nicht in %1 bereitgestellt werden.
Bitte ändern Sie die Datei- oder Verzeichnisattribute oder
installieren Sie ein geegeignetes Programm für diese Aufgabe.
.
Language=FRA
'%3' ne peuvent pas être essuyés d'une manière bloquée par %1.
Le dossier est comprimé ou chiffré par le système de fichiers,
ceci exige des routines de niveau bas non fournies dans %1.
Veuillez changer les attributs de dossier ou d'annuaire,
ou installez une utilité spéciale de but pour cette tâche.
.
Language=ESN
%1 no puede limpiar '%3' de manera segura.
El fichero ha sido comprimido o cifrado por el sistema de ficheros.
Esto requiere unas rutinas de bajo nivel no soportadas por %1.
Por favor, cambie los atributos del archivo o directorio, o bien
instale una utilidad de propósito específico para esta tarea.
.
Language=ITA
'%3' non puo' essere completamente rimosso in modo sicuro da %1.
Il file e' compresso o cifrato dal file system,
questo richiede routine di basso livello non fornite da %1.
Per favore cambiare gli attributi del file o directory,
oppure installare una utility apposita per questa funzione.
.
Language=HUN
A '%3' fájlt nem lehet a %1 segítségével biztonságosan megsemmisíteni.
A fájl tömörítette vagy titkosította a fájlrendszer,
ehhez olyan alacsony szintû rutinokra lenne szükség amit %1 nem támogat.
Kérem változtassa meg a fájl vagy könyvtár hozzáférési jogait,
vagy telepítsen speciális alkalmazást erre a feladatra.
.
Language=NOR
'%3' cannot be shredded in a secure way by %1.
The file is compressed or encrypted by the file system,
this requires low level routines not provided in %1.
Please either change the file or directory attributes,
or install a special purpose utility for this task.
.
Language=NLD
'%3' kan niet veilig door %1 worden vernietigd.
Het bestand is gecomprimeerd of versleuteld door het bestandssysteem.
Dit vereist low-levelroutines die niet in %1 worden ondersteund.
Wijzig de bestands- of mapattributen, of installeer een speciaal
programma voor deze taak.
.
Language=DNK
'%3' kan ikke overskrives på en sikker måde af %1.
Denne fil er komprimeret eller krypteret af filsystemet,
og overskrivning vil kræve systemrutiner som ikke er tilgængelige i %1.
Ændr venligst fil eller mappeattributter,
eller installer et specielt program til denne opgave.
.
Language=POL
Nie można bezpiecznie usunąć '%3' z użyciem %1.
Plik jest skompresowany lub zaszyfrowany przez system plików,
wymagane jest użycie algorytmu niskiego poziomu niedostępnego w %1.
Zmień proszę atrybut pliku lub katalogu albo zainstaluj
odpowiednie narzędzie dla tego zadania.
.
Language=CHI
'%3' cannot be shredded in a secure way by %1.
The file is compressed or encrypted by the file system,
this requires low level routines not provided in %1.
Please either change the file or directory attributes,
or install a special purpose utility for this task.
.
Language=PTG
'%3' cannot be shredded in a secure way by %1.
The file is compressed or encrypted by the file system,
this requires low level routines not provided in %1.
Please either change the file or directory attributes,
or install a special purpose utility for this task.
.
Language=PTB
'%3' não pode ser destruído de maneira segura por %1.
O arquivo está compactado ou encriptado pelo sistema de arquivos,
Esta operação requer rotinas de baixo nível não suportadas por %1.
Por favor, mude os permissões do arquivo ou do diretório,
ou instale um utilitário com o propósito específico para esta tarefa.
.
Language=RUS
%1 не может уничтожить '%3' безопасным способом.
Файл сжат или зашифрован средствами файловой системы,
что требует низкоуровневых операций, не предусмотренных в %1.
Пожалуйста, измените дополнительные атрибуты файла, каталога
или установите для этой задачи специализированную программу.
.
Language=CZH
%1 nemůže bezpečně skartovat '%3'.
Soubor je komprimován nebo zašifrován souborovým systémem,
jsou nutné nízkoúrovňové postupy, které %1 neposkytuje.
Buď změňte atributy souboru nebo adresáře anebo instalujte
pro tuto úlohu speciální utilitu.
.
Language=FIN
Tiedostoa '%3' ei voi tuhota turvallisesti %1-ohjelmalla.
Tiedosto on tiivistetty ja salattu tiedostojärjestelmän
avulla ja sen käsitteli vaatisi matalan tason rutiineja,
joita ei ole %1-ohjelmassa. Muuta tiedosto- tai
hakemistoattribuutteja tuhoamista varten tai käytä sopivaa
erikoissovellusta.
.

;//
;//	Rel 1.2
;//
;//	This is used together with a checkbox, so that we can
;//	display warnings etc, and then ask the user if he wants
;//	to see this warning again, or not.
;//
MessageId=770
Severity=Warning
Facility=Application
SymbolicName=INF_DONTREPEAT
Language=ENU
Don't show this message again.
.
Language=SVE
Visa inte detta meddelande igen.
.
Language=DEU
Diese Meldung nicht wieder anzeigen.
.
Language=FRA
Ne plus afficher ce message.
.
Language=ESN
Omitir este mensaje.
.
Language=ITA
Non ripetere questo messaggio.
.
Language=HUN
Ne mutassa többet ezt az üzenetet.
.
Language=NOR
Don't show this message again.
.
Language=NLD
Dit bericht niet meer weergeven.
.
Language=DNK
Vis ikke denne besked igen.
.
Language=POL
Nie pokazuj ponownie tego komunikatu.
.
Language=CHI
Don't show this message again.
.
Language=PTG
Don't show this message again.
.
Language=PTB
Não mostrar esta mensagem novamente.
.
Language=RUS
Не показывать это сообщение.
.
Language=CZH
Tuto zprávu už znovu nezobrazovat.
.
Language=FIN
Älä näytä tätä sanomaa enää.
.

;//
;//	Rel 1.2 - Used when a wiping operation fails for some reason.
;//
MessageId=780
Severity=Error
Facility=Application
SymbolicName=MSG_WIPE_ERROR
Language=ENU
Shredding of '%3' failed, %4
.
Language=SVE
Överskrivning av '%3' misslyckades, %4
.
Language=DEU
Löschen der Datei '%3' fehlgeschlagen, %4
.
Language=FRA
Erreur lors du brouillage de '%3', %4
.
Language=ESN
Error al limpiar '%3', %4
.
Language=ITA
Errore nel rimuovere completamente '%3', %4
.
Language=HUN
A '%3' megsemmisítése nem sikerült, %4
.
Language=NOR
Shredding of '%3' failed, %4
.
Language=NLD
Vernietigen van '%3' mislukt. %4
.
Language=DNK
Overskrivning af '%3' mislykkedes, %4
.
Language=POL
Błąd niszczenia '%3', %4
.
Language=CHI
Shredding of '%3' failed, %4
.
Language=PTG
Shredding of '%3' failed, %4
.
Language=PTB
Erro ao destruir '%3', %4
.
Language=RUS
Не удалось уничтожить '%3', %4
.
Language=CZH
Skartace '%3' selhala, %4
.
Language=FIN
Tiedoston '%3' päällekirjoitus epäonnistui, %4
.

;//
;// Rel 1.2.2 - Menu choice for renaming a file and give
;//	it a new, anonymous one.
;//
MessageId=790
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_RENAME
Language=ENU
Rename
.
Language=SVE
Ändra namn
.
Language=DEU
Umbenennen
.
Language=FRA
Retitrez
.
Language=ESN
Renombrar
.
Language=ITA
Rinomina
.
Language=HUN
Átnevezés
.
Language=NOR
Rename
.
Language=NLD
Naam wijzigen
.
Language=DNK
Omdøb
.
Language=POL
Zmień nazwę
.
Language=CHI
Rename
.
Language=PTG
Rename
.
Language=PTB
Renomear
.
Language=RUS
Переименовать
.
Language=CZH
Přejmenovat
.
Language=FIN
Nimeä uudelleen
.

;//
;// Rel 1.2.2 - Menu help for renaming a file and give
;//	it a new, anonymous one.
;//
MessageId=800
Severity=Informational
Facility=Application
SymbolicName=HLP_MENU_RENAME
Language=ENU
Rename with an anonymous name. The original will be restored on decryption.
.
Language=SVE
Ändra till ett anonymt namn. Originalet återställs vid dekryptering.
.
Language=DEU
Umbenennen mit einem anonymen Namen. Das Original wird bei Entschlüsslung wiederhergestellt.
.
Language=FRA
Retitrez avec un nom anonyme.  L'original sera reconstitué sur le déchiffrage.
.
Language=ESN
Renombra con un nombre anónimo. El nombre original será restaurado al descifrar.
.
Language=ITA
Rinomina con un nome anonimo. L'originale verra' ripristinato nella decifrazione.
.
Language=HUN
Átnevezés anonim névre. Az eredeti nevet visszakapja visszafejtésnél.
.
Language=NOR
Rename with an anonymous name. The original will be restored on decryption.
.
Language=NLD
De naam naar een anonieme naam wijzigen. De originele naam wordt hersteld bij het ontsleutelen.
.
Language=DNK
Omdøb med et anonymt navn. Det oprindelige navn vil blive gendannet under dekrypteringen.
.
Language=POL
Zmień nazwę na dowolną. Oryginalna nazwa zostanie odtworzona podczas odszyfrowywania.
.
Language=CHI
Rename with an anonymous name. The original will be restored on decryption.
.
Language=PTG
Rename with an anonymous name. The original will be restored on decryption.
.
Language=PTB
Renomear como anônimo. O original será restituído ao decriptar.
.
Language=RUS
Переименовать анонимным именем. Оригинальное будет восстановлено при расшифровке.
.
Language=CZH
Přejmenovat anonymním jménem. Původní bude obnoveno při dešifrování.
.
Language=FIN
Nimeää uudelleen anonyymisti. Alkuperäinen nimi palautetaan salakoodauksen purkamisen yhteydessä.
.

;//
;// Rel 1.3.1
;//
;// Generic file errors, intended for use with the
;// .File() CAssert member.
;//
MessageId=810
Severity=Error
Facility=Application
SymbolicName=ERR_FILE
Language=ENU
'%3': %4
.
Language=SVE
'%3': %4
.
Language=DEU
'%3': %4
.
Language=FRA
'%3': %4
.
Language=ESN
'%3': %4
.
Language=ITA
'%3': %4
.
Language=HUN
'%3': %4
.
Language=NOR
'%3': %4
.
Language=NLD
'%3': %4
.
Language=DNK
'%3': %4
.
Language=POL
'%3': %4
.
Language=CHI
'%3': %4
.
Language=PTG
'%3': %4
.
Language=PTB
'%3': %4
.
Language=RUS
'%3': %4
.
Language=CZH
'%3': %4
.
Language=FIN
'%3': %4
.

;//
;// Rel 1.3.1
;//
;//	No valid standard output available, but needed.
;//
MessageId=820
Severity=Error
Facility=Application
SymbolicName=ERR_NO_STDOUT
Language=ENU
Standard Output must be file or pipe.
.
Language=SVE
Standard Output måste vara fil eller pipe.
.
Language=DEU
Standard Ausgabe muß eine Datei oder Pipe sein.
.
Language=FRA
La sortie standard doit être un fichier ou un pipe.
.
Language=ESN
La salida estándar debe ser un fichero o una tubería.
.
Language=ITA
Lo Standard Output deve essere un file o pipe.
.
Language=HUN
Standard kimenet fájl vagy pipe kell, hogy legyen.
.
Language=NOR
Standard Output must be file or pipe.
.
Language=NLD
Standaarduitvoer moet een bestand of pipe zijn.
.
Language=DNK
Standard Output skal være en fil eller pipe.
.
Language=POL
Standardowe Wyjście musi być plikiem lub strumieniem.
.
Language=CHI
Standard Output must be file or pipe.
.
Language=PTG
Standard Output must be file or pipe.
.
Language=PTB
A saída padrão deve ser um arquivo ou pipe.
.
Language=RUS
Стандартный выход должен быть файл или поток.
.
Language=CZH
Standardní výstup musí být soubor nebo roura.
.
Language=FIN
Vakiotulosteen tulee olla tiedosto tai putki.
.

;//
;// Rel 1.5 - Right Click Menu choice for one-by-one copy to self-extracting archive.
;//
MessageId=830
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_SFXENCDEF
Language=ENU
Encrypt copy to .EXE
.
Language=SVE
Kryptera kopia till .EXE
.
Language=DEU
Kopie als .EXE verschlüsseln
.
Language=FRA
Crypter et créer exécutable
.
Language=ESN
Cifrar a archivo autodescifrable
.
Language=ITA
Cifrare -> .EXE
.
Language=HUN
Titkosítás .EXE fájlba
.
Language=NOR
Encrypt copy to .EXE
.
Language=NLD
Kopie versleutelen naar .EXE
.
Language=DNK
Krypter kopi til .EXE
.
Language=POL
Zaszyfruj kopię pliku do .EXE
.
Language=CHI
Encrypt copy to .EXE
.
Language=PTG
Encrypt copy to .EXE
.
Language=PTB
Encriptar para .EXE
.
Language=RUS
Шифровать копию в .EXE
.
Language=CZH
Zašifrovat kopii do .EXE
.
Language=FIN
Salakoodaa kopio EXE:nä
.

;//
;// Rel 1.5 - Menu help for one-by-one copy to self-extracting archive,
;// shown in the status bar of Windows Explorer, if enabled.
;//
MessageId=840
Severity=Informational
Facility=Application
SymbolicName=HLP_MENU_SFXENCDEF
Language=ENU
Encrypt and copy to self decrypting program file(s).
.
Language=SVE
Kryptera och kopiera till självdekrypterande programfil(er).
.
Language=DEU
Verschlüsseln und in Selbstentschlüsselnde(s) Programm(e) kopieren.
.
Language=FRA
Crypte le fichier pour en faire une archive auto-décryptante.
.
Language=ESN
Cifrar y copiar a archivo(s) auto-descifrable(s).
.
Language=ITA
Cifrare e copiare in uno o più file auto-decifrante/i.
.
Language=HUN
Titkosítás és másolás önkicsomagoló program fájl(ok)ba.
.
Language=NOR
Encrypt and copy to self decrypting program file(s).
.
Language=NLD
Versleutelen en kopiëren naar zichzelf ontsleutelend(e) programmabestand(en).
.
Language=DNK
Krypter og kopier til selvdekrypterende programfil(er).
.
Language=POL
Zaszyfruj i utwórz samo odszyfrowujący się plik(ki).
.
Language=CHI
Encrypt and copy to self decrypting program file(s).
.
Language=PTG
Encrypt and copy to self decrypting program file(s).
.
Language=PTB
Encriptar e copiar para arquivo(s) auto-decifrável(is).
.
Language=RUS
Шифровать и копировать в саморасшифровывающийся исполняемый файл(ы).
.
Language=CZH
Zašifrovat a zkopírovat do auto-dešifrujícího programového souboru(ů).
.
Language=FIN
Salakoodaa ja kopioi itseavautuvaksi(-viksi) ohjelmatiedostoksi(-toiksi).
.

;//
;// Rel 1.5 - Right Click Menu choice for many-to-one copy to self-extracting archive.
;// It needs to be short!
;//
MessageId=850
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_SFXENCNAME
Language=ENU
Encrypt and copy to one .EXE
.
Language=SVE
Kryptera och kopiera till en .EXE
.
Language=DEU
Verschlüsseln & in .EXE kopieren
.
Language=FRA
Crypter et créer exécutable unique
.
Language=ESN
Cifrar y copiar a un sólo auto-descifrable
.
Language=ITA
Cifrare & Copiare in un unico .EXE
.
Language=HUN
Titkosítás egyetlen .EXE fájlba
.
Language=NOR
Encrypt and copy to one .EXE
.
Language=NLD
Versleutelen en kopiëren naar één .EXE
.
Language=DNK
Krypter og kopier til én .EXE
.
Language=POL
Zaszyfruj i utwórz jeden plik .EXE
.
Language=CHI
Encrypt and copy to one .EXE
.
Language=PTG
Encrypt and copy to one .EXE
.
Language=PTB
Encriptar e copiar somente para um .EXE
.
Language=RUS
Шифровать и копировать в один .EXE
.
Language=CZH
Zašifrovat a zkopírovat do jednoho .EXE
.
Language=FIN
Salakoodaa ja kopioi yhteen EXE-tiedostoon.
.

;//
;// Rel 1.5 - Menu help for many-to-one copy to self-extracting archive,
;// shown in the status bar of Windows Explorer for example.
;//
MessageId=860
Severity=Informational
Facility=Application
SymbolicName=HLP_MENU_SFXENCNAME
Language=ENU
Encrypt and copy all to one single self decrypting program file.
.
Language=SVE
Kryptera och kopiera alla till en samlad självdekrypterande programfil.
.
Language=DEU
Verschlüsseln und alles in ein Selbstentschlüsselndes Programm kopieren.
.
Language=FRA
Crypte tous les fichiers pour en faire une unique archive auto-décryptante.
.
Language=ESN
Cifrar y copiar todo a un sólo archivo auto-descifrable
.
Language=ITA
Cifrare e copiare tutti i file in un unico file auto-decifrante.
.
Language=HUN
Titkosítás és másolás egyetlen önkicsomagoló program fájlba.
.
Language=NOR
Encrypt and copy all to one single self decrypting program file.
.
Language=NLD
Alles versleutelen en kopiëren naar één zelf-ontsleutelend programmabestand.
.
Language=DNK
Krypter og kopier til en enkelt selvdekrypterende programfil.
.
Language=POL
Zaszyfruj i utwórz jeden samo odszyfrowujący się plik.
.
Language=CHI
Encrypt and copy all to one single self decrypting program file.
.
Language=PTG
Encrypt and copy all to one single self decrypting program file.
.
Language=PTB
Encriptar e copiar todos para somente um único arquivo auto-decifrável.
.
Language=RUS
Шифровать и копировать все в один саморасшифровывающийся исполняемый файл.
.
Language=CZH
Zašifrovat a zkopírovat vše do jednoho auto-dešifrujícího programového souboru.
.
Language=FIN
Salakoodaa ja kopioi kaikki yhteen itseavautuvaan ohjelmatiedostoon.
.

;//
;// Rel 1.5 - Error message shown when an attempt is made to decrypt
;// a file without the standard extension, i.e. .xxx. This is to avoid
;// confusion by users - based on a real story.
;//
MessageId=870
Severity=Error
Facility=Application
SymbolicName=MSG_INVALID_EXT
Language=ENU
The file name has the wrong extension and should not decrypted with %1,
please rename or use the correct application.
.
Language=SVE
Felaktigt filtillägg, denna fil skall ej dekrypteras med %1.
Ändra namnet eller avänd rätt applikation.
.
Language=DEU
Der Dateiname hatte eine falsche Endung - die Datei sollte nicht mit %1 entschlüsselt werden,
Bitte benennen Sie die Datei um oder benutzen Sie die korrekte Anwendung.
.
Language=FRA
Mauvaise extension du nom de fichier : celui-ci ne devrait pas être
décrypté avec %1. Veuillez le renommer ou utiliser la bonne application.
.
Language=ESN
La extensión de este archivo indica que no se debe descifrar con %1,
Por favor, cambie el nombre del mismo o utilice la aplicación asociada.
.
Language=ITA
Il nome del file possiede un'estensione sbagliata e non può essere decifrato con %1,
per favore, rinominarlo o usare l'applicazione corretta.
.
Language=HUN
A fájl kiterjesztése nem megfelelõ: ezt nem kellene %1 segítségével
visszafejteni, kérem nevezze át vagy a megfelelõ alkalmazást használja.
.
Language=NOR
The file name has the wrong extension and should not decrypted with %1,
please rename or use the correct application.
.
Language=NLD
Het bestand heeft de verkeerde extensie en mag niet worden ontsleuteld met %1.
Wijzig de bestandsnaam of gebruik de juiste toepassing.
.
Language=DNK
Denne fil har den forkerte type og bør ikke blive dekrypteret med %1,
omdøb eller benyt den rette applikation.
.
Language=POL
Nieodpowiednie rozszerzenie nazwy pliku by odszyfrować z użyciem %1,
zmień proszę rozszerzenie pliku lub użyj poprawnej aplikacji.
.
Language=CHI
The file name has the wrong extension and should not decrypted with %1,
please rename or use the correct application.
.
Language=PTG
The file name has the wrong extension and should not decrypted with %1,
please rename or use the correct application.
.
Language=PTB
O nome do arquivo contém uma extensão desconhecida e não pode ser decriptado com %1,
Por favor renomeie-o ou use o aplicativo correto.
.
Language=RUS
Имя файла имеет неверное расширение и не может быть расшифровано %1,
пожалуйста, переименуйте или используйте соответствующее приложение.
.
Language=CZH
Soubor má chybnou příponu a %1 ho nemůže dešifrovat,
prosím přejmenujte ho nebo použijte správnou aplikaci.
.
Language=FIN
Tiedostonimen pääteosa on väärä eikä sitä voi avata %1-ohjelmalla,
nimeä tiedosto uudelleen tai käytä oikeaa sovellusta.
.

;//
;// Rel 1.5 - Used as a header for the frame where we ask for a key file in
;// the passphrase dialogs.
;//
MessageId=880
Severity=Informational
Facility=Application
SymbolicName=INF_FRAME_KEYFILE
Language=ENU
Key-File
.
Language=SVE
Nyckelfil
.
Language=DEU
Schlüssel-Datei
.
Language=FRA
Fichier-clef
.
Language=ESN
Fichero llave
.
Language=ITA
Key-File
.
Language=HUN
Kulcsfájl
.
Language=NOR
Key-File
.
Language=NLD
Sleutelbestand
.
Language=DNK
Nøglefil
.
Language=POL
Plik-Klucz
.
Language=CHI
Key-File
.
Language=PTG
Key-File
.
Language=PTB
Arquivo-Chave
.
Language=RUS
Файл ключа
.
Language=CZH
Soubor s klíčem
.
Language=FIN
Avaintiedosto
.

;//
;// Rel 1.5 - The right click menu to generate a new key file.
;//
MessageId=890
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_KEYFILE
Language=ENU
Make Key-File
.
Language=SVE
Skapa Nyckelfil
.
Language=DEU
Schlüssel-Datei erstellen
.
Language=FRA
Créer fichier-clef
.
Language=ESN
Crear Fichero llave
.
Language=ITA
Crea un Key-File
.
Language=HUN
Kulcsfájl létrehozása
.
Language=NOR
Make Key-File
.
Language=NLD
Sleutelbestand maken
.
Language=DNK
Skabe nøglefil
.
Language=POL
Utwórz Plik-Klucz
.
Language=CHI
Make Key-File
.
Language=PTG
Make Key-File
.
Language=PTB
Criar Arquivo-Chave
.
Language=RUS
Создать файл ключа
.
Language=CZH
Vytvořit soubor s klíčem
.
Language=FIN
Tee avaintiedosto
.

;//
;// Rel 1.5 - The text shown as a warning pop-up message box before the actual
;// dialog to make a key file.
;//
MessageId=900
Severity=Informational
Facility=Application
SymbolicName=INF_MAKE_KEYFILE
Language=ENU
This will generate random data and save as a key-file. Only store on removable media.
Print backup and store in safe place.
%n%nUsing a key-file is optional, but provides much stronger security than a passphrase.
%n%nIf this file is lost, so are documents encrypted with it! NEVER encrypt a key-file itself!
.
Language=SVE
Genererar slumpdata och sparas som nyckelfil. Spara endast till flyttbart media!
Skriv därför ut säkerhetskopia och spara på ett säkert ställe.
%n%nDet är inte nödvändigt att använda en nyckelfil, men det ger högre säkerhet.
%n%nOm nyckelfilen går förlorad, förloras även alla dokument som krypterats med den! Kryptera
ALDRIG en nyckelfil!
.
Language=DEU
Dies wird Zufallsdaten in einer Schlüssel-Datei speichern. Nur auch Wechseldatenträgern speichern.
Eine Sicherheitskopie ausdrucken und sicher aufbewahren.
%n%nEine Schlüssel-Datei zu verwenden ist optional, aber bietet höhere Sicherheit als nur ein Passwort.
%n%nWenn die Schlüssel-Datei verloren geht sind auch alle damit verschlüsselten Daten verloren!
.
Language=FRA
Ceci va générer des données aléatoires et les sauvegarder dans un fichier-clef. Ce
fichier ne doit être sauvegardé que sur un support amovible. Imprimez-en une copie
de sécurité et conservez-la en lieu sûr.
%n%nUtiliser un fichier-clef n'est pas obligatoire, mais est plus sûr qu'un simple
mot de passe.
%n%nSi ce fichier est perdu, les documents cryptés avec le seront également!
.
Language=ESN
Esto generará datos aleatorios y los guardará como Fichero llave. Almacénelos en medios extraíbles únicamente.
Imprima una copia y conservela en un lugar seguro.
%n%nUtilizar un Fichero llave es opcional, pero proporciona una seguridad muy superior a una simple contraseña.
%n%nSi este Fichero llave se pierde, con el perderá usted los documentos que haya cifrado usándolo!
.
Language=ITA
Verranno ora generati dati casuali e salvati come un key-file. Memorizzalo solamente su supporti rimovibili.
Eseguire il backup e custodire in un luogo sicuro.
%n%nL'utilizzo di un key-file è optional, ma fornisce una sicurezza maggiore rispetto alla sola parola chiave.
%n%nSe questo file andasse perduto, lo sarebbero anche i documenti criptati con esso!
.
Language=HUN
Véletlenszerû adatokat hoz létre és kulcsfájlként menti. Csak mobil tárolón tárolja.
Nyomtasson biztonsági másolatot és tartsa megbízható helyen.
%n%nA kulcsfájl használata opcionális, de sokkal nagyobb biztonságot ad, mint a kulcsmondat.
%n%nHa a kulcsfájl elvész, a vele titkosított dokumentumok is!
.
Language=NOR
This will generate random data and save as a key-file. Only store on removable media.
Print backup and store in safe place.
%n%nUsing a key-file is optional, but provides much stronger security than a passphrase.
%n%nIf this file is lost, so are documents encrypted with it!
.
Language=NLD
Hiermee worden willekeurige gegevens gegenereerd die vervolgens als sleutelbestand worden opgeslagen.
Bewaar dit bestand uitsluitend op verwijderbare media. Druk een backup af en bewaar die op een veilige plaats.
%n%nGebruik van een sleutelbestand is optioneel, maar biedt wel veel betere veiligheid dan een wachtwoord.
%n%nAls u dit sleutelbestand kwijtraakt, gaan alle daarmee versleutelde bestanden verloren!
.
Language=DNK
Dette vil skabe tilfældige data og gemme dem som en nøglefil. Gem kun på flytbare medier. Udskriv en kopi og gem et sikkert sted.
%n%nBrug af en nøglefil er frivillig, men giver langt bedre sikkerhed end et kodeord.
%n%nHvis denne fil mistes, bliver bliver de krypterede filer uanvendelige. Krypter ALDRIG nøglefilen selv!
.
Language=POL
Wygenerowane zostaną losowe dane i utworzony zostanie Plik-Klucz. Klucz zapisuj jedynie na urządzeniach przenośnych.
Wykonaj kopię klucza i przechowuj go w bezpiecznym miejscu.
%n%nUżywanie plików-kluczy jest opcjonalne lecz dzięki nim uzyskasz znacznie większe bezpieczeństwo niż użycie hasła.
%n%nJednak pamiętaj, że w przypadku zagubienia klucza, utracisz również dokumenty nim zaszyfrowane! NIGDY nie szyfruj Pliku-Klucza!
.
Language=CHI
This will generate random data and save as a key-file. Only store on removable media.
Print backup and store in safe place.
%n%nUsing a key-file is optional, but provides much stronger security than a passphrase.
%n%nIf this file is lost, so are documents encrypted with it! NEVER encrypt a key-file itself!
.
Language=PTG
This will generate random data and save as a key-file. Only store on removable media.
Print backup and store in safe place.
%n%nUsing a key-file is optional, but provides much stronger security than a passphrase.
%n%nIf this file is lost, so are documents encrypted with it! NEVER encrypt a key-file itself!
.
Language=PTB
Isto irá gerar dados aleatórios que serão salvos como arquivo-chave. Armazene-o somente em mídias removíveis.
Faça um backup e guarde-o em lugar seguro.
%n%nUsar um arquivo-chave é opcional, mas ele proporciona uma segurança muito maior do que a senha.
%n%nSe este arquivo for perdido, você não poderá mais acessar os documentos que foram encriptados com ele!
NUNCA encripte uma arquivo-chave!
.
Language=RUS
Будут сгенерированы случайные данные и сохранены как файл ключа. Храните только на съемных носителях.
Сделайте копию файла ключа и храните его в безопасном месте.
%n%nИспользование файла ключа необязательно, но обеспечивает более высокий уровень безопасности, чем пароль!
%n%nЕсли этот файл потерян, то и документы, им зашифрованные, тоже!
Внимание!!! НИКОГДА не шифруйте файл ключа им же!
.
Language=CZH
Budou generována náhodná data a uložena jako soubor s klíčem. Ukládejte jen na výměnná média.
Vytiskněte si kopii a uložte na bezpečném místě.
%n%nPoužití souboru s klíčem je volitelné, ale přináší mnohem vyšší bezpečnost než heslo.
%n%nKdyž je tento soubor ztracen, přijdete o dokumenty, které jsou pomocí něj zašifrované!
NIKDY nešifrujte samotný soubor s klíčem!
.
Language=FIN
Tämä luo satunnaisdataa ja tallentaa sen avaintiedostona. Säilytä tiedostoa vain irtolevyllä.
Tulosta varmistuskopio ja pane varmaan paikkaan.
%n%nAvaintiedoston käyttäminen on vapaaehtoista, mutta se antaa paljon vahvemman suojauksen kuin salasana.
%n%nJos tämä avaintiedosto häviää, kaikki asiakirjat, jotka on sillä suojattu, on menetetty!
ÄLÄ KOSKAAN salakoodaa itse avaintiedostoja!
.

;//
;// Rel 1.5 - The help-text for the menu to generate a new key file.
;//
MessageId=910
Severity=Informational
Facility=Application
SymbolicName=HLP_MENU_KEYFILE
Language=ENU
Generate random data and save as a key-file. Don't lose this file!
.
Language=SVE
Generera slumpdata och spara som nyckelfil. Tappa inte bort den!
.
Language=DEU
Zufallsdaten generieren und als Schlüssel-Datei speichern. Diese Datei auf keinen Fall verlieren!
.
Language=FRA
Génère des données aléatoires pour créer un fichier-clef. Fichier à ne pas égarer!
.
Language=ESN
Generar datos aleatorios y guardar como Fichero llave. ¡No pierda este fichero!
.
Language=ITA
Genera dati casuali e salvali come un key-file. Non perdere questo file!
.
Language=HUN
Véletlenszerû adatokat hoz létre és kulcsfájlként menti. Ne veszítse el ezt a fájlt!
.
Language=NOR
Generate random data and save as a key-file. Don't lose this file!
.
Language=NLD
Willekeurige gegevens genereren en die opslaan als sleutelbestand. Raak dit bestand niet kwijt!
.
Language=DNK
Skab tilfældige data og gem som en nøglefil. Mist ikke denne fil!
.
Language=POL
Wygeneruj losowe dane i zapisz Plik-Klucz. Nie zgub tego pliku!
.
Language=CHI
Generate random data and save as a key-file. Don't lose this file!
.
Language=PTG
Generate random data and save as a key-file. Don't lose this file!
.
Language=PTB
Gerar dados aleatórios e salvar como arquivo-chave. Não perca este arquivo!
.
Language=RUS
Генерировать случайные данные и сохранить как файл ключа. Не теряйте этот файл!
.
Language=CZH
Generovat náhodná data a uložit je jako soubor s klíčem. Neztraťte tento soubor!
.
Language=FIN
Luo satunnaisdataa ja tallentaa sen avaintiedostona. Älä kadota tätä tiedostoa!
.

;//
;// Rel 1.5 - Specific extra warning text for multi file-wipe.
;//
MessageId=920
Severity=Warning
Facility=Application
SymbolicName=WRN_REALLY_WIPE_ALL
Language=ENU
Do you really want to overwrite %2 and all the rest of the selected files with
random data and then permanently delete them?
%n%nThis cannot be undone!
.
Language=SVE
Vill verkligen skriva över %2 och alla anda valda filer med slumpässigt data och
sedan permanent ta bort dem?
%n%nDetta går inte att ångra!
.
Language=DEU
Wollen Sie wirklich %2 und die übrigen ausgewählten Dateien mit Zufallsdaten
überschreiben und dann permanent löschen?
%n%nDies kann nicht rückgängig gemacht werden!
.
Language=FRA
Souhaitez-vous réellement réécrire %2 et le reste des fichiers sélectionnés avec
des données aléatoires et les supprimer après de manière définitive?
%n%nLes fichiers ainsi supprimés ne seront pas récupérables!
.
Language=ESN
¿Está usted seguro de que quiere sobreescribir %2 y los demás ficheros seleccionados con
datos aleatorios y por tanto eliminarlos definitivamente?
%n%n¡Esta operación no tiene vuelta atrás!
.
Language=ITA
Vuoi veramente sovrascrivere %2 a tutto il resto dei file selezionati con
dati casuali e successivamente cancellarli in modo permanente?
Do you really want to overwrite %2 and all the rest of the selected files with
%n%nQuesta operazione non è reversibile!
.
Language=HUN
Tényleg szeretné felülírni a %2 fájlt és a többi kiválasztott fájlt
véletlenszerû adatokkal és véglegesen törölni õket?
%n%nnEz visszavonhatatlan!
.
Language=NOR
Do you really want to overwrite %2 and all the rest of the selected files with
random data and then permanently delete them?
%n%nThis cannot be undone!
.
Language=NLD
Wilt u '%2' en alle andere geselecteerde bestanden echt overschrijven met
willekeurige gegevens en die vervolgens definitief verwijderen?
%n%nDit kan niet ongedaan worden gemaakt!
.
Language=DNK
Ønsker du virkelig at overskrive %2 og resten af de valgte filer med tilfældige data og slette dem permanent?
%n%nDette kan ikke fortrydes!
.
Language=POL
Czy na pewno chcesz nadpisać losowymi danymi, a tym samym na stałe usunąć plik %2
i wszystkie pozostałe wybrane pliki?
%n%nTej operacji nie będzie można cofnąć!
.
Language=CHI
Do you really want to overwrite %2 and all the rest of the selected files with
random data and then permanently delete them?
%n%nThis cannot be undone!
.
Language=PTG
Do you really want to overwrite %2 and all the rest of the selected files with
random data and then permanently delete them?
%n%nThis cannot be undone!
.
Language=PTB
Você realmente quer sobrescrever %2 e todos os arquivos selecionados com
dados aleatórios e deletá-los permanentemente?
%n%nEsta operação não pode ser desfeita!
.
Language=RUS
Вы действительно хотите перезаписать %2 и все остальные выбранные файлы
случайными данными и окончательно удалить их?
%n%nЭто не может быть отменено!
.
Language=CZH
Skutečně chcete přepsat %2 a všechny další vybrané soubory náhodnými daty
a následně je nenávratně odstranit?
%n%nAkci nelze vrátit zpět!
.
Language=FIN
Haluatko todella päällekirjoittaa tiedoston %2 sekä muut valitut tiedostot
satunnaisdatalla ja sitten poistaa ne lopullisesti?
%n%nTätä toimenpidettä ei voi peruuttaa!
.

;//
;// Rel 1.5 - Default file name for key-file.
;//
MessageId=930
Severity=Informational
Facility=Application
SymbolicName=INF_KEYFILE_NAME
Language=ENU
My Key-File.txt
.
Language=SVE
Min Nyckelfil.txt
.
Language=DEU
Meine Schlüssel-Datei.txt
.
Language=FRA
Mon fichier-clef.txt
.
Language=ESN
Mi Fichero llave.txt
.
Language=ITA
Il Mio Key-File.txt
.
Language=HUN
Kulcsfájlom.txt
.
Language=NOR
My Key-File.txt
.
Language=NLD
Mijn sleutelbestand.txt
.
Language=DNK
Min nøglefil.txt
.
Language=POL
Mój Plik-Klucz.txt
.
Language=CHI
My Key-File.txt
.
Language=PTG
My Key-File.txt
.
Language=PTB
Meu arquivo-chave.txt
.
Language=RUS
Мой файл ключа.txt
.
Language=CZH
Můj Soubor-s-klíčem.txt
.
Language=FIN
Oma avaintiedostoni.txt
.

;//
;// Rel 1.5 - Warn that the save is about to be done on a non-removable
;//           drive. This is used when generating key files, they really
;//           never should be stored on fixed media.
;//
MessageId=940
Severity=Warning
Facility=Application
SymbolicName=WRN_NOT_REMOVABLE
Language=ENU
The key-file will be saved to what appears to be a non-removable drive. Only
store key-files on diskettes, USB-drives and similar devices that can
be physically removed from the computer.
.
Language=SVE
Nyckelfilen sparas till vad som verkar vara en fast hårddisk. Nyckelfiler
bör endast sparas på disketter, USB-enheter och liknande som
kan tas ut och förvaras fritt från datorn.
.
Language=DEU
Die Schlüssel-Datei wird anscheinend auf eine Festplatte gespeichert. Sie
sollten Schlüssel-Dateien nur auf Datenträgern speichern, die sich physikalisch
aus dem Computer entfernen lassen, zum Beispiel Disketten oder USB-Sticks.
.
Language=FRA
Le fichier-clef va être sauvegardé sur ce qui semble être un support non-amovible.
Vous ne devriez sauvegarder vos fichiers-clef que sur disquette, clefs USB ou
tout autre support qui peut être déconnecté de l'ordinateur.
.
Language=ESN
El Fichero llave va a ser guardado en lo que parece un disco fijo. Guarde
los Ficheros llave únicamente en disquetes, discos USB u otros dispositivos que
puedan ser extraídos físicamente de su equipo.
.
Language=ITA
Il key-file verrà salvato su quello che sembra essere un disco non-rimovibile.
Memorizza i key-files su dischetti, dischi-USB e dispositivi simili che
possono essere fisicamente rimossi dal computer.
.
Language=HUN
Úgy tûnik, hogy a kulcsfájlt nem mobil tárolóra menti. Kulcsfájlt csak hajlékony-
lemezen, USB-drive-on vagy hasonló eszközön tároljon, amit fizikailag le tud
választani a számítógéprõl.
.
Language=NOR
The key-file will be saved to what appears to be a non-removable drive. Only
store key-files on diskettes, USB-drives and similar devices that can
be physically removed from the computer.
.
Language=NLD
Het sleutelbestand wordt opgeslagen op wat niet een verwijderbare schijf lijkt.
Bewaar sleutelbestanden uitsluitend op diskettes, USB-drives en soortgelijke apparaten
die fysiek van de computer kunnen worden verwijderd.
.
Language=DNK
Denne nøglefil vil blive gemt på, hvad der ser ud til at være et ikke-flytbart medie.
Gem kun nøglefiler på disketter, USB-drev og lignende, der fysisk kan fjernes fra
computeren.
.
Language=POL
Plik-Klucz ma zostać zapisany na dysku, który prawdopodobnie nie jest urządzeniem przenośnym. Staraj się trzymać
pliki-klucze jedynie na dyskietkach, pen-drive'ach lub innych podobnych urządzeniach przenośnych, czyli takich,
które mogą być fizycznie odłączone od komputera.
.
Language=CHI
The key-file will be saved to what appears to be a non-removable drive. Only
store key-files on diskettes, USB-drives and similar devices that can
be physically removed from the computer.
.
Language=PTG
The key-file will be saved to what appears to be a non-removable drive. Only
store key-files on diskettes, USB-drives and similar devices that can
be physically removed from the computer.
.
Language=PTB
O arquivo-chave será salvo numa mídia que não parece ser removível. Somente
armazene arquivos-chaves em disquetes, drives USB ou dispositivos semelhantes que possam ser
fisicamente removidos de seu computador.
.
Language=RUS
Кажется, файл ключа будет сохранен на несъемный диск.
Храните файлы ключей только на дискетах, USB-дисках и подобных устройствах,
которые могут быть физически удалены из компьютера.
.
Language=CZH
Soubor s klíčem bude uložen na zařízení, které nevypadá jako výměnné. Ukládejte
soubor s klíčem pouze na diskety, USB klíčenky a podobná zařízení, která mohou
být fyzicky odpojena od počítače.
.
Language=FIN
Avaintiedostoa ollaan tallentamassa levylle, joka ei ole poistettavissa koneesta.
Tallenna avaintiedostot vain levykkeille, muistitikuille tai muille irtolevyille.
.

;//
;// Rel 1.5 - Inform the use about how key-files are used.
;//
MessageId=950
Severity=Informational
Facility=Application
SymbolicName=INF_KEYFILE_USE
Language=ENU
You are about to use a key-file to encrypt. This is optional.
%n%nThis will give you the strongest
possible protection, but you must keep the key-file secret!
%n%nKey-files are made with the Explorer menu in a selected folder.
%n%nKeep it secret, keep it safe!
.
Language=SVE
Här väljer du att använda en nyckelfil. Detta är valfritt.
%n%nDetta garanterar den högsta möjliga säkerheten, så länge nyckelfilen
hålls hemlig.
%n%nDu skapar en nyckelfil med Explorer-menyn i en vald mapp.
%n%nHåll den hemlig, förvara den säkert!
.
Language=DEU
Sie sind dabei, eine Schlüssel-Datei zum verschlüsseln zu benutzen. Dies ist optional.
%n%nEs gibt ihnen den stärksten Schutz, aber die Schlüssel-Datei muß geheim bleiben!
%n%nSchlüssel-Dateien können über das Explorer-Menü im ausgewählten Ordner hergestellt werden.
%n%nHalten Sie die Datei zu Ihrer Sicherheit geheim!
.
Language=FRA
Vous allez utiliser un fichier-clef pour crypter des données. Ceci est
facultatif.
%n%nUn fichier-clef vous donnera la meilleure sécurité, mais il faut
absolument garder votre fichier-clef secret!
%n%nLes fichiers-clef sont créés via le menu dans un fichier
sélectionné.
%n%nGardez-le caché, mettez-le en sûreté!
.
Language=ESN
Está a punto de usar un Fichero llave para cifrar los datos. Esto es opcional.
%n%n¡Le proporcionará a sus datos el mayor nivel posible de protección,
pero deberá usted mantener el Fichero llave secreto!
%n%nLos Ficheros llave se crean con el menú del Explorador en la carpeta seleccionada.
%n%nManténgalos siempre secretos y a salvo!
.
Language=ITA
Stai per usare un key-file per cifrare. E' una scelta opzionale.
%n%nQuesta scelta ti darà la più
sicura protezione possibile, ma devi custodire con cura il key-file!
%n%nIl key-file viene creato dal menu Explorer in una cartella selezionata.
%n%nMantienilo segreto, tienilo al sicuro!
.
Language=HUN
Ön kulcsfájlt használ a titkosításhoz, ami fakultatív dolog.
%n%nEz a lehetséges legerõsebb védelmet
biztosítja, de a kulcsfájlt titokban kell tartania!
%n%nKulcsfájlt az Explorer menübõl készíthet a kiválasztott könyvtárban.
%n%nTartsa titokban, tartsa biztonságban!
.
Language=NOR
You are about to use a key-file to encrypt. This is optional.
%n%nThis will give you the strongest
possible protection, but you must keep the key-file secret!
%n%nKey-files are made with the Explorer menu in a selected folder.
%n%nKeep it secret, keep it safe!
.
Language=NLD
U gaat een sleutelbestand gebruiken voor versleuteling. Dit is optioneel.
%n%nDit biedt de beste beveiliging, maar u moet het sleutelbestand geheim houden!
%n%nSleutelbestanden worden gemaakt met het menu Verkenner in een geselecteerde map.
%n%nHoud ze geheim en bewaar ze goed!
.
Language=DNK
Du er ved at benytte en nøglefil til at kryptere. Dette er frivilligt.
%n%nDet vil give dig den bedst mulige sikkerhed, men du må holde nøglefilen hemmelig!
%n%nNøglefiler laves med stifindermenuen i den valgte mappe.
%n%nHold den hemmelig og hold den gemt!
.
Language=POL
Zamierzasz użyć Pliku-Klucza. Użycie plików-kluczy do szyfrowania jest opcjonalne.
%n%nPamiętaj, że umożliwi Ci to uzyskanie najsilnieszego dostępnego
zabezpieczenia tylko wtedy, gdy będziesz trzymał Plik-Klucz w bezpiecznym miejscu!
%n%nUżywając menu Eksplorera utworzysz Plik-Klucz w wybranym przez Ciebie folderze.
%n%nPrzechowuj Klucz w sekrecie, a dane będą bezpieczne!
.
Language=CHI
You are about to use a key-file to encrypt. This is optional.
%n%nThis will give you the strongest
possible protection, but you must keep the key-file secret!
%n%nKey-files are made with the Explorer menu in a selected folder.
%n%nKeep it secret, keep it safe!
.
Language=PTG
You are about to use a key-file to encrypt. This is optional.
%n%nThis will give you the strongest
possible protection, but you must keep the key-file secret!
%n%nKey-files are made with the Explorer menu in a selected folder.
%n%nKeep it secret, keep it safe!
.
Language=PTB
Você está prestes a usar um arquivo-chave para encriptar dados. Isto é opcional.
%n%nIsto irá lhe fornecer a maior
proteção possível, mas você deve manter o arquivo-chave seguro!
%n%nArquivos-chaves são criados através do menu do Explorer na pasta selecionada.
%n%nMantenha-o protegido e seguro!
.
Language=RUS
Вы собираетесь использовать для шифрования файл ключа. Это необязательно.
%n%nЭто даст вам возможность сильнейшей защиты, но вы должны держать файл ключа в секрете!
%n%nФайл ключа создается из меню Проводника в выбранной папке.
%n%nХраните его в секрете, храните его в безопасности!
.
Language=CZH
Chystáte se použít k zašifrování soubor s klíčem. Toto je volitelné.
%n%nZískáte nejsilněší ochranu, ale musíte uchovávat soubor s klíčem v bezpečí!
%n%nSoubory s klíčem jsou vytvořeny z menu Průzkumníka ve vybrané složce.
%n%nUdržujte je v tajnosti, udržujte je v bezpečí!
.
Language=FIN
Olet salakoodaamassa tietoja avaintiedostoa käyttäen. Tämä on valinnaista.
%n%nTämä antaa sinulle vahvimman mahdollisen suojauksen, mutta sinun täytyy
pitää avaintiedosto salassa!
%n%nAvaintiedostot luodaan valittuun hakemistoon kontekstivalikosta.
%n%nPitämällä avaintiedoston salassa turvaat tietosi!
.

;//
;// Rel 1.5 - Right-Click menu choice to start the notify script, after the fact.
;//
MessageId=960
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_NOTIFYME
Language=ENU
Notify Me
.
Language=SVE
Uppdateringsmeddelanden
.
Language=DEU
Benachrichtigungen
.
Language=FRA
Notifications de mise à jour
.
Language=ESN
Manténgame informado
.
Language=ITA
Notificami gli Update
.
Language=HUN
Értesítés frissítésrõl
.
Language=NOR
Notify Me
.
Language=NLD
Melding weergeven
.
Language=DNK
Besked om nye udgaver
.
Language=POL
Powiadom mnie
.
Language=CHI
Notify Me
.
Language=PTG
Notify Me
.
Language=PTB
Mantenha-me informado
.
Language=RUS
Уведомить меня
.
Language=CZH
Informovat mě
.
Language=FIN
Notify Me
.

;//
;// Rel 1.5 - One line help text for Right-Click menu choice to start the notify script, after the fact.
;//
MessageId=970
Severity=Informational
Facility=Application
SymbolicName=HLP_MENU_NOTIFYME
Language=ENU
Notify Me
.
Language=SVE
Uppdateringsmeddelanden
.
Language=DEU
Benachrichtigungen
.
Language=FRA
Notifications de mise à jour
.
Language=ESN
Manténgame informado
.
Language=ITA
Notificami gli Update
.
Language=HUN
Értesítés frissítésrõl
.
Language=NOR
Notify Me
.
Language=NLD
Melding weergeven
.
Language=DNK
Besked om nye udgaver
.
Language=POL
Powiadom mnie
.
Language=CHI
Notify Me
.
Language=PTG
Notify Me
.
Language=PTB
Mantenha-me informado
.
Language=RUS
Уведомить меня
.
Language=CZH
Informovat mě
.
Language=FIN
Tiedottaa päivityksistä
.

;//
;// Rel 1.5 - One line help text for Right-Click menu choice to show Documentation
;//
MessageId=980
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_DOCS
Language=ENU
Documentation
.
Language=SVE
Dokumentation (Engelsk)
.
Language=DEU
Dokumentation (Englisch)
.
Language=FRA
Documentation (Anglais)
.
Language=ESN
Documentación (en inglés)
.
Language=ITA
Documentazione (Inglese)
.
Language=HUN
Dokumentáció
.
Language=NOR
Documentation
.
Language=NLD
Documentatie (Engelstalig)
.
Language=DNK
Dokumentation (Engelsk)
.
Language=POL
Dokumentacja
.
Language=CHI
Documentation
.
Language=PTG
Documentation
.
Language=PTB
Documentação (Inglês)
.
Language=RUS
Документация
.
Language=CZH
Dokumentace
.
Language=FIN
Dokumentaatio (englanniksi)
.

;//
;// Rel 1.5 - One line help text for Right-Click menu choice to show help/readme.
;//
MessageId=990
Severity=Informational
Facility=Application
SymbolicName=HLP_MENU_DOCS
Language=ENU
Show the documentation.
.
Language=SVE
Visa dokumentationen, på engelska.
.
Language=DEU
Zeigt die Dokumentation, in Englisch.
.
Language=FRA
Affiche la documentation, en anglais.
.
Language=ESN
Mostrar ayuda/fichero léeme (en inglés).
.
Language=ITA
Mostrami la documentazione, in Inglese.
.
Language=HUN
Mutassa a dokumentációt.
.
Language=NOR
Show the documentation.
.
Language=NLD
Documentatie weergeven.
.
Language=DNK
Vis dokumentationen, på engelsk.
.
Language=POL
Pokaż dokumentację.
.
Language=CHI
Show the documentation.
.
Language=PTG
Show the documentation.
.
Language=PTB
Mostrar documentação (Inglês).
.
Language=RUS
Показать документацию.
.
Language=CZH
Zobrazit dokumentaci.
.
Language=FIN
Näyttää englanninkielisen dokumentaation.
.

;//
;// Rel 1.5 - Right-Click menu choice to show About box
;//
MessageId=1000
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_ABOUT
Language=ENU
About
.
Language=SVE
Om
.
Language=DEU
Info
.
Language=FRA
A propos
.
Language=ESN
Acerca de
.
Language=ITA
Informazioni su...
.
Language=HUN
Info
.
Language=NOR
About
.
Language=NLD
Info
.
Language=DNK
Om
.
Language=POL
O programie
.
Language=CHI
About
.
Language=PTG
About
.
Language=PTB
Sobre
.
Language=RUS
О программе
.
Language=CZH
O programu
.
Language=FIN
Tietoja
.

;//
;// Rel 1.5 - One line help text for Right-Click menu choice to show About box.
;//
MessageId=1010
Severity=Informational
Facility=Application
SymbolicName=HLP_MENU_ABOUT
Language=ENU
About
.
Language=SVE
Om
.
Language=DEU
Info
.
Language=FRA
A propos
.
Language=ESN
Acerca de
.
Language=ITA
Informazioni su...
.
Language=HUN
Info
.
Language=NOR
About
.
Language=NLD
Info
.
Language=DNK
Om
.
Language=POL
O programie
.
Language=CHI
About
.
Language=PTG
About
.
Language=PTB
Sobre
.
Language=RUS
О программе
.
Language=CZH
O programu
.
Language=FIN
Tietoja
.

;//
;// Rel 1.5.2.x - Right-click menu choice to report a bug.
;//
MessageId=1015
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_BUGREPORT
Language=ENU
Report a problem
.
Language=SVE
Felanmälan
.
Language=DEU
Einen Fehler melden
.
Language=FRA
Rapporter un problème
.
Language=ESN
Report a problem
.
Language=ITA
Report a problem
.
Language=HUN
Probléma jelentése
.
Language=NOR
Report a problem
.
Language=NLD
Probleem rapporteren
.
Language=DNK
Giv besked om fejl
.
Language=POL
Zgłoś problem
.
Language=CHI
Report a problem
.
Language=PTG
Report a problem
.
Language=PTB
Reportar problema
.
Language=RUS
Сообщить о проблеме
.
Language=CZH
Nahlásit problém
.
Language=FIN
Raportoi ongelmasta
.

;//
;// Rel 1.5.2.x - Right-click menu choice to report a bug - Help message displayed in
;// the status bar, and also displayed as a message box before the actual launching of
;// the bug report tool. Formulated rather generically, so that the registry-set actual
;// URL/Program to launch will fit the description. In the standard version, this launches
;// a sourceforge bug report tracker page.
;//
MessageId=1020
Severity=Informational
Facility=Application
SymbolicName=HLP_MENU_BUGREPORT
Language=ENU
A new window with a bug reporting tool will be opened. Internet-connection is required.
.
Language=SVE
Ett nytt fönster öppnas med ett verktyg där du kan rapportera felet. Internetuppkoppling krävs.
.
Language=DEU
Ein neues Fenster zur Fehlerberichterstattung wird geöffnet. Es wird eine Internet-Verbindung benötigt.
.
Language=FRA
Une nouvelle fenêtre avec un outil de rapport de bogue va s'ouvrir. Une connexion Internet est requise.
.
Language=ESN
A new window with a bug reporting tool will be opened. Internet-connection is required.
.
Language=ITA
Verra' aperta una nuova finestra con uno strumento di reporting dei bug. E' richiesta una connessione ad Internet.
.
Language=HUN
Új ablak nyílik meg a programhiba bejelentõ eszközzel. Internet-kapcsolat szükséges.
.
Language=NOR
A new window with a bug reporting tool will be opened. Internet-connection is required.
.
Language=NLD
Er wordt een nieuw venster met een foutrapportageprogramma geopend. Een Internetverbinding is vereist.
.
Language=DNK
Et nyt vindue med fejlrapporteringsværktøj vil blive åbnet. Internetforbindelse er nødvendig.
.
Language=POL
Otworzone zostanie nowe okno narzędzia do zgłaszania błędów. Wymagane jest połączenie z Internetem.
.
Language=CHI
A new window with a bug reporting tool will be opened. Internet-connection is required.
.
Language=PTG
A new window with a bug reporting tool will be opened. Internet-connection is required.
.
Language=PTB
Uma nova janela com a ferramenta para reportar bugs será aberta. É requerida conexão com a Internet.
.
Language=RUS
Будет открыто новое окно с отчетом об ошибке. Потребуется соединение c Интернетом.
.
Language=CZH
Bude otevřeno nové okno s nástrojem pro ohlášení chyby. Je nutné internetové připojení.
.
Language=FIN
Avaa uuden ikkunan, jossa on ohjelmavirheen raportointityökalu. Nettiyhteys on pakollinen.
.

;//
;// Rel 1.5.4.3 - License has expired due to too many uses.
;// the status bar, and also displayed as a message box before the actual launching of
;// the bug report tool. Formulated rather generically, so that the registry-set actual
;// URL/Program to launch will fit the description. In the standard version, this launches
;// a sourceforge bug report tracker page.
;//
MessageId=1025
Severity=Warning
Facility=Application
SymbolicName=WRN_EXPIRED_USES
Language=ENU
Thank you for trying %1! You have now used it
%2 times and this trial version is thus expired. Please
consider purchasing a license and activate it again.
.
Language=SVE
Tack för att du provat %1! Du har nu använt det
%2 gånger, och din prövotid är därmed slut. Vänligen
överväg att köpa en licens och återaktivera alla funktioner.
.
Language=DEU
Danke das Sie das Programm testen, %1! Sie haben es bisher
%2 mal benutzt, daher ist diese Testversion abgelaufen. Bitte
erwerben Sie eine Lizenz um das Programm wieder zu aktivieren.
.
Language=FRA
Merci d'essayer %1! Vous l'avez maintenant utilisé %2 fois
et cette version d'évaluation est donc expirée. Veuillez
envisager l'achat d'une licence d'exploitation pour la réactiver.
.
Language=ESN
Thank you for trying %1! You have now used it
%2 times and this trial version is thus expired. Please
consider purchasing a license and activate it again.
.
Language=ITA
Grazie per aver provato %1! Hai usato il programma
%2 volte e questa versione di prova e' scaduta. Per favore,
considera l'acquisto di una licenza e attivala nuovamente.
.
Language=HUN
Köszönjük, hogy kipróbálta %1-t! Ön eddig ezt
%2 alkalommal használta és a próbaverzió lejárt. Kérem
igényeljen licensz-t majd aktiválja újra.
.
Language=NOR
Thank you for trying %1! You have now used it
%2 times and this trial version is thus expired. Please
consider purchasing a license and activate it again.
.
Language=NLD
Hartelijk dank voor het uitproberen van %1! U hebt het nu
%2 keer geprobeerd en de testversie is nu verlopen. Koop
a.u.b. een licentie en activeer het programma opnieuw.
.
Language=DNK
Mange tak fordi du prøver %1! Du har nu benyttet det
%2 gange og denne prøveudgave er udløbet. Overvej venligst
at købe en licens og aktiver den igen.
.
Language=POL
Dziękujemy za wypróbowanie %1! Użyłeś program %2 razy.
Wersja próbna właśnie wygasła.
Zakup licencję i ponownie aktywuj program.
.
Language=CHI
Thank you for trying %1! You have now used it
%2 times and this trial version is thus expired. Please
consider purchasing a license and activate it again.
.
Language=PTG
Thank you for trying %1! You have now used it
%2 times and this trial version is thus expired. Please
consider purchasing a license and activate it again.
.
Language=PTB
Obrigado por utilizar %1! Você utilizou
%2 vezes e esta versão de teste expirou. Por favor
adquira a licença para ativá-la novamente.
.
Language=RUS
Спасибо за пробное использование %1! Вы использовали
программу %2 раз и поэтому тестовый период истек.
Пожалуйста, рассмотрите покупку лицензии и активации продукта.
.
Language=CZH
Děkujeme za vyzkoušení %1! Nyní jste aplikaci použili
%2 krát a tím vypršela trial verze. Prosím
zvažte zakoupení licence a proveďte novou aktivaci.
.
Language=FIN
Kiitos %1-ohjelman kokeilemisesta! Olet nyt käyttänyt sitä
%2 kertaa ja tämä kokeiluversio ei toimi enää. Hanki
lisenssi ja aktivoi ohjelma uudelleen.
.

;//
;// Rel 1.5.4.3 - Prompt for the name of the licensee - what we actually sign, in
;// the license enter window. This should fit above an edit box.
;//
MessageId=1030
Severity=Informational
Facility=Application
SymbolicName=INF_ENTER_LICENSEE
Language=ENU
Issued to
.
Language=SVE
Utfärdat till
.
Language=DEU
Ausgestellt für
.
Language=FRA
Licencié à
.
Language=ESN
Issued to
.
Language=ITA
Rilasciata a
.
Language=HUN
Felhasználó
.
Language=NOR
Issued to
.
Language=NLD
Afgegeven aan
.
Language=DNK
Udstedt til
.
Language=POL
Licencja dla
.
Language=CHI
Issued to
.
Language=PTG
Issued to
.
Language=PTB
Licenciado para
.
Language=RUS
Владелец лицензии
.
Language=CZH
Vystaveno pro
.
Language=FIN
Lisenssinhaltija:
.

;//
;// Rel 1.5.4.3 - Prompt for signature, the 36-character code in
;// the license enter window. This should fit above an edit box.
;//
MessageId=1035
Severity=Informational
Facility=Application
SymbolicName=INF_ENTER_SIGNATURE
Language=ENU
Activation code
.
Language=SVE
Aktiveringskod
.
Language=DEU
Aktivierungscode
.
Language=FRA
Code d'activation
.
Language=ESN
Activation code
.
Language=ITA
Codice di attivazione
.
Language=HUN
Aktiválási kód
.
Language=NOR
Activation code
.
Language=NLD
Activeringscode
.
Language=DNK
Aktiveringskode
.
Language=POL
Kod aktywacji
.
Language=CHI
Activation code
.
Language=PTG
Activation code
.
Language=PTB
Código de ativação
.
Language=RUS
Код активации
.
Language=CZH
Aktivační kód
.
Language=FIN
Aktivointikoodi
.

;//
;// Rel 1.5.4.3 - The shell extension menu label for the license handler.
;//
MessageId=1040
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_LICENSEMGR
Language=ENU
Product Activation
.
Language=SVE
Produktaktivering
.
Language=DEU
Produktaktivierung
.
Language=FRA
Activation du produit
.
Language=ESN
Product Activation
.
Language=ITA
Attivazione del prodotto
.
Language=HUN
Termék aktiválása
.
Language=NOR
Product Activation
.
Language=NLD
Productactivering
.
Language=DNK
Produktaktivering
.
Language=POL
Aktywacja produktu
.
Language=CHI
Product Activation
.
Language=PTG
Product Activation
.
Language=PTB
Ativação do produto
.
Language=RUS
Активация продукта
.
Language=CZH
Aktivace produktu
.
Language=FIN
Tuoteaktivointi
.

MessageId=1045
Severity=Informational
Facility=Application
SymbolicName=HLP_MENU_LICENSEMGR
Language=ENU
Enter the product activation code.
.
Language=SVE
Kontrollera och mata in produktaktiveringsnyckeln.
.
Language=DEU
Bitte den Produktaktivierungscode eingeben.
.
Language=FRA
Veuillez entrer le code d'activation du produit.
.
Language=ESN
Enter the product activation code.
.
Language=ITA
Inserisci il codice di attivazione del prodotto
.
Language=HUN
Írja be a termék aktiválási kódját.
.
Language=NOR
Enter the product activation code.
.
Language=NLD
Voer de activeringscode voor dit product in.
.
Language=DNK
Indtast produktaktiveringskode.
.
Language=POL
Wprowadź kod aktywacyjny produktu.
.
Language=CHI
Enter the product activation code.
.
Language=PTG
Enter the product activation code.
.
Language=PTB
Insira o código de ativação do produto.
.
Language=RUS
Введите код активации продукта.
.
Language=CZH
Zadejte aktivační kód produktu.
.
Language=FIN
Syötä tuotteen aktivointikoodi.
.

;//
;// Rel 1.5.4.3 - The message shown when an invalid product activation (license
;// signature) is entered.
;//
MessageId=1050
Severity=Informational
Facility=Application
SymbolicName=INF_BADLIC
Language=ENU
Invalid activation code, please try again.
.
Language=SVE
Ogiltig aktiveringskod, försök igen.
.
Language=DEU
Ungültiger Aktivierungscode, bitte versuchen Sie es noch einmal.
.
Language=FRA
Code d'activation invalide, veuillez réessayer.
.
Language=ESN
Invalid activation code, please try again.
.
Language=ITA
Codice di attivazione non valido, prova ancora, per favore.
.
Language=HUN
Nem érvényes aktiválási kód, kérem próbálja újra.
.
Language=NOR
Invalid activation code, please try again.
.
Language=NLD
Onjuiste activeringscode. Probeer het nog een keer.
.
Language=DNK
Ugyldig aktiveringskode, prøv igen.
.
Language=POL
Błędny kod aktywacyjny, spróbuj ponownie.
.
Language=CHI
Invalid activation code, please try again.
.
Language=PTG
Invalid activation code, please try again.
.
Language=PTB
Código de ativação inválido, por favor tente novamente.
.
Language=RUS
Недействительный код активации, попытайтесь снова.
.
Language=CZH
Chybný aktivační kód, prosím zkuste znovu.
.
Language=FIN
Virheellinen aktivointikoodi, yritä uudelleen.
.

;//
;// Rel 1.5.4.3 - The Message we attach after typically "Program 1.1b4.3" in the
;// title bar when we're in a trial mode. The result may be "Program 1.1b4.3 [Trial 19/25]"
;//
MessageId=1055
Severity=Informational
Facility=Application
SymbolicName=INF_TRIALCOUNT
Language=ENU
 [Trial %2/%3]
.
Language=SVE
 [Prov %2/%3]
.
Language=DEU
 [Test %2/%3]
.
Language=FRA
 [Essai %2/%3]
.
Language=ESN
 [Trial %2/%3]
.
Language=ITA
 [Prova %2/%3]
.
Language=HUN
 [Próba %2/%3]
.
Language=NOR
 [Trial %2/%3]
.
Language=NLD
 [Test %2/%3]
.
Language=DNK
 [Prøve %2/%3]
.
Language=POL
 [Wersja próbna %2/%3]
.
Language=CHI
 [Trial %2/%3]
.
Language=PTG
 [Trial %2/%3]
.
Language=PTB
 [Teste %2/%3]
.
Language=RUS
 [Тестовый период %2/%3]
.
Language=CZH
 [Vyzkoušení %2/%3]
.
Language=FIN
 [Kokeilukerta %2/%3]
.

;//
;// Rel 1.5.4.6+ - When we implement a new file format, which is in the planning, the
;// strategy is to update when re-encrypting but legacy-support the old format for quite
;// a few versions. We then want inform the user with a message that we'll be rewriting
;// in a new format incompatible with old versions. This is an OK-only dialog, with a
;// 'Do not show this dialog again' checkbox at the bottom.
;//
MessageId=1060
Severity=Informational
Facility=Application
SymbolicName=INF_NEWFORMAT
Language=ENU
Data will be encrypted with an updated format that previous program versions cannot read.
.
Language=SVE
Data krypteras med ett uppdaterat format som tidigare programversioner ej kan dekryptera.
.
Language=DEU
Daten werden mit einem aktualisierten Format verschlüsselt, das von älteren Programmversionen nicht gelesen werden kann.
.
Language=FRA
Les données vont être cryptées dans un nouveau format que les versions précédentes du programme ne pourront pas lire.
.
Language=ESN
Data will be encrypted with an updated format that previous program versions cannot read.
.
Language=ITA
I dati verranno cifrati con un formato aggiornato che le precedenti versioni del programma non possono leggere.
.
Language=HUN
Az adatot új formátumban titkosítjuk amit a régi verziójú program nem képes olvasni.
.
Language=NOR
Data will be encrypted with an updated format that previous program versions cannot read.
.
Language=NLD
Gegevens worden versleuteld in een nieuw formaat dat niet kan worden gelezen door eerdere softwareversies.
.
Language=DNK
Data vil blive krypteret med et nyt format som tidligere udgaver ikke kan læse.
.
Language=POL
Dane zostaną zaszyfowane w nowym formacie. Poprzednie wersje programu nie będą mogły tego odtworzyć.
.
Language=CHI
Data will be encrypted with an updated format that previous program versions cannot read.
.
Language=PTG
Data will be encrypted with an updated format that previous program versions cannot read.
.
Language=PTB
Os dados serão encriptados com um formato atualizado em que as versões anteriores não poderão acessá-los.
.
Language=RUS
Данные будут зашифрованы в обновленном формате, который предыдущие версии программы не смогут прочитать.
.
Language=CZH
Data budou zašifrována v aktualizovaném formátu, který předchozí verze programu nemohou číst.
.
Language=FIN
Tiedot salakoodataan päivitetyssä muodossa, jota ohjelman aiemmat versiot eivät kykene lukemaan.
.

;//
;// Rel 1.5.4.6+ - This is your typical 'More...' button. It should be same as used in Windows
;// for dialog buttons indicating that more information is available. Normally, the window will
;// expand downwards to show more info. It must be short, one word, to fit the button.
;//
MessageId=1065
Severity=Informational
Facility=Application
SymbolicName=INF_MORE
Language=ENU
More >>
.
Language=SVE
Mer >>
.
Language=DEU
Mehr >>
.
Language=FRA
Plus >>
.
Language=ESN
More >>
.
Language=ITA
Avanti >>
.
Language=HUN
Többet >>
.
Language=NOR
More >>
.
Language=NLD
Meer >>
.
Language=DNK
Mere >>
.
Language=POL
Więcej >>
.
Language=CHI
More >>
.
Language=PTG
More >>
.
Language=PTB
Mais >>
.
Language=RUS
Больше >>
.
Language=CZH
Více >>
.
Language=FIN
Lisää >>
.

;//
;// Rel 1.5.4.6+ - This is your typical 'Less...' button. It should be same as used in Windows
;// for dialog buttons indicating that less information is available. Normally, the window will
;// contract upwards to show less info. It must be short, one word, to fit the button.
;//
MessageId=1070
Severity=Informational
Facility=Application
SymbolicName=INF_LESS
Language=ENU
<< Less
.
Language=SVE
<< Mindre
.
Language=DEU
<< Weniger
.
Language=FRA
<< Moins
.
Language=ESN
<< Less
.
Language=ITA
<< Indietro
.
Language=HUN
<< Elrejt
.
Language=NOR
<< Less
.
Language=NLD
<< Minder
.
Language=DNK
<< Mindre
.
Language=POL
<< Mniej
.
Language=CHI
<< Less
.
Language=PTG
<< Less
.
Language=PTB
<< Menos
.
Language=RUS
<< Меньше
.
Language=CZH
<< Méně
.
Language=FIN
<< Vähemmän
.

;//
;// Rel 1.5.4.6+ - Encryption dialog checkbox, if checked the program
;// will rename the file after encryption to a new, anonymous name.
;// See also INF_SAVE_ENCKEY and INF_SAVE_DECKEY.
;//
MessageId=1075
Severity=Informational
Facility=Application
SymbolicName=INF_SAVE_RENAME
Language=ENU
Rename
.
Language=SVE
Ändra namn
.
Language=DEU
Umbenennen
.
Language=FRA
Renommer
.
Language=ESN
Renombrar
.
Language=ITA
Rinomina
.
Language=HUN
Átnevezés
.
Language=NOR
Rename
.
Language=NLD
Naam wijzigen
.
Language=DNK
Omdøb
.
Language=POL
Zmień nazwę
.
Language=CHI
Rename
.
Language=PTG
Rename
.
Language=PTB
Renomear
.
Language=RUS
Переименовать
.
Language=CZH
Přejmenovat
.
Language=FIN
Nimeä uudelleen
.

;//
;// Rel 1.5.4.6+ - A menu choice to make the enter-key dialog and it's
;// options show. The purpose is to allow the user to enter default keys
;// for encryption and decryption as well as to change the sticky
;// options.
;//
MessageId=1080
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_ENTER_KEYS
Language=ENU
Enter default options and passphrase
.
Language=SVE
Ange standardval och lösenord
.
Language=DEU
Bitte Standard-Optionen und Passphrase eingeben
.
Language=FRA
Entrer les valeurs par défaut des options et des mots de passe.
.
Language=ESN
Enter default options and passphrase
.
Language=ITA
Inserisci le opzioni di default e la parola chiave
.
Language=HUN
Alapértelmezett opciók és kulcsmondat
.
Language=NOR
Enter default options and passphrase
.
Language=NLD
Standaardopties en -wachtwoord invoeren
.
Language=DNK
Indtast standardvalg og kodeord
.
Language=POL
Wprowadź domyślne opcje oraz hasło
.
Language=CHI
Enter default options and passphrase
.
Language=PTG
Enter default options and passphrase
.
Language=PTB
Insira as opções padrão e a senha
.
Language=RUS
Ввод пароля и изменение опций по умолчанию
.
Language=CZH
Zadat výchozí volby a heslo
.
Language=FIN
Syötä oletusvaihtoehdot ja salasana
.

;//
;// Rel 1.5.4.6+ - The help text shown in the status bar for INF_MENU_ENTER_KEYS
;//
MessageId=1085
Severity=Informational
Facility=Application
SymbolicName=INF_HLP_ENTER_KEYS
Language=ENU
Enter a default passphrase for encryption and/or decryption and change defaults for options.
.
Language=SVE
Ange standardlösenord för kryptering och/eller dekryptering samt ändra standardvärden för vissa valmöjligheter.
.
Language=DEU
Standard-Passphrase für ent/verschlüsselung eingeben und Optionen einstellen.
.
Language=FRA
Entrer un mot de passe par défaut pour le cryptage et/ou le décryptage, et changer les valeurs par défaut des options.
.
Language=ESN
Enter a default passphrase for encryption and/or decryption and change defaults for options.
.
Language=ITA
Inserisci una parola chiave di default per la cifratura e/o per la decifratura e cambia i valori di default per le opzioni.
.
Language=HUN
Írja be az alapértelmezett kulcsmondatot titkosításhoz vagy visszafejtéshez, és adja meg az opciók alapértelmezését.
.
Language=NOR
Enter a default passphrase for encryption and/or decryption and change defaults for options.
.
Language=NLD
Een standaardwachtwoord voor versleuteling en/of ontsleuteling invoeren en standaardinstellingen wijzigen.
.
Language=DNK
Indtast et standard kodeord for kryptering og/eller dekryptering samt ændre standardværdier for visse valgmuligheder.
.
Language=POL
Wprowadź domyślne hasło dla szyfrowania i/lub oszyfrowania oraz zmień domyślne opcje.
.
Language=CHI
Enter a default passphrase for encryption and/or decryption and change defaults for options.
.
Language=PTG
Enter a default passphrase for encryption and/or decryption and change defaults for options.
.
Language=PTB
Insira a senha padrão para encriptação e/ou decriptação e mude as opções padrão.
.
Language=RUS
Ввод пароля для шифрования и/или расшифровки и изменения опций, используемых по умолчанию.
.
Language=CZH
Zadat výchozí heslo pro šifrování anebo dešifrování a změnit výchozí volby.
.
Language=FIN
Syötä oletussalasana salakoodausta ja/tai sen purkua varten sekä muuta muita oletusarvoja.
.

;//
;// Rel 1.6.1+ - A message shown when an attempt is made to open a file that cannot be opened due to sharing
;// violation. The most common cause is that the file is already opened by Xecrets File Classic. %2 is to be interpreted as
;// as the error message from Windows in this case.
;//
MessageId=1090
Severity=Warning
Facility=Application
SymbolicName=WRN_SHARING_VIOLATION
Language=ENU
%2 You, or someone else, have it open already. Do you want to try opening '%3' read-only instead?
.
Language=SVE
%2 Du, eller någon annan, har redan öppnat dokumentet. Vill du prova att öppna '%3' med skrivskydd istället?
.
Language=DEU
%2 You, or someone else, have it open already. Do you want to try opening '%3' read-only instead?
.
Language=FRA
%2 You, or someone else, have it open already. Do you want to try opening '%3' read-only instead?
.
Language=ESN
%2 You, or someone else, have it open already. Do you want to try opening '%3' read-only instead?
.
Language=ITA
%2 You, or someone else, have it open already. Do you want to try opening '%3' read-only instead?
.
Language=HUN
%2 You, or someone else, have it open already. Do you want to try opening '%3' read-only instead?
.
Language=NOR
%2 You, or someone else, have it open already. Do you want to try opening '%3' read-only instead?
.
Language=NLD
%2 U of iemand anders hebt het bestand al open. Wilt u proberen '%3' te openen als alleen-lezen?
.
Language=DNK
%2 Du, eller en anden, har allerede åbnet dokumentet. Vil du prøve at åbne '%3' som skrivebeskyttet i stedet?
.
Language=POL
%2 Ten plik jest już otwarty. Czy chcesz spróbować otworzyć '%3' w trybie tylko do odczytu?
.
Language=CHI
%2 You, or someone else, have it open already. Do you want to try opening '%3' read-only instead?
.
Language=PTG
%2 You, or someone else, have it open already. Do you want to try opening '%3' read-only instead?
.
Language=PTB
%2 Você, ou outra pessoa, já está com este arquivo aberto. Deseja abrir o arquivo '%3' como somente-leitura?
.
Language=RUS
%2 Вы или кто-то еще уже открыли этот файл. Попробовать открыть '%3' только для чтения?
.
Language=CZH
%2 vy nebo někdo jiný již má otevřeno. Chcete místo toho zkusit otevřít '%3' jen pro čtení?
.
Language=FIN
%2 Sinulla, tai jollakulla muulla, on jo tämä asiakirja auki. Haluaisitko avata tiedoston '%3' vain luku -tilassa?
.

;//
;// Rel 1.6.2 - Warn about attempting to encrypt what appears not to be a key-file generated
;// by us. The main risk with this is that it might be an attempt to encrypt a file with itself
;// as key-file, and also that it might be an axcrypted file, which is subsequently decrypted
;// and due to the security features of Xecrets File Classic, an re-encryption will never re-create an identical
;// file. Both cases may result in data-loss.
;//
MessageId=1100
Severity=Informational
Facility=Application
SymbolicName=INF_KEYFILE_NOT_ENCRYPT
Language=ENU
It appears you may be about to use a non-standard key-file, instead of one
created by the program. Improper use may result in loss of data.
Are you sure you want to do this?
.
Language=SVE
Det verkar som du försöker använda en godtycklig fil som nyckelfil, istället
för en som programmet har skapat. Ett misstag kan leda till dataförlust.
Är du säker du vill göra detta?
.
Language=DEU
It appears you may be about to use a non-standard key-file, instead of one
created by the program. Improper use may result in loss of data.
Are you sure you want to do this?
.
Language=FRA
It appears you may be about to use a non-standard key-file, instead of one
created by the program. Improper use may result in loss of data.
Are you sure you want to do this?
.
Language=ESN
It appears you may be about to use a non-standard key-file, instead of one
created by the program. Improper use may result in loss of data.
Are you sure you want to do this?
.
Language=ITA
It appears you may be about to use a non-standard key-file, instead of one
created by the program. Improper use may result in loss of data.
Are you sure you want to do this?
.
Language=HUN
It appears you may be about to use a non-standard key-file, instead of one
created by the program. Improper use may result in loss of data.
Are you sure you want to do this?
.
Language=NOR
It appears you may be about to use a non-standard key-file, instead of one
created by the program. Improper use may result in loss of data.
Are you sure you want to do this?
.
Language=NLD
U lijkt een niet-standaard sleutelbestand te willen gebruiken in plaats van
een sleutelbestand dat door het programma is gegenereerd. Onjuist gebruik
kan mogelijk leiden tot gegevensverlies. Weet u zeker dat u dit wilt doen?
.
Language=DNK
Det virker som om du er ved at benytte en ikke-standard nøgle-fil,
i stedet for en som er skabt af dette program. Forkert brug kan føre til tab af data.
Er du sikker på, at du vil gøre dette?
.
Language=POL
Wygląda na to, że chcesz użyć niestandardowego Pliku-Klucza, wygenerowanego przez inny program.
Użycie nieprawidłowego klucza może uszkodzić dane.
Jesteś pewien(a), że chcesz kontynuować?
.
Language=CHI
It appears you may be about to use a non-standard key-file, instead of one
created by the program. Improper use may result in loss of data.
Are you sure you want to do this?
.
Language=PTG
It appears you may be about to use a non-standard key-file, instead of one
created by the program. Improper use may result in loss of data.
Are you sure you want to do this?
.
Language=PTB
Parece que você está tentando usar um arquivo-chave que não foi gerado pelo programa.
O uso incorreto pode acarretar na perda de dados.
Você tem certeza que deseja continuar?
.
Language=RUS
Кажется, вы собираетесь использовать нестандартный файл ключа вместо созданного когда-то программой.
Использование такого ключа может привести к потере данных.
Вы уверены, что хотите это сделать?
.
Language=CZH
Zdá se, že se chystáte použít nestandardní soubor s klíčem místo klíče vytvořeného
programem. Nesprávné použití může způsobit ztrátu dat.
Jste si jist, že to chcete udělat?
.
Language=FIN
Vaikuttaa siltä, että olet aikeissa käyttää epästandardia avaintiedostoa ohjelman
luoman tiedoston asemasta. Virheellinen avaintiedostojen käyttö voi johtaa tietojen
katoamiseen. Oletko varma?
.

;//
;// Rel 1.6.2 - Warn about attempting to encrypt what appears to be a file located in a
;// system or program folder. This could be very risky, and cause system malfunction,
;// so it's generally not a good idea.
;//
MessageId=1110
Severity=Informational
Facility=Application
SymbolicName=INF_SYSTEM_FOLDER_WARN
Language=ENU
It appears you may be about to encrypt a system or program file. This may cause
system instability or crashes. Are you sure you want to do this?
.
Language=SVE
Det verkar som du vill kryptera en system- eller programfil. Detta kan orsaka
systemstörningar och krascher.
Är du säker du vill göra detta?
.
Language=DEU
It appears you may be about to encrypt a system or program file. This may cause
system instability or crashes. Are you sure you want to do this?
.
Language=FRA
It appears you may be about to encrypt a system or program file. This may cause
system instability or crashes. Are you sure you want to do this?
.
Language=ESN
It appears you may be about to encrypt a system or program file. This may cause
system instability or crashes. Are you sure you want to do this?
.
Language=ITA
It appears you may be about to encrypt a system or program file. This may cause
system instability or crashes. Are you sure you want to do this?
.
Language=HUN
It appears you may be about to encrypt a system or program file. This may cause
system instability or crashes. Are you sure you want to do this?
.
Language=NOR
It appears you may be about to encrypt a system or program file. This may cause
system instability or crashes. Are you sure you want to do this?
.
Language=NLD
U lijkt een systeem- of programmabestand te willen versleutelen. Dit kan mogelijk
leiden tot instabiliteit van het systeem of vastlopers. Weet u zeker dat u dit wilt doen?
.
Language=DNK
Det virker som om du er ved at kryptere en system- eller programfil.
Det kan gøre systemet ustabilt eller få det til at gå ned.
Er du sikker på, at du vil gøre dette?
.
Language=POL
Wygląda na to, że chcesz zaszyfrować aplikację lub plik systemowy. Może to spowodować
niestabilnośc systemu, a nawet jego uszkodzenie. Jesteś pewien(a), że chcesz kontynuować?
.
Language=CHI
It appears you may be about to encrypt a system or program file. This may cause
system instability or crashes. Are you sure you want to do this?
.
Language=PTG
It appears you may be about to encrypt a system or program file. This may cause
system instability or crashes. Are you sure you want to do this?
.
Language=PTB
Parece que você está tentando encriptar um arquivo do sistema. Isto pode causar
a instabilidade do sistema ou fazer com que ele pare de funcionar. Você tem certeza que deseja continuar?
.
Language=RUS
Кажется, вы собираетесь зашифровать файл используемый системой или программой.
Это может вызвать неустойчивую работу системы или сбой.
Вы уверены, что хотите это сделать?
.
Language=CZH
Zdá se, že se chystáte zašifrovat systémový nebo programový soubor. To může
způsobit nestabilitu systému nebo pády. Jste si jist, že to chcete udělat?
.
Language=FIN
Vaikuttaa siltä, että olet aikeissa salakoodata järjestelmä- tai ohjelmatiedostoa.
Tämä voi aiheuttaa järjestelmän epävakautta tai kaatumisia. Oletko varma?
.

;//
;// Rel 1.7 - The prompt for the 'Language' selection in the shell extension.
;//
MessageId=1120
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_LANGUAGE
Language=ENU
Language
.
Language=SVE
Språk
.
Language=DEU
Sprache
.
Language=FRA
Langue
.
Language=ESN
Idioma
.
Language=ITA
Lingua
.
Language=HUN
Nyelv
.
Language=NOR
Språk
.
Language=NLD
Taal
.
Language=DNK
Sprog
.
Language=POL
Język
.
Language=CHI
Language
.
Language=PTG
Language
.
Language=PTB
Idioma
.
Language=RUS
Язык
.
Language=CZH
Jazyk
.
Language=FIN
Kieli
.

;//
;// Rel 1.7 - The help for the 'Language' selection in the shell extension.
;//
MessageId=1130
Severity=Informational
Facility=Application
SymbolicName=HLP_MENU_LANGUAGE
Language=ENU
Select language
.
Language=SVE
Välj språk
.
Language=DEU
Wählen Sie die Sprache
.
Language=FRA
Choisissez la langue
.
Language=ESN
Seleccionar idioma
.
Language=ITA
Scegli la lingua
.
Language=HUN
Válasszon nyelvet
.
Language=NOR
Velg språk
.
Language=NLD
Kies een taal
.
Language=DNK
Vælg sprog
.
Language=POL
Wybierz język
.
Language=CHI
Select language
.
Language=PTG
Select language
.
Language=PTB
Selecione um idioma
.
Language=RUS
Выбор языка
.
Language=CZH
Zvolte jazyk
.
Language=FIN
Valitse kieli
.

;//
;// Rel 1.7 - The text for a language name
;// *** Do NOT translate - the whole point is that this should always be in the language it is the name of
;//
MessageId=1140
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_ENGLISH
Language=ENU
English
.
Language=SVE
English
.
Language=DEU
English
.
Language=FRA
English
.
Language=ESN
English
.
Language=ITA
English
.
Language=HUN
English
.
Language=NOR
English
.
Language=NLD
English
.
Language=DNK
English
.
Language=POL
English
.
Language=CHI
English
.
Language=PTG
English
.
Language=PTB
English
.
Language=RUS
English
.
Language=CZH
English
.
Language=FIN
English
.

;//
;// Rel 1.7 - The text for a language name
;// *** Do NOT translate - the whole point is that this should always be in the language it is the name of
;//
MessageId=1150
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_DANISH
Language=ENU
Dansk
.
Language=SVE
Dansk
.
Language=DEU
Dansk
.
Language=FRA
Dansk
.
Language=ESN
Dansk
.
Language=ITA
Dansk
.
Language=HUN
Dansk
.
Language=NOR
Dansk
.
Language=NLD
Dansk
.
Language=DNK
Dansk
.
Language=POL
Dansk
.
Language=CHI
Dansk
.
Language=PTG
Dansk
.
Language=PTB
Dansk
.
Language=RUS
Dansk
.
Language=CZH
Dansk
.
Language=FIN
Dansk
.

;//
;// Rel 1.7 - The text for a language name
;// *** Do NOT translate - the whole point is that this should always be in the language it is the name of
;//
MessageId=1160
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_GERMAN
Language=ENU
Deutsch
.
Language=SVE
Deutsch
.
Language=DEU
Deutsch
.
Language=FRA
Deutsch
.
Language=ESN
Deutsch
.
Language=ITA
Deutsch
.
Language=HUN
Deutsch
.
Language=NOR
Deutsch
.
Language=NLD
Deutsch
.
Language=DNK
Deutsch
.
Language=POL
Deutsch
.
Language=CHI
Deutsch
.
Language=PTG
Deutsch
.
Language=PTB
Deutsch
.
Language=RUS
Deutsch
.
Language=CZH
Deutsch
.
Language=FIN
Deutsch
.

;//
;// Rel 1.7 - The text for a language name
;// *** Do NOT translate - the whole point is that this should always be in the language it is the name of
;//
MessageId=1170
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_DUTCH
Language=ENU
Nederlands
.
Language=SVE
Nederlands
.
Language=DEU
Nederlands
.
Language=FRA
Nederlands
.
Language=ESN
Nederlands
.
Language=ITA
Nederlands
.
Language=HUN
Nederlands
.
Language=NOR
Nederlands
.
Language=NLD
Nederlands
.
Language=DNK
Nederlands
.
Language=POL
Nederlands
.
Language=CHI
Nederlands
.
Language=PTG
Nederlands
.
Language=PTB
Nederlands
.
Language=RUS
Nederlands
.
Language=CZH
Nederlands
.
Language=FIN
Nederlands
.

;//
;// Rel 1.7 - The text for a language name
;// *** Do NOT translate - the whole point is that this should always be in the language it is the name of
;//
MessageId=1180
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_HUNGARIAN
Language=ENU
Magyar
.
Language=SVE
Magyar
.
Language=DEU
Magyar
.
Language=FRA
Magyar
.
Language=ESN
Magyar
.
Language=ITA
Magyar
.
Language=HUN
Magyar
.
Language=NOR
Magyar
.
Language=NLD
Magyar
.
Language=DNK
Magyar
.
Language=POL
Magyar
.
Language=CHI
Magyar
.
Language=PTG
Magyar
.
Language=PTB
Magyar
.
Language=RUS
Magyar
.
Language=CZH
Magyar
.
Language=FIN
Magyar
.

;//
;// Rel 1.7 - The text for a language name
;// *** Do NOT translate - the whole point is that this should always be in the language it is the name of
;//
MessageId=1190
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_SPANISH
Language=ENU
Español
.
Language=SVE
Español
.
Language=DEU
Español
.
Language=FRA
Español
.
Language=ESN
Español
.
Language=ITA
Español
.
Language=HUN
Español
.
Language=NOR
Español
.
Language=NLD
Español
.
Language=DNK
Español
.
Language=POL
Español
.
Language=CHI
Español
.
Language=PTG
Español
.
Language=PTB
Español
.
Language=RUS
Español
.
Language=CZH
Español
.
Language=FIN
Español
.

;//
;// Rel 1.7 - The text for a language name
;// *** Do NOT translate - the whole point is that this should always be in the language it is the name of
;//
MessageId=1200
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_FRENCH
Language=ENU
Français
.
Language=SVE
Français
.
Language=DEU
Français
.
Language=FRA
Français
.
Language=ESN
Français
.
Language=ITA
Français
.
Language=HUN
Français
.
Language=NOR
Français
.
Language=NLD
Français
.
Language=DNK
Français
.
Language=POL
Français
.
Language=CHI
Français
.
Language=PTG
Français
.
Language=PTB
Français
.
Language=RUS
Français
.
Language=CZH
Français
.
Language=FIN
Français
.

;//
;// Rel 1.7 - The text for a language name
;// *** Do NOT translate - the whole point is that this should always be in the language it is the name of
;//
MessageId=1210
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_ITALIAN
Language=ENU
Italiano
.
Language=SVE
Italiano
.
Language=DEU
Italiano
.
Language=FRA
Italiano
.
Language=ESN
Italiano
.
Language=ITA
Italiano
.
Language=HUN
Italiano
.
Language=NOR
Italiano
.
Language=NLD
Italiano
.
Language=DNK
Italiano
.
Language=POL
Italiano
.
Language=CHI
Italiano
.
Language=PTG
Italiano
.
Language=PTB
Italiano
.
Language=RUS
Italiano
.
Language=CZH
Italiano
.
Language=FIN
Italiano
.

;//
;// Rel 1.7 - The text for a language name
;// *** Do NOT translate - the whole point is that this should always be in the language it is the name of
;//
MessageId=1220
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_NORWEGIAN
Language=ENU
Norsk
.
Language=SVE
Norsk
.
Language=DEU
Norsk
.
Language=FRA
Norsk
.
Language=ESN
Norsk
.
Language=ITA
Norsk
.
Language=HUN
Norsk
.
Language=NOR
Norsk
.
Language=NLD
Norsk
.
Language=DNK
Norsk
.
Language=POL
Norsk
.
Language=CHI
Norsk
.
Language=PTG
Norsk
.
Language=PTB
Norsk
.
Language=RUS
Norsk
.
Language=CZH
Norsk
.
Language=FIN
Norsk
.

;//
;// Rel 1.7 - The text for a language name
;// *** Do NOT translate - the whole point is that this should always be in the language it is the name of
;//
MessageId=1230
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_SWEDISH
Language=ENU
Svenska
.
Language=SVE
Svenska
.
Language=DEU
Svenska
.
Language=FRA
Svenska
.
Language=ESN
Svenska
.
Language=ITA
Svenska
.
Language=HUN
Svenska
.
Language=NOR
Svenska
.
Language=NLD
Svenska
.
Language=DNK
Svenska
.
Language=POL
Svenska
.
Language=CHI
Svenska
.
Language=PTG
Svenska
.
Language=PTB
Svenska
.
Language=RUS
Svenska
.
Language=CZH
Svenska
.
Language=FIN
Svenska
.

;//
;// Rel 1.7 - The xecrets hyperlink text in passphrase dialogs etc. The length in characters should not exceed the
;//           length of the english text, since space is limited in the dialog
;//
MessageId=1240
Severity=Informational
Facility=Application
SymbolicName=INF_HOMEPAGE_HYPERLINK
Language=ENU
Xecrets File Home
.
Language=SVE
Xecrets File Home
.
Language=DEU
Xecrets File Home
.
Language=FRA
Xecrets File Home
.
Language=ESN
Xecrets File Home
.
Language=ITA
Xecrets File Home
.
Language=HUN
Xecrets File Home
.
Language=NOR
Xecrets File Home
.
Language=NLD
Xecrets File Home
.
Language=DNK
Xecrets File Home
.
Language=POL
Xecrets File Home
.
Language=CHI
Xecrets File Home
.
Language=PTG
Xecrets File Home
.
Language=PTB
Xecrets File Home
.
Language=RUS
Xecrets File Home
.
Language=CZH
Xecrets File Home
.
Language=FIN
Xecrets File Home
.

;//
;// Rel 1.7 - A warning about a launch of an executable
;//
MessageId=1250
Severity=Warning
Facility=Application
SymbolicName=WRN_DANGEROUS_LAUNCH
Language=ENU
The encrypted file is a program. Do you want to allow %2 to run?
.
Language=SVE
Den krypterade filen är ett program. Vill du tillåta att %2 körs?
.
Language=DEU
The encrypted file is a program. Do you want to allow %2 to run?
.
Language=FRA
The encrypted file is a program. Do you want to allow %2 to run?
.
Language=ESN
The encrypted file is a program. Do you want to allow %2 to run?
.
Language=ITA
The encrypted file is a program. Do you want to allow %2 to run?
.
Language=HUN
The encrypted file is a program. Do you want to allow %2 to run?
.
Language=NOR
The encrypted file is a program. Do you want to allow %2 to run?
.
Language=NLD
Het versleutelde bestand is een programmabestand. Wilt u dat %2 het start?
.
Language=DNK
The encrypted file is a program. Do you want to allow %2 to run?
.
Language=POL
Zaszyfrowany plik jest plikiem uruchomieniowym. Czy chcesz zezwolić na uruchomienie %2?
.
Language=CHI
The encrypted file is a program. Do you want to allow %2 to run?
.
Language=PTG
The encrypted file is a program. Do you want to allow %2 to run?
.
Language=PTB
O arquivo codificado é um programa. Você deseja que %2 execute-o?
.
Language=RUS
Шифрованный файл является программой. Разрешить выполнение %2 ?
.
Language=CZH
Zašifrovaný soubor je program. Chcete povolit spuštění %2?
.
Language=FIN
Suojattu tiedosto on ohjelma. Ajetaanko %2?
.

;//
;// Rel 1.7.1984 - The text for a language name
;// *** Do NOT translate - the whole point is that this should always be in the language it is the name of
;//
MessageId=1260
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_BRAZILPORTUGUESE
Language=ENU
Português do Brasil
.
Language=SVE
Português do Brasil
.
Language=DEU
Português do Brasil
.
Language=FRA
Português do Brasil
.
Language=ESN
Português do Brasil
.
Language=ITA
Português do Brasil
.
Language=HUN
Português do Brasil
.
Language=NOR
Português do Brasil
.
Language=NLD
Português do Brasil
.
Language=DNK
Português do Brasil
.
Language=POL
Português do Brasil
.
Language=CHI
Português do Brasil
.
Language=PTG
Português do Brasil
.
Language=PTB
Português do Brasil
.
Language=RUS
Português do Brasil
.
Language=CZH
Português do Brasil
.
Language=FIN
Português do Brasil
.

;//
;// Rel 1.7.2062 - The text for a language name
;// *** Do NOT translate - the whole point is that this should always be in the language it is the name of
;//
MessageId=1270
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_POLISH
Language=ENU
Polski
.
Language=SVE
Polski
.
Language=DEU
Polski
.
Language=FRA
Polski
.
Language=ESN
Polski
.
Language=ITA
Polski
.
Language=HUN
Polski
.
Language=NOR
Polski
.
Language=NLD
Polski
.
Language=DNK
Polski
.
Language=POL
Polski
.
Language=CHI
Polski
.
Language=PTG
Polski
.
Language=PTB
Polski
.
Language=RUS
Polski
.
Language=CZH
Polski
.
Language=FIN
Polski
.

;//
;// Rel 1.7.2062 - The text for a language name
;// *** Do NOT translate - the whole point is that this should always be in the language it is the name of
;//
MessageId=1280
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_RUSSIAN
Language=ENU
Русский
.
Language=SVE
Русский
.
Language=DEU
Русский
.
Language=FRA
Русский
.
Language=ESN
Русский
.
Language=ITA
Русский
.
Language=HUN
Русский
.
Language=NOR
Русский
.
Language=NLD
Русский
.
Language=DNK
Русский
.
Language=POL
Русский
.
Language=CHI
Русский
.
Language=PTG
Русский
.
Language=PTB
Русский
.
Language=RUS
Русский
.
Language=CZH
Русский
.
Language=FIN
Русский
.

;//
;// Rel 1.7.2966+ - The text for a language name
;// *** Do NOT translate - the whole point is that this should always be in the language it is the name of
;//
MessageId=1290
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_CZECH
Language=ENU
Česky
.
Language=SVE
Česky
.
Language=DEU
Česky
.
Language=FRA
Česky
.
Language=ESN
Česky
.
Language=ITA
Česky
.
Language=HUN
Česky
.
Language=NOR
Česky
.
Language=NLD
Česky
.
Language=DNK
Česky
.
Language=POL
Česky
.
Language=CHI
Česky
.
Language=PTG
Česky
.
Language=PTB
Česky
.
Language=RUS
Česky
.
Language=CZH
Česky
.
Language=FIN
Česky
.

;//
;// Rel 1.7.3064+ - The text for a language name
;// *** Do NOT translate - the whole point is that this should always be in the language it is the name of
;//
MessageId=1300
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_FINNISH
Language=ENU
Suomi
.
Language=SVE
Suomi
.
Language=DEU
Suomi
.
Language=FRA
Suomi
.
Language=ESN
Suomi
.
Language=ITA
Suomi
.
Language=HUN
Suomi
.
Language=NOR
Suomi
.
Language=NLD
Suomi
.
Language=DNK
Suomi
.
Language=POL
Suomi
.
Language=CHI
Suomi
.
Language=PTG
Suomi
.
Language=PTB
Suomi
.
Language=RUS
Suomi
.
Language=CZH
Suomi
.
Language=FIN
Suomi
.

;// **********************************************************************
;// ***                                                                ***
;// ***                                                                ***
;// *** ONLY INTERNAL MESSAGES FROM HERE - DO NOT TRANSLATE BELOW THIS ***
;// ***                                                                ***
;// ***                                                                ***
;// **********************************************************************

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9000
Severity=Error
Facility=Application
SymbolicName=MSG_VIEW_SIZE
Language=ENU
Internal configuration error. The MAX_VIEW_SIZE must be >= System allocation granularity.
.
Language=SVE
Internal configuration error. The MAX_VIEW_SIZE must be >= System allocation granularity.
.
Language=DEU
Internal configuration error. The MAX_VIEW_SIZE must be >= System allocation granularity.
.
Language=FRA
Internal configuration error. The MAX_VIEW_SIZE must be >= System allocation granularity.
.
Language=ESN
Internal configuration error. The MAX_VIEW_SIZE must be >= System allocation granularity.
.
Language=ITA
Internal configuration error. The MAX_VIEW_SIZE must be >= System allocation granularity.
.
Language=HUN
Internal configuration error. The MAX_VIEW_SIZE must be >= System allocation granularity.
.
Language=NOR
Internal configuration error. The MAX_VIEW_SIZE must be >= System allocation granularity.
.
Language=NLD
Internal configuration error. The MAX_VIEW_SIZE must be >= System allocation granularity.
.
Language=DNK
Internal configuration error. The MAX_VIEW_SIZE must be >= System allocation granularity.
.
Language=POL
Internal configuration error. The MAX_VIEW_SIZE must be >= System allocation granularity.
.
Language=CHI
Internal configuration error. The MAX_VIEW_SIZE must be >= System allocation granularity.
.
Language=PTG
Internal configuration error. The MAX_VIEW_SIZE must be >= System allocation granularity.
.
Language=PTB
Internal configuration error. The MAX_VIEW_SIZE must be >= System allocation granularity.
.
Language=RUS
Internal configuration error. The MAX_VIEW_SIZE must be >= System allocation granularity.
.
Language=CZH
Internal configuration error. The MAX_VIEW_SIZE must be >= System allocation granularity.
.
Language=FIN
Internal configuration error. The MAX_VIEW_SIZE must be >= System allocation granularity.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9005
Severity=Error
Facility=Application
SymbolicName=MSG_MAP_VIEW
Language=ENU
MapView(): %2
.
Language=SVE
MapView(): %2
.
Language=DEU
MapView(): %2
.
Language=FRA
MapView(): %2
.
Language=ESN
MapView(): %2
.
Language=ITA
MapView(): %2
.
Language=HUN
MapView(): %2
.
Language=NOR
MapView(): %2
.
Language=NLD
MapView(): %2
.
Language=DNK
MapView(): %2
.
Language=POL
MapView(): %2
.
Language=CHI
MapView(): %2
.
Language=PTG
MapView(): %2
.
Language=PTB
MapView(): %2
.
Language=RUS
MapView(): %2
.
Language=CZH
MapView(): %2
.
Language=FIN
MapView(): %2
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9010
Severity=Error
Facility=Application
SymbolicName=MSG_MEMORY_ALLOC
Language=ENU
Memory allocation error in %3
.
Language=SVE
Memory allocation error in %3
.
Language=DEU
Memory allocation error in %3
.
Language=FRA
Memory allocation error in %3
.
Language=ESN
Memory allocation error in %3
.
Language=ITA
Memory allocation error in %3
.
Language=HUN
Memory allocation error in %3
.
Language=NOR
Memory allocation error in %3
.
Language=NLD
Memory allocation error in %3
.
Language=DNK
Memory allocation error in %3
.
Language=POL
Memory allocation error in %3
.
Language=CHI
Memory allocation error in %3
.
Language=PTG
Memory allocation error in %3
.
Language=PTB
Memory allocation error in %3
.
Language=RUS
Memory allocation error in %3
.
Language=CZH
Memory allocation error in %3
.
Language=FIN
Memory allocation error in %3
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9015
Severity=Error
Facility=Application
SymbolicName=MSG_PREAMBLE_NOT_FIRST
Language=ENU
Wrapped file format error or file may be damaged. Preamble header must be first in wrapped file.
.
Language=SVE
Wrapped file format error or file may be damaged. Preamble header must be first in wrapped file.
.
Language=DEU
Wrapped file format error or file may be damaged. Preamble header must be first in wrapped file.
.
Language=FRA
Wrapped file format error or file may be damaged. Preamble header must be first in wrapped file.
.
Language=ESN
Wrapped file format error or file may be damaged. Preamble header must be first in wrapped file.
.
Language=ITA
Wrapped file format error or file may be damaged. Preamble header must be first in wrapped file.
.
Language=HUN
Wrapped file format error or file may be damaged. Preamble header must be first in wrapped file.
.
Language=NOR
Wrapped file format error or file may be damaged. Preamble header must be first in wrapped file.
.
Language=NLD
Wrapped file format error or file may be damaged. Preamble header must be first in wrapped file.
.
Language=DNK
Wrapped file format error or file may be damaged. Preamble header must be first in wrapped file.
.
Language=POL
Wrapped file format error or file may be damaged. Preamble header must be first in wrapped file.
.
Language=CHI
Wrapped file format error or file may be damaged. Preamble header must be first in wrapped file.
.
Language=PTG
Wrapped file format error or file may be damaged. Preamble header must be first in wrapped file.
.
Language=PTB
Wrapped file format error or file may be damaged. Preamble header must be first in wrapped file.
.
Language=RUS
Wrapped file format error or file may be damaged. Preamble header must be first in wrapped file.
.
Language=CZH
Wrapped file format error or file may be damaged. Preamble header must be first in wrapped file.
.
Language=FIN
Wrapped file format error or file may be damaged. Preamble header must be first in wrapped file.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9020
Severity=Error
Facility=Application
SymbolicName=MSG_MISSING_SECTION
Language=ENU
Internal error or damaged file, missing expected header section '%3'.
.
Language=SVE
Internal error or damaged file, missing expected header section '%3'.
.
Language=DEU
Internal error or damaged file, missing expected header section '%3'.
.
Language=FRA
Internal error or damaged file, missing expected header section '%3'.
.
Language=ESN
Internal error or damaged file, missing expected header section '%3'.
.
Language=ITA
Internal error or damaged file, missing expected header section '%3'.
.
Language=HUN
Internal error or damaged file, missing expected header section '%3'.
.
Language=NOR
Internal error or damaged file, missing expected header section '%3'.
.
Language=NLD
Internal error or damaged file, missing expected header section '%3'.
.
Language=DNK
Internal error or damaged file, missing expected header section '%3'.
.
Language=POL
Internal error or damaged file, missing expected header section '%3'.
.
Language=CHI
Internal error or damaged file, missing expected header section '%3'.
.
Language=PTG
Internal error or damaged file, missing expected header section '%3'.
.
Language=PTB
Internal error or damaged file, missing expected header section '%3'.
.
Language=RUS
Internal error or damaged file, missing expected header section '%3'.
.
Language=CZH
Internal error or damaged file, missing expected header section '%3'.
.
Language=FIN
Internal error or damaged file, missing expected header section '%3'.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9025
Severity=Error
Facility=Application
SymbolicName=MSG_VERSION_TWICE
Language=ENU
Wrapped file format error or file may be damaged. Version header seen more than once.
.
Language=SVE
Wrapped file format error or file may be damaged. Version header seen more than once.
.
Language=DEU
Wrapped file format error or file may be damaged. Version header seen more than once.
.
Language=FRA
Wrapped file format error or file may be damaged. Version header seen more than once.
.
Language=ESN
Wrapped file format error or file may be damaged. Version header seen more than once.
.
Language=ITA
Wrapped file format error or file may be damaged. Version header seen more than once.
.
Language=HUN
Wrapped file format error or file may be damaged. Version header seen more than once.
.
Language=NOR
Wrapped file format error or file may be damaged. Version header seen more than once.
.
Language=NLD
Wrapped file format error or file may be damaged. Version header seen more than once.
.
Language=DNK
Wrapped file format error or file may be damaged. Version header seen more than once.
.
Language=POL
Wrapped file format error or file may be damaged. Version header seen more than once.
.
Language=CHI
Wrapped file format error or file may be damaged. Version header seen more than once.
.
Language=PTG
Wrapped file format error or file may be damaged. Version header seen more than once.
.
Language=PTB
Wrapped file format error or file may be damaged. Version header seen more than once.
.
Language=RUS
Wrapped file format error or file may be damaged. Version header seen more than once.
.
Language=CZH
Wrapped file format error or file may be damaged. Version header seen more than once.
.
Language=FIN
Wrapped file format error or file may be damaged. Version header seen more than once.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9030
Severity=Error
Facility=Application
SymbolicName=ERR_HEADER_TWICE
Language=ENU
Wrapped file format error or file may be damaged. '%3' header seen more than once.
.
Language=SVE
Wrapped file format error or file may be damaged. '%3' header seen more than once.
.
Language=DEU
Wrapped file format error or file may be damaged. '%3' header seen more than once.
.
Language=FRA
Wrapped file format error or file may be damaged. '%3' header seen more than once.
.
Language=ESN
Wrapped file format error or file may be damaged. '%3' header seen more than once.
.
Language=ITA
Wrapped file format error or file may be damaged. '%3' header seen more than once.
.
Language=HUN
Wrapped file format error or file may be damaged. '%3' header seen more than once.
.
Language=NOR
Wrapped file format error or file may be damaged. '%3' header seen more than once.
.
Language=NLD
Wrapped file format error or file may be damaged. '%3' header seen more than once.
.
Language=DNK
Wrapped file format error or file may be damaged. '%3' header seen more than once.
.
Language=POL
Wrapped file format error or file may be damaged. '%3' header seen more than once.
.
Language=CHI
Wrapped file format error or file may be damaged. '%3' header seen more than once.
.
Language=PTG
Wrapped file format error or file may be damaged. '%3' header seen more than once.
.
Language=PTB
Wrapped file format error or file may be damaged. '%3' header seen more than once.
.
Language=RUS
Wrapped file format error or file may be damaged. '%3' header seen more than once.
.
Language=CZH
Wrapped file format error or file may be damaged. '%3' header seen more than once.
.
Language=FIN
Wrapped file format error or file may be damaged. '%3' header seen more than once.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9035
Severity=Error
Facility=Application
SymbolicName=MSG_DEFLATE_INIT
Language=ENU
Error during compression, cannot initialize.
.
Language=SVE
Error during compression, cannot initialize.
.
Language=DEU
Error during compression, cannot initialize.
.
Language=FRA
Error during compression, cannot initialize.
.
Language=ESN
Error during compression, cannot initialize.
.
Language=ITA
Error during compression, cannot initialize.
.
Language=HUN
Error during compression, cannot initialize.
.
Language=NOR
Error during compression, cannot initialize.
.
Language=NLD
Error during compression, cannot initialize.
.
Language=DNK
Error during compression, cannot initialize.
.
Language=POL
Error during compression, cannot initialize.
.
Language=CHI
Error during compression, cannot initialize.
.
Language=PTG
Error during compression, cannot initialize.
.
Language=PTB
Error during compression, cannot initialize.
.
Language=RUS
Error during compression, cannot initialize.
.
Language=CZH
Error during compression, cannot initialize.
.
Language=FIN
Error during compression, cannot initialize.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9040
Severity=Error
Facility=Application
SymbolicName=MSG_DEFLATE_SYNC
Language=ENU
Error during compression, cannot continue.
.
Language=SVE
Error during compression, cannot continue.
.
Language=DEU
Error during compression, cannot continue.
.
Language=FRA
Error during compression, cannot continue.
.
Language=ESN
Error during compression, cannot continue.
.
Language=ITA
Error during compression, cannot continue.
.
Language=HUN
Error during compression, cannot continue.
.
Language=NOR
Error during compression, cannot continue.
.
Language=NLD
Error during compression, cannot continue.
.
Language=DNK
Error during compression, cannot continue.
.
Language=POL
Error during compression, cannot continue.
.
Language=CHI
Error during compression, cannot continue.
.
Language=PTG
Error during compression, cannot continue.
.
Language=PTB
Error during compression, cannot continue.
.
Language=RUS
Error during compression, cannot continue.
.
Language=CZH
Error during compression, cannot continue.
.
Language=FIN
Error during compression, cannot continue.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9045
Severity=Error
Facility=Application
SymbolicName=MSG_COMPRESS_FINISH
Language=ENU
Error when ending compression, operation failed.
.
Language=SVE
Error when ending compression, operation failed.
.
Language=DEU
Error when ending compression, operation failed.
.
Language=FRA
Error when ending compression, operation failed.
.
Language=ESN
Error when ending compression, operation failed.
.
Language=ITA
Error when ending compression, operation failed.
.
Language=HUN
Error when ending compression, operation failed.
.
Language=NOR
Error when ending compression, operation failed.
.
Language=NLD
Error when ending compression, operation failed.
.
Language=DNK
Error when ending compression, operation failed.
.
Language=POL
Error when ending compression, operation failed.
.
Language=CHI
Error when ending compression, operation failed.
.
Language=PTG
Error when ending compression, operation failed.
.
Language=PTB
Error when ending compression, operation failed.
.
Language=RUS
Error when ending compression, operation failed.
.
Language=CZH
Error when ending compression, operation failed.
.
Language=FIN
Error when ending compression, operation failed.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9050
Severity=Error
Facility=Application
SymbolicName=MSG_INFLATE_INIT
Language=ENU
Error initializing decompression, operation failed.
.
Language=SVE
Error initializing decompression, operation failed.
.
Language=DEU
Error initializing decompression, operation failed.
.
Language=FRA
Error initializing decompression, operation failed.
.
Language=ESN
Error initializing decompression, operation failed.
.
Language=ITA
Error initializing decompression, operation failed.
.
Language=HUN
Error initializing decompression, operation failed.
.
Language=NOR
Error initializing decompression, operation failed.
.
Language=NLD
Error initializing decompression, operation failed.
.
Language=DNK
Error initializing decompression, operation failed.
.
Language=POL
Error initializing decompression, operation failed.
.
Language=CHI
Error initializing decompression, operation failed.
.
Language=PTG
Error initializing decompression, operation failed.
.
Language=PTB
Error initializing decompression, operation failed.
.
Language=RUS
Error initializing decompression, operation failed.
.
Language=CZH
Error initializing decompression, operation failed.
.
Language=FIN
Error initializing decompression, operation failed.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9055
Severity=Error
Facility=Application
SymbolicName=MSG_INFLATE_ERROR
Language=ENU
Error during decompression, operation failed.
.
Language=SVE
Error during decompression, operation failed.
.
Language=DEU
Error during decompression, operation failed.
.
Language=FRA
Error during decompression, operation failed.
.
Language=ESN
Error during decompression, operation failed.
.
Language=ITA
Error during decompression, operation failed.
.
Language=HUN
Error during decompression, operation failed.
.
Language=NOR
Error during decompression, operation failed.
.
Language=NLD
Error during decompression, operation failed.
.
Language=DNK
Error during decompression, operation failed.
.
Language=POL
Error during decompression, operation failed.
.
Language=CHI
Error during decompression, operation failed.
.
Language=PTG
Error during decompression, operation failed.
.
Language=PTB
Error during decompression, operation failed.
.
Language=RUS
Error during decompression, operation failed.
.
Language=CZH
Error during decompression, operation failed.
.
Language=FIN
Error during decompression, operation failed.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9060
Severity=Error
Facility=Application
SymbolicName=MSG_INFLATE_FINISH
Language=ENU
Error during final decompression, operation failed.
.
Language=SVE
Error during final decompression, operation failed.
.
Language=DEU
Error during final decompression, operation failed.
.
Language=FRA
Error during final decompression, operation failed.
.
Language=ESN
Error during final decompression, operation failed.
.
Language=ITA
Error during final decompression, operation failed.
.
Language=HUN
Error during final decompression, operation failed.
.
Language=NOR
Error during final decompression, operation failed.
.
Language=NLD
Error during final decompression, operation failed.
.
Language=DNK
Error during final decompression, operation failed.
.
Language=POL
Error during final decompression, operation failed.
.
Language=CHI
Error during final decompression, operation failed.
.
Language=PTG
Error during final decompression, operation failed.
.
Language=PTB
Error during final decompression, operation failed.
.
Language=RUS
Error during final decompression, operation failed.
.
Language=CZH
Error during final decompression, operation failed.
.
Language=FIN
Error during final decompression, operation failed.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9065
Severity=Error
Facility=Application
SymbolicName=MSG_INFLATE_END
Language=ENU
Error at decompression end, operation failed.
.
Language=SVE
Error at decompression end, operation failed.
.
Language=DEU
Error at decompression end, operation failed.
.
Language=FRA
Error at decompression end, operation failed.
.
Language=ESN
Error at decompression end, operation failed.
.
Language=ITA
Error at decompression end, operation failed.
.
Language=HUN
Error at decompression end, operation failed.
.
Language=NOR
Error at decompression end, operation failed.
.
Language=NLD
Error at decompression end, operation failed.
.
Language=DNK
Error at decompression end, operation failed.
.
Language=POL
Error at decompression end, operation failed.
.
Language=CHI
Error at decompression end, operation failed.
.
Language=PTG
Error at decompression end, operation failed.
.
Language=PTB
Error at decompression end, operation failed.
.
Language=RUS
Error at decompression end, operation failed.
.
Language=CZH
Error at decompression end, operation failed.
.
Language=FIN
Error at decompression end, operation failed.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9070
Severity=Error
Facility=Application
SymbolicName=MSG_SET_REG_VALUE
Language=ENU
Failed to set value for sub-key '%3' in the registry, %2
.
Language=SVE
Failed to set value for sub-key '%3' in the registry, %2
.
Language=DEU
Failed to set value for sub-key '%3' in the registry, %2
.
Language=FRA
Failed to set value for sub-key '%3' in the registry, %2
.
Language=ESN
Failed to set value for sub-key '%3' in the registry, %2
.
Language=ITA
Failed to set value for sub-key '%3' in the registry, %2
.
Language=HUN
Failed to set value for sub-key '%3' in the registry, %2
.
Language=NOR
Failed to set value for sub-key '%3' in the registry, %2
.
Language=NLD
Failed to set value for sub-key '%3' in the registry, %2
.
Language=DNK
Failed to set value for sub-key '%3' in the registry, %2
.
Language=POL
Failed to set value for sub-key '%3' in the registry, %2
.
Language=CHI
Failed to set value for sub-key '%3' in the registry, %2
.
Language=PTG
Failed to set value for sub-key '%3' in the registry, %2
.
Language=PTB
Failed to set value for sub-key '%3' in the registry, %2
.
Language=RUS
Failed to set value for sub-key '%3' in the registry, %2
.
Language=CZH
Failed to set value for sub-key '%3' in the registry, %2
.
Language=FIN
Failed to set value for sub-key '%3' in the registry, %2
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9075
Severity=Error
Facility=Application
SymbolicName=MSG_CLOSE_REG_KEY
Language=ENU
Failed to close handle to key, %2
.
Language=SVE
Failed to close handle to key, %2
.
Language=DEU
Failed to close handle to key, %2
.
Language=FRA
Failed to close handle to key, %2
.
Language=ESN
Failed to close handle to key, %2
.
Language=ITA
Failed to close handle to key, %2
.
Language=HUN
Failed to close handle to key, %2
.
Language=NOR
Failed to close handle to key, %2
.
Language=NLD
Failed to close handle to key, %2
.
Language=DNK
Failed to close handle to key, %2
.
Language=POL
Failed to close handle to key, %2
.
Language=CHI
Failed to close handle to key, %2
.
Language=PTG
Failed to close handle to key, %2
.
Language=PTB
Failed to close handle to key, %2
.
Language=RUS
Failed to close handle to key, %2
.
Language=CZH
Failed to close handle to key, %2
.
Language=FIN
Failed to close handle to key, %2
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9080
Severity=Error
Facility=Application
SymbolicName=MSG_PARSE_COMMAND_INTERNAL
Language=ENU
Internal error parsing command line.
.
Language=SVE
Internal error parsing command line.
.
Language=DEU
Internal error parsing command line.
.
Language=FRA
Internal error parsing command line.
.
Language=ESN
Internal error parsing command line.
.
Language=ITA
Internal error parsing command line.
.
Language=HUN
Internal error parsing command line.
.
Language=NOR
Internal error parsing command line.
.
Language=NLD
Internal error parsing command line.
.
Language=DNK
Internal error parsing command line.
.
Language=POL
Internal error parsing command line.
.
Language=CHI
Internal error parsing command line.
.
Language=PTG
Internal error parsing command line.
.
Language=PTB
Internal error parsing command line.
.
Language=RUS
Internal error parsing command line.
.
Language=CZH
Internal error parsing command line.
.
Language=FIN
Internal error parsing command line.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9085
Severity=Error
Facility=Application
SymbolicName=MSG_CREATE_MUTEX
Language=ENU
Error creating mutex '%3'.
.
Language=SVE
Error creating mutex '%3'.
.
Language=DEU
Error creating mutex '%3'.
.
Language=FRA
Error creating mutex '%3'.
.
Language=ESN
Error creating mutex '%3'.
.
Language=ITA
Error creating mutex '%3'.
.
Language=HUN
Error creating mutex '%3'.
.
Language=NOR
Error creating mutex '%3'.
.
Language=NLD
Error creating mutex '%3'.
.
Language=DNK
Error creating mutex '%3'.
.
Language=POL
Error creating mutex '%3'.
.
Language=CHI
Error creating mutex '%3'.
.
Language=PTG
Error creating mutex '%3'.
.
Language=PTB
Error creating mutex '%3'.
.
Language=RUS
Error creating mutex '%3'.
.
Language=CZH
Error creating mutex '%3'.
.
Language=FIN
Error creating mutex '%3'.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9090
Severity=Error
Facility=Application
SymbolicName=MSG_CREATE_EVENT
Language=ENU
Error creating event '%3' (%2).
.
Language=SVE
Error creating event '%3' (%2).
.
Language=DEU
Error creating event '%3' (%2).
.
Language=FRA
Error creating event '%3' (%2).
.
Language=ESN
Error creating event '%3' (%2).
.
Language=ITA
Error creating event '%3' (%2).
.
Language=HUN
Error creating event '%3' (%2).
.
Language=NOR
Error creating event '%3' (%2).
.
Language=NLD
Error creating event '%3' (%2).
.
Language=DNK
Error creating event '%3' (%2).
.
Language=POL
Error creating event '%3' (%2).
.
Language=CHI
Error creating event '%3' (%2).
.
Language=PTG
Error creating event '%3' (%2).
.
Language=PTB
Error creating event '%3' (%2).
.
Language=RUS
Error creating event '%3' (%2).
.
Language=CZH
Error creating event '%3' (%2).
.
Language=FIN
Error creating event '%3' (%2).
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9095
Severity=Error
Facility=Application
SymbolicName=MSG_CREATE_REQUEST_MAP
Language=ENU
Error creating file mapping '%3' for interprocess communication of requests to the %1 server.
.
Language=SVE
Error creating file mapping '%3' for interprocess communication of requests to the %1 server.
.
Language=DEU
Error creating file mapping '%3' for interprocess communication of requests to the %1 server.
.
Language=FRA
Error creating file mapping '%3' for interprocess communication of requests to the %1 server.
.
Language=ESN
Error creating file mapping '%3' for interprocess communication of requests to the %1 server.
.
Language=ITA
Error creating file mapping '%3' for interprocess communication of requests to the %1 server.
.
Language=HUN
Error creating file mapping '%3' for interprocess communication of requests to the %1 server.
.
Language=NOR
Error creating file mapping '%3' for interprocess communication of requests to the %1 server.
.
Language=NLD
Error creating file mapping '%3' for interprocess communication of requests to the %1 server.
.
Language=DNK
Error creating file mapping '%3' for interprocess communication of requests to the %1 server.
.
Language=POL
Error creating file mapping '%3' for interprocess communication of requests to the %1 server.
.
Language=CHI
Error creating file mapping '%3' for interprocess communication of requests to the %1 server.
.
Language=PTG
Error creating file mapping '%3' for interprocess communication of requests to the %1 server.
.
Language=PTB
Error creating file mapping '%3' for interprocess communication of requests to the %1 server.
.
Language=RUS
Error creating file mapping '%3' for interprocess communication of requests to the %1 server.
.
Language=CZH
Error creating file mapping '%3' for interprocess communication of requests to the %1 server.
.
Language=FIN
Error creating file mapping '%3' for interprocess communication of requests to the %1 server.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9100
Severity=Error
Facility=Application
SymbolicName=MSG_INIT_APPLICATION
Language=ENU
Internal or System error in call to InitApplication(), %2
.
Language=SVE
Internal or System error in call to InitApplication(), %2
.
Language=DEU
Internal or System error in call to InitApplication(), %2
.
Language=FRA
Internal or System error in call to InitApplication(), %2
.
Language=ESN
Internal or System error in call to InitApplication(), %2
.
Language=ITA
Internal or System error in call to InitApplication(), %2
.
Language=HUN
Internal or System error in call to InitApplication(), %2
.
Language=NOR
Internal or System error in call to InitApplication(), %2
.
Language=NLD
Internal or System error in call to InitApplication(), %2
.
Language=DNK
Internal or System error in call to InitApplication(), %2
.
Language=POL
Internal or System error in call to InitApplication(), %2
.
Language=CHI
Internal or System error in call to InitApplication(), %2
.
Language=PTG
Internal or System error in call to InitApplication(), %2
.
Language=PTB
Internal or System error in call to InitApplication(), %2
.
Language=RUS
Internal or System error in call to InitApplication(), %2
.
Language=CZH
Internal or System error in call to InitApplication(), %2
.
Language=FIN
Internal or System error in call to InitApplication(), %2
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9105
Severity=Error
Facility=Application
SymbolicName=MSG_INIT_INSTANCE
Language=ENU
Internal or System error in call to InitInstance(), %2
.
Language=SVE
Internal or System error in call to InitInstance(), %2
.
Language=DEU
Internal or System error in call to InitInstance(), %2
.
Language=FRA
Internal or System error in call to InitInstance(), %2
.
Language=ESN
Internal or System error in call to InitInstance(), %2
.
Language=ITA
Internal or System error in call to InitInstance(), %2
.
Language=HUN
Internal or System error in call to InitInstance(), %2
.
Language=NOR
Internal or System error in call to InitInstance(), %2
.
Language=NLD
Internal or System error in call to InitInstance(), %2
.
Language=DNK
Internal or System error in call to InitInstance(), %2
.
Language=POL
Internal or System error in call to InitInstance(), %2
.
Language=CHI
Internal or System error in call to InitInstance(), %2
.
Language=PTG
Internal or System error in call to InitInstance(), %2
.
Language=PTB
Internal or System error in call to InitInstance(), %2
.
Language=RUS
Internal or System error in call to InitInstance(), %2
.
Language=CZH
Internal or System error in call to InitInstance(), %2
.
Language=FIN
Internal or System error in call to InitInstance(), %2
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9110
Severity=Error
Facility=Application
SymbolicName=MSG_AES_ERROR
Language=ENU
Internal configuration error in the Advanced Encryption Standard library.
%4
.
Language=SVE
Internal configuration error in the Advanced Encryption Standard library.
%4
.
Language=DEU
Internal configuration error in the Advanced Encryption Standard library.
%4
.
Language=FRA
Internal configuration error in the Advanced Encryption Standard library.
%4
.
Language=ESN
Internal configuration error in the Advanced Encryption Standard library.
%4
.
Language=ITA
Internal configuration error in the Advanced Encryption Standard library.
%4
.
Language=HUN
Internal configuration error in the Advanced Encryption Standard library.
%4
.
Language=NOR
Internal configuration error in the Advanced Encryption Standard library.
%4
.
Language=NLD
Internal configuration error in the Advanced Encryption Standard library.
%4
.
Language=DNK
Internal configuration error in the Advanced Encryption Standard library.
%4
.
Language=POL
Internal configuration error in the Advanced Encryption Standard library.
%4
.
Language=CHI
Internal configuration error in the Advanced Encryption Standard library.
%4
.
Language=PTG
Internal configuration error in the Advanced Encryption Standard library.
%4
.
Language=PTB
Internal configuration error in the Advanced Encryption Standard library.
%4
.
Language=RUS
Internal configuration error in the Advanced Encryption Standard library.
%4
.
Language=CZH
Internal configuration error in the Advanced Encryption Standard library.
%4
.
Language=FIN
Internal configuration error in the Advanced Encryption Standard library.
%4
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9115
Severity=Error
Facility=Application
SymbolicName=MSG_INTERNAL_ERROR
Language=ENU
Internal error in %3. Please report.
.
Language=SVE
Internal error in %3. Please report.
.
Language=DEU
Internal error in %3. Please report.
.
Language=FRA
Internal error in %3. Please report.
.
Language=ESN
Internal error in %3. Please report.
.
Language=ITA
Internal error in %3. Please report.
.
Language=HUN
Internal error in %3. Please report.
.
Language=NOR
Internal error in %3. Please report.
.
Language=NLD
Internal error in %3. Please report.
.
Language=DNK
Internal error in %3. Please report.
.
Language=POL
Internal error in %3. Please report.
.
Language=CHI
Internal error in %3. Please report.
.
Language=PTG
Internal error in %3. Please report.
.
Language=PTB
Internal error in %3. Please report.
.
Language=RUS
Internal error in %3. Please report.
.
Language=CZH
Internal error in %3. Please report.
.
Language=FIN
Internal error in %3. Please report.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9120
Severity=Error
Facility=Application
SymbolicName=MSG_CRYPTO_HEAP_CONSTRUCT
Language=ENU
Irrecoverable error constructing CryptoHeap(), %4.
.
Language=SVE
Irrecoverable error constructing CryptoHeap(), %4.
.
Language=DEU
Irrecoverable error constructing CryptoHeap(), %4.
.
Language=FRA
Irrecoverable error constructing CryptoHeap(), %4.
.
Language=ESN
Irrecoverable error constructing CryptoHeap(), %4.
.
Language=ITA
Irrecoverable error constructing CryptoHeap(), %4.
.
Language=HUN
Irrecoverable error constructing CryptoHeap(), %4.
.
Language=NOR
Irrecoverable error constructing CryptoHeap(), %4.
.
Language=NLD
Irrecoverable error constructing CryptoHeap(), %4.
.
Language=DNK
Irrecoverable error constructing CryptoHeap(), %4.
.
Language=POL
Irrecoverable error constructing CryptoHeap(), %4.
.
Language=CHI
Irrecoverable error constructing CryptoHeap(), %4.
.
Language=PTG
Irrecoverable error constructing CryptoHeap(), %4.
.
Language=PTB
Irrecoverable error constructing CryptoHeap(), %4.
.
Language=RUS
Irrecoverable error constructing CryptoHeap(), %4.
.
Language=CZH
Irrecoverable error constructing CryptoHeap(), %4.
.
Language=FIN
Irrecoverable error constructing CryptoHeap(), %4.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9125
Severity=Error
Facility=Application
SymbolicName=MSG_CRYPTO_HEAP_DESTRUCT
Language=ENU
Irrecoverable error destructing CryptoHeap(), %4.
.
Language=SVE
Irrecoverable error destructing CryptoHeap(), %4.
.
Language=DEU
Irrecoverable error destructing CryptoHeap(), %4.
.
Language=FRA
Irrecoverable error destructing CryptoHeap(), %4.
.
Language=ESN
Irrecoverable error destructing CryptoHeap(), %4.
.
Language=ITA
Irrecoverable error destructing CryptoHeap(), %4.
.
Language=HUN
Irrecoverable error destructing CryptoHeap(), %4.
.
Language=NOR
Irrecoverable error destructing CryptoHeap(), %4.
.
Language=NLD
Irrecoverable error destructing CryptoHeap(), %4.
.
Language=DNK
Irrecoverable error destructing CryptoHeap(), %4.
.
Language=POL
Irrecoverable error destructing CryptoHeap(), %4.
.
Language=CHI
Irrecoverable error destructing CryptoHeap(), %4.
.
Language=PTG
Irrecoverable error destructing CryptoHeap(), %4.
.
Language=PTB
Irrecoverable error destructing CryptoHeap(), %4.
.
Language=RUS
Irrecoverable error destructing CryptoHeap(), %4.
.
Language=CZH
Irrecoverable error destructing CryptoHeap(), %4.
.
Language=FIN
Irrecoverable error destructing CryptoHeap(), %4.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9130
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_ERROR
Language=ENU
>>ERROR<<
.
Language=SVE
>>ERROR<<
.
Language=DEU
>>ERROR<<
.
Language=FRA
>>ERROR<<
.
Language=ESN
>>ERROR<<
.
Language=ITA
>>ERROR<<
.
Language=HUN
>>ERROR<<
.
Language=NOR
>>ERROR<<
.
Language=NLD
>>ERROR<<
.
Language=DNK
>>ERROR<<
.
Language=POL
>>ERROR<<
.
Language=CHI
>>ERROR<<
.
Language=PTG
>>ERROR<<
.
Language=PTB
>>ERROR<<
.
Language=RUS
>>ERROR<<
.
Language=CZH
>>ERROR<<
.
Language=FIN
>>ERROR<<
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9135
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_DEBUG
Language=ENU
Debug
.
Language=SVE
Debug
.
Language=DEU
Debug
.
Language=FRA
Debug
.
Language=ESN
Debug
.
Language=ITA
Debug
.
Language=HUN
Debug
.
Language=NOR
Debug
.
Language=NLD
Debug
.
Language=DNK
Debug
.
Language=POL
Debug
.
Language=CHI
Debug
.
Language=PTG
Debug
.
Language=PTB
Debug
.
Language=RUS
Debug
.
Language=CZH
Debug
.
Language=FIN
Debug
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9140
Severity=Informational
Facility=Application
SymbolicName=HLP_MENU_DEBUG
Language=ENU
Debug: Display the file name and do nothing.
.
Language=SVE
Debug: Display the file name and do nothing.
.
Language=DEU
Debug: Display the file name and do nothing.
.
Language=FRA
Debug: Display the file name and do nothing.
.
Language=ESN
Debug: Display the file name and do nothing.
.
Language=ITA
Debug: Display the file name and do nothing.
.
Language=HUN
Debug: Display the file name and do nothing.
.
Language=NOR
Debug: Display the file name and do nothing.
.
Language=NLD
Debug: Display the file name and do nothing.
.
Language=DNK
Debug: Display the file name and do nothing.
.
Language=POL
Debug: Display the file name and do nothing.
.
Language=CHI
Debug: Display the file name and do nothing.
.
Language=PTG
Debug: Display the file name and do nothing.
.
Language=PTB
Debug: Display the file name and do nothing.
.
Language=RUS
Debug: Display the file name and do nothing.
.
Language=CZH
Debug: Display the file name and do nothing.
.
Language=FIN
Debug: Display the file name and do nothing.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9145
Severity=Error
Facility=Application
SymbolicName=MSG_MEMORY_LEAK
Language=ENU
Possible memory leak of %2 bytes in %3 including heap overhead.
.
Language=SVE
Possible memory leak of %2 bytes in %3 including heap overhead.
.
Language=DEU
Possible memory leak of %2 bytes in %3 including heap overhead.
.
Language=FRA
Possible memory leak of %2 bytes in %3 including heap overhead.
.
Language=ESN
Possible memory leak of %2 bytes in %3 including heap overhead.
.
Language=ITA
Possible memory leak of %2 bytes in %3 including heap overhead.
.
Language=HUN
Possible memory leak of %2 bytes in %3 including heap overhead.
.
Language=NOR
Possible memory leak of %2 bytes in %3 including heap overhead.
.
Language=NLD
Possible memory leak of %2 bytes in %3 including heap overhead.
.
Language=DNK
Possible memory leak of %2 bytes in %3 including heap overhead.
.
Language=POL
Possible memory leak of %2 bytes in %3 including heap overhead.
.
Language=CHI
Possible memory leak of %2 bytes in %3 including heap overhead.
.
Language=PTG
Possible memory leak of %2 bytes in %3 including heap overhead.
.
Language=PTB
Possible memory leak of %2 bytes in %3 including heap overhead.
.
Language=RUS
Possible memory leak of %2 bytes in %3 including heap overhead.
.
Language=CZH
Possible memory leak of %2 bytes in %3 including heap overhead.
.
Language=FIN
Possible memory leak of %2 bytes in %3 including heap overhead.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9150
Severity=Informational
Facility=Application
SymbolicName=INF_APP_QUIT
Language=ENU
%1 is terminating due to user request.%0
.
Language=SVE
%1 is terminating due to user request.%0
.
Language=DEU
%1 is terminating due to user request.%0
.
Language=FRA
%1 is terminating due to user request.%0
.
Language=ESN
%1 is terminating due to user request.%0
.
Language=ITA
%1 is terminating due to user request.%0
.
Language=HUN
%1 is terminating due to user request.%0
.
Language=NOR
%1 is terminating due to user request.%0
.
Language=NLD
%1 is terminating due to user request.%0
.
Language=DNK
%1 is terminating due to user request.%0
.
Language=POL
%1 is terminating due to user request.%0
.
Language=CHI
%1 is terminating due to user request.%0
.
Language=PTG
%1 is terminating due to user request.%0
.
Language=PTB
%1 is terminating due to user request.%0
.
Language=RUS
%1 is terminating due to user request.%0
.
Language=CZH
%1 is terminating due to user request.%0
.
Language=FIN
%1 is terminating due to user request.%0
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9155
Severity=Informational
Facility=Application
SymbolicName=INF_APP_START
Language=ENU
***** %1 is starting the main thread.%0
.
Language=SVE
***** %1 is starting the main thread.%0
.
Language=DEU
***** %1 is starting the main thread.%0
.
Language=FRA
***** %1 is starting the main thread.%0
.
Language=ESN
***** %1 is starting the main thread.%0
.
Language=ITA
***** %1 is starting the main thread.%0
.
Language=HUN
***** %1 is starting the main thread.%0
.
Language=NOR
***** %1 is starting the main thread.%0
.
Language=NLD
***** %1 is starting the main thread.%0
.
Language=DNK
***** %1 is starting the main thread.%0
.
Language=POL
***** %1 is starting the main thread.%0
.
Language=CHI
***** %1 is starting the main thread.%0
.
Language=PTG
***** %1 is starting the main thread.%0
.
Language=PTB
***** %1 is starting the main thread.%0
.
Language=RUS
***** %1 is starting the main thread.%0
.
Language=CZH
***** %1 is starting the main thread.%0
.
Language=FIN
***** %1 is starting the main thread.%0
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9160
Severity=Informational
Facility=Application
SymbolicName=INF_DEBUG
Language=ENU
Debug: %2%0
.
Language=SVE
Debug: %2%0
.
Language=DEU
Debug: %2%0
.
Language=FRA
Debug: %2%0
.
Language=ESN
Debug: %2%0
.
Language=ITA
Debug: %2%0
.
Language=HUN
Debug: %2%0
.
Language=NOR
Debug: %2%0
.
Language=NLD
Debug: %2%0
.
Language=DNK
Debug: %2%0
.
Language=POL
Debug: %2%0
.
Language=CHI
Debug: %2%0
.
Language=PTG
Debug: %2%0
.
Language=PTB
Debug: %2%0
.
Language=RUS
Debug: %2%0
.
Language=CZH
Debug: %2%0
.
Language=FIN
Debug: %2%0
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9165
Severity=Informational
Facility=Application
SymbolicName=INF_DEBUG2
Language=ENU
Debug: %2 (%3)%0
.
Language=SVE
Debug: %2 (%3)%0
.
Language=DEU
Debug: %2 (%3)%0
.
Language=FRA
Debug: %2 (%3)%0
.
Language=ESN
Debug: %2 (%3)%0
.
Language=ITA
Debug: %2 (%3)%0
.
Language=HUN
Debug: %2 (%3)%0
.
Language=NOR
Debug: %2 (%3)%0
.
Language=NLD
Debug: %2 (%3)%0
.
Language=DNK
Debug: %2 (%3)%0
.
Language=POL
Debug: %2 (%3)%0
.
Language=CHI
Debug: %2 (%3)%0
.
Language=PTG
Debug: %2 (%3)%0
.
Language=PTB
Debug: %2 (%3)%0
.
Language=RUS
Debug: %2 (%3)%0
.
Language=CZH
Debug: %2 (%3)%0
.
Language=FIN
Debug: %2 (%3)%0
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9170
Severity=Informational
Facility=Application
SymbolicName=INF_SAVED_ENTROPY
Language=ENU
Saving half of entropy pool to registry.%0
.
Language=SVE
Saving half of entropy pool to registry.%0
.
Language=DEU
Saving half of entropy pool to registry.%0
.
Language=FRA
Saving half of entropy pool to registry.%0
.
Language=ESN
Saving half of entropy pool to registry.%0
.
Language=ITA
Saving half of entropy pool to registry.%0
.
Language=HUN
Saving half of entropy pool to registry.%0
.
Language=NOR
Saving half of entropy pool to registry.%0
.
Language=NLD
Saving half of entropy pool to registry.%0
.
Language=DNK
Saving half of entropy pool to registry.%0
.
Language=POL
Saving half of entropy pool to registry.%0
.
Language=CHI
Saving half of entropy pool to registry.%0
.
Language=PTG
Saving half of entropy pool to registry.%0
.
Language=PTB
Saving half of entropy pool to registry.%0
.
Language=RUS
Saving half of entropy pool to registry.%0
.
Language=CZH
Saving half of entropy pool to registry.%0
.
Language=FIN
Saving half of entropy pool to registry.%0
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9175
Severity=Informational
Facility=Application
SymbolicName=INF_LOADED_ENTROPY
Language=ENU
Loading half of entropy pool from registry.%0
.
Language=SVE
Loading half of entropy pool from registry.%0
.
Language=DEU
Loading half of entropy pool from registry.%0
.
Language=FRA
Loading half of entropy pool from registry.%0
.
Language=ESN
Loading half of entropy pool from registry.%0
.
Language=ITA
Loading half of entropy pool from registry.%0
.
Language=HUN
Loading half of entropy pool from registry.%0
.
Language=NOR
Loading half of entropy pool from registry.%0
.
Language=NLD
Loading half of entropy pool from registry.%0
.
Language=DNK
Loading half of entropy pool from registry.%0
.
Language=POL
Loading half of entropy pool from registry.%0
.
Language=CHI
Loading half of entropy pool from registry.%0
.
Language=PTG
Loading half of entropy pool from registry.%0
.
Language=PTB
Loading half of entropy pool from registry.%0
.
Language=RUS
Loading half of entropy pool from registry.%0
.
Language=CZH
Loading half of entropy pool from registry.%0
.
Language=FIN
Loading half of entropy pool from registry.%0
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9180
Severity=Informational
Facility=Application
SymbolicName=INF_GATHERING_ENTROPY
Language=ENU
Gathering %2 bits of entropy to the pool.%0
.
Language=SVE
Gathering %2 bits of entropy to the pool.%0
.
Language=DEU
Gathering %2 bits of entropy to the pool.%0
.
Language=FRA
Gathering %2 bits of entropy to the pool.%0
.
Language=ESN
Gathering %2 bits of entropy to the pool.%0
.
Language=ITA
Gathering %2 bits of entropy to the pool.%0
.
Language=HUN
Gathering %2 bits of entropy to the pool.%0
.
Language=NOR
Gathering %2 bits of entropy to the pool.%0
.
Language=NLD
Gathering %2 bits of entropy to the pool.%0
.
Language=DNK
Gathering %2 bits of entropy to the pool.%0
.
Language=POL
Gathering %2 bits of entropy to the pool.%0
.
Language=CHI
Gathering %2 bits of entropy to the pool.%0
.
Language=PTG
Gathering %2 bits of entropy to the pool.%0
.
Language=PTB
Gathering %2 bits of entropy to the pool.%0
.
Language=RUS
Gathering %2 bits of entropy to the pool.%0
.
Language=CZH
Gathering %2 bits of entropy to the pool.%0
.
Language=FIN
Gathering %2 bits of entropy to the pool.%0
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9185
Severity=Informational
Facility=Application
SymbolicName=INF_USING_ENTROPY
Language=ENU
Using %2 bits of entropy from the pool.%0
.
Language=SVE
Using %2 bits of entropy from the pool.%0
.
Language=DEU
Using %2 bits of entropy from the pool.%0
.
Language=FRA
Using %2 bits of entropy from the pool.%0
.
Language=ESN
Using %2 bits of entropy from the pool.%0
.
Language=ITA
Using %2 bits of entropy from the pool.%0
.
Language=HUN
Using %2 bits of entropy from the pool.%0
.
Language=NOR
Using %2 bits of entropy from the pool.%0
.
Language=NLD
Using %2 bits of entropy from the pool.%0
.
Language=DNK
Using %2 bits of entropy from the pool.%0
.
Language=POL
Using %2 bits of entropy from the pool.%0
.
Language=CHI
Using %2 bits of entropy from the pool.%0
.
Language=PTG
Using %2 bits of entropy from the pool.%0
.
Language=PTB
Using %2 bits of entropy from the pool.%0
.
Language=RUS
Using %2 bits of entropy from the pool.%0
.
Language=CZH
Using %2 bits of entropy from the pool.%0
.
Language=FIN
Using %2 bits of entropy from the pool.%0
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9190
Severity=Error
Facility=Application
SymbolicName=ERR_UNTRAPPED
Language=ENU
Internal error, untrapped exception: %4
.
Language=SVE
Internal error, untrapped exception: %4
.
Language=DEU
Internal error, untrapped exception: %4
.
Language=FRA
Internal error, untrapped exception: %4
.
Language=ESN
Internal error, untrapped exception: %4
.
Language=ITA
Internal error, untrapped exception: %4
.
Language=HUN
Internal error, untrapped exception: %4
.
Language=NOR
Internal error, untrapped exception: %4
.
Language=NLD
Internal error, untrapped exception: %4
.
Language=DNK
Internal error, untrapped exception: %4
.
Language=POL
Internal error, untrapped exception: %4
.
Language=CHI
Internal error, untrapped exception: %4
.
Language=PTG
Internal error, untrapped exception: %4
.
Language=PTB
Internal error, untrapped exception: %4
.
Language=RUS
Internal error, untrapped exception: %4
.
Language=CZH
Internal error, untrapped exception: %4
.
Language=FIN
Internal error, untrapped exception: %4
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9195
Severity=Error
Facility=Application
SymbolicName=ERR_ARGUMENT
Language=ENU
Internal error, invalid function argument in %3
.
Language=SVE
Internal error, invalid function argument in %3
.
Language=DEU
Internal error, invalid function argument in %3
.
Language=FRA
Internal error, invalid function argument in %3
.
Language=ESN
Internal error, invalid function argument in %3
.
Language=ITA
Internal error, invalid function argument in %3
.
Language=HUN
Internal error, invalid function argument in %3
.
Language=NOR
Internal error, invalid function argument in %3
.
Language=NLD
Internal error, invalid function argument in %3
.
Language=DNK
Internal error, invalid function argument in %3
.
Language=POL
Internal error, invalid function argument in %3
.
Language=CHI
Internal error, invalid function argument in %3
.
Language=PTG
Internal error, invalid function argument in %3
.
Language=PTB
Internal error, invalid function argument in %3
.
Language=RUS
Internal error, invalid function argument in %3
.
Language=CZH
Internal error, invalid function argument in %3
.
Language=FIN
Internal error, invalid function argument in %3
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9200
Severity=Error
Facility=Application
SymbolicName=ERR_MMTIMER
Language=ENU
Multimedia timer error in %4.
.
Language=SVE
Multimedia timer error in %4.
.
Language=DEU
Multimedia timer error in %4.
.
Language=FRA
Multimedia timer error in %4.
.
Language=ESN
Multimedia timer error in %4.
.
Language=ITA
Multimedia timer error in %4.
.
Language=HUN
Multimedia timer error in %4.
.
Language=NOR
Multimedia timer error in %4.
.
Language=NLD
Multimedia timer error in %4.
.
Language=DNK
Multimedia timer error in %4.
.
Language=POL
Multimedia timer error in %4.
.
Language=CHI
Multimedia timer error in %4.
.
Language=PTG
Multimedia timer error in %4.
.
Language=PTB
Multimedia timer error in %4.
.
Language=RUS
Multimedia timer error in %4.
.
Language=CZH
Multimedia timer error in %4.
.
Language=FIN
Multimedia timer error in %4.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9205
Severity=Warning
Facility=Application
SymbolicName=WRN_GATHER_THREAD
Language=ENU
Warning - could not stop the Gather thread gracefully.%0
.
Language=SVE
Warning - could not stop the Gather thread gracefully.%0
.
Language=DEU
Warning - could not stop the Gather thread gracefully.%0
.
Language=FRA
Warning - could not stop the Gather thread gracefully.%0
.
Language=ESN
Warning - could not stop the Gather thread gracefully.%0
.
Language=ITA
Warning - could not stop the Gather thread gracefully.%0
.
Language=HUN
Warning - could not stop the Gather thread gracefully.%0
.
Language=NOR
Warning - could not stop the Gather thread gracefully.%0
.
Language=NLD
Warning - could not stop the Gather thread gracefully.%0
.
Language=DNK
Warning - could not stop the Gather thread gracefully.%0
.
Language=POL
Warning - could not stop the Gather thread gracefully.%0
.
Language=CHI
Warning - could not stop the Gather thread gracefully.%0
.
Language=PTG
Warning - could not stop the Gather thread gracefully.%0
.
Language=PTB
Warning - could not stop the Gather thread gracefully.%0
.
Language=RUS
Warning - could not stop the Gather thread gracefully.%0
.
Language=CZH
Warning - could not stop the Gather thread gracefully.%0
.
Language=FIN
Warning - could not stop the Gather thread gracefully.%0
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9210
Severity=Warning
Facility=Application
SymbolicName=WRN_FLIPPER_THREAD
Language=ENU
Warning - could not stop the Flipper thread gracefully.%0
.
Language=SVE
Warning - could not stop the Flipper thread gracefully.%0
.
Language=DEU
Warning - could not stop the Flipper thread gracefully.%0
.
Language=FRA
Warning - could not stop the Flipper thread gracefully.%0
.
Language=ESN
Warning - could not stop the Flipper thread gracefully.%0
.
Language=ITA
Warning - could not stop the Flipper thread gracefully.%0
.
Language=HUN
Warning - could not stop the Flipper thread gracefully.%0
.
Language=NOR
Warning - could not stop the Flipper thread gracefully.%0
.
Language=NLD
Warning - could not stop the Flipper thread gracefully.%0
.
Language=DNK
Warning - could not stop the Flipper thread gracefully.%0
.
Language=POL
Warning - could not stop the Flipper thread gracefully.%0
.
Language=CHI
Warning - could not stop the Flipper thread gracefully.%0
.
Language=PTG
Warning - could not stop the Flipper thread gracefully.%0
.
Language=PTB
Warning - could not stop the Flipper thread gracefully.%0
.
Language=RUS
Warning - could not stop the Flipper thread gracefully.%0
.
Language=CZH
Warning - could not stop the Flipper thread gracefully.%0
.
Language=FIN
Warning - could not stop the Flipper thread gracefully.%0
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9215
Severity=Warning
Facility=Application
SymbolicName=WRN_USERENTROPY_THREAD
Language=ENU
Warning - could not stop the User Entropy thread gracefully.%0
.
Language=SVE
Warning - could not stop the User Entropy thread gracefully.%0
.
Language=DEU
Warning - could not stop the User Entropy thread gracefully.%0
.
Language=FRA
Warning - could not stop the User Entropy thread gracefully.%0
.
Language=ESN
Warning - could not stop the User Entropy thread gracefully.%0
.
Language=ITA
Warning - could not stop the User Entropy thread gracefully.%0
.
Language=HUN
Warning - could not stop the User Entropy thread gracefully.%0
.
Language=NOR
Warning - could not stop the User Entropy thread gracefully.%0
.
Language=NLD
Warning - could not stop the User Entropy thread gracefully.%0
.
Language=DNK
Warning - could not stop the User Entropy thread gracefully.%0
.
Language=POL
Warning - could not stop the User Entropy thread gracefully.%0
.
Language=CHI
Warning - could not stop the User Entropy thread gracefully.%0
.
Language=PTG
Warning - could not stop the User Entropy thread gracefully.%0
.
Language=PTB
Warning - could not stop the User Entropy thread gracefully.%0
.
Language=RUS
Warning - could not stop the User Entropy thread gracefully.%0
.
Language=CZH
Warning - could not stop the User Entropy thread gracefully.%0
.
Language=FIN
Warning - could not stop the User Entropy thread gracefully.%0
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9220
Severity=Informational
Facility=Application
SymbolicName=MSG_OSCILLATOR
Language=ENU
The bit oscillator appears to run at %2MHz.%0
.
Language=SVE
The bit oscillator appears to run at %2MHz.%0
.
Language=DEU
The bit oscillator appears to run at %2MHz.%0
.
Language=FRA
The bit oscillator appears to run at %2MHz.%0
.
Language=ESN
The bit oscillator appears to run at %2MHz.%0
.
Language=ITA
The bit oscillator appears to run at %2MHz.%0
.
Language=HUN
The bit oscillator appears to run at %2MHz.%0
.
Language=NOR
The bit oscillator appears to run at %2MHz.%0
.
Language=NLD
The bit oscillator appears to run at %2MHz.%0
.
Language=DNK
The bit oscillator appears to run at %2MHz.%0
.
Language=POL
The bit oscillator appears to run at %2MHz.%0
.
Language=CHI
The bit oscillator appears to run at %2MHz.%0
.
Language=PTG
The bit oscillator appears to run at %2MHz.%0
.
Language=PTB
The bit oscillator appears to run at %2MHz.%0
.
Language=RUS
The bit oscillator appears to run at %2MHz.%0
.
Language=CZH
The bit oscillator appears to run at %2MHz.%0
.
Language=FIN
The bit oscillator appears to run at %2MHz.%0
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9225
Severity=Informational
Facility=Application
SymbolicName=INF_ENTROPY_START
Language=ENU
Starting entropy collector.%0
.
Language=SVE
Starting entropy collector.%0
.
Language=DEU
Starting entropy collector.%0
.
Language=FRA
Starting entropy collector.%0
.
Language=ESN
Starting entropy collector.%0
.
Language=ITA
Starting entropy collector.%0
.
Language=HUN
Starting entropy collector.%0
.
Language=NOR
Starting entropy collector.%0
.
Language=NLD
Starting entropy collector.%0
.
Language=DNK
Starting entropy collector.%0
.
Language=POL
Starting entropy collector.%0
.
Language=CHI
Starting entropy collector.%0
.
Language=PTG
Starting entropy collector.%0
.
Language=PTB
Starting entropy collector.%0
.
Language=RUS
Starting entropy collector.%0
.
Language=CZH
Starting entropy collector.%0
.
Language=FIN
Starting entropy collector.%0
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9230
Severity=Informational
Facility=Application
SymbolicName=INF_ENTROPY_STOP
Language=ENU
Stopping entropy collector.%0
.
Language=SVE
Stopping entropy collector.%0
.
Language=DEU
Stopping entropy collector.%0
.
Language=FRA
Stopping entropy collector.%0
.
Language=ESN
Stopping entropy collector.%0
.
Language=ITA
Stopping entropy collector.%0
.
Language=HUN
Stopping entropy collector.%0
.
Language=NOR
Stopping entropy collector.%0
.
Language=NLD
Stopping entropy collector.%0
.
Language=DNK
Stopping entropy collector.%0
.
Language=POL
Stopping entropy collector.%0
.
Language=CHI
Stopping entropy collector.%0
.
Language=PTG
Stopping entropy collector.%0
.
Language=PTB
Stopping entropy collector.%0
.
Language=RUS
Stopping entropy collector.%0
.
Language=CZH
Stopping entropy collector.%0
.
Language=FIN
Stopping entropy collector.%0
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9235
Severity=Informational
Facility=Application
SymbolicName=INF_WINDOWS_ENTROPY
Language=ENU
Added a byte of Window state change to entropy pool.%0
.
Language=SVE
Added a byte of Window state change to entropy pool.%0
.
Language=DEU
Added a byte of Window state change to entropy pool.%0
.
Language=FRA
Added a byte of Window state change to entropy pool.%0
.
Language=ESN
Added a byte of Window state change to entropy pool.%0
.
Language=ITA
Added a byte of Window state change to entropy pool.%0
.
Language=HUN
Added a byte of Window state change to entropy pool.%0
.
Language=NOR
Added a byte of Window state change to entropy pool.%0
.
Language=NLD
Added a byte of Window state change to entropy pool.%0
.
Language=DNK
Added a byte of Window state change to entropy pool.%0
.
Language=POL
Added a byte of Window state change to entropy pool.%0
.
Language=CHI
Added a byte of Window state change to entropy pool.%0
.
Language=PTG
Added a byte of Window state change to entropy pool.%0
.
Language=PTB
Added a byte of Window state change to entropy pool.%0
.
Language=RUS
Added a byte of Window state change to entropy pool.%0
.
Language=CZH
Added a byte of Window state change to entropy pool.%0
.
Language=FIN
Added a byte of Window state change to entropy pool.%0
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
MessageId=9240
Severity=Informational
Facility=Application
SymbolicName=INF_MOUSE_ENTROPY
Language=ENU
Added a byte of Mouse position change to entropy pool.%0
.
Language=SVE
Added a byte of Mouse position change to entropy pool.%0
.
Language=DEU
Added a byte of Mouse position change to entropy pool.%0
.
Language=FRA
Added a byte of Mouse position change to entropy pool.%0
.
Language=ESN
Added a byte of Mouse position change to entropy pool.%0
.
Language=ITA
Added a byte of Mouse position change to entropy pool.%0
.
Language=HUN
Added a byte of Mouse position change to entropy pool.%0
.
Language=NOR
Added a byte of Mouse position change to entropy pool.%0
.
Language=NLD
Added a byte of Mouse position change to entropy pool.%0
.
Language=DNK
Added a byte of Mouse position change to entropy pool.%0
.
Language=POL
Added a byte of Mouse position change to entropy pool.%0
.
Language=CHI
Added a byte of Mouse position change to entropy pool.%0
.
Language=PTG
Added a byte of Mouse position change to entropy pool.%0
.
Language=PTB
Added a byte of Mouse position change to entropy pool.%0
.
Language=RUS
Added a byte of Mouse position change to entropy pool.%0
.
Language=CZH
Added a byte of Mouse position change to entropy pool.%0
.
Language=FIN
Added a byte of Mouse position change to entropy pool.%0
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
;//
;//	Rel 1.2
;//
;// This is/should never be used to display, so translation need
;// not be perfect. It is used as a placeholder to generate a proper
;// error id.
;//
MessageId=9245
Severity=Error
Facility=Application
SymbolicName=ERR_UNSPECIFIED
Language=ENU
Unspecified error.
.
Language=SVE
Unspecified error.
.
Language=DEU
Unspecified error.
.
Language=FRA
Unspecified error.
.
Language=ESN
Unspecified error.
.
Language=ITA
Unspecified error.
.
Language=HUN
Unspecified error.
.
Language=NOR
Unspecified error.
.
Language=NLD
Unspecified error.
.
Language=DNK
Unspecified error.
.
Language=POL
Unspecified error.
.
Language=CHI
Unspecified error.
.
Language=PTG
Unspecified error.
.
Language=PTB
Unspecified error.
.
Language=RUS
Unspecified error.
.
Language=CZH
Unspecified error.
.
Language=FIN
Unspecified error.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
;//
;//	Rel 1.2.1 - Only used for it's code. This code is
;// returned when in server mode no passphrase was
;// found for an encryption or decryption.
;//	No translation needed - the text is never shown.
;//
MessageId=9250
Severity=Error
Facility=Application
SymbolicName=ERR_NO_PASSPHRASE
Language=ENU
No Passphrase.
.
Language=SVE
No Passphrase.
.
Language=DEU
No Passphrase.
.
Language=FRA
No Passphrase.
.
Language=ESN
No Passphrase.
.
Language=ITA
Nessuna Password.
.
Language=HUN
No Passphrase.
.
Language=NOR
No Passphrase.
.
Language=NLD
No Passphrase.
.
Language=DNK
No Passphrase.
.
Language=POL
No Passphrase.
.
Language=CHI
No Passphrase.
.
Language=PTG
No Passphrase.
.
Language=PTB
No Passphrase.
.
Language=RUS
No Passphrase.
.
Language=CZH
No Passphrase.
.
Language=FIN
No Passphrase.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
;//
;//	Rel 1.2.1 - Only used for log-file entries.
;//	it is written when an attempt is made to
;// launch and open in server mode
;//
MessageId=9255
Severity=Error
Facility=Application
SymbolicName=ERR_LOG_OPEN_IN_SERVER_MODE
Language=ENU
An attempt was made to open and launch '%2' in server mode.
.
Language=SVE
An attempt was made to open and launch '%2' in server mode.
.
Language=DEU
An attempt was made to open and launch '%2' in server mode.
.
Language=FRA
An attempt was made to open and launch '%2' in server mode.
.
Language=ESN
An attempt was made to open and launch '%2' in server mode.
.
Language=ITA
An attempt was made to open and launch '%2' in server mode.
.
Language=HUN
An attempt was made to open and launch '%2' in server mode.
.
Language=NOR
An attempt was made to open and launch '%2' in server mode.
.
Language=NLD
An attempt was made to open and launch '%2' in server mode.
.
Language=DNK
An attempt was made to open and launch '%2' in server mode.
.
Language=POL
An attempt was made to open and launch '%2' in server mode.
.
Language=CHI
An attempt was made to open and launch '%2' in server mode.
.
Language=PTG
An attempt was made to open and launch '%2' in server mode.
.
Language=PTB
An attempt was made to open and launch '%2' in server mode.
.
Language=RUS
An attempt was made to open and launch '%2' in server mode.
.
Language=CZH
An attempt was made to open and launch '%2' in server mode.
.
Language=FIN
An attempt was made to open and launch '%2' in server mode.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
;//
;//	Rel 1.2.1 - Only used for log-file entries.
;//	it is written when an attempt is made to
;// prompt for a passphrase in server mode.
;//
MessageId=9260
Severity=Error
Facility=Application
SymbolicName=ERR_KEYPROMPT_SERVER_MODE
Language=ENU
Passphrase was needed in server mode.
.
Language=SVE
Passphrase was needed in server mode.
.
Language=DEU
Passphrase was needed in server mode.
.
Language=FRA
Passphrase was needed in server mode.
.
Language=ESN
Passphrase was needed in server mode.
.
Language=ITA
Passphrase was needed in server mode.
.
Language=HUN
Passphrase was needed in server mode.
.
Language=NOR
Passphrase was needed in server mode.
.
Language=NLD
Passphrase was needed in server mode.
.
Language=DNK
Passphrase was needed in server mode.
.
Language=POL
Passphrase was needed in server mode.
.
Language=CHI
Passphrase was needed in server mode.
.
Language=PTG
Passphrase was needed in server mode.
.
Language=PTB
Passphrase was needed in server mode.
.
Language=RUS
Passphrase was needed in server mode.
.
Language=CZH
Passphrase was needed in server mode.
.
Language=FIN
Passphrase was needed in server mode.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
;//
;//	Rel 1.2.1 - Only used for log-file entries.
;//
MessageId=9265
Severity=Informational
Facility=Application
SymbolicName=INF_SERVER_SHELL
Language=ENU
Executed command '%2' in server mode.
.
Language=SVE
Executed command '%2' in server mode.
.
Language=DEU
Executed command '%2' in server mode.
.
Language=FRA
Executed command '%2' in server mode.
.
Language=ESN
Executed command '%2' in server mode.
.
Language=ITA
Executed command '%2' in server mode.
.
Language=HUN
Executed command '%2' in server mode.
.
Language=NOR
Executed command '%2' in server mode.
.
Language=NLD
Executed command '%2' in server mode.
.
Language=DNK
Executed command '%2' in server mode.
.
Language=POL
Executed command '%2' in server mode.
.
Language=CHI
Executed command '%2' in server mode.
.
Language=PTG
Executed command '%2' in server mode.
.
Language=PTB
Executed command '%2' in server mode.
.
Language=RUS
Executed command '%2' in server mode.
.
Language=CZH
Executed command '%2' in server mode.
.
Language=FIN
Executed command '%2' in server mode.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
;//
;//	Rel 1.2.1 - Only used for log-file entrys.
;//
MessageId=9270
Severity=Error
Facility=Application
SymbolicName=ERR_SERVER_SHELL
Language=ENU
Failed to execute command '%2' due to '%3' in server mode.
.
Language=SVE
Failed to execute command '%2' due to '%3' in server mode.
.
Language=DEU
Failed to execute command '%2' due to '%3' in server mode.
.
Language=FRA
Failed to execute command '%2' due to '%3' in server mode.
.
Language=ESN
Failed to execute command '%2' due to '%3' in server mode.
.
Language=ITA
Failed to execute command '%2' due to '%3' in server mode.
.
Language=HUN
Failed to execute command '%2' due to '%3' in server mode.
.
Language=NOR
Failed to execute command '%2' due to '%3' in server mode.
.
Language=NLD
Failed to execute command '%2' due to '%3' in server mode.
.
Language=DNK
Failed to execute command '%2' due to '%3' in server mode.
.
Language=POL
Failed to execute command '%2' due to '%3' in server mode.
.
Language=CHI
Failed to execute command '%2' due to '%3' in server mode.
.
Language=PTG
Failed to execute command '%2' due to '%3' in server mode.
.
Language=PTB
Failed to execute command '%2' due to '%3' in server mode.
.
Language=RUS
Failed to execute command '%2' due to '%3' in server mode.
.
Language=CZH
Failed to execute command '%2' due to '%3' in server mode.
.
Language=FIN
Failed to execute command '%2' due to '%3' in server mode.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
;//
;// Rel 1.2.2 - Only used for log-file entries
;//
MessageId=9275
Severity=Informational
Facility=Application
SymbolicName=INF_COMPRESS_RATIO
Language=ENU
Approximate compression ratio for %2 is %3.
.
Language=SVE
Approximate compression ratio for %2 is %3.
.
Language=DEU
Approximate compression ratio for %2 is %3.
.
Language=FRA
Approximate compression ratio for %2 is %3.
.
Language=ESN
Approximate compression ratio for %2 is %3.
.
Language=ITA
Approximate compression ratio for %2 is %3.
.
Language=HUN
Approximate compression ratio for %2 is %3.
.
Language=NOR
Approximate compression ratio for %2 is %3.
.
Language=NLD
Approximate compression ratio for %2 is %3.
.
Language=DNK
Approximate compression ratio for %2 is %3.
.
Language=POL
Approximate compression ratio for %2 is %3.
.
Language=CHI
Approximate compression ratio for %2 is %3.
.
Language=PTG
Approximate compression ratio for %2 is %3.
.
Language=PTB
Approximate compression ratio for %2 is %3.
.
Language=RUS
Approximate compression ratio for %2 is %3.
.
Language=CZH
Approximate compression ratio for %2 is %3.
.
Language=FIN
Approximate compression ratio for %2 is %3.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
;//
;// Rel 1.4.2 - Menu choice for brute forceing
;//
MessageId=9280
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_BRUTEFORCE
Language=ENU
Bruteforce
.
Language=SVE
Bruteforce
.
Language=DEU
Bruteforce
.
Language=FRA
Bruteforce
.
Language=ESN
Bruteforce
.
Language=ITA
Bruteforce
.
Language=HUN
Bruteforce
.
Language=NOR
Bruteforce
.
Language=NLD
Bruteforce
.
Language=DNK
Bruteforce
.
Language=POL
Bruteforce
.
Language=CHI
Bruteforce
.
Language=PTG
Bruteforce
.
Language=PTB
Bruteforce
.
Language=RUS
Bruteforce
.
Language=CZH
Bruteforce
.
Language=FIN
Bruteforce
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
;//
;// Rel 1.4.2 - Menu help for brute forceing
;//
MessageId=9285
Severity=Informational
Facility=Application
SymbolicName=HLP_MENU_BRUTEFORCE
Language=ENU
(Re)Start attempted brute force open.
.
Language=SVE
(Re)Start attempted brute force open.
.
Language=DEU
(Re)Start attempted brute force open.
.
Language=FRA
(Re)Start attempted brute force open.
.
Language=ESN
(Re)Start attempted brute force open.
.
Language=ITA
(Re)Start attempted brute force open.
.
Language=HUN
(Re)Start attempted brute force open.
.
Language=NOR
(Re)Start attempted brute force open.
.
Language=NLD
(Re)Start attempted brute force open.
.
Language=DNK
(Re)Start attempted brute force open.
.
Language=POL
(Re)Start attempted brute force open.
.
Language=CHI
(Re)Start attempted brute force open.
.
Language=PTG
(Re)Start attempted brute force open.
.
Language=PTB
(Re)Start attempted brute force open.
.
Language=RUS
(Re)Start attempted brute force open.
.
Language=CZH
(Re)Start attempted brute force open.
.
Language=FIN
(Re)Start attempted brute force open.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
;//
;// Rel 1.4.2 - Menu choice for getting header info in hex to clipboard
;//
MessageId=9290
Severity=Informational
Facility=Application
SymbolicName=INF_MENU_HEXCOPY
Language=ENU
Copy Meta Info
.
Language=SVE
Copy Meta Info
.
Language=DEU
Copy Meta Info
.
Language=FRA
Copy Meta Info
.
Language=ESN
Copy Meta Info
.
Language=ITA
Copy Meta Info
.
Language=HUN
Copy Meta Info
.
Language=NOR
Copy Meta Info
.
Language=NLD
Copy Meta Info
.
Language=DNK
Copy Meta Info
.
Language=POL
Copy Meta Info
.
Language=CHI
Copy Meta Info
.
Language=PTG
Copy Meta Info
.
Language=PTB
Copy Meta Info
.
Language=RUS
Copy Meta Info
.
Language=CZH
Copy Meta Info
.
Language=FIN
Copy Meta Info
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
;//
;// Rel 1.4.2 - Menu help for getting header info in hex to clipboard
;//
MessageId=9295
Severity=Informational
Facility=Application
SymbolicName=HLP_MENU_HEXCOPY
Language=ENU
Copy file meta information to clipboard in hex form. Use only when instructed.
.
Language=SVE
Copy file meta information to clipboard in hex form. Use only when instructed.
.
Language=DEU
Copy file meta information to clipboard in hex form. Use only when instructed.
.
Language=FRA
Copy file meta information to clipboard in hex form. Use only when instructed.
.
Language=ESN
Copy file meta information to clipboard in hex form. Use only when instructed.
.
Language=ITA
Copy file meta information to clipboard in hex form. Use only when instructed.
.
Language=HUN
Copy file meta information to clipboard in hex form. Use only when instructed.
.
Language=NOR
Copy file meta information to clipboard in hex form. Use only when instructed.
.
Language=NLD
Copy file meta information to clipboard in hex form. Use only when instructed.
.
Language=DNK
Copy file meta information to clipboard in hex form. Use only when instructed.
.
Language=POL
Copy file meta information to clipboard in hex form. Use only when instructed.
.
Language=CHI
Copy file meta information to clipboard in hex form. Use only when instructed.
.
Language=PTG
Copy file meta information to clipboard in hex form. Use only when instructed.
.
Language=PTB
Copy file meta information to clipboard in hex form. Use only when instructed.
.
Language=RUS
Copy file meta information to clipboard in hex form. Use only when instructed.
.
Language=CZH
Copy file meta information to clipboard in hex form. Use only when instructed.
.
Language=FIN
Copy file meta information to clipboard in hex form. Use only when instructed.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
;//
;// Rel 1.2.2
;//	Only for used as an exit code! No translation needed.
;//
MessageId=9300
Severity=Warning
Facility=Application
SymbolicName=WRN_NO_HAVE_KEY
Language=ENU
Key not in cache.
.
Language=SVE
Key not in cache.
.
Language=DEU
Key not in cache.
.
Language=FRA
Key not in cache.
.
Language=ESN
Key not in cache.
.
Language=ITA
Key not in cache.
.
Language=HUN
Key not in cache.
.
Language=NOR
Key not in cache.
.
Language=NLD
Key not in cache.
.
Language=DNK
Key not in cache.
.
Language=POL
Key not in cache.
.
Language=CHI
Key not in cache.
.
Language=PTG
Key not in cache.
.
Language=PTB
Key not in cache.
.
Language=RUS
Key not in cache.
.
Language=CZH
Key not in cache.
.
Language=FIN
Key not in cache.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
;//
;// Rel 1.2.2
;//	Only for used as an exit code! No translation needed.
;//
MessageId=9305
Severity=Warning
Facility=Application
SymbolicName=WRN_IGNORED
Language=ENU
Ignored.
.
Language=SVE
Ignored.
.
Language=DEU
Ignored.
.
Language=FRA
Ignored.
.
Language=ESN
Ignored.
.
Language=ITA
Ignored.
.
Language=HUN
Ignored.
.
Language=NOR
Ignored.
.
Language=NLD
Ignored.
.
Language=DNK
Ignored.
.
Language=POL
Ignored.
.
Language=CHI
Ignored.
.
Language=PTG
Ignored.
.
Language=PTB
Ignored.
.
Language=RUS
Ignored.
.
Language=CZH
Ignored.
.
Language=FIN
Ignored.
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
;//
;// Rel 1.3.1
;//
;//	No visible error message, but a return status indicating
;// no tag was found.
;// No translation necessary.
;//
MessageId=9310
Severity=Error
Facility=Application
SymbolicName=ERR_NO_IDTAG
Language=ENU
No IdTag
.
Language=SVE
No IdTag
.
Language=DEU
Kein IdTag
.
Language=FRA
No IdTag
.
Language=ESN
No IdTag
.
Language=ITA
No IdTag
.
Language=HUN
No IdTag
.
Language=NOR
No IdTag
.
Language=NLD
No IdTag
.
Language=DNK
No IdTag
.
Language=POL
No IdTag
.
Language=CHI
No IdTag
.
Language=PTG
No IdTag
.
Language=PTB
No IdTag
.
Language=RUS
No IdTag
.
Language=CZH
No IdTag
.
Language=FIN
No IdTag
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
;//
;// Rel 1.5 - Not an error, just a non-zero return to terminate operations
;// without error when necessary. There is no text associated with this.
;//
MessageId=9315
Severity=Informational
Facility=Application
SymbolicName=INF_NOERROR
Language=ENU
.
Language=SVE
.
Language=DEU
.
Language=FRA
.
Language=ESN
.
Language=ITA
.
Language=HUN
.
Language=NOR
.
Language=NLD
.
Language=DNK
.
Language=POL
.
Language=CHI
.
Language=PTG
.
Language=PTB
.
Language=RUS
.
Language=CZH
.
Language=FIN
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
;//
;// Rel 1.5 - Not an error, just return code to indicate that a folder was
;// deleted at the end of a folder event. There is no text associated.
;//
MessageId=9320
Severity=Informational
Facility=Application
SymbolicName=INF_IT_FOLDER_DEL
Language=ENU
.
Language=SVE
.
Language=DEU
.
Language=FRA
.
Language=ESN
.
Language=ITA
.
Language=HUN
.
Language=NOR
.
Language=NLD
.
Language=DNK
.
Language=POL
.
Language=CHI
.
Language=PTG
.
Language=PTB
.
Language=RUS
.
Language=CZH
.
Language=FIN
.

;// *******************************************
;// *** INTERNAL MESSAGE - DO NOT TRANSLATE ***
;// *******************************************
;//
;// Rel 1.5.4.3 - Generic error message with context in a function
;//
MessageId=9325
Severity=Informational
Facility=Application
SymbolicName=ERR_GENERIC_FUNC
Language=ENU
%4 in %3
.
Language=SVE
%4 in %3
.
Language=DEU
%4 in %3
.
Language=FRA
%4 in %3
.
Language=ESN
%4 in %3
.
Language=ITA
%4 in %3
.
Language=HUN
%4 in %3
.
Language=NOR
%4 in %3
.
Language=NLD
%4 in %3
.
Language=DNK
%4 in %3
.
Language=POL
%4 in %3
.
Language=CHI
%4 in %3
.
Language=PTG
%4 in %3
.
Language=PTB
%4 in %3
.
Language=RUS
%4 in %3
.
Language=CZH
%4 in %3
.
Language=FIN
%4 in %3
.

