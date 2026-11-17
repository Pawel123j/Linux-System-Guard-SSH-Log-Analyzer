# System Guard — SSH Log Analyzer

Lokalna aplikacja do analizy logów SSH. Rozpoznaje udane i nieudane logowania, nieistniejące konta, adresy IP wysokiego ryzyka oraz przerwane połączenia.

## Uruchomienie panelu

~~~bash
pnpm dev
~~~

Następnie otwórz adres wyświetlony w terminalu. Możesz zaimportować plik auth.log, secure albo plik tekstowy z wpisami sshd.

## Co zapisuje aplikacja

Historia analiz, lokalna lista blokad oraz progi ryzyka są przechowywane wyłącznie w pamięci przeglądarki danego urządzenia. Pełne logi nie są tam zapisywane.

Adres webhooka Slack jest trzymany wyłącznie w aktywnej sesji przeglądarki. Po wyraźnym zaznaczeniu opcji automatycznej może wysyłać alerty wysokiego ryzyka. Funkcja e-mail tworzy gotową wiadomość w domyślnym kliencie pocztowym; nie wymaga ani nie przechowuje danych SMTP.

## Monitor logów na żywo

Dołączony agent nasłuchuje wskazanego pliku i udostępnia nowe linie wyłącznie przez adres 127.0.0.1.

~~~bash
pnpm monitor -- --file /var/log/auth.log
~~~

W panelu wybierz „Uruchom odczyt”. Domyślny adres to http://127.0.0.1:8789/events.

Do lokalnego testu możesz użyć przykładowego pliku:

~~~bash
pnpm monitor -- --file fixtures/ssh-auth.log --from-start
~~~

Agent nie zmienia pliku logu, nie wykonuje poleceń zapory i nie otwiera portu w sieci — nasłuchuje wyłącznie na lokalnym adresie loopback.

## Fail2ban

Dodaj zweryfikowane adresy IP do lokalnej listy blokad, a następnie pobierz skrypt z poleceniami fail2ban-client set sshd banip. Przed uruchomieniem sprawdź wygenerowaną listę i upewnij się, że nazwa jaila sshd pasuje do konfiguracji serwera.
