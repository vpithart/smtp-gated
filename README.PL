--------------------------------------------------------------------
SMTP-Proxy (alias SMTP-gated)
Strona domowa projektu: http://smtp-proxy.klolik.org
Bartlomiej Korupczynski
bartek {malpa} klolik {kropka} org
(c) Warszawa 2004-2005
--------------------------------------------------------------------


WSTEP / INTRODUCTION
--------------------

Co potrafi lub nie potrafi:
- Skanowanie odbywa sie na bie¿±co; nie ma w zwi±zku z tym opó¼nieñ i
ewentualnych timeout-ów serwera {byæ mo¿e clamsmtpd te¿ tak robi}
- Akceptuje STARTTLS oraz PIPELINING (w przygotowaniu tak¿e akceptacja
chunking RFC3030)
- Umo¿liwia zbudowanie farmy 'skanerów' (wymaga to spatchowanego oidentd,
byæ mo¿e wkrótce wprowadzê jakie¶ prostsze rozwi±zanie), dla jednego b±d¼
kilku routerów. (*)
- Umo¿liwia wstawianie w nag³ówku informacji o ¼ród³owym IP (i ewentualnie
idencie - patrz punkt poprzedni)
- Dzia³a z kilkoma platformami obs³uguj±cymi NAT.
- Ma bardzo fajny podgl±d w to co siê aktualnie dzieje ;)
- Umo¿liwia wprowadzenie ograniczeñ na ilo¶æ sesji: wszystkich, per IP
(ewentualnie per ident - patrz punkt *)
- Odrzucanie po³±czeñ przy wysokim loadavg (z komunikatem)
- Ograniczenie skanowania do przesy³ek mniejszych ni¿ administrator sobie
za¿yczy
- Wspó³praca z clamav oraz mksd (to drugie nie testowane od jakiego¶ czasu)
- Umo¿liwia skanowaniem spamassasinem ka¿dej przesy³ki (rezultaty l±duj± w
syslogu).
- Dla ka¿dego po³±czenia tworzy nowy proces
- (obecnie) Nie obs³uguje akcji w wypadku napotkania wirusa; do klienta
dociera wy³±cznie komunikat o jego napotkaniu. W przygotowaniu jest blokada
czasowa dla takiego osobnika.
- Nie ma zbyt uporz±dkowanego kodu ;]
- Brak szczególnej dokumentacji


Wbrew pozorom nie ma (narazie) supportu dla PostgreSQL.
Obsluga BDAT nie jest obecnie (<=1.4.4) przetestowana i prawdopodobnie nie
dziala.


INSTALACJA / INSTALLATION
-------------------------

Plik wykonywalny instaluje sie domyslnie w /usr/local/sbin.
Do kompilacji potrzebne sa naglowki netfilter-a. Jesli jadro zainstalowane
zostalo z dystrybucji, to zazwyczaj oznacza to koniecznosc instalacji pakietu
iptables-dev badz iptables-devel.


1. Kompilacja

	./configure
	make

   Jesli nie zostanie wykryty ipfw na FreeBSD, mozna sprobowac tak:

	./configure --enable-nat
	make

   Interesujace moga byc takze polskie komunikaty (--with-lang=pl).
   Pelna lista opcji akceptowanych przez skrypt configure:

	./configure --help

   Uwaga! "--enable-chunking" obecnie nie dziala poprawnie, wiec nie
   nalezy jej wlaczac.

   Support dla mksd jest w³±czany, je¶li configure znajdzie plik z nag³ówkami
   libmksd.h (np. w /usr/include). Do pe³ni szczê¶cia potrzebny jest tak¿e 
   libmksd.a dostêpny w katalogu z bibliotekami (np. /usr/lib/).

2. Instalacja (domyslnie w /usr/local/sbin)

	make install

   W katalogu lib/ znajduja sie skrypty startowe dla debiana i redhata,
   ktore nalezy umiescic w /etc/rc.d/init.d/

   Jesli uaktualniasz starsza wersje, koniecznie zajrzyj do punktu
   "KONFIGURACJA - ZMIANY".


KONFIGURACJA - ZMIANY / CONFIGURATION - CHANGES
-----------------------------------------------

Podczas aktualizacji wersji, nalezy uwzglednic zmiany wprowadzone w formacie
pliku konfiguracyjnego:

1.4.14-rc1
	Zmiana opcji konfiguracyjnych:
	- use_netfilter => mode
	- lookup_port => remote_port
	- max_per_*_lock => lock_on
	- leave_on_* => spool_leave_on
	- spam_block (usunieta)
	- clamd_path => antivirus_path
	- spamd_path => antispam_path
	- antivirus_type, antispam_type (nowe)

1.4.12-rc10
	Zmiany wielu opcji konfiguracyjnych

1.4.12-rc5
	Zmiana nazwy opcji nat_header na nat_header_type. Jesli nie
	uaktualnisz pliku konfiguracyjnego, naglowek nie bedzie
	wstawiany.


KONFIGURACJA / CONFIGURATION
----------------------------

1. Wszystkie opcje konfiguracyjne opisane sa w pliku src/options.h
   (wystarczy znalezc tekst "smtp-proxy.isp").

2. Uzywane ustawienia mozna zweryfikowac poprzez:

	smtp-gated -t /etc/smtp-gated.conf
	smtp-gated -T /etc/smtp-gated.conf (*)

   Powinna sie wyswietlic rzeczywista konfiguracja uzywane przez program.
   Jesli nie pokaze sie nic, nalezy poszukac bledow w logach systemowych.
   (*) drugie wywolanie pokazuje dodatkowo uzywane teksty komunikatow.
   Komunikaty takze mozna dostosowac do wlasnych potrzeb.

3. Utworzenie katalogow potrzebnych do pracy

   Skaner musi miec dostep do plikow "spool_path" (domyslnie jest to
   /var/spool/smtp-gated/msg). Ja preferuje takie rozwiazanie:

	mkdir -p /var/spool/smtp-gated/{msg,lock}
	chown -R smtpgw:smtpgw /var/spool/smtp-gated
	chmod 750 /var/spool/smtp-gated

   A nastepnie dodanie np. ClamAV do grupy smtpgw.
   Powyzszy chown mozna tez zamienic na:

	chown -R smtpgw:clamav /var/spool/smtp-gated

4. Plik konfiguracyjny do edycji mozna przygotowac przez:

	smtp-gated -t >nowy_plik

   Wartosci domyslne (lub nie uzywane) nalezy zakomentowac, aby nie
   przeszkadzaly przy upgrade-ach. Zostawiamy tylko to co jest inne
   niz domyslne. Linie zaczynajace sie od znakow '#' oraz ';' sa ignorowane.
   Ignorowane sa takze spacje i tabulatory na poczatku i koncu linii, oraz
   po nazwie opcji. Wszystkie inne znaki sa traktowane jako czesc parametru
   (takze cudzyslowy).

   Nalezy ustawic podstawowe opcje (podane wartosci sa przykladowe):

	proxy_name	smtp-proxy.isp
	mode		nat
	bind_address	127.0.0.1
	antivirus_type	clamd
	antispam_type	spamassassin
	set_user	smtpgw
	nat_header_type	full

   Dla maszyn wieloprocesorowych, mozna podwyzszyc wartosci nastepujacych
   opcji:

	max_load	4
	spam_max_load	2

5a. Przekierowanie iptables (Linux).

	iptables -t nat -A PREROUTING -p tcp --dport 25
		-j DNAT --to ip_proxy:port_proxy

   Najlepiej jednak przekierowac wylacznie polaczenia z interfejsu
   wewnetrznego i sieci wewnetrznej, np.:

	iptables -t nat -A PREROUTING -p tcp --dport 25
		-i eth1 -s 192.168.1.0/24 -j DNAT --to ip_proxy:port_proxy

	Oczywi¶cie powyzsza wersja jest najprostsza z mozliwych.
	Nalezy ja dostosowac do wlasnej konfiguracji.

5b. Przekierowanie ipfw (FreeBSD):

	ipfw add 10 fwd ip_proxy,port_proxy
		from 192.168.1.0/24 to any 25 via fxp0

5c. Przekierowanie ipfilter (FreeBSD/NetBSD). W pliku /etc/ipnat.conf:

	rdr fxp0 0/0 port 25 -> 127.0.0.1 port 9199

6. Status demona mozemy uzyskac poprzez:

	/etc/rc.d/init.d/smtp-gated status

7. Do testowania mozesz uzyc sygnatury testowej Eicar dostepnej pod adresem
   http://www.eicar.com/anti_virus_test_file.htm


UWAGA!
   Jesli dzieje sie cos nie halo i nie wiadomo o co chodzi - w pierwszej
   kolejnosci sprawdz logi systemowe.

   Poziom logowania okreslony przez log_level dotyczy *wszystkich* wpisow,
   a co za tym idzie ustawiony zbyt nisko moze wyciac np. wpisy dotyczace
   adresow e-mail.

   Sprobuj tez wywolac smtp-gated -t /etc/plik_konfiguracyjny i przejrzyj
   wyniki.


WSPARCIE DLA MKSD / MKSD SCANNER SUPPORT
----------------------------------------

Aby u¿ywaæ mksd nale¿y najpierw skompilowaæ bibliotekê libmksd (jest w pakiecie
dystrybucyjnym mksd w archiwum src.tgz, nale¿y go rozpakowaæ i w katalogu inne/
wykonaæ make). Dwa pliki, tj. libmksd.h oraz libmksd.a nale¿y przekopiowaæ do
katalogu src/ ¼róde³ smtp-gated. Nastêpnie nale¿y wywo³aæ:

	./configure --enable-mksd

(ewentualnie z dodatkowymi parametrami). Po poprawnym skompilowaniu, wsparcie
dla mksd mo¿na sprawdziæ w dyrektywach wy¶wietlanych przez:

	smtp-gated -V


BEZPIECZENSTWO / SECURITY
-------------------------

1. Nigdy, przenigdy, nie uruchamiaj proxy z prawami roota w srodowisku
   produkcyjnym. Jesli probujesz to robic, to znaczy, ze powinienes najpierw
   poczytac jakas chocby najmarniejsza ksiazeczke o administracji Unixami.

2. Nalezy wziac pod uwage fakt, iz nie zabezpieczony smtp-gated (czyli w
   domyslnej konfiguracji) bedzie open-relay-em (czyli de facto pomaga
   spamerom i wirusom). Rozwiazaniem tego problemu moga byc:

   a) Zabezpieczenie portu na ktorym slucha smtp-gated przy pomocy iptables

	iptables -I INPUT -p tcp --dport 9199 ! -s 192.168.1.0/24 -j DROP

      badz

	iptables -I INPUT -p tcp --dport 9199 -i eth0 -j DROP

      gdzie:
         192.168.1.0: siec wewnetrzna
         eth0: interfejs zewnetrzny (do Internetu)

   b) Ustawienie bind_address na 127.0.0.1 lub na adres interfejsu sieci
      wewnetrznej.

3. Na wiekszosci systemow porty od 1024 w zwyz, moga byc uzywane przez dowolnego
   uzytkownika. Nie nalezy wiec ich uzywac na serwerze z publicznym dostepem do
   shella. Nalezy wtedy zmienic "port" na dowolny nieuzywany, ponizej 1024.
 
4. Wszystkie wiadomosci sa przechowywane w plikach tymczasowych. Nalezy
   ograniczyc do nich dostep dla innych uzytkownikow. Dostep musi byc jednak
   zapewniony dla ClamAV i ewentualnie SpamAssassina. Najlatwiej to uzyskac
   ustawiajac odpowiednie grupy dla procesow.


INNE / MISCELANEOUS
-------------------

Uzywasz tego oprogramowania na wlasne ryzyko. Autor nie ponosi
odpowiedzialnosci za jakiekolwiek straty badz szkody spowodowane jego
uzyciem, ani odpowiedzialnosci z jakichkolwiek innych przyczyn.

Jesli uzywasz programu powyzej miesiaca, chetnie sie dowiem o jego
stabilnosci. Tym chetniej im bedzie ona nizsza ;) Wszelkie tego typu
informacje prosze na maila, wraz z gzip-owanym logiem.

Adres: smtp-proxy {ma³pa} klolik {kropka} org


PODZIEKOWANIA / THANKS TO
-------------------------

Dla Grzegorza Janoszki za zgloszenie kilku niedorobek.


: vim: set textwidth=80 tabstop=4 shiftwidth=4 :

