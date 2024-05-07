lazy_static::lazy_static! {
pub static ref T: std::collections::HashMap<&'static str, &'static str> =
    [
        ("Status", "Stanje"),
        ("Your Desktop", "Vaše namizje"),
        ("desk_tip", "Do vašega namizja lahko dostopate s spodnjim IDjem in geslom"),
        ("Password", "Geslo"),
        ("Ready", "Pripravljen"),
        ("Established", "Povezava vzpostavljena"),
        ("connecting_status", "Vzpostavljanje povezave z omrežjem RustDesk..."),
        ("Enable service", "Omogoči storitev"),
        ("Start service", "Zaženi storitev"),
        ("Service is running", "Storitev se izvaja"),
        ("Service is not running", "Storitev se ne izvaja"),
        ("not_ready_status", "Ni pripravljeno, preverite vašo mrežno povezavo"),
        ("Control Remote Desktop", "Nadzoruj oddaljeno namizje"),
        ("Transfer file", "Prenos datotek"),
        ("Connect", "Poveži"),
        ("Recent sessions", "Nedavne seje"),
        ("Address book", "Adresar"),
        ("Confirmation", "Potrditev"),
        ("TCP tunneling", "TCP tuneliranje"),
        ("Remove", "Odstrani"),
        ("Refresh random password", "Osveži naključno geslo"),
        ("Set your own password", "Nastavi lastno geslo"),
        ("Enable keyboard/mouse", "Omogoči tipkovnico in miško"),
        ("Enable clipboard", "Omogoči odložišče"),
        ("Enable file transfer", "Omogoči prenos datotek"),
        ("Enable TCP tunneling", "Omogoči TCP tuneliranje"),
        ("IP Whitelisting", "Omogoči seznam dovoljenih IPjev"),
        ("ID/Relay Server", "Strežnik za ID/posredovanje"),
        ("Import server config", "Uvozi nastavitve strežnika"),
        ("Export Server Config", "Izvozi nastavitve strežnika"),
        ("Import server configuration successfully", "Nastavitve strežnika uspešno uvožene"),
        ("Export server configuration successfully", "Nastavitve strežnika uspešno izvožene"),
        ("Invalid server configuration", "Neveljavne nastavitve strežnika"),
        ("Clipboard is empty", "Odložišče je prazno"),
        ("Stop service", "Ustavi storitev"),
        ("Change ID", "Spremeni ID"),
        ("Your new ID", ""),
        ("length %min% to %max%", ""),
        ("starts with a letter", ""),
        ("allowed characters", ""),
        ("id_change_tip", "Dovoljeni znaki so a-z, A-Z (brez šumnikov), 0-9 in _. Prvi znak mora biti črka, dolžina od 6 do 16 znakov."),
        ("Website", "Spletna stran"),
        ("About", "O programu"),
        ("Slogan_tip", ""),
        ("Privacy Statement", ""),
        ("Mute", "Izklopi zvok"),
        ("Build Date", ""),
        ("Version", ""),
        ("Home", ""),
        ("Audio Input", "Avdio vhod"),
        ("Enhancements", "Izboljšave"),
        ("Hardware Codec", "Strojni kodek"),
        ("Adaptive bitrate", "Prilagodljiva bitna hitrost"),
        ("ID Server", "ID strežnik"),
        ("Relay Server", "Posredniški strežnik"),
        ("API Server", "API strežnik"),
        ("invalid_http", "mora se začeti s http:// ali https://"),
        ("Invalid IP", "Neveljaven IP"),
        ("Invalid format", "Neveljavna oblika"),
        ("server_not_support", "Strežnik še ne podpira"),
        ("Not available", "Ni na voljo"),
        ("Too frequent", "Prepogosto"),
        ("Cancel", "Prekliči"),
        ("Skip", "Izpusti"),
        ("Close", "Zapri"),
        ("Retry", "Ponovi"),
        ("OK", "V redu"),
        ("Password Required", "Potrebno je geslo"),
        ("Please enter your password", "Vnesite vaše geslo"),
        ("Remember password", "Zapomni si geslo"),
        ("Wrong Password", "Napačno geslo"),
        ("Do you want to enter again?", "Želite znova vnesti?"),
        ("Connection Error", "Napaka pri povezavi"),
        ("Error", "Napaka"),
        ("Reset by the peer", "Povezava prekinjena"),
        ("Connecting...", "Povezovanje..."),
        ("Connection in progress. Please wait.", "Vzpostavljanje povezave, prosim počakajte."),
        ("Please try 1 minute later", "Poizkusite čez 1 minuto"),
        ("Login Error", "Napaka pri prijavi"),
        ("Successful", "Uspešno"),
        ("Connected, waiting for image...", "Povezava vzpostavljena, čakam na sliko..."),
        ("Name", "Ime"),
        ("Type", "Vrsta"),
        ("Modified", "Čas spremembe"),
        ("Size", "Velikost"),
        ("Show Hidden Files", "Prikaži skrite datoteke"),
        ("Receive", "Prejmi"),
        ("Send", "Pošlji"),
        ("Refresh File", "Osveži datoteko"),
        ("Local", "Lokalno"),
        ("Remote", "Oddaljeno"),
        ("Remote Computer", "Oddaljeni računalnik"),
        ("Local Computer", "Lokalni računalnik"),
        ("Confirm Delete", "Potrdi izbris"),
        ("Delete", "Izbriši"),
        ("Properties", "Lastnosti"),
        ("Multi Select", "Večkratna izbira"),
        ("Select All", "Izberi vse"),
        ("Unselect All", "Počisti vse"),
        ("Empty Directory", "Prazen imenik"),
        ("Not an empty directory", "Imenik ni prazen"),
        ("Are you sure you want to delete this file?", "Ali res želite izbrisati to datoteko?"),
        ("Are you sure you want to delete this empty directory?", "Ali res želite izbrisati to prazno mapo?"),
        ("Are you sure you want to delete the file of this directory?", "Ali res želite datoteko iz mape?"),
        ("Do this for all conflicts", "Naredi to za vse"),
        ("This is irreversible!", "Tega dejanja ni mogoče razveljaviti!"),
        ("Deleting", "Brisanje"),
        ("files", "datoteke"),
        ("Waiting", "Čakanje"),
        ("Finished", "Opravljeno"),
        ("Speed", "Hitrost"),
        ("Custom Image Quality", "Kakovost slike po meri"),
        ("Privacy mode", "Zasebni način"),
        ("Block user input", "Onemogoči uporabnikov vnos"),
        ("Unblock user input", "Omogoči uporabnikov vnos"),
        ("Adjust Window", "Prilagodi okno"),
        ("Original", "Originalno"),
        ("Shrink", "Skrči"),
        ("Stretch", "Raztegni"),
        ("Scrollbar", "Drsenje z drsniki"),
        ("ScrollAuto", "Samodejno drsenje"),
        ("Good image quality", "Visoka kakovost slike"),
        ("Balanced", "Uravnoteženo"),
        ("Optimize reaction time", "Optimiraj odzivni čas"),
        ("Custom", "Po meri"),
        ("Show remote cursor", "Prikaži oddaljeni kazalec miške"),
        ("Show quality monitor", "Prikaži nadzornik kakovosti"),
        ("Disable clipboard", "Onemogoči odložišče"),
        ("Lock after session end", "Zakleni ob koncu seje"),
        ("Insert", "Vstavi"),
        ("Insert Lock", "Zakleni oddaljeni računalnik"),
        ("Refresh", "Osveži"),
        ("ID does not exist", "ID ne obstaja"),
        ("Failed to connect to rendezvous server", "Ni se bilo mogoče povezati na povezovalni strežnik"),
        ("Please try later", "Poizkusite znova kasneje"),
        ("Remote desktop is offline", "Oddaljeno namizje ni dosegljivo"),
        ("Key mismatch", "Ključ ni ustrezen"),
        ("Timeout", "Časovna omejitev"),
        ("Failed to connect to relay server", "Ni se bilo mogoče povezati na posredniški strežnik"),
        ("Failed to connect via rendezvous server", "Ni se bilo mogoče povezati preko povezovalnega strežnika"),
        ("Failed to connect via relay server", "Ni se bilo mogoče povezati preko posredniškega strežnika"),
        ("Failed to make direct connection to remote desktop", "Ni bilo mogoče vzpostaviti neposredne povezave z oddaljenim namizjem"),
        ("Set Password", "Nastavi geslo"),
        ("OS Password", "Geslo operacijskega sistema"),
        ("install_tip", "Zaradi nadzora uporabniškega računa, RustDesk v nekaterih primerih na oddaljeni strani ne deluje pravilno. Temu se lahko izognete z namestitvijo."),
        ("Click to upgrade", "Klikni za nadgradnjo"),
        ("Click to download", "Klikni za prenos"),
        ("Click to update", "Klikni za posodobitev"),
        ("Configure", "Nastavi"),
        ("config_acc", "Za oddaljeni nadzor namizja morate RustDesku dodeliti pravico za dostopnost"),
        ("config_screen", "Za oddaljeni dostop do namizja morate RustDesku dodeliti pravico snemanje zaslona"),
        ("Installing ...", "Nameščanje..."),
        ("Install", "Namesti"),
        ("Installation", "Namestitev"),
        ("Installation Path", "Pot za namestitev"),
        ("Create start menu shortcuts", "Ustvari bližnjice v meniju Začetek"),
        ("Create desktop icon", "Ustvari ikono na namizju"),
        ("agreement_tip", "Z namestitvijo se strinjate z licenčno pogodbo"),
        ("Accept and Install", "Sprejmi in namesti"),
        ("End-user license agreement", "Licenčna pogodba za končnega uporabnika"),
        ("Generating ...", "Ustvarjanje ..."),
        ("Your installation is lower version.", "Vaša namestitev je starejša"),
        ("not_close_tcp_tip", "Med uporabo tunela ne zaprite tega okna"),
        ("Listening ...", "Poslušam ..."),
        ("Remote Host", "Oddaljeni gostitelj"),
        ("Remote Port", "Oddaljena vrata"),
        ("Action", "Dejanje"),
        ("Add", "Dodaj"),
        ("Local Port", "Lokalna vrata"),
        ("Local Address", "Lokalni naslov"),
        ("Change Local Port", "Spremeni lokalna vrata"),
        ("setup_server_tip", "Za hitrejšo povezavo uporabite lasten strežnik"),
        ("Too short, at least 6 characters.", "Prekratek, mora biti najmanj 6 znakov."),
        ("The confirmation is not identical.", "Potrditev ni enaka."),
        ("Permissions", "Dovoljenja"),
        ("Accept", "Sprejmi"),
        ("Dismiss", "Opusti"),
        ("Disconnect", "Prekini povezavo"),
        ("Enable file copy and paste", "Dovoli kopiranje in lepljenje datotek"),
        ("Connected", "Povezan"),
        ("Direct and encrypted connection", "Neposredna šifrirana povezava"),
        ("Relayed and encrypted connection", "Posredovana šifrirana povezava"),
        ("Direct and unencrypted connection", "Neposredna nešifrirana povezava"),
        ("Relayed and unencrypted connection", "Posredovana šifrirana povezava"),
        ("Enter Remote ID", "Vnesi oddaljeni ID"),
        ("Enter your password", "Vnesi geslo"),
        ("Logging in...", "Prijavljanje..."),
        ("Enable RDP session sharing", "Omogoči deljenje RDP seje"),
        ("Auto Login", "Samodejna prijava"),
        ("Enable direct IP access", "Omogoči neposredni dostop preko IP"),
        ("Rename", "Preimenuj"),
        ("Space", "Prazno"),
        ("Create desktop shortcut", "Ustvari bližnjico na namizju"),
        ("Change Path", "Spremeni pot"),
        ("Create Folder", "Ustvari mapo"),
        ("Please enter the folder name", "Vnesite ime mape"),
        ("Fix it", "Popravi"),
        ("Warning", "Opozorilo"),
        ("Login screen using Wayland is not supported", "Prijava z Waylandom ni podprta"),
        ("Reboot required", "Potreben je ponovni zagon"),
        ("Unsupported display server", "Nepodprt zaslonski strežnik"),
        ("x11 expected", "Pričakovan X11"),
        ("Port", "Vrata"),
        ("Settings", "Nastavitve"),
        ("Username", "Uporabniško ime"),
        ("Invalid port", "Neveljavno geslo"),
        ("Closed manually by the peer", "Povezavo ročno prekinil odjemalec"),
        ("Enable remote configuration modification", "Omogoči oddaljeno spreminjanje nastavitev"),
        ("Run without install", "Zaženi brez namestitve"),
        ("Connect via relay", ""),
        ("Always connect via relay", "Vedno poveži preko posrednika"),
        ("whitelist_tip", "Dostop je možen samo iz dovoljenih IPjev"),
        ("Login", "Prijavi"),
        ("Verify", ""),
        ("Remember me", ""),
        ("Trust this device", ""),
        ("Verification code", ""),
        ("verification_tip", ""),
        ("Logout", "Odjavi"),
        ("Tags", "Oznake"),
        ("Search ID", "Išči ID"),
        ("whitelist_sep", "Naslovi ločeni z vejico, podpičjem, presledkom ali novo vrstico"),
        ("Add ID", "Dodaj ID"),
        ("Add Tag", "Dodaj oznako"),
        ("Unselect all tags", ""),
        ("Network error", "Omrežna napaka"),
        ("Username missed", "Up. ime izpuščeno"),
        ("Password missed", "Geslo izpuščeno"),
        ("Wrong credentials", "Napačne poverilnice"),
        ("The verification code is incorrect or has expired", ""),
        ("Edit Tag", "Uredi oznako"),
        ("Forget Password", "Pozabi geslo"),
        ("Favorites", "Priljubljene"),
        ("Add to Favorites", "Dodaj med priljubljene"),
        ("Remove from Favorites", "Odstrani iz priljubljenih"),
        ("Empty", "Prazno"),
        ("Invalid folder name", "Napačno ime mape"),
        ("Socks5 Proxy", "Socks5 posredniški strežnik"),
        ("Socks5/Http(s) Proxy", "Socks5/Http(s) posredniški strežnik"),
        ("Discovered", "Odkriti"),
        ("install_daemon_tip", "Za samodejni zagon ob vklopu računalnika je potrebno dodati sistemsko storitev"),
        ("Remote ID", "Oddaljeni ID"),
        ("Paste", "Prilepi"),
        ("Paste here?", "Prilepi tu?"),
        ("Are you sure to close the connection?", "Ali želite prekiniti povezavo?"),
        ("Download new version", "Prenesi novo različico"),
        ("Touch mode", "Način dotika"),
        ("Mouse mode", "Način mišle"),
        ("One-Finger Tap", "Tap z enim prstom"),
        ("Left Mouse", "Leva tipka miške"),
        ("One-Long Tap", "Dolg tap z enim prstom"),
        ("Two-Finger Tap", "Tap z dvema prstoma"),
        ("Right Mouse", "Desna tipka miške"),
        ("One-Finger Move", "Premik z enim prstom"),
        ("Double Tap & Move", "Dvojni tap in premik"),
        ("Mouse Drag", "Vlečenje z miško"),
        ("Three-Finger vertically", "Triprstno navpično"),
        ("Mouse Wheel", "Miškino kolesce"),
        ("Two-Finger Move", "Premik z dvema prstoma"),
        ("Canvas Move", "Premik platna"),
        ("Pinch to Zoom", "Povečava s približevanjem prstov"),
        ("Canvas Zoom", "Povečava platna"),
        ("Reset canvas", "Ponastavi platno"),
        ("No permission of file transfer", "Ni pravic za prenos datotek"),
        ("Note", "Opomba"),
        ("Connection", "Povezava"),
        ("Share Screen", "Deli zaslon"),
        ("Chat", "Pogovor"),
        ("Total", "Skupaj"),
        ("items", "elementi"),
        ("Selected", "Izbrano"),
        ("Screen Capture", "Zajem zaslona"),
        ("Input Control", "Nadzor vnosa"),
        ("Audio Capture", "Zajem zvoka"),
        ("File Connection", "Datotečna povezava"),
        ("Screen Connection", "Zaslonska povezava"),
        ("Do you accept?", "Ali sprejmete?"),
        ("Open System Setting", "Odpri sistemske nastavitve"),
        ("How to get Android input permission?", "Kako pridobiti dovoljenje za vnos na Androidu?"),
        ("android_input_permission_tip1", "Za oddaljeni nadzor vaše naprave Android, je potrebno RustDesku dodeliti pravico za dostopnost."),
        ("android_input_permission_tip2", "Pojdite v sistemske nastavitve, poiščite »Nameščene storitve« in vklopite storitev »RustDesk Input«."),
        ("android_new_connection_tip", "Prejeta je bila zahteva za oddaljeni nadzor vaše naprave."),
        ("android_service_will_start_tip", "Z vklopom zajema zaslona se bo samodejno zagnala storitev, ki omogoča da oddaljene naprave pošljejo zahtevo za povezavo na vašo napravo."),
        ("android_stop_service_tip", "Z zaustavitvijo storitve bodo samodejno prekinjene vse oddaljene povezave."),
        ("android_version_audio_tip", "Trenutna različica Androida ne omogoča zajema zvoka. Za zajem zvoka nadgradite na Android 10 ali novejši."),
        ("android_start_service_tip", ""),
        ("android_permission_may_not_change_tip", ""),
        ("Account", "Račun"),
        ("Overwrite", "Prepiši"),
        ("This file exists, skip or overwrite this file?", "Datoteka obstaja, izpusti ali prepiši?"),
        ("Quit", "Izhod"),
        ("Help", "Pomoč"),
        ("Failed", "Ni uspelo"),
        ("Succeeded", "Uspelo"),
        ("Someone turns on privacy mode, exit", "Vklopljen je zasebni način, izhod"),
        ("Unsupported", "Ni podprto"),
        ("Peer denied", "Odjemalec zavrnil"),
        ("Please install plugins", "Namestite vključke"),
        ("Peer exit", "Odjemalec se je zaprl"),
        ("Failed to turn off", "Ni bilo mogoče izklopiti"),
        ("Turned off", "Izklopljeno"),
        ("Language", "Jezik"),
        ("Keep RustDesk background service", "Ohrani RustDeskovo storitev v ozadju"),
        ("Ignore Battery Optimizations", "Prezri optimizacije baterije"),
        ("android_open_battery_optimizations_tip", "Če želite izklopiti to možnost, pojdite v nastavitve aplikacije RustDesk, poiščite »Baterija« in izklopite »Neomejeno«"),
        ("Start on boot", ""),
        ("Start the screen sharing service on boot, requires special permissions", ""),
        ("Connection not allowed", "Povezava ni dovoljena"),
        ("Legacy mode", "Stari način"),
        ("Map mode", "Način preslikave"),
        ("Translate mode", "Način prevajanja"),
        ("Use permanent password", "Uporabi stalno geslo"),
        ("Use both passwords", "Uporabi obe gesli"),
        ("Set permanent password", "Nastavi stalno geslo"),
        ("Enable remote restart", "Omogoči oddaljeni ponovni zagon"),
        ("Restart remote device", "Znova zaženi oddaljeno napravo"),
        ("Are you sure you want to restart", "Ali ste prepričani, da želite znova zagnati"),
        ("Restarting remote device", "Ponovni zagon oddaljene naprave"),
        ("remote_restarting_tip", "Oddaljena naprava se znova zaganja, prosim zaprite to sporočilo in se čez nekaj časa povežite s stalnim geslom."),
        ("Copied", "Kopirano"),
        ("Exit Fullscreen", "Izhod iz celozaslonskega načina"),
        ("Fullscreen", "Celozaslonski način"),
        ("Mobile Actions", "Dejanja za prenosne naprave"),
        ("Select Monitor", "Izberite zaslon"),
        ("Control Actions", "Dejanja za nadzor"),
        ("Display Settings", "Nastavitve zaslona"),
        ("Ratio", "Razmerje"),
        ("Image Quality", "Kakovost slike"),
        ("Scroll Style", "Način drsenja"),
        ("Show Toolbar", ""),
        ("Hide Toolbar", ""),
        ("Direct Connection", "Neposredna povezava"),
        ("Relay Connection", "Posredovana povezava"),
        ("Secure Connection", "Zavarovana povezava"),
        ("Insecure Connection", "Nezavarovana povezava"),
        ("Scale original", "Originalna velikost"),
        ("Scale adaptive", "Prilagojena velikost"),
        ("General", "Splošno"),
        ("Security", "Varnost"),
        ("Theme", "Tema"),
        ("Dark Theme", "Temna tema"),
        ("Light Theme", ""),
        ("Dark", "Temna"),
        ("Light", "Svetla"),
        ("Follow System", "Sistemska"),
        ("Enable hardware codec", "Omogoči strojno pospeševanje"),
        ("Unlock Security Settings", "Odkleni varnostne nastavitve"),
        ("Enable audio", "Omogoči zvok"),
        ("Unlock Network Settings", "Odkleni mrežne nastavitve"),
        ("Server", "Strežnik"),
        ("Direct IP Access", "Neposredni dostop preko IPja"),
        ("Proxy", "Posredniški strežnik"),
        ("Apply", "Uveljavi"),
        ("Disconnect all devices?", "Odklopi vse naprave?"),
        ("Clear", "Počisti"),
        ("Audio Input Device", "Vhodna naprava za zvok"),
        ("Use IP Whitelisting", "Omogoči seznam dovoljenih IP naslovov"),
        ("Network", "Mreža"),
        ("Pin Toolbar", ""),
        ("Unpin Toolbar", ""),
        ("Recording", "Snemanje"),
        ("Directory", "Imenik"),
        ("Automatically record incoming sessions", "Samodejno snemaj vhodne seje"),
        ("Change", "Spremeni"),
        ("Start session recording", "Začni snemanje seje"),
        ("Stop session recording", "Ustavi snemanje seje"),
        ("Enable recording session", "Omogoči snemanje seje"),
        ("Enable LAN discovery", "Omogoči odkrivanje lokalnega omrežja"),
        ("Deny LAN discovery", "Onemogoči odkrivanje lokalnega omrežja"),
        ("Write a message", "Napiši spoorčilo"),
        ("Prompt", "Poziv"),
        ("Please wait for confirmation of UAC...", "Počakajte za potrditev nadzora uporabniškega računa"),
        ("elevated_foreground_window_tip", "Trenutno aktivno okno na oddaljenem računalniku zahteva višje pravice za upravljanje. Oddaljenega uporabnika lahko prosite, da okno minimizira, ali pa kliknite gumb za povzdig pravic v oknu za upravljanje povezave. Če se želite izogniti temu problemu, na oddaljenem računalniku RustDesk namestite."),
        ("Disconnected", "Brez povezave"),
        ("Other", "Drugo"),
        ("Confirm before closing multiple tabs", "Zahtevajte potrditev pred zapiranjem večih zavihkov"),
        ("Keyboard Settings", "Nastavitve tipkovnice"),
        ("Full Access", "Poln dostop"),
        ("Screen Share", "Deljenje zaslona"),
        ("Wayland requires Ubuntu 21.04 or higher version.", "Wayland zahteva Ubuntu 21.04 ali novejši"),
        ("Wayland requires higher version of linux distro. Please try X11 desktop or change your OS.", "Zahtevana je novejša različica Waylanda. Posodobite vašo distribucijo ali pa uporabite X11."),
        ("JumpLink", "Pogled"),
        ("Please Select the screen to be shared(Operate on the peer side).", "Izberite zaslon za delitev (na oddaljeni strani)."),
        ("Show RustDesk", "Prikaži RustDesk"),
        ("This PC", "Ta računalnik"),
        ("or", "ali"),
        ("Continue with", "Nadaljuj z"),
        ("Elevate", "Povzdig pravic"),
        ("Zoom cursor", "Prilagodi velikost miškinega kazalca"),
        ("Accept sessions via password", "Sprejmi seje z geslom"),
        ("Accept sessions via click", "Sprejmi seje s potrditvijo"),
        ("Accept sessions via both", "Sprejmi seje z geslom ali potrditvijo"),
        ("Please wait for the remote side to accept your session request...", "Počakajte, da oddaljeni računalnik sprejme povezavo..."),
        ("One-time Password", "Enkratno geslo"),
        ("Use one-time password", "Uporabi enkratno geslo"),
        ("One-time password length", "Dolžina enkratnega gesla"),
        ("Request access to your device", "Zahtevaj dostop do svoje naprave"),
        ("Hide connection management window", "Skrij okno za upravljanje povezave"),
        ("hide_cm_tip", "Dovoli skrivanje samo pri sprejemanju sej z geslom"),
        ("wayland_experiment_tip", "Podpora za Wayland je v preizkusni fazi. Uporabite X11, če rabite nespremljan dostop."),
        ("Right click to select tabs", "Desno-kliknite za izbiro zavihkov"),
        ("Skipped", "Izpuščeno"),
        ("Add to address book", "Dodaj v adresar"),
        ("Group", "Skupina"),
        ("Search", "Iskanje"),
        ("Closed manually by web console", "Ročno zaprto iz spletne konzole"),
        ("Local keyboard type", "Lokalna vrsta tipkovnice"),
        ("Select local keyboard type", "Izberite lokalno vrsto tipkovnice"),
        ("software_render_tip", ""),
        ("Always use software rendering", ""),
        ("config_input", ""),
        ("config_microphone", ""),
        ("request_elevation_tip", ""),
        ("Wait", ""),
        ("Elevation Error", ""),
        ("Ask the remote user for authentication", ""),
        ("Choose this if the remote account is administrator", ""),
        ("Transmit the username and password of administrator", ""),
        ("still_click_uac_tip", ""),
        ("Request Elevation", ""),
        ("wait_accept_uac_tip", ""),
        ("Elevate successfully", ""),
        ("uppercase", ""),
        ("lowercase", ""),
        ("digit", ""),
        ("special character", ""),
        ("length>=8", ""),
        ("Weak", ""),
        ("Medium", ""),
        ("Strong", ""),
        ("Switch Sides", ""),
        ("Please confirm if you want to share your desktop?", ""),
        ("Display", ""),
        ("Default View Style", ""),
        ("Default Scroll Style", ""),
        ("Default Image Quality", ""),
        ("Default Codec", ""),
        ("Bitrate", ""),
        ("FPS", ""),
        ("Auto", ""),
        ("Other Default Options", ""),
        ("Voice call", ""),
        ("Text chat", ""),
        ("Stop voice call", ""),
        ("relay_hint_tip", ""),
        ("Reconnect", ""),
        ("Codec", ""),
        ("Resolution", ""),
        ("No transfers in progress", ""),
        ("Set one-time password length", ""),
        ("RDP Settings", ""),
        ("Sort by", ""),
        ("New Connection", ""),
        ("Restore", ""),
        ("Minimize", ""),
        ("Maximize", ""),
        ("Your Device", ""),
        ("empty_recent_tip", ""),
        ("empty_favorite_tip", ""),
        ("empty_lan_tip", ""),
        ("empty_address_book_tip", ""),
        ("eg: admin", ""),
        ("Empty Username", ""),
        ("Empty Password", ""),
        ("Me", ""),
        ("identical_file_tip", ""),
        ("show_monitors_tip", ""),
        ("View Mode", ""),
        ("login_linux_tip", ""),
        ("verify_rustdesk_password_tip", ""),
        ("remember_account_tip", ""),
        ("os_account_desk_tip", ""),
        ("OS Account", ""),
        ("another_user_login_title_tip", ""),
        ("another_user_login_text_tip", ""),
        ("xorg_not_found_title_tip", ""),
        ("xorg_not_found_text_tip", ""),
        ("no_desktop_title_tip", ""),
        ("no_desktop_text_tip", ""),
        ("No need to elevate", ""),
        ("System Sound", ""),
        ("Default", ""),
        ("New RDP", ""),
        ("Fingerprint", ""),
        ("Copy Fingerprint", ""),
        ("no fingerprints", ""),
        ("Select a peer", ""),
        ("Select peers", ""),
        ("Plugins", ""),
        ("Uninstall", ""),
        ("Update", ""),
        ("Enable", ""),
        ("Disable", ""),
        ("Options", ""),
        ("resolution_original_tip", ""),
        ("resolution_fit_local_tip", ""),
        ("resolution_custom_tip", ""),
        ("Collapse toolbar", ""),
        ("Accept and Elevate", ""),
        ("accept_and_elevate_btn_tooltip", ""),
        ("clipboard_wait_response_timeout_tip", ""),
        ("Incoming connection", ""),
        ("Outgoing connection", ""),
        ("Exit", ""),
        ("Open", ""),
        ("logout_tip", ""),
        ("Service", ""),
        ("Start", ""),
        ("Stop", ""),
        ("exceed_max_devices", ""),
        ("Sync with recent sessions", ""),
        ("Sort tags", ""),
        ("Open connection in new tab", ""),
        ("Move tab to new window", ""),
        ("Can not be empty", ""),
        ("Already exists", ""),
        ("Change Password", ""),
        ("Refresh Password", ""),
        ("ID", ""),
        ("Grid View", ""),
        ("List View", ""),
        ("Select", ""),
        ("Toggle Tags", ""),
        ("pull_ab_failed_tip", ""),
        ("push_ab_failed_tip", ""),
        ("synced_peer_readded_tip", ""),
        ("Change Color", ""),
        ("Primary Color", ""),
        ("HSV Color", ""),
        ("Installation Successful!", ""),
        ("Installation failed!", ""),
        ("Reverse mouse wheel", ""),
        ("{} sessions", ""),
        ("scam_title", ""),
        ("scam_text1", ""),
        ("scam_text2", ""),
        ("Don't show again", ""),
        ("I Agree", ""),
        ("Decline", ""),
        ("Timeout in minutes", ""),
        ("auto_disconnect_option_tip", ""),
        ("Connection failed due to inactivity", ""),
        ("Check for software update on startup", ""),
        ("upgrade_rustdesk_server_pro_to_{}_tip", ""),
        ("pull_group_failed_tip", ""),
        ("Filter by intersection", ""),
        ("Remove wallpaper during incoming sessions", ""),
        ("Test", ""),
        ("display_is_plugged_out_msg", ""),
        ("No displays", ""),
        ("elevated_switch_display_msg", ""),
        ("Open in new window", ""),
        ("Show displays as individual windows", ""),
        ("Use all my displays for the remote session", ""),
        ("selinux_tip", ""),
        ("Change view", ""),
        ("Big tiles", ""),
        ("Small tiles", ""),
        ("List", ""),
        ("Virtual display", ""),
        ("Plug out all", ""),
        ("True color (4:4:4)", ""),
        ("Enable blocking user input", ""),
        ("id_input_tip", ""),
        ("privacy_mode_impl_mag_tip", ""),
        ("privacy_mode_impl_virtual_display_tip", ""),
        ("Enter privacy mode", ""),
        ("Exit privacy mode", ""),
        ("idd_not_support_under_win10_2004_tip", ""),
        ("switch_display_elevated_connections_tip", ""),
        ("input_source_1_tip", ""),
        ("input_source_2_tip", ""),
        ("capture_display_elevated_connections_tip", ""),
        ("Swap control-command key", ""),
        ("swap-left-right-mouse", ""),
        ("2FA code", ""),
        ("More", ""),
        ("enable-2fa-title", ""),
        ("enable-2fa-desc", ""),
        ("wrong-2fa-code", ""),
        ("enter-2fa-title", ""),
        ("Email verification code must be 6 characters.", ""),
        ("2FA code must be 6 digits.", ""),
        ("Multiple Windows sessions found", ""),
        ("Please select the session you want to connect to", ""),
        ("powered_by_me", ""),
        ("outgoing_only_desk_tip", ""),
        ("preset_password_warning", ""),
        ("Security Alert", ""),
        ("My address book", ""),
        ("Personal", ""),
        ("Owner", ""),
        ("Set shared password", ""),
        ("Exist in", ""),
        ("Read-only", ""),
        ("Read/Write", ""),
        ("Full Control", ""),
        ("share_warning_tip", ""),
        ("Everyone", ""),
        ("ab_web_console_tip", ""),
        ("allow-only-conn-window-open-tip", ""),
        ("no_need_privacy_mode_no_physical_displays_tip", ""),
        ("Follow remote cursor", ""),
        ("Follow remote window focus", ""),
        ("default_proxy_tip", ""),
        ("no_audio_input_device_tip", ""),
    ].iter().cloned().collect();
}
