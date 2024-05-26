use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        let app_dir = std::env::var("APPDIR").unwrap_or("".to_string());
        let mut so_path = "/usr/lib/rustdesk/libsciter-gtk.so".to_owned();
        for (prefix, dir) in [
            ("", "/usr"),
            ("", "/app"),
            (&app_dir, "/usr"),
            (&app_dir, "/app"),
        ]
        .iter()
        {
            let path = format!("{prefix}{dir}/lib/rustdesk/libsciter-gtk.so");
            if std::path::Path::new(&path).exists() {
                so_path = path;
                break;
            }
        }
        sciter::set_library(&so_path).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
	let app_title = "InfoMaster Remote Desktop";
    frame.set_title(&app_title); //(JEM)
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        crate::using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String, test_with_proxy: bool) -> String {
        test_if_valid_server(host, test_with_proxy)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn http_request(&self, url: String, method: String, body: Option<String>, header: String) {
        http_request(url, method, body, header)
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn get_http_status(&self, url: String) -> Option<String> {
        get_async_http_status(url)
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn has_vram(&self) -> bool {
        has_vram()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn default_video_save_directory(&self) -> String {
        default_video_save_directory()
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(&id).to_owned()
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }

    fn has_valid_2fa(&self) -> bool {
        has_valid_2fa()
    }

    fn generate2fa(&self) -> String {
        generate2fa()
    }

    pub fn verify2fa(&self, code: String) -> bool {
        verify2fa(code)
    }

    fn generate_2fa_img_src(&self, data: String) -> String {
        let v = qrcode_generator::to_png_to_vec(data, qrcode_generator::QrCodeEcc::Low, 128)
            .unwrap_or_default();
        let s = hbb_common::sodiumoxide::base64::encode(
            v,
            hbb_common::sodiumoxide::base64::Variant::Original,
        );
        format!("data:image/png;base64,{s}")
    }

    pub fn check_hwcodec(&self) {
        check_hwcodec()
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String, bool);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn has_vram();
        fn get_langs();
        fn default_video_save_directory();
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
        fn has_valid_2fa();
        fn generate2fa();
        fn generate_2fa_img_src(String);
        fn verify2fa(String);
        fn check_hwcodec();
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,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".into()
    }
}
