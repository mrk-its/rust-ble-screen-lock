#[macro_use]
extern crate log;
mod bluezhci;
mod gnomesessionmanager;
mod gnomescreensaver;
mod gnomeidlemonitor;
mod loginmanager;

use dbus::{Connection, BusType, SignalArgs, arg};
use std::error::Error;
use std::collections::HashMap;
use std::time::Duration;
use std::thread::sleep;
use bluezhci::{OrgBluezAdapter1,OrgFreedesktopDBusPropertiesPropertiesChanged as PropertiesChanged};
use gnomesessionmanager::{OrgGnomeSessionManager, OrgFreedesktopDBusProperties};
use gnomescreensaver::OrgGnomeScreenSaver;
use gnomeidlemonitor::OrgGnomeMutterIdleMonitor;
use loginmanager::OrgFreedesktopLogin1ManagerPrepareForSleep as LoginManagerPrepareForSleep;

use clap::{Arg, App};
use env_logger;

struct Opts {
    adapter_path: String,
    mac_address: Option<String>,
    min_rssi: Option<i16>,
    verbose: bool,
    debug: bool,
    lock_idle_time: Option<u64>,
    auto_unlock: bool,
}

fn system_dbus_connect() -> Result<Connection, Box<Error>> {
    let connection = Connection::get_private(BusType::System)?;
    connection.add_match(
        &PropertiesChanged::match_str(Some(&"org.bluez".into()), None)
    )?;
    connection.add_match(
        &LoginManagerPrepareForSleep::match_str(Some(&"org.freedesktop.login1".into()), None)
    )?;
    Ok(connection)
}

fn session_dbus_connect() -> Result<Connection, Box<Error>> {
    let connection = Connection::get_private(BusType::Session)?;
    Ok(connection)
}

fn start_discovery(bz: &dbus::ConnPath<'_, &dbus::Connection>, opts: &Opts) -> Result<(), Box<Error>> {
    let result = bz.start_discovery();
    info!("start_discovery: {:?}", result);
    result?;
    let mut map: HashMap<&str, arg::Variant<Box<arg::RefArg>>> = HashMap::new();
    map.insert("Transport", arg::Variant(Box::new("le".to_string())));
    if let Some(rssi) = opts.min_rssi {
        map.insert("RSSI", arg::Variant(Box::new(-rssi)));
    }
    debug!("set_discovery_filter: {:?}", &map);
    let result = bz.set_discovery_filter(map);
    info!("set_discovery_filter: {:?}", result);
    result?;
    Ok(())
}

fn stop_discovery(bz: &dbus::ConnPath<'_, &dbus::Connection>, opts: &Opts) -> Result<(), Box<Error>> {
    let result = bz.stop_discovery();
    info!("stop_discovery: {:?}", result);
    result?;
    Ok(())
}

fn get_variant<T: 'static>(value: &arg::Variant<Box<arg::RefArg>>) -> Option<T>
where T: Clone {
    arg::cast::<T>(&value.0).map(|v| v.clone())
}

fn get_opt_variant<T: 'static>(value: Option<&arg::Variant<Box<arg::RefArg>>>) -> Option<T>
where T:Clone {
    match value {
        Some(v) => get_variant::<T>(v),
        None => None,
    }
}

fn process_events(opts: &Opts) -> Result<(), Box<Error>> {
    let device_name = opts.mac_address.as_ref().map(mac_address_to_device_name);
    let connection = system_dbus_connect()?;
    let session_connection = session_dbus_connect()?;
    let bz = connection.with_path("org.bluez", &opts.adapter_path, 5000);
    let sm = session_connection.with_path("org.gnome.SessionManager", "/org/gnome/SessionManager", 5000);
    let screen_saver = session_connection.with_path("org.gnome.ScreenSaver", "/org/gnome/ScreenSaver", 5000);
    let idle_monitor = session_connection.with_path("org.gnome.Mutter.IdleMonitor", "/org/gnome/Mutter/IdleMonitor/Core", 5000);

    let device_prefix = format!("{}/dev_", opts.adapter_path);
    let mut ignore_events = false;

    start_discovery(&bz, &opts)?;

    loop {
        if let Ok(idle_time) = idle_monitor.get_idletime() {
            debug!("idle time: {}", idle_time);
            if let Some(lock_idle_time) = opts.lock_idle_time {
                if idle_time > lock_idle_time {
                    let result = screen_saver.lock();
                    info!("screen saver locked: {:?}", result);
                }
            }
        }
        for msg in connection.incoming(0) {
            debug!("msg: {:?}", msg);
            match LoginManagerPrepareForSleep::from_message(&msg) {
                Some(msg) => {
                    let _result = if msg.arg0 {
                        ignore_events = true;
                        stop_discovery(&bz, &opts)
                    } else {
                        ignore_events = false;
                        start_discovery(&bz, &opts)
                    };
                    info!("prepare for sleep: {}", msg.arg0);
                },
                _ => (),
            }
            match (msg.path(), PropertiesChanged::from_message(&msg)) {
                (Some(path), Some(props)) => {
                    if *path == opts.adapter_path {
                        let powered = get_opt_variant::<bool>(props.changed_properties.get("Powered"));
                        if powered.is_some() && powered.unwrap() {
                            ignore_events = false;
                            start_discovery(&bz, &opts)?;
                        }
                    }
                    if !path.starts_with(&device_prefix) {
                        continue
                    }
                    let dev_itf = connection.with_path("org.bluez", &path, 5000);
                    let rssi = get_opt_variant::<i16>(props.changed_properties.get("RSSI")).map(|v| v.to_string());
                    let name = get_opt_variant::<String>(dev_itf.get("org.bluez.Device1", "Name").ok().as_ref());
                    let msg_mac_addr = &path[device_prefix.len()..].replace("_", ":").to_lowercase();
                    let is_device_present = match &device_name {
                        Some(name) => path.ends_with(name),
                        None => false,
                    };
                    if device_name.is_none() || is_device_present || opts.verbose {
                        println!("{} rssi: {} {:?}", msg_mac_addr, rssi.unwrap_or("".to_string()), name.unwrap_or("".to_string()));
                    }
                    if is_device_present && !ignore_events {
                        let cookie = sm.inhibit("ble-scanner", 1, "tracked device nearby", 4 | 8)?;
                        info!("SessionManager.inhibit cookie: {}", cookie);
                        sm.uninhibit(cookie).unwrap_or(());
                        if opts.auto_unlock {
                            info!("unlocking screen saver");
                            screen_saver.set_active(false).unwrap_or(());
                        }
                    }
                },
                _ => ()
            };
        }
        sleep(Duration::from_millis(100));
    }
}

fn validate_mac_address(mac_address: String) -> Result<(), String> {
    let mut parts = mac_address.split(":");
    if parts.clone().count() != 6
       || !parts.all(|v| v.len() == 2 && i32::from_str_radix(v, 16).is_ok())
    {
        return Err("invalid mac address format".to_string())
    }
    Ok(())
}

fn mac_address_to_device_name(mac_address: &String) -> String {
    "dev_".chars().chain(
        mac_address
        .chars()
        .map(|v| if v == ':' {'_'} else {v})
        .map(|v| v.to_ascii_uppercase())
    ).collect()
}

fn validate_int(value: String) -> Result<(), String> {
    value.parse::<u64>().map(|_|{}).map_err(|_|"can't parse integer".to_string())
}

fn main() -> Result<(), Box<Error>> {
    let matches = App::new("rust-ble-unlock")
        .version("0.1.0")
        .author("mrk")
        .arg(Arg::with_name("adapter-path").short("p").default_value("/org/bluez/hci0"))
        .arg(
            Arg::with_name("mac-address")
            .short("a")
            .long("mac-address")
            .help("MAC address of monitored device")
            .takes_value(true)
            .validator(validate_mac_address)
        )
        .arg(Arg::with_name("verbose").short("v").long("verbose"))
        .arg(Arg::with_name("debug").short("d").long("debug"))
        .arg(Arg::with_name("auto-unlock").short("u").long("auto-unlock"))
        .arg(
            Arg::with_name("lock-idle-time")
            .short("t")
            .long("lock-idle-time")
            .help("in seconds. If not set system settings will be used")
            .takes_value(true)
            .validator(validate_int)
        )
        .arg(
            Arg::with_name("rssi")
            .short("r").long("rssi")
            .help("absolute value of rssi threshold")
            .takes_value(true)
            .validator(validate_int)
        )
        .get_matches();

    let opts = Opts {
        adapter_path: matches.value_of("adapter-path").unwrap().into(),
        mac_address: matches.value_of("mac-address").map(|v|v.into()),
        min_rssi: matches.value_of("rssi").map(|v| v.parse().unwrap()),
        verbose: matches.is_present("verbose"),
        debug: matches.is_present("debug"),
        auto_unlock: matches.is_present("auto-unlock"),
        lock_idle_time: matches.value_of("lock-idle-time").map(|v| v.parse::<u64>().unwrap() * 1000),
    };

    let mut builder = env_logger::Builder::from_default_env();
    if opts.debug {
        builder.filter(None, log::LevelFilter::Debug)
    } else {
        &mut builder
    }.init();
    process_events(&opts)
}
