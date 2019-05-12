// This code was autogenerated with dbus-codegen-rust, see https://github.com/diwic/dbus-rs

#![allow(dead_code)]
use dbus as dbus;
use dbus::arg;
use dbus::tree;

pub trait OrgFreedesktopDBusProperties {
    type Err;
    fn get(&self, interface_name: &str, property_name: &str) -> Result<arg::Variant<Box<arg::RefArg + 'static>>, Self::Err>;
    fn get_all(&self, interface_name: &str) -> Result<::std::collections::HashMap<String, arg::Variant<Box<arg::RefArg + 'static>>>, Self::Err>;
    fn set(&self, interface_name: &str, property_name: &str, value: arg::Variant<Box<arg::RefArg>>) -> Result<(), Self::Err>;
}

impl<'a, C: ::std::ops::Deref<Target=dbus::Connection>> OrgFreedesktopDBusProperties for dbus::ConnPath<'a, C> {
    type Err = dbus::Error;

    fn get(&self, interface_name: &str, property_name: &str) -> Result<arg::Variant<Box<arg::RefArg + 'static>>, Self::Err> {
        let mut m = self.method_call_with_args(&"org.freedesktop.DBus.Properties".into(), &"Get".into(), |msg| {
            let mut i = arg::IterAppend::new(msg);
            i.append(interface_name);
            i.append(property_name);
        })?;
        m.as_result()?;
        let mut i = m.iter_init();
        let value: arg::Variant<Box<arg::RefArg + 'static>> = i.read()?;
        Ok(value)
    }

    fn get_all(&self, interface_name: &str) -> Result<::std::collections::HashMap<String, arg::Variant<Box<arg::RefArg + 'static>>>, Self::Err> {
        let mut m = self.method_call_with_args(&"org.freedesktop.DBus.Properties".into(), &"GetAll".into(), |msg| {
            let mut i = arg::IterAppend::new(msg);
            i.append(interface_name);
        })?;
        m.as_result()?;
        let mut i = m.iter_init();
        let properties: ::std::collections::HashMap<String, arg::Variant<Box<arg::RefArg + 'static>>> = i.read()?;
        Ok(properties)
    }

    fn set(&self, interface_name: &str, property_name: &str, value: arg::Variant<Box<arg::RefArg>>) -> Result<(), Self::Err> {
        let mut m = self.method_call_with_args(&"org.freedesktop.DBus.Properties".into(), &"Set".into(), |msg| {
            let mut i = arg::IterAppend::new(msg);
            i.append(interface_name);
            i.append(property_name);
            i.append(value);
        })?;
        m.as_result()?;
        Ok(())
    }
}

pub fn org_freedesktop_dbus_properties_server<F, T, D>(factory: &tree::Factory<tree::MTFn<D>, D>, data: D::Interface, f: F) -> tree::Interface<tree::MTFn<D>, D>
where
    D: tree::DataType,
    D::Method: Default,
    D::Signal: Default,
    T: OrgFreedesktopDBusProperties<Err=tree::MethodErr>,
    F: 'static + for <'z> Fn(& 'z tree::MethodInfo<tree::MTFn<D>, D>) -> & 'z T,
{
    let i = factory.interface("org.freedesktop.DBus.Properties", data);
    let f = ::std::sync::Arc::new(f);
    let fclone = f.clone();
    let h = move |minfo: &tree::MethodInfo<tree::MTFn<D>, D>| {
        let mut i = minfo.msg.iter_init();
        let interface_name: &str = i.read()?;
        let property_name: &str = i.read()?;
        let d = fclone(minfo);
        let value = d.get(interface_name, property_name)?;
        let rm = minfo.msg.method_return();
        let rm = rm.append1(value);
        Ok(vec!(rm))
    };
    let m = factory.method("Get", Default::default(), h);
    let m = m.in_arg(("interface_name", "s"));
    let m = m.in_arg(("property_name", "s"));
    let m = m.out_arg(("value", "v"));
    let i = i.add_m(m);

    let fclone = f.clone();
    let h = move |minfo: &tree::MethodInfo<tree::MTFn<D>, D>| {
        let mut i = minfo.msg.iter_init();
        let interface_name: &str = i.read()?;
        let d = fclone(minfo);
        let properties = d.get_all(interface_name)?;
        let rm = minfo.msg.method_return();
        let rm = rm.append1(properties);
        Ok(vec!(rm))
    };
    let m = factory.method("GetAll", Default::default(), h);
    let m = m.in_arg(("interface_name", "s"));
    let m = m.out_arg(("properties", "a{sv}"));
    let i = i.add_m(m);

    let fclone = f.clone();
    let h = move |minfo: &tree::MethodInfo<tree::MTFn<D>, D>| {
        let mut i = minfo.msg.iter_init();
        let interface_name: &str = i.read()?;
        let property_name: &str = i.read()?;
        let value: arg::Variant<Box<arg::RefArg>> = i.read()?;
        let d = fclone(minfo);
        d.set(interface_name, property_name, value)?;
        let rm = minfo.msg.method_return();
        Ok(vec!(rm))
    };
    let m = factory.method("Set", Default::default(), h);
    let m = m.in_arg(("interface_name", "s"));
    let m = m.in_arg(("property_name", "s"));
    let m = m.in_arg(("value", "v"));
    let i = i.add_m(m);
    let s = factory.signal("PropertiesChanged", Default::default());
    let s = s.arg(("interface_name", "s"));
    let s = s.arg(("changed_properties", "a{sv}"));
    let s = s.arg(("invalidated_properties", "as"));
    let i = i.add_s(s);
    i
}

#[derive(Debug, Default)]
pub struct OrgFreedesktopDBusPropertiesPropertiesChanged {
    pub interface_name: String,
    pub changed_properties: ::std::collections::HashMap<String, arg::Variant<Box<arg::RefArg + 'static>>>,
    pub invalidated_properties: Vec<String>,
}

impl dbus::SignalArgs for OrgFreedesktopDBusPropertiesPropertiesChanged {
    const NAME: &'static str = "PropertiesChanged";
    const INTERFACE: &'static str = "org.freedesktop.DBus.Properties";
    fn append(&self, i: &mut arg::IterAppend) {
        arg::RefArg::append(&self.interface_name, i);
        arg::RefArg::append(&self.changed_properties, i);
        arg::RefArg::append(&self.invalidated_properties, i);
    }
    fn get(&mut self, i: &mut arg::Iter) -> Result<(), arg::TypeMismatchError> {
        self.interface_name = i.read()?;
        self.changed_properties = i.read()?;
        self.invalidated_properties = i.read()?;
        Ok(())
    }
}

pub trait OrgFreedesktopDBusIntrospectable {
    type Err;
    fn introspect(&self) -> Result<String, Self::Err>;
}

impl<'a, C: ::std::ops::Deref<Target=dbus::Connection>> OrgFreedesktopDBusIntrospectable for dbus::ConnPath<'a, C> {
    type Err = dbus::Error;

    fn introspect(&self) -> Result<String, Self::Err> {
        let mut m = self.method_call_with_args(&"org.freedesktop.DBus.Introspectable".into(), &"Introspect".into(), |_| {
        })?;
        m.as_result()?;
        let mut i = m.iter_init();
        let xml_data: String = i.read()?;
        Ok(xml_data)
    }
}

pub fn org_freedesktop_dbus_introspectable_server<F, T, D>(factory: &tree::Factory<tree::MTFn<D>, D>, data: D::Interface, f: F) -> tree::Interface<tree::MTFn<D>, D>
where
    D: tree::DataType,
    D::Method: Default,
    T: OrgFreedesktopDBusIntrospectable<Err=tree::MethodErr>,
    F: 'static + for <'z> Fn(& 'z tree::MethodInfo<tree::MTFn<D>, D>) -> & 'z T,
{
    let i = factory.interface("org.freedesktop.DBus.Introspectable", data);
    let f = ::std::sync::Arc::new(f);
    let fclone = f.clone();
    let h = move |minfo: &tree::MethodInfo<tree::MTFn<D>, D>| {
        let d = fclone(minfo);
        let xml_data = d.introspect()?;
        let rm = minfo.msg.method_return();
        let rm = rm.append1(xml_data);
        Ok(vec!(rm))
    };
    let m = factory.method("Introspect", Default::default(), h);
    let m = m.out_arg(("xml_data", "s"));
    let i = i.add_m(m);
    i
}

pub trait OrgFreedesktopDBusPeer {
    type Err;
    fn ping(&self) -> Result<(), Self::Err>;
    fn get_machine_id(&self) -> Result<String, Self::Err>;
}

impl<'a, C: ::std::ops::Deref<Target=dbus::Connection>> OrgFreedesktopDBusPeer for dbus::ConnPath<'a, C> {
    type Err = dbus::Error;

    fn ping(&self) -> Result<(), Self::Err> {
        let mut m = self.method_call_with_args(&"org.freedesktop.DBus.Peer".into(), &"Ping".into(), |_| {
        })?;
        m.as_result()?;
        Ok(())
    }

    fn get_machine_id(&self) -> Result<String, Self::Err> {
        let mut m = self.method_call_with_args(&"org.freedesktop.DBus.Peer".into(), &"GetMachineId".into(), |_| {
        })?;
        m.as_result()?;
        let mut i = m.iter_init();
        let machine_uuid: String = i.read()?;
        Ok(machine_uuid)
    }
}

pub fn org_freedesktop_dbus_peer_server<F, T, D>(factory: &tree::Factory<tree::MTFn<D>, D>, data: D::Interface, f: F) -> tree::Interface<tree::MTFn<D>, D>
where
    D: tree::DataType,
    D::Method: Default,
    T: OrgFreedesktopDBusPeer<Err=tree::MethodErr>,
    F: 'static + for <'z> Fn(& 'z tree::MethodInfo<tree::MTFn<D>, D>) -> & 'z T,
{
    let i = factory.interface("org.freedesktop.DBus.Peer", data);
    let f = ::std::sync::Arc::new(f);
    let fclone = f.clone();
    let h = move |minfo: &tree::MethodInfo<tree::MTFn<D>, D>| {
        let d = fclone(minfo);
        d.ping()?;
        let rm = minfo.msg.method_return();
        Ok(vec!(rm))
    };
    let m = factory.method("Ping", Default::default(), h);
    let i = i.add_m(m);

    let fclone = f.clone();
    let h = move |minfo: &tree::MethodInfo<tree::MTFn<D>, D>| {
        let d = fclone(minfo);
        let machine_uuid = d.get_machine_id()?;
        let rm = minfo.msg.method_return();
        let rm = rm.append1(machine_uuid);
        Ok(vec!(rm))
    };
    let m = factory.method("GetMachineId", Default::default(), h);
    let m = m.out_arg(("machine_uuid", "s"));
    let i = i.add_m(m);
    i
}

pub trait OrgGnomeSessionManager {
    type Err;
    fn setenv(&self, variable: &str, value: &str) -> Result<(), Self::Err>;
    fn get_locale(&self, category: i32) -> Result<String, Self::Err>;
    fn initialization_error(&self, message: &str, fatal: bool) -> Result<(), Self::Err>;
    fn register_client(&self, app_id: &str, client_startup_id: &str) -> Result<dbus::Path<'static>, Self::Err>;
    fn unregister_client(&self, client_id: dbus::Path) -> Result<(), Self::Err>;
    fn inhibit(&self, app_id: &str, toplevel_xid: u32, reason: &str, flags: u32) -> Result<u32, Self::Err>;
    fn uninhibit(&self, inhibit_cookie: u32) -> Result<(), Self::Err>;
    fn is_inhibited(&self, flags: u32) -> Result<bool, Self::Err>;
    fn get_clients(&self) -> Result<Vec<dbus::Path<'static>>, Self::Err>;
    fn get_inhibitors(&self) -> Result<Vec<dbus::Path<'static>>, Self::Err>;
    fn is_autostart_condition_handled(&self, condition: &str) -> Result<bool, Self::Err>;
    fn shutdown(&self) -> Result<(), Self::Err>;
    fn reboot(&self) -> Result<(), Self::Err>;
    fn can_shutdown(&self) -> Result<bool, Self::Err>;
    fn logout(&self, mode: u32) -> Result<(), Self::Err>;
    fn is_session_running(&self) -> Result<bool, Self::Err>;
    fn request_shutdown(&self) -> Result<(), Self::Err>;
    fn request_reboot(&self) -> Result<(), Self::Err>;
    fn get_session_name(&self) -> Result<String, Self::Err>;
    fn get_renderer(&self) -> Result<String, Self::Err>;
    fn get_session_is_active(&self) -> Result<bool, Self::Err>;
    fn get_inhibited_actions(&self) -> Result<u32, Self::Err>;
}

impl<'a, C: ::std::ops::Deref<Target=dbus::Connection>> OrgGnomeSessionManager for dbus::ConnPath<'a, C> {
    type Err = dbus::Error;

    fn setenv(&self, variable: &str, value: &str) -> Result<(), Self::Err> {
        let mut m = self.method_call_with_args(&"org.gnome.SessionManager".into(), &"Setenv".into(), |msg| {
            let mut i = arg::IterAppend::new(msg);
            i.append(variable);
            i.append(value);
        })?;
        m.as_result()?;
        Ok(())
    }

    fn get_locale(&self, category: i32) -> Result<String, Self::Err> {
        let mut m = self.method_call_with_args(&"org.gnome.SessionManager".into(), &"GetLocale".into(), |msg| {
            let mut i = arg::IterAppend::new(msg);
            i.append(category);
        })?;
        m.as_result()?;
        let mut i = m.iter_init();
        let value: String = i.read()?;
        Ok(value)
    }

    fn initialization_error(&self, message: &str, fatal: bool) -> Result<(), Self::Err> {
        let mut m = self.method_call_with_args(&"org.gnome.SessionManager".into(), &"InitializationError".into(), |msg| {
            let mut i = arg::IterAppend::new(msg);
            i.append(message);
            i.append(fatal);
        })?;
        m.as_result()?;
        Ok(())
    }

    fn register_client(&self, app_id: &str, client_startup_id: &str) -> Result<dbus::Path<'static>, Self::Err> {
        let mut m = self.method_call_with_args(&"org.gnome.SessionManager".into(), &"RegisterClient".into(), |msg| {
            let mut i = arg::IterAppend::new(msg);
            i.append(app_id);
            i.append(client_startup_id);
        })?;
        m.as_result()?;
        let mut i = m.iter_init();
        let client_id: dbus::Path<'static> = i.read()?;
        Ok(client_id)
    }

    fn unregister_client(&self, client_id: dbus::Path) -> Result<(), Self::Err> {
        let mut m = self.method_call_with_args(&"org.gnome.SessionManager".into(), &"UnregisterClient".into(), |msg| {
            let mut i = arg::IterAppend::new(msg);
            i.append(client_id);
        })?;
        m.as_result()?;
        Ok(())
    }

    fn inhibit(&self, app_id: &str, toplevel_xid: u32, reason: &str, flags: u32) -> Result<u32, Self::Err> {
        let mut m = self.method_call_with_args(&"org.gnome.SessionManager".into(), &"Inhibit".into(), |msg| {
            let mut i = arg::IterAppend::new(msg);
            i.append(app_id);
            i.append(toplevel_xid);
            i.append(reason);
            i.append(flags);
        })?;
        m.as_result()?;
        let mut i = m.iter_init();
        let inhibit_cookie: u32 = i.read()?;
        Ok(inhibit_cookie)
    }

    fn uninhibit(&self, inhibit_cookie: u32) -> Result<(), Self::Err> {
        let mut m = self.method_call_with_args(&"org.gnome.SessionManager".into(), &"Uninhibit".into(), |msg| {
            let mut i = arg::IterAppend::new(msg);
            i.append(inhibit_cookie);
        })?;
        m.as_result()?;
        Ok(())
    }

    fn is_inhibited(&self, flags: u32) -> Result<bool, Self::Err> {
        let mut m = self.method_call_with_args(&"org.gnome.SessionManager".into(), &"IsInhibited".into(), |msg| {
            let mut i = arg::IterAppend::new(msg);
            i.append(flags);
        })?;
        m.as_result()?;
        let mut i = m.iter_init();
        let is_inhibited: bool = i.read()?;
        Ok(is_inhibited)
    }

    fn get_clients(&self) -> Result<Vec<dbus::Path<'static>>, Self::Err> {
        let mut m = self.method_call_with_args(&"org.gnome.SessionManager".into(), &"GetClients".into(), |_| {
        })?;
        m.as_result()?;
        let mut i = m.iter_init();
        let clients: Vec<dbus::Path<'static>> = i.read()?;
        Ok(clients)
    }

    fn get_inhibitors(&self) -> Result<Vec<dbus::Path<'static>>, Self::Err> {
        let mut m = self.method_call_with_args(&"org.gnome.SessionManager".into(), &"GetInhibitors".into(), |_| {
        })?;
        m.as_result()?;
        let mut i = m.iter_init();
        let inhibitors: Vec<dbus::Path<'static>> = i.read()?;
        Ok(inhibitors)
    }

    fn is_autostart_condition_handled(&self, condition: &str) -> Result<bool, Self::Err> {
        let mut m = self.method_call_with_args(&"org.gnome.SessionManager".into(), &"IsAutostartConditionHandled".into(), |msg| {
            let mut i = arg::IterAppend::new(msg);
            i.append(condition);
        })?;
        m.as_result()?;
        let mut i = m.iter_init();
        let handled: bool = i.read()?;
        Ok(handled)
    }

    fn shutdown(&self) -> Result<(), Self::Err> {
        let mut m = self.method_call_with_args(&"org.gnome.SessionManager".into(), &"Shutdown".into(), |_| {
        })?;
        m.as_result()?;
        Ok(())
    }

    fn reboot(&self) -> Result<(), Self::Err> {
        let mut m = self.method_call_with_args(&"org.gnome.SessionManager".into(), &"Reboot".into(), |_| {
        })?;
        m.as_result()?;
        Ok(())
    }

    fn can_shutdown(&self) -> Result<bool, Self::Err> {
        let mut m = self.method_call_with_args(&"org.gnome.SessionManager".into(), &"CanShutdown".into(), |_| {
        })?;
        m.as_result()?;
        let mut i = m.iter_init();
        let is_available: bool = i.read()?;
        Ok(is_available)
    }

    fn logout(&self, mode: u32) -> Result<(), Self::Err> {
        let mut m = self.method_call_with_args(&"org.gnome.SessionManager".into(), &"Logout".into(), |msg| {
            let mut i = arg::IterAppend::new(msg);
            i.append(mode);
        })?;
        m.as_result()?;
        Ok(())
    }

    fn is_session_running(&self) -> Result<bool, Self::Err> {
        let mut m = self.method_call_with_args(&"org.gnome.SessionManager".into(), &"IsSessionRunning".into(), |_| {
        })?;
        m.as_result()?;
        let mut i = m.iter_init();
        let running: bool = i.read()?;
        Ok(running)
    }

    fn request_shutdown(&self) -> Result<(), Self::Err> {
        let mut m = self.method_call_with_args(&"org.gnome.SessionManager".into(), &"RequestShutdown".into(), |_| {
        })?;
        m.as_result()?;
        Ok(())
    }

    fn request_reboot(&self) -> Result<(), Self::Err> {
        let mut m = self.method_call_with_args(&"org.gnome.SessionManager".into(), &"RequestReboot".into(), |_| {
        })?;
        m.as_result()?;
        Ok(())
    }

    fn get_session_name(&self) -> Result<String, Self::Err> {
        <Self as dbus::stdintf::org_freedesktop_dbus::Properties>::get(&self, "org.gnome.SessionManager", "SessionName")
    }

    fn get_renderer(&self) -> Result<String, Self::Err> {
        <Self as dbus::stdintf::org_freedesktop_dbus::Properties>::get(&self, "org.gnome.SessionManager", "Renderer")
    }

    fn get_session_is_active(&self) -> Result<bool, Self::Err> {
        <Self as dbus::stdintf::org_freedesktop_dbus::Properties>::get(&self, "org.gnome.SessionManager", "SessionIsActive")
    }

    fn get_inhibited_actions(&self) -> Result<u32, Self::Err> {
        <Self as dbus::stdintf::org_freedesktop_dbus::Properties>::get(&self, "org.gnome.SessionManager", "InhibitedActions")
    }
}

pub fn org_gnome_session_manager_server<F, T, D>(factory: &tree::Factory<tree::MTFn<D>, D>, data: D::Interface, f: F) -> tree::Interface<tree::MTFn<D>, D>
where
    D: tree::DataType,
    D::Method: Default,
    D::Property: Default,
    D::Signal: Default,
    T: OrgGnomeSessionManager<Err=tree::MethodErr>,
    F: 'static + for <'z> Fn(& 'z tree::MethodInfo<tree::MTFn<D>, D>) -> & 'z T,
{
    let i = factory.interface("org.gnome.SessionManager", data);
    let f = ::std::sync::Arc::new(f);
    let fclone = f.clone();
    let h = move |minfo: &tree::MethodInfo<tree::MTFn<D>, D>| {
        let mut i = minfo.msg.iter_init();
        let variable: &str = i.read()?;
        let value: &str = i.read()?;
        let d = fclone(minfo);
        d.setenv(variable, value)?;
        let rm = minfo.msg.method_return();
        Ok(vec!(rm))
    };
    let m = factory.method("Setenv", Default::default(), h);
    let m = m.in_arg(("variable", "s"));
    let m = m.in_arg(("value", "s"));
    let i = i.add_m(m);

    let fclone = f.clone();
    let h = move |minfo: &tree::MethodInfo<tree::MTFn<D>, D>| {
        let mut i = minfo.msg.iter_init();
        let category: i32 = i.read()?;
        let d = fclone(minfo);
        let value = d.get_locale(category)?;
        let rm = minfo.msg.method_return();
        let rm = rm.append1(value);
        Ok(vec!(rm))
    };
    let m = factory.method("GetLocale", Default::default(), h);
    let m = m.in_arg(("category", "i"));
    let m = m.out_arg(("value", "s"));
    let i = i.add_m(m);

    let fclone = f.clone();
    let h = move |minfo: &tree::MethodInfo<tree::MTFn<D>, D>| {
        let mut i = minfo.msg.iter_init();
        let message: &str = i.read()?;
        let fatal: bool = i.read()?;
        let d = fclone(minfo);
        d.initialization_error(message, fatal)?;
        let rm = minfo.msg.method_return();
        Ok(vec!(rm))
    };
    let m = factory.method("InitializationError", Default::default(), h);
    let m = m.in_arg(("message", "s"));
    let m = m.in_arg(("fatal", "b"));
    let i = i.add_m(m);

    let fclone = f.clone();
    let h = move |minfo: &tree::MethodInfo<tree::MTFn<D>, D>| {
        let mut i = minfo.msg.iter_init();
        let app_id: &str = i.read()?;
        let client_startup_id: &str = i.read()?;
        let d = fclone(minfo);
        let client_id = d.register_client(app_id, client_startup_id)?;
        let rm = minfo.msg.method_return();
        let rm = rm.append1(client_id);
        Ok(vec!(rm))
    };
    let m = factory.method("RegisterClient", Default::default(), h);
    let m = m.in_arg(("app_id", "s"));
    let m = m.in_arg(("client_startup_id", "s"));
    let m = m.out_arg(("client_id", "o"));
    let i = i.add_m(m);

    let fclone = f.clone();
    let h = move |minfo: &tree::MethodInfo<tree::MTFn<D>, D>| {
        let mut i = minfo.msg.iter_init();
        let client_id: dbus::Path = i.read()?;
        let d = fclone(minfo);
        d.unregister_client(client_id)?;
        let rm = minfo.msg.method_return();
        Ok(vec!(rm))
    };
    let m = factory.method("UnregisterClient", Default::default(), h);
    let m = m.in_arg(("client_id", "o"));
    let i = i.add_m(m);

    let fclone = f.clone();
    let h = move |minfo: &tree::MethodInfo<tree::MTFn<D>, D>| {
        let mut i = minfo.msg.iter_init();
        let app_id: &str = i.read()?;
        let toplevel_xid: u32 = i.read()?;
        let reason: &str = i.read()?;
        let flags: u32 = i.read()?;
        let d = fclone(minfo);
        let inhibit_cookie = d.inhibit(app_id, toplevel_xid, reason, flags)?;
        let rm = minfo.msg.method_return();
        let rm = rm.append1(inhibit_cookie);
        Ok(vec!(rm))
    };
    let m = factory.method("Inhibit", Default::default(), h);
    let m = m.in_arg(("app_id", "s"));
    let m = m.in_arg(("toplevel_xid", "u"));
    let m = m.in_arg(("reason", "s"));
    let m = m.in_arg(("flags", "u"));
    let m = m.out_arg(("inhibit_cookie", "u"));
    let i = i.add_m(m);

    let fclone = f.clone();
    let h = move |minfo: &tree::MethodInfo<tree::MTFn<D>, D>| {
        let mut i = minfo.msg.iter_init();
        let inhibit_cookie: u32 = i.read()?;
        let d = fclone(minfo);
        d.uninhibit(inhibit_cookie)?;
        let rm = minfo.msg.method_return();
        Ok(vec!(rm))
    };
    let m = factory.method("Uninhibit", Default::default(), h);
    let m = m.in_arg(("inhibit_cookie", "u"));
    let i = i.add_m(m);

    let fclone = f.clone();
    let h = move |minfo: &tree::MethodInfo<tree::MTFn<D>, D>| {
        let mut i = minfo.msg.iter_init();
        let flags: u32 = i.read()?;
        let d = fclone(minfo);
        let is_inhibited = d.is_inhibited(flags)?;
        let rm = minfo.msg.method_return();
        let rm = rm.append1(is_inhibited);
        Ok(vec!(rm))
    };
    let m = factory.method("IsInhibited", Default::default(), h);
    let m = m.in_arg(("flags", "u"));
    let m = m.out_arg(("is_inhibited", "b"));
    let i = i.add_m(m);

    let fclone = f.clone();
    let h = move |minfo: &tree::MethodInfo<tree::MTFn<D>, D>| {
        let d = fclone(minfo);
        let clients = d.get_clients()?;
        let rm = minfo.msg.method_return();
        let rm = rm.append1(clients);
        Ok(vec!(rm))
    };
    let m = factory.method("GetClients", Default::default(), h);
    let m = m.out_arg(("clients", "ao"));
    let i = i.add_m(m);

    let fclone = f.clone();
    let h = move |minfo: &tree::MethodInfo<tree::MTFn<D>, D>| {
        let d = fclone(minfo);
        let inhibitors = d.get_inhibitors()?;
        let rm = minfo.msg.method_return();
        let rm = rm.append1(inhibitors);
        Ok(vec!(rm))
    };
    let m = factory.method("GetInhibitors", Default::default(), h);
    let m = m.out_arg(("inhibitors", "ao"));
    let i = i.add_m(m);

    let fclone = f.clone();
    let h = move |minfo: &tree::MethodInfo<tree::MTFn<D>, D>| {
        let mut i = minfo.msg.iter_init();
        let condition: &str = i.read()?;
        let d = fclone(minfo);
        let handled = d.is_autostart_condition_handled(condition)?;
        let rm = minfo.msg.method_return();
        let rm = rm.append1(handled);
        Ok(vec!(rm))
    };
    let m = factory.method("IsAutostartConditionHandled", Default::default(), h);
    let m = m.in_arg(("condition", "s"));
    let m = m.out_arg(("handled", "b"));
    let i = i.add_m(m);

    let fclone = f.clone();
    let h = move |minfo: &tree::MethodInfo<tree::MTFn<D>, D>| {
        let d = fclone(minfo);
        d.shutdown()?;
        let rm = minfo.msg.method_return();
        Ok(vec!(rm))
    };
    let m = factory.method("Shutdown", Default::default(), h);
    let i = i.add_m(m);

    let fclone = f.clone();
    let h = move |minfo: &tree::MethodInfo<tree::MTFn<D>, D>| {
        let d = fclone(minfo);
        d.reboot()?;
        let rm = minfo.msg.method_return();
        Ok(vec!(rm))
    };
    let m = factory.method("Reboot", Default::default(), h);
    let i = i.add_m(m);

    let fclone = f.clone();
    let h = move |minfo: &tree::MethodInfo<tree::MTFn<D>, D>| {
        let d = fclone(minfo);
        let is_available = d.can_shutdown()?;
        let rm = minfo.msg.method_return();
        let rm = rm.append1(is_available);
        Ok(vec!(rm))
    };
    let m = factory.method("CanShutdown", Default::default(), h);
    let m = m.out_arg(("is_available", "b"));
    let i = i.add_m(m);

    let fclone = f.clone();
    let h = move |minfo: &tree::MethodInfo<tree::MTFn<D>, D>| {
        let mut i = minfo.msg.iter_init();
        let mode: u32 = i.read()?;
        let d = fclone(minfo);
        d.logout(mode)?;
        let rm = minfo.msg.method_return();
        Ok(vec!(rm))
    };
    let m = factory.method("Logout", Default::default(), h);
    let m = m.in_arg(("mode", "u"));
    let i = i.add_m(m);

    let fclone = f.clone();
    let h = move |minfo: &tree::MethodInfo<tree::MTFn<D>, D>| {
        let d = fclone(minfo);
        let running = d.is_session_running()?;
        let rm = minfo.msg.method_return();
        let rm = rm.append1(running);
        Ok(vec!(rm))
    };
    let m = factory.method("IsSessionRunning", Default::default(), h);
    let m = m.out_arg(("running", "b"));
    let i = i.add_m(m);

    let fclone = f.clone();
    let h = move |minfo: &tree::MethodInfo<tree::MTFn<D>, D>| {
        let d = fclone(minfo);
        d.request_shutdown()?;
        let rm = minfo.msg.method_return();
        Ok(vec!(rm))
    };
    let m = factory.method("RequestShutdown", Default::default(), h);
    let i = i.add_m(m);

    let fclone = f.clone();
    let h = move |minfo: &tree::MethodInfo<tree::MTFn<D>, D>| {
        let d = fclone(minfo);
        d.request_reboot()?;
        let rm = minfo.msg.method_return();
        Ok(vec!(rm))
    };
    let m = factory.method("RequestReboot", Default::default(), h);
    let i = i.add_m(m);

    let p = factory.property::<&str, _>("SessionName", Default::default());
    let p = p.access(tree::Access::Read);
    let fclone = f.clone();
    let p = p.on_get(move |a, pinfo| {
        let minfo = pinfo.to_method_info();
        let d = fclone(&minfo);
        a.append(d.get_session_name()?);
        Ok(())
    });
    let i = i.add_p(p);

    let p = factory.property::<&str, _>("Renderer", Default::default());
    let p = p.access(tree::Access::Read);
    let fclone = f.clone();
    let p = p.on_get(move |a, pinfo| {
        let minfo = pinfo.to_method_info();
        let d = fclone(&minfo);
        a.append(d.get_renderer()?);
        Ok(())
    });
    let i = i.add_p(p);

    let p = factory.property::<bool, _>("SessionIsActive", Default::default());
    let p = p.access(tree::Access::Read);
    let fclone = f.clone();
    let p = p.on_get(move |a, pinfo| {
        let minfo = pinfo.to_method_info();
        let d = fclone(&minfo);
        a.append(d.get_session_is_active()?);
        Ok(())
    });
    let i = i.add_p(p);

    let p = factory.property::<u32, _>("InhibitedActions", Default::default());
    let p = p.access(tree::Access::Read);
    let fclone = f.clone();
    let p = p.on_get(move |a, pinfo| {
        let minfo = pinfo.to_method_info();
        let d = fclone(&minfo);
        a.append(d.get_inhibited_actions()?);
        Ok(())
    });
    let i = i.add_p(p);
    let s = factory.signal("ClientAdded", Default::default());
    let s = s.arg(("id", "o"));
    let i = i.add_s(s);
    let s = factory.signal("ClientRemoved", Default::default());
    let s = s.arg(("id", "o"));
    let i = i.add_s(s);
    let s = factory.signal("InhibitorAdded", Default::default());
    let s = s.arg(("id", "o"));
    let i = i.add_s(s);
    let s = factory.signal("InhibitorRemoved", Default::default());
    let s = s.arg(("id", "o"));
    let i = i.add_s(s);
    let s = factory.signal("SessionRunning", Default::default());
    let i = i.add_s(s);
    let s = factory.signal("SessionOver", Default::default());
    let i = i.add_s(s);
    i
}

#[derive(Debug, Default)]
pub struct OrgGnomeSessionManagerClientAdded {
    pub id: dbus::Path<'static>,
}

impl dbus::SignalArgs for OrgGnomeSessionManagerClientAdded {
    const NAME: &'static str = "ClientAdded";
    const INTERFACE: &'static str = "org.gnome.SessionManager";
    fn append(&self, i: &mut arg::IterAppend) {
        arg::RefArg::append(&self.id, i);
    }
    fn get(&mut self, i: &mut arg::Iter) -> Result<(), arg::TypeMismatchError> {
        self.id = i.read()?;
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct OrgGnomeSessionManagerClientRemoved {
    pub id: dbus::Path<'static>,
}

impl dbus::SignalArgs for OrgGnomeSessionManagerClientRemoved {
    const NAME: &'static str = "ClientRemoved";
    const INTERFACE: &'static str = "org.gnome.SessionManager";
    fn append(&self, i: &mut arg::IterAppend) {
        arg::RefArg::append(&self.id, i);
    }
    fn get(&mut self, i: &mut arg::Iter) -> Result<(), arg::TypeMismatchError> {
        self.id = i.read()?;
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct OrgGnomeSessionManagerInhibitorAdded {
    pub id: dbus::Path<'static>,
}

impl dbus::SignalArgs for OrgGnomeSessionManagerInhibitorAdded {
    const NAME: &'static str = "InhibitorAdded";
    const INTERFACE: &'static str = "org.gnome.SessionManager";
    fn append(&self, i: &mut arg::IterAppend) {
        arg::RefArg::append(&self.id, i);
    }
    fn get(&mut self, i: &mut arg::Iter) -> Result<(), arg::TypeMismatchError> {
        self.id = i.read()?;
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct OrgGnomeSessionManagerInhibitorRemoved {
    pub id: dbus::Path<'static>,
}

impl dbus::SignalArgs for OrgGnomeSessionManagerInhibitorRemoved {
    const NAME: &'static str = "InhibitorRemoved";
    const INTERFACE: &'static str = "org.gnome.SessionManager";
    fn append(&self, i: &mut arg::IterAppend) {
        arg::RefArg::append(&self.id, i);
    }
    fn get(&mut self, i: &mut arg::Iter) -> Result<(), arg::TypeMismatchError> {
        self.id = i.read()?;
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct OrgGnomeSessionManagerSessionRunning {
}

impl dbus::SignalArgs for OrgGnomeSessionManagerSessionRunning {
    const NAME: &'static str = "SessionRunning";
    const INTERFACE: &'static str = "org.gnome.SessionManager";
    fn append(&self, _: &mut arg::IterAppend) {
    }
    fn get(&mut self, _: &mut arg::Iter) -> Result<(), arg::TypeMismatchError> {
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct OrgGnomeSessionManagerSessionOver {
}

impl dbus::SignalArgs for OrgGnomeSessionManagerSessionOver {
    const NAME: &'static str = "SessionOver";
    const INTERFACE: &'static str = "org.gnome.SessionManager";
    fn append(&self, _: &mut arg::IterAppend) {
    }
    fn get(&mut self, _: &mut arg::Iter) -> Result<(), arg::TypeMismatchError> {
        Ok(())
    }
}