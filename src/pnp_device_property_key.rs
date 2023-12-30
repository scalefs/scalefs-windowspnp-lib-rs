// Copyright (c) ScaleFS LLC; used with permission
// Licensed under the MIT License

// use windows::core::GUID;
use windows_sys::{
    // core::GUID,
    Win32::Devices::Properties::DEVPROPKEY,
    Win32::UI::Shell::PropertiesSystem::PROPERTYKEY,
};

#[derive(PartialEq, Eq, Hash)]
pub struct PnpDevicePropertyKey {
    pub fmtid: windows::core::GUID,
    pub pid: u32,
}
impl PnpDevicePropertyKey {
    pub fn to_devpropkey(&self) -> DEVPROPKEY {
        DEVPROPKEY {
            fmtid: windows_sys::core::GUID { data1: self.fmtid.data1, data2: self.fmtid.data2, data3: self.fmtid.data3, data4: self.fmtid.data4 },
            pid: self.pid
        }
    }
}
impl From<DEVPROPKEY> for PnpDevicePropertyKey {
    fn from(item: DEVPROPKEY) -> Self {
        PnpDevicePropertyKey {
            fmtid: windows::core::GUID::from_values(item.fmtid.data1, item.fmtid.data2, item.fmtid.data3, item.fmtid.data4),
            pid: item.pid
        }
    }
}
impl From<PROPERTYKEY> for PnpDevicePropertyKey {
    fn from(item: PROPERTYKEY) -> Self {
        let fmtid_windows_guid = windows::core::GUID { data1: item.fmtid.data1, data2: item.fmtid.data2, data3: item.fmtid.data3, data4: item.fmtid.data4 };

        PnpDevicePropertyKey {
            fmtid: fmtid_windows_guid, // item.fmtid,
            pid: item.pid
        }
    }
}

