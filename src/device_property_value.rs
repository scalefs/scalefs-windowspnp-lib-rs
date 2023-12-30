// Copyright (c) ScaleFS LLC; used with permission
// Licensed under the MIT License

use windows_sys::{
    core::GUID,
    Win32::Devices::Properties::DEVPROPTYPE,
    Win32::System::Registry::REG_VALUE_TYPE,
};

pub enum DevicePropertyValue {
    ArrayOfValues(/*array: */Vec<DevicePropertyValue>),
    Boolean(/*value: */bool),
    Byte(/*value: */u8),
    Guid(/*value: */GUID),
    ListOfValues(/*list: */Vec<DevicePropertyValue>),
    String(/*value: */String),
    UInt16(/*value: */u16),
    UInt32(/*value: */u32),
    UnsupportedPropertyDataType(/*property_data_type: */DEVPROPTYPE),
    UnsupportedRegistryDataType(/*registry_data_type: */REG_VALUE_TYPE),
}
