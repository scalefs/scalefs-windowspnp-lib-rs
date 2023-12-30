// Copyright (c) ScaleFS LLC; used with permission
// Licensed under the MIT License

use crate::{
    PnpDevicePropertyKey,
    PnpDevicePropertyValue,
};
use std::collections::HashMap;

pub struct PnpDeviceNodeInfo {
    // device instance id (applies to all devices)
    pub device_instance_id: String,
    // NOTE: the container_id is probably unique, but is _not_ guaranteed to be unique; see: https://techcommunity.microsoft.com/t5/microsoft-usb-blog/how-to-generate-a-container-id-for-a-usb-device-part-2/ba-p/270726
    // NOTE: the container_id should be available for virutally all devices, but perhaps _not_ for root hubs (and maybe not for hubs at all...TBD)
    pub container_id: Option<String>,
    //
    // device instance properties (optional; these should be available for all devices)
    pub device_instance_properties: Option<HashMap<PnpDevicePropertyKey, PnpDevicePropertyValue>>,
    //
    // device setup class properties (optional) (also, they are available for most devices but not ALL devices)
    pub device_setup_class_properties: Option<HashMap<PnpDevicePropertyKey, PnpDevicePropertyValue>>,
    //
    // device path (only applies to device interfaces; will be None otherwise)
    pub device_path: Option<String>,
    // interface properties (optional) (also, they only apply to device interfaces; will be None otherwise)
    pub device_interface_properties: Option<HashMap<PnpDevicePropertyKey, PnpDevicePropertyValue>>,
    // interface class properties (optional) (also, they only apply to device interfaces; will be None otherwise)
    pub device_interface_class_properties: Option<HashMap<PnpDevicePropertyKey, PnpDevicePropertyValue>>,
}
