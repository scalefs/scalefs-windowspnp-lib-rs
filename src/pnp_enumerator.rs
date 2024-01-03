// Copyright (c) ScaleFS LLC; used with permission
// Licensed under the MIT License

use crate::{
    EnumerateError,
    EnumerateOption,
    EnumerateSpecifier,
    PnpDeviceNodeInfo,
    PnpDevicePropertyKey,
    PnpDevicePropertyValue,
};
use scalefs_common::win32_utils;
use scalefs_primitives::defer;
use std::collections::HashMap;
use windows::{
    Win32::Devices::DeviceAndDriverInstallation::{
        DIGCF_ALLCLASSES, DIGCF_DEVICEINTERFACE, DIGCF_PRESENT,
    },
    Win32::Foundation::{
        ERROR_INVALID_DATA, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS,
    },
};
use windows_sys::{
    core::GUID,
    Win32::Devices::DeviceAndDriverInstallation::{
        HDEVINFO,
        SP_DEVINFO_DATA,
        SetupDiDestroyDeviceInfoList, 
        SetupDiEnumDeviceInfo,
        SetupDiGetClassDevsW,
        SetupDiGetDeviceInstanceIdW,
    },
    Win32::Foundation::INVALID_HANDLE_VALUE,
};

pub struct PnpEnumerator {
}
//
impl PnpEnumerator {
    pub fn enumerate_present_devices() -> Result<Vec<PnpDeviceNodeInfo>, EnumerateError> {
        let options = vec![EnumerateOption::IncludeInstanceProperties, EnumerateOption::IncludeDeviceInterfaceProperties, EnumerateOption::IncludeSetupClassProperties, EnumerateOption::IncludeDeviceInterfaceClassProperties];
        
        PnpEnumerator::enumerate_present_devices_with_options(EnumerateSpecifier::AllDevices, options)
    }
    //
    pub fn enumerate_present_devices_by_device_interface_class(device_interface_class_guid: GUID) -> Result<Vec<PnpDeviceNodeInfo>, EnumerateError> {
        let options = vec![EnumerateOption::IncludeInstanceProperties, EnumerateOption::IncludeDeviceInterfaceProperties, EnumerateOption::IncludeSetupClassProperties, EnumerateOption::IncludeDeviceInterfaceClassProperties];
        return PnpEnumerator::enumerate_present_devices_with_options(EnumerateSpecifier::DeviceInterfaceClassGuid(device_interface_class_guid), options);
    }
    //
    pub fn enumerate_present_devices_by_device_setup_class(device_setup_class_guid: GUID) -> Result<Vec<PnpDeviceNodeInfo>, EnumerateError> {
        let options = vec![EnumerateOption::IncludeInstanceProperties, EnumerateOption::IncludeDeviceInterfaceProperties, EnumerateOption::IncludeSetupClassProperties, EnumerateOption::IncludeDeviceInterfaceClassProperties];
        return PnpEnumerator::enumerate_present_devices_with_options(EnumerateSpecifier::DeviceSetupClassGuid(device_setup_class_guid), options);
    }
    //
    pub fn enumerate_present_devices_by_pnp_enumerator_id(pnp_enumerator_id: &str) -> Result<Vec<PnpDeviceNodeInfo>, EnumerateError> {
        let options = vec![EnumerateOption::IncludeInstanceProperties, EnumerateOption::IncludeDeviceInterfaceProperties, EnumerateOption::IncludeSetupClassProperties, EnumerateOption::IncludeDeviceInterfaceClassProperties];
        return PnpEnumerator::enumerate_present_devices_with_options(EnumerateSpecifier::PnpEnumeratorId(pnp_enumerator_id.to_string()), options);
    }
    //
    pub fn enumerate_present_devices_with_options(enumerate_specifier: EnumerateSpecifier, options: Vec<EnumerateOption>) -> Result<Vec<PnpDeviceNodeInfo>, EnumerateError> {
        let mut result = Vec::<PnpDeviceNodeInfo>::new();

        // configure our variables based on the enumerate specifier
        //
        let pnp_enumerator: Option<String>;
        let class_guid: Option<*const GUID>;
        let device_interface_class_guid: Option<*const GUID>;
        let mut flags = DIGCF_PRESENT;
        match enumerate_specifier {
            EnumerateSpecifier::AllDevices => {
                pnp_enumerator = None;
                class_guid = None;
                device_interface_class_guid = None;
                flags |= DIGCF_ALLCLASSES;
            },
            EnumerateSpecifier::DeviceInterfaceClassGuid(interface_class_guid) => {
                pnp_enumerator = None;
                class_guid = Some(&interface_class_guid);
                device_interface_class_guid = Some(&interface_class_guid);
                flags |= DIGCF_DEVICEINTERFACE;
            },
            EnumerateSpecifier::DeviceSetupClassGuid(setup_class_guid) => {
                pnp_enumerator = None;
                class_guid = Some(&setup_class_guid);
                device_interface_class_guid = None;
                // flags |= 0;
            },
            EnumerateSpecifier::PnpDeviceInstanceId(ref instance_id, optional_interface_class_guid) => {
                pnp_enumerator = Some(instance_id.clone());
                class_guid = None;
                device_interface_class_guid = match optional_interface_class_guid {
                    Some(value) => Some(&value),
                    None => None,
                };
                flags |= DIGCF_DEVICEINTERFACE | DIGCF_ALLCLASSES;
            },
            EnumerateSpecifier::PnpEnumeratorId(ref enumerator_id) => {
                pnp_enumerator = Some(enumerator_id.clone());
                class_guid = None;
                device_interface_class_guid = None;
                flags |= DIGCF_ALLCLASSES;
            }
        };

        // parse options
        //
        let mut include_instance_properties = false;
        let mut include_device_interface_class_properties = false;
        let mut include_device_interface_properties = false;
        let mut include_setup_class_properties = false;
        for option in options {
            match option {
                EnumerateOption::IncludeInstanceProperties => {
                    include_instance_properties = true;
                },
                EnumerateOption::IncludeDeviceInterfaceClassProperties => {
                    include_device_interface_class_properties = true;    
                },
                EnumerateOption::IncludeDeviceInterfaceProperties => {
                    include_device_interface_properties = true;
                },
                EnumerateOption::IncludeSetupClassProperties => {
                    include_setup_class_properties = true;
                },
            }
        }

        // see: https://docs.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetclassdevsw
        // NOTE: due to the way that the SetupDiGetClassDevsW is declared in windows-rs, we need to pass it a PCWSTR which wraps a Vec<u16>; since the underlying vector cannot be garbage collected before the PCWSTR is used, we create it here (in this scope)
        let pnp_enumerator_as_utf16_chars: Vec<u16>; // NOTE: critically, we create the utf16 chars vector here so that it remains in scope during this function call (i.e. after we create a pointer to it). 
                                                     //       DO NOT move this variable into the "let pnp_enumerator_as_pwstr = match" block
        let pnp_enumerator_as_pwstr = match pnp_enumerator {
            Some(value) => {
                pnp_enumerator_as_utf16_chars = (value + "\0").encode_utf16().collect(); // NOTE: critically, we assign the underlying vector to a variable which will remain in scope during this function call
                pnp_enumerator_as_utf16_chars.as_ptr()
            },
            None => {
                std::ptr::null()
            }
        };
        //        
        let handle_to_device_info_set: HDEVINFO;
        if let Some(some_class_guid) = class_guid {
            handle_to_device_info_set = unsafe { SetupDiGetClassDevsW(some_class_guid, pnp_enumerator_as_pwstr, 0, flags) };
        } else {
            handle_to_device_info_set = unsafe { SetupDiGetClassDevsW(std::ptr::null_mut(), pnp_enumerator_as_pwstr, 0, flags) };
        }
        if handle_to_device_info_set as isize == INVALID_HANDLE_VALUE {
            let win32_error = win32_utils::get_last_error_as_win32_error();
            return Err(EnumerateError::Win32Error(win32_error.0));
        }
        //
        // NOTE: we must clean up the device info set created by SetupDiGetClassDevsW; we do that here via the defer macro within a scoped block
        {
            defer! {
                let destroy_result = unsafe { SetupDiDestroyDeviceInfoList(handle_to_device_info_set) };
                debug_assert!(destroy_result != 0, "Could not clean up device info set; win32 error: {}", win32_utils::get_last_error_as_win32_error().0);
            }

            // enumerate all the devices in the device info set
            // NOTE: we use a for loop here, but we intend to exit it early once we find the final device; the upper bound is simply a maximum placeholder; we use this construct so that device_index auto-increments each iteration (even if we call 'continue')
            for device_index in 0..u32::MAX {
                // capture the device info data for this device; we'll extract several pieces of information from this data set
                //
                let mut devinfo_data: SP_DEVINFO_DATA = SP_DEVINFO_DATA { cbSize: 0, ClassGuid: GUID::from_u128(0), DevInst: 0, Reserved: 0 };
                devinfo_data.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;
                //
                // see: https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdienumdeviceinfo
                let enum_device_info_result = unsafe { SetupDiEnumDeviceInfo(handle_to_device_info_set, device_index, &mut devinfo_data) };
                if enum_device_info_result == 0 {
                    let win32_error = win32_utils::get_last_error_as_win32_error();
                    if win32_error == ERROR_NO_MORE_ITEMS {
                        // if we are out of items to enumerate, break out of the loop now
                        break;
                    }

                    return Err(EnumerateError::Win32Error(win32_error.0));
                }

                // using the device info data, capture the device instance ID for this device
                let device_instance_id = match get_device_instance_id_from_devinfo_data(handle_to_device_info_set, &devinfo_data) {
                    Ok(value) => value,
                    Err(GetDeviceInstanceIdFromDevinfoDataError::StringDecodingError(decoding_error)) => {
                        debug_assert!(false, "Invalid string encoding when attempting to get the device instance id");
                        return Err(EnumerateError::StringDecodingError(decoding_error));
                    },
                    Err(GetDeviceInstanceIdFromDevinfoDataError::Win32Error(win32_error)) => {
                        return Err(EnumerateError::Win32Error(win32_error));
                    },
                };

                //
                //
                //
                //
                //
                // TODO: capture values for all the other PnpDeviceNodeInfo elements; in the meantime, here are empty fillers
                let container_id: Option<String> = None;
                let device_instance_properties: Option<HashMap<PnpDevicePropertyKey, PnpDevicePropertyValue>> = None;
                let device_setup_class_properties: Option<HashMap<PnpDevicePropertyKey, PnpDevicePropertyValue>> = None;
                let device_path: Option<String> = None;
                let device_interface_properties: Option<HashMap<PnpDevicePropertyKey, PnpDevicePropertyValue>> = None;
                let device_interface_class_properties: Option<HashMap<PnpDevicePropertyKey, PnpDevicePropertyValue>> = None;
                //
                //
                //
                //
                //

                // add this device node's info to our result vector
                let device_node_info = PnpDeviceNodeInfo {
                    device_instance_id,
                    container_id,
                    //
                    // device instance properties (optional; these should be available for all devices)
                    device_instance_properties,
                    //
                    // device setup class properties (optional, as they only apply to devnodes with device class guids)
                    device_setup_class_properties,
                    //
                    // interface properties (optional, as they only apply to device interfaces)
                    device_path,
                    device_interface_properties,
                    device_interface_class_properties,
                };
                result.push(device_node_info);
            }            
        }

        // return all of the device instances we found
        Ok(result)
    }
}

//

enum GetDeviceInstanceIdFromDevinfoDataError {
    StringDecodingError(/*error: */std::string::FromUtf16Error),
    Win32Error(/*win32_error: */u32),
}

fn get_device_instance_id_from_devinfo_data(handle_to_device_info_set: HDEVINFO, devinfo_data: &SP_DEVINFO_DATA) -> Result<String, GetDeviceInstanceIdFromDevinfoDataError> {
    // get the size of the device instance id, null-terminated, as a count of utf-16 characters; we'll get an error code of ERROR_INSUFFICIENT_BUFFER and the required_size prarameter will contain the required size
    // see: https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceinstanceidw
    let mut required_size: u32 = 0;
    let get_device_instance_id_result = unsafe { SetupDiGetDeviceInstanceIdW(handle_to_device_info_set, devinfo_data, std::ptr::null_mut() /* null */, 0, &mut required_size) };
    if get_device_instance_id_result == 0 {
        let win32_error = win32_utils::get_last_error_as_win32_error();
        if win32_error == ERROR_INSUFFICIENT_BUFFER {
            // this is the expected error (i.e. the error we intentionally induced); continue
        } else {
            // otherwise, return the error to our caller
            return Err(GetDeviceInstanceIdFromDevinfoDataError::Win32Error(win32_error.0));
        }
    } else {
        debug_assert!(false, "SetupDiGetDeviceInstanceIdW returned success when we asked it for the required buffer size; it should always return false in this circumstance (since device ids are null terminated and can therefore never be zero bytes in length)");
        return Err(GetDeviceInstanceIdFromDevinfoDataError::Win32Error(ERROR_INVALID_DATA.0));
    }
    //
    if required_size == 0 {
        debug_assert!(false, "Device instance ID has zero bytes (and is required to have at least one byte...the null terminator); aborting.");
        return Err(GetDeviceInstanceIdFromDevinfoDataError::Win32Error(ERROR_INVALID_DATA.0));
    }
    //
    // allocate memory for the device instance id via a zeroed utf16 vector; then create a PWSTR instance which uses that vector as its mutable data region
    let mut device_instance_id_as_utf16_chars = Vec::<u16>::with_capacity(required_size as usize);
    device_instance_id_as_utf16_chars.resize(device_instance_id_as_utf16_chars.capacity(), 0);
    let device_instance_id_as_pwstr = device_instance_id_as_utf16_chars.as_mut_ptr();
    //
    // get the device instance id as a PWSTR
    // see: https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceinstanceidw
    let get_device_instance_id_result = unsafe { SetupDiGetDeviceInstanceIdW(handle_to_device_info_set, devinfo_data, device_instance_id_as_pwstr, required_size, std::ptr::null_mut()) };
    if get_device_instance_id_result == 0 {
        let win32_error = win32_utils::get_last_error_as_win32_error();
        return Err(GetDeviceInstanceIdFromDevinfoDataError::Win32Error(win32_error.0));
    }
    // NOTE: the device instance id is null-terminated, so we omit the final character (e.g. '\0')
    let device_instance_id = match String::from_utf16(&device_instance_id_as_utf16_chars[0..((required_size as usize) - 1)]) {
        Ok(value) => value,
        Err(decoding_error) => {
            return Err(GetDeviceInstanceIdFromDevinfoDataError::StringDecodingError(decoding_error));
        }
    };

    Ok(device_instance_id)
}

