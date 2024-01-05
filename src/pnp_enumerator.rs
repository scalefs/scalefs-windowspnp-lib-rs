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
use scalefs_uuid::Uuid;
use std::collections::HashMap;
use std::str::FromStr;
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
        SPDRP_BASE_CONTAINERID,
        HDEVINFO,
        SP_DEVINFO_DATA,
        SetupDiDestroyDeviceInfoList, 
        SetupDiEnumDeviceInfo,
        SetupDiGetClassDevsW,
        SetupDiGetDeviceInstanceIdW,
        SetupDiGetDeviceRegistryPropertyW,
    },
    Win32::Devices::Properties::{
        DEVPROP_TYPE_BYTE,
        DEVPROP_TYPE_BOOLEAN,
        DEVPROP_TYPE_GUID,
        DEVPROP_TYPE_SECURITY_DESCRIPTOR_STRING,
        DEVPROP_TYPE_STRING,
        DEVPROP_TYPE_UINT16,
        DEVPROP_TYPE_UINT32,
        DEVPROP_TYPEMOD_ARRAY,
        DEVPROP_TYPEMOD_LIST,
        MAX_DEVPROP_TYPE,
        MAX_DEVPROP_TYPEMOD,
        DEVPROPTYPE,
    },
    Win32::Foundation::INVALID_HANDLE_VALUE,
    Win32::System::Registry::{
        REG_DWORD,
        REG_MULTI_SZ,
        REG_SZ,
        REG_VALUE_TYPE
    },
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

                // for all devices: capture the base container id of the device
                //
                // NOTE: we could probably also get this data using the modern setup API by retrieving the device instance property "DEVPKEY_Device_BaseContainerId"...which might be preferable to using the legacy device registry property value mechanism; note that its type is GUID instead of String
                // NOTE: SPDRP_BASE_CONTAINERID is not listed as an allowed property at https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceregistrypropertyw -- this may be an additional reason to look at transitioning this call to the modern setup API
                let base_container_id_as_string = match get_device_registry_property_value(handle_to_device_info_set, &mut devinfo_data, SPDRP_BASE_CONTAINERID) {
                    Ok(value) => {
                        match value {
                            PnpDevicePropertyValue::String(value_as_string) => value_as_string,
                            _ => {
                                debug_assert!(false, "get_device_registry_property_value returned a non-string value for SPDRP_BASE_CONTAINERID");
                                return Err(EnumerateError::Win32Error(ERROR_INVALID_DATA.0));
                            },
                        }
                    },
                    Err(GetDevicePropertyValueError::StringDecodingError(decoding_error)) => {
                        return Err(EnumerateError::StringDecodingError(decoding_error));
                    },
                    Err(GetDevicePropertyValueError::StringListTerminationError) => {
                        debug_assert!(false, "BUG: Win32 setupapi's list of strings was not properly terminated with an extra null terminator.");
                        return Err(EnumerateError::StringTerminationDecodingError);
                    },
                    Err(GetDevicePropertyValueError::StringTerminationError) => {
                        debug_assert!(false, "BUG: Win32 setupapi's string (or final string in a list of strings) was not properly terminated with a null terminator.");
                        return Err(EnumerateError::StringTerminationDecodingError);
                    },
                    Err(GetDevicePropertyValueError::Win32Error(win32_error)) => {
                        return Err(EnumerateError::Win32Error(win32_error));
                    },
                };
                let base_container_id: Option<Uuid> = match Uuid::from_str(&base_container_id_as_string) {
                    Ok(base_container_id_as_uuid) => {
                        if base_container_id_as_uuid.is_nil_uuid() == false {
                            Some(base_container_id_as_uuid) 
                        } else {
                            // a zeroed GUID value indicates that there is no container
                            // see: https://learn.microsoft.com/en-us/windows-hardware/drivers/install/overview-of-container-ids
                            None
                        }
                    },
                    Err(_) => {
                        debug_assert!(false, "get_device_registry_property_value returned an invalid (non-Guid) string value for SPDRP_BASE_CONTAINERID");
                        return Err(EnumerateError::Win32Error(ERROR_INVALID_DATA.0));
                    },
                };

                //
                //
                //
                //
                //
                // TODO: capture values for all the other PnpDeviceNodeInfo elements; in the meantime, here are empty fillers
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
                    base_container_id,
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

//

pub enum GetDevicePropertyValueError {
    StringListTerminationError,
    StringDecodingError(/*error: */std::string::FromUtf16Error),
    StringTerminationError,
    Win32Error(/*win32_error: */u32),
}

fn check_setup_di_get_device_xxx_property_required_size_result(setup_di_get_device_xxx_property_result: i32, required_size: u32) -> Result<(), GetDevicePropertyValueError> {
    if setup_di_get_device_xxx_property_result == 0 {
        let win32_error = win32_utils::get_last_error_as_win32_error();
        match win32_error {
            ERROR_INSUFFICIENT_BUFFER => {
                // this is the expected error condition; we'll resize our buffer to match required_size
            },
            _ => {
                return Err(GetDevicePropertyValueError::Win32Error(win32_error.0));
            }
        }
    } else {
        // we don't expect the operation to succeed with a null buffer and zero-length buffer size.
        debug_assert!(false, "SetupDiGetDeviceXXXPropertyResultW succeeded, even though we passed it no buffer.");

        // return an error if requiredSize is non-zero; otherwise, continue with the understanding that the property has a size of zero
        if required_size > 0 {
            return Err(GetDevicePropertyValueError::Win32Error(ERROR_INVALID_DATA.0));
        }
    }

    Ok(())
}

//

fn get_device_registry_property_value(device_info_set: HDEVINFO, device_info_data: *mut SP_DEVINFO_DATA, property_key: u32) -> Result<PnpDevicePropertyValue, GetDevicePropertyValueError> {
    // get the type and size of the device interface property
    // see: https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceregistrypropertyw
    let mut property_registry_data_type_as_u32: u32 = 0;
    let mut required_size: u32 = 0;
    let get_device_registry_property_result = unsafe { SetupDiGetDeviceRegistryPropertyW(device_info_set, device_info_data, property_key, &mut property_registry_data_type_as_u32, std::ptr::null_mut(), 0, &mut required_size) };
    if let Err(error) = check_setup_di_get_device_xxx_property_required_size_result(get_device_registry_property_result, required_size) {
        return Err(error);
    }

    // retrieve the property
    let mut property_buffer = Vec::<u8>::with_capacity(required_size as usize);
    property_buffer.resize(property_buffer.capacity(), 0);
    //
    let get_device_registry_property_result = unsafe { SetupDiGetDeviceRegistryPropertyW(device_info_set, device_info_data, property_key, &mut property_registry_data_type_as_u32, property_buffer.as_mut_ptr() as *mut u8, required_size, std::ptr::null_mut()) };
    if get_device_registry_property_result == 0 {
        let win32_error = win32_utils::get_last_error_as_win32_error();
        return Err(GetDevicePropertyValueError::Win32Error(win32_error.0));
    }

    // map the registry property type to the modern "Windows Vista" device property data type
    let property_type = match property_registry_data_type_as_u32 as REG_VALUE_TYPE {
        REG_DWORD => {
            DEVPROP_TYPE_UINT32
        },
        REG_MULTI_SZ => {
            DEVPROP_TYPE_STRING | DEVPROP_TYPEMOD_LIST
        },
        REG_SZ => {
            DEVPROP_TYPE_STRING
        },
        _ => {
            debug_assert!(false, "Unknown registry data type; consider supporting this registry data type");
            return Ok(PnpDevicePropertyValue::UnsupportedRegistryDataType(property_registry_data_type_as_u32));
        }
    };

    // convert the property buffer into a property value
    let property_value = match convert_property_buffer_into_device_property_value(property_buffer, property_type) {
        Ok(value) => {
            // NOTE: as we are reusing the convert_property_buffer_into_device_property_value function (i.e. using the DevicePropertyValue's function for DeviceRegistryPropertyValues), we need to remap the "unsupported data type" back to the actual registry data type
            match value {
                PnpDevicePropertyValue::UnsupportedPropertyDataType(_) => PnpDevicePropertyValue::UnsupportedRegistryDataType(property_registry_data_type_as_u32),
                _ => value,
            }
        },
        Err(err) => return Err(err),
    };

    Ok(property_value)
}

//

fn convert_property_buffer_into_device_property_value(property_buffer: Vec<u8>, property_type_as_u32: u32) -> Result<PnpDevicePropertyValue, GetDevicePropertyValueError> {
    let property_buffer_length = property_buffer.len();

    let mut property_value_is_array = false;
    let mut property_value_is_list = false;
    //
    let property_type_mask = calculate_mask_to_fit_value(MAX_DEVPROP_TYPE);
    let property_type_mods_mask = property_type_mask ^ calculate_mask_to_fit_value(MAX_DEVPROP_TYPEMOD);
    //
    // extract the property type modifier (if any) from the passed-in property type
    let property_type_mod = property_type_as_u32 & property_type_mods_mask;
    //
    // strip any specified mod from the property type value
    let property_type_without_mods = (property_type_as_u32 & property_type_mask) as DEVPROPTYPE;

    match property_type_mod {
        0 => {
            // no mods
        },
        DEVPROP_TYPEMOD_ARRAY => {
            // see: https://docs.microsoft.com/en-us/windows-hardware/drivers/install/devprop-typemod-array
            match property_type_without_mods {
                DEVPROP_TYPE_BYTE |
                DEVPROP_TYPE_BOOLEAN |
                DEVPROP_TYPE_GUID |
                DEVPROP_TYPE_UINT16 | 
                DEVPROP_TYPE_UINT32 => {
                    // these fixed-size value types are allowed
                    property_value_is_array = true;
                },
                _ => {
                    // no other types are allowed
                    debug_assert!(false, "Device type mod should only be applied to fixed-size value types; do we have a new fixed-size value type to handle?");
                    return Ok(PnpDevicePropertyValue::UnsupportedPropertyDataType(property_type_as_u32));
                }
            }
        },
        DEVPROP_TYPEMOD_LIST => {
            // see: https://docs.microsoft.com/en-us/windows-hardware/drivers/install/devprop-typemod-list
            match property_type_without_mods {
                DEVPROP_TYPE_STRING |
                DEVPROP_TYPE_SECURITY_DESCRIPTOR_STRING => {
                    // these string types are allowed
                    property_value_is_list = true;
                },
                _ => {
                    // no other types are allowed
                    debug_assert!(false, "Device type mod should only be applied to string types; do we have a new string type to handle?");
                    return Ok(PnpDevicePropertyValue::UnsupportedPropertyDataType(property_type_as_u32));
                }
            }
        },
        _ => {
            // if there are any property type mods which we don't handle, return UnsupportedPropertyDataType (and assert during debug, so we know there are new mods to handle)
            debug_assert!(false, "Unhandled device type mod");
            return Ok(PnpDevicePropertyValue::UnsupportedPropertyDataType(property_type_as_u32));
        }
    }

    // NOTE: all of the fixed-sized value types follow the same pattern (i.e. is or is not array, fixed-size data copied from a byte buffer, wrapped and returned as an PnpDevicePropertyValue) so we wrap up the common functionality in a named closure (and let it use a type-specific named closure to do the value parsing)
    let create_return_value_for_fixed_size_property_closure = |fixed_size_of_value_type: usize, property_value_is_array: bool, buffer_to_pnp_device_property_value_closure: fn(&[u8]) -> PnpDevicePropertyValue | { 
        if property_value_is_array == true {
            if property_buffer_length % fixed_size_of_value_type != 0 { 
                debug_assert!(false, "Invalid property value size");
                return Err(GetDevicePropertyValueError::Win32Error(ERROR_INVALID_DATA.0));
            }

            let mut array_of_property_values = Vec::<PnpDevicePropertyValue>::new();
            for property_buffer_chunk in property_buffer.chunks(fixed_size_of_value_type) {
                array_of_property_values.push(buffer_to_pnp_device_property_value_closure(&property_buffer_chunk));
            }

            Ok(PnpDevicePropertyValue::ArrayOfValues(array_of_property_values))
        } else {
            if property_buffer_length != fixed_size_of_value_type { 
                debug_assert!(false, "Invalid property value size");
                return Err(GetDevicePropertyValueError::Win32Error(ERROR_INVALID_DATA.0));
            }

            Ok(buffer_to_pnp_device_property_value_closure(&property_buffer))
        }
    };

    match property_type_without_mods {
        DEVPROP_TYPE_BYTE => {
            let fixed_size_of_value_type = 1;

            let buffer_to_pnp_device_property_value_closure = |buffer: &[u8]| {
                // convert the byte array to a uint8
                let value = buffer[0];
                return PnpDevicePropertyValue::Byte(value);
            };

            create_return_value_for_fixed_size_property_closure(fixed_size_of_value_type, property_value_is_array, buffer_to_pnp_device_property_value_closure)
        },
        DEVPROP_TYPE_BOOLEAN => {
            let fixed_size_of_value_type = 1;

            let buffer_to_pnp_device_property_value_closure = |buffer: &[u8]| {
                // convert the byte array to a bool
                let value = buffer[0] != 0;
                return PnpDevicePropertyValue::Boolean(value);
            };

            create_return_value_for_fixed_size_property_closure(fixed_size_of_value_type, property_value_is_array, buffer_to_pnp_device_property_value_closure)
        },
        DEVPROP_TYPE_GUID => {
            let fixed_size_of_value_type = 16;

            let buffer_to_pnp_device_property_value_closure = |buffer: &[u8]| {
                // convert the byte array to a guid (using native endian)
                let value = Uuid { 
                    data1: u32::from_ne_bytes(buffer[0..=3].try_into().ok().unwrap()), 
                    data2: u16::from_ne_bytes(buffer[4..=5].try_into().ok().unwrap()), 
                    data3: u16::from_ne_bytes(buffer[6..=7].try_into().ok().unwrap()), 
                    data4: buffer[8..=15].try_into().unwrap()
                };
                return PnpDevicePropertyValue::Guid(value);
            };    

            create_return_value_for_fixed_size_property_closure(fixed_size_of_value_type, property_value_is_array, buffer_to_pnp_device_property_value_closure)
        },
        DEVPROP_TYPE_STRING => {
            if property_buffer_length % 2 != 0 {
                debug_assert!(false, "Invalid property value size");
                return Err(GetDevicePropertyValueError::Win32Error(ERROR_INVALID_DATA.0));
            }

            let mut property_value_as_utf16_chars = Vec::<u16>::with_capacity(property_buffer_length / 2);
            for index in 0..property_value_as_utf16_chars.capacity() {
                let element: [u8; 2] = property_buffer[(2*index)..=(2*index)+1].try_into().ok().unwrap();
                property_value_as_utf16_chars.push(u16::from_ne_bytes(element));
            }

            if property_value_as_utf16_chars.len() == 0 {
                debug_assert!(false, "Invalid property value size; strings and string lists must be null-terminated");
                return Err(GetDevicePropertyValueError::Win32Error(ERROR_INVALID_DATA.0));
            }

            if property_value_is_list == true {
                // NOTE: this list is effectively a REG_MULTI_SZ; it has a final null terminator which terminates the list (and should not be interpreted as an empty string)
                match property_value_as_utf16_chars.pop() {
                    Some(0/*'\0'*/) => {
                        // this is the correct terminator value; proceed
                    },
                    _ => {
                        // if the last character was not a null terminator, return an error
                        return Err(GetDevicePropertyValueError::StringListTerminationError);
                    }
                }

                // NOTE: if the list is not an empty list, the final string must be null terminated
                if property_value_as_utf16_chars.len() > 0 {
                    // NOTE: we are not removing the final character at this time; we're just verifying that the last string in the list is indeed null-terminated
                    match property_value_as_utf16_chars.last() {
                        Some(0/*'\0'*/) => {
                            // this is the correct terminator value; proceed
                        },
                        _ => {
                            // if the last character was not a null terminator, return an error
                            return Err(GetDevicePropertyValueError::StringTerminationError);
                        }
                    }    
                }

                // list of null-terminated strings, separated by their null terminators
                let mut list_of_strings = Vec::<PnpDevicePropertyValue>::new();

                // NOTE: this function relies on the fact that the last string should also be null-terminated
                let mut current_string_as_utf16_chars = Vec::<u16>::new();
                for utf16_char in property_value_as_utf16_chars {
                    current_string_as_utf16_chars.push(utf16_char);

                    if utf16_char == 0x00 /*'\0'*/ {
                        // convert the utf16 char vector to a string
                        let utf16_chars_as_string = match String::from_utf16(&current_string_as_utf16_chars[0..(current_string_as_utf16_chars.len() - 1)]) {
                            Ok(value) => value,
                            Err(decoding_error) => {
                                return Err(GetDevicePropertyValueError::StringDecodingError(decoding_error));
                            }
                        };

                        list_of_strings.push(PnpDevicePropertyValue::String(utf16_chars_as_string));

                        // reset our current string
                        current_string_as_utf16_chars = Vec::new();
                    }
                }

                Ok(PnpDevicePropertyValue::ListOfValues(list_of_strings))
            } else {
                // single null-terminated string

                match property_value_as_utf16_chars.last() {
                    Some(0/*'\0'*/) => {
                        // this is the correct terminator value; proceed
                    },
                    _ => {
                        // if the last character was not a null terminator, return an error
                        return Err(GetDevicePropertyValueError::StringTerminationError);
                    }
                }

                // convert the utf16 char vector to a string
                // NOTE: this is handling UTF-16 properly, but VSCode misprints some Unicode symbols incorrectly in the terminal window.  For instance, the text "Microsoft® 2.4GHz Transceiver v9.0" appears as "Microsoft┬« 2.4GHz Transceiver v9.0"--but this is only an artifact of VSCode.
                let property_buffer_as_string = match String::from_utf16(&property_value_as_utf16_chars[0..(property_value_as_utf16_chars.len() - 1)]) {
                    Ok(value) => value,
                    Err(decoding_error) => {
                        return Err(GetDevicePropertyValueError::StringDecodingError(decoding_error));
                    }
                };
            
                Ok(PnpDevicePropertyValue::String(property_buffer_as_string))
            }
        },
        DEVPROP_TYPE_UINT16 => {
            let fixed_size_of_value_type = 2;

            let buffer_to_pnp_device_property_value_closure = |buffer: &[u8]| {
                // convert the byte array to a uint16 (using native endian)
                let value = u16::from_ne_bytes(buffer[0..=1].try_into().ok().unwrap());
                return PnpDevicePropertyValue::UInt16(value);
            };

            create_return_value_for_fixed_size_property_closure(fixed_size_of_value_type, property_value_is_array, buffer_to_pnp_device_property_value_closure)
        },
        DEVPROP_TYPE_UINT32 => {
            let fixed_size_of_value_type = 4;

            let buffer_to_pnp_device_property_value_closure = |buffer: &[u8]| {
                // convert the byte array to a uint32 (using native endian)
                let value = u32::from_ne_bytes(buffer[0..=3].try_into().ok().unwrap());
                return PnpDevicePropertyValue::UInt32(value);
            };

            create_return_value_for_fixed_size_property_closure(fixed_size_of_value_type, property_value_is_array, buffer_to_pnp_device_property_value_closure)
        },
        _ => {
            Ok(PnpDevicePropertyValue::UnsupportedPropertyDataType(property_type_as_u32))
        }
    }
}

// NOTE: this function calculates a mask which will fit any value equal to or less than the supplied value; if the value is not a power of two (minus one)...then the mask will also cover any numbers up to the next power of two (minus one)
fn calculate_mask_to_fit_value(value: u32) -> u32 {
    let mut number_of_high_zero_bits = 0;
    for index in 0..=31 {
        if (value & (1 << (31 - index))) != 0 {
            break;
        }

        number_of_high_zero_bits += 1;
    }

    let result = 0xFFFF_FFFF_u32 >> number_of_high_zero_bits; 

    result
}
