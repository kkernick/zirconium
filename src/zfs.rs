//! This file contains the Bindings and Wrappers for libzfs.
#![allow(dead_code, clippy::missing_docs_in_private_items)]

use bstr::{BStr, BString};
use nix::{errno::Errno, unistd::pipe};
use spawn::{HandleError, SpawnError, Spawner, StreamMode};
use std::{
    ffi::{CStr, CString, NulError, c_char, c_int, c_void},
    io::{self, Write},
    ptr::{NonNull, null, null_mut},
    rc::Rc,
    thread::sleep,
    time::Duration,
};
use thiserror::Error;
use tss_esapi::structures::SensitiveData;

/// Specify a Filesystem/Dataset
const ZFS_TYPE_FILESYSTEM: c_int = 1 << 0;

/// Specify a Volume/Pool
const ZFS_TYPE_VOLUME: c_int = 1 << 2;

/// Raw libzfs handle
#[repr(C)]
struct LibZfsHandle {
    _private: [u8; 0],
}

/// Raw zfs handle
#[repr(C)]
struct ZfsHandle {
    _private: [u8; 0],
}

/// Raw zpool handle
#[repr(C)]
struct ZpoolHandle {
    _private: [u8; 0],
}

/// Raw `NvList` pointer
#[repr(C)]
struct NvList {
    _private: [u8; 0],
}

// We need to link with libnvpair.
#[link(name = "nvpair")]
unsafe extern "C" {}

// Raw bindings
#[link(name = "zfs")]
unsafe extern "C" {

    /// Initialize a handle for all libzfs operations.
    ///
    /// We use a Rc to reuse these as much as possible.
    fn libzfs_init() -> *mut LibZfsHandle;

    /// Cleanup the libzfs handle.
    fn libzfs_fini(hdl: *mut LibZfsHandle);

    /// Open a dataset/volume.
    fn zfs_open(hdl: *mut LibZfsHandle, name: *const c_char, types: c_int) -> *mut ZfsHandle;

    /// Close a dataset/volume.
    fn zfs_close(zhp: *mut ZfsHandle);

    /// Get the system property
    fn zfs_name_to_prop(name: *const c_char) -> c_int;

    /// Get the value of a property
    fn zfs_prop_get(
        zhp: *mut ZfsHandle,
        prop: c_int,
        propbuf: *mut c_char,
        proplen: usize,
        source: *mut c_int,
        statbuf: *mut c_char,
        statlen: usize,
        literal: c_int,
    ) -> c_int;

    /// Iterate across all pools
    fn zpool_iter(
        hdl: *mut LibZfsHandle,
        callback: unsafe extern "C" fn(zhp: *mut ZpoolHandle, data: *mut c_void) -> c_int,
        data: *mut c_void,
    ) -> c_int;

    /// Get the name of a dataset
    fn zfs_get_name(zhp: *const ZfsHandle) -> *const c_char;

    /// Iterate across all datasets
    fn zfs_iter_filesystems(
        zhp: *mut ZfsHandle,
        callback: unsafe extern "C" fn(child: *mut ZfsHandle, data: *mut c_void) -> c_int,
        data: *mut c_void,
    ) -> c_int;

    /// Get the name of a pool
    fn zpool_get_name(zhp: *mut ZpoolHandle) -> *const c_char;

    /// Close a pool
    fn zpool_close(zhp: *mut ZpoolHandle);

    /// Get user properties
    fn zfs_get_user_props(zhp: *mut ZfsHandle) -> *mut NvList;

    /// Lookup values in a `NvList`
    fn nvlist_lookup_nvlist(
        nvl: *const NvList,
        name: *const c_char,
        value: *mut *mut NvList,
    ) -> c_int;

    /// Lookup a key in a `NvList`
    fn nvlist_lookup_string(
        nvl: *const NvList,
        name: *const c_char,
        value: *mut *const c_char,
    ) -> c_int;

    /// Set a property
    fn zfs_prop_set(zhp: *mut ZfsHandle, propname: *const c_char, value: *const c_char) -> c_int;

    /// Set a user property
    fn zfs_prop_user(name: *const c_char) -> c_int;

    /// Import a pool using its discovered configuration.
    fn zpool_import(
        hdl: *mut LibZfsHandle,
        config: *mut NvList,
        newname: *const c_char,
        altroot: *mut c_char,
    ) -> c_int;

    /// Mount a dataset using its configured mountpoint.
    fn zfs_mount(zhp: *mut ZfsHandle, options: *const c_char, flags: c_int) -> c_int;

    /// Mount a dataset at an explicit path (useful for legacy mountpoints).
    fn zfs_mount_at(
        zhp: *mut ZfsHandle,
        options: *const c_char,
        flags: c_int,
        mountpoint: *const c_char,
    ) -> c_int;

    /// Check whether a dataset is mounted.
    fn zfs_is_mounted(zhp: *mut ZfsHandle, where_: *mut *mut c_char) -> c_int;

    /// Unmount a filesystem and applicable mounted descendants.
    fn zfs_unmountall(zhp: *mut ZfsHandle, flags: c_int) -> c_int;

    /// Unmount a single filesystem. `mountpoint` may be null.
    fn zfs_unmount(zhp: *mut ZfsHandle, mountpoint: *const c_char, flags: c_int) -> c_int;

    /// Inherit a property, removing its local value.
    fn zfs_prop_inherit(zhp: *mut ZfsHandle, propname: *const c_char, received: c_int) -> c_int;
}

/// Collect Pools
unsafe extern "C" fn collect_pool(zhp: *mut ZpoolHandle, data: *mut c_void) -> c_int {
    unsafe {
        let name = zpool_get_name(zhp);
        if !name.is_null() {
            let name = CStr::from_ptr(name);
            let pools = &mut *data.cast::<Vec<String>>();

            pools.push(name.to_string_lossy().into_owned());
        }
        zpool_close(zhp);
        0
    }
}

/// Collect Datasets
unsafe extern "C" fn collect_filesystems(zhp: *mut ZfsHandle, data: *mut c_void) -> c_int {
    unsafe {
        let name = zfs_get_name(zhp);
        if !name.is_null() {
            let name = CStr::from_ptr(name);
            let datasets = &mut *data.cast::<Vec<String>>();
            datasets.push(name.to_string_lossy().into_owned());
        }
        let rc = zfs_iter_filesystems(zhp, collect_filesystems, data);
        zfs_close(zhp);
        rc
    }
}

/// Errors for the Handle
#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid string: {0}")]
    Null(#[from] NulError),

    #[error("Failed to initialize libzfs")]
    Init,

    #[error("Failed to open dataset")]
    OpenDataset,

    #[error("Failed to iterate over pools")]
    PoolIteration,

    #[error("Failed to iterate over datasets")]
    DatasetIteration,

    #[error("Failed to read dataset property: {0}")]
    Property(&'static str),

    #[error("Process error: {0}")]
    Process(String),

    #[error("Failed to spawn process: {0}")]
    Spawn(#[from] SpawnError),

    #[error("Failed to communicate with process: {0}")]
    Handle(#[from] HandleError),

    #[error("Library error: {0}")]
    Errno(#[from] Errno),

    #[error("Too many attempts")]
    TooMany(),

    #[error("Failed to set property: {0}")]
    SetProperty(&'static str),

    #[error("Not a valid user property name")]
    InvalidUserProperty,

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("libzfs operation failed: {0}")]
    LibZfs(&'static str),
}

/// A libzfs Handle that closes when it falls out of scope.
pub struct LibZfsContext(NonNull<LibZfsHandle>);
impl Drop for LibZfsContext {
    fn drop(&mut self) {
        unsafe {
            libzfs_fini(self.0.as_ptr());
        }
    }
}

/// A zfs handle that closes when it falls out of scope.
struct DatasetHandle(NonNull<ZfsHandle>);
impl Drop for DatasetHandle {
    fn drop(&mut self) {
        unsafe {
            zfs_close(self.0.as_ptr());
        }
    }
}

/// Initialize a new libzfs Handle.
///
/// This is useful if you want to share a single handle with multiple handles.
///
/// ## Errors
///
/// If we cannot get a libzfs handle.
pub fn init_libzfs() -> Result<Rc<LibZfsContext>, Error> {
    let hdl = NonNull::new(unsafe { libzfs_init() }).ok_or(Error::Init)?;
    Ok(Rc::new(LibZfsContext(hdl)))
}

/// Handle a ZFS dataset/volume.
pub struct Handle {
    /// The name of the dataset
    dataset: String,

    /// A libzfs handle
    hdl: Rc<LibZfsContext>,

    /// The dataset handle.
    zhp: DatasetHandle,
}

impl Handle {
    /// Construct a new `Handle` for the dataset with an existing libzfs handle
    ///
    /// ## Errors
    ///
    /// If the dataset is not a valid `CString`, or does not point to a valid dataset
    /// we can open
    pub fn new_with(dataset: &str, hdl: Rc<LibZfsContext>) -> Result<Self, Error> {
        let dataset_c = CString::new(dataset)?;

        let zhp = NonNull::new(unsafe {
            zfs_open(
                hdl.0.as_ptr(),
                dataset_c.as_ptr(),
                ZFS_TYPE_FILESYSTEM | ZFS_TYPE_VOLUME,
            )
        })
        .ok_or(Error::OpenDataset)?;

        Ok(Self {
            dataset: dataset.to_owned(),
            hdl,
            zhp: DatasetHandle(zhp),
        })
    }

    /// Construct a new `Handle` for the dataset
    ///
    /// ## Errors
    ///
    /// If we cannot initialize a new libzfs handle.
    pub fn new(dataset: &str) -> Result<Self, Error> {
        Self::new_with(dataset, init_libzfs()?)
    }

    /// Return handles for all currently imported pools.
    ///
    /// ## Errors
    ///
    /// If we cannot get a new libzfs handle.
    pub fn pools() -> Result<Vec<Self>, Error> {
        let hdl = init_libzfs()?;
        let mut names = Vec::<String>::new();

        let rc = unsafe {
            zpool_iter(
                hdl.0.as_ptr(),
                collect_pool,
                (&raw mut names).cast::<c_void>(),
            )
        };

        if rc != 0 {
            Err(Error::PoolIteration)
        } else {
            names
                .into_iter()
                .map(|name| Self::new_with(&name, Rc::clone(&hdl)))
                .collect()
        }
    }

    /// Get the name of the dataset
    #[must_use]
    pub fn name(&self) -> &str {
        &self.dataset
    }

    /// Get a standard ZFS property.
    ///
    /// ## Errors
    ///
    /// If the property in not valid, or could not be retrieved.
    pub fn get(&self, prop: &str) -> Result<BString, Error> {
        let prop_c = CString::new(prop)?;
        let prop_id = unsafe { zfs_name_to_prop(prop_c.as_ptr()) };

        if prop_id < 0 {
            return Err(Error::Property("unknown standard property"));
        }

        let mut buf = [0 as c_char; 4096];

        let rc = unsafe {
            zfs_prop_get(
                self.zhp.0.as_ptr(),
                prop_id,
                buf.as_mut_ptr(),
                buf.len(),
                null_mut(),
                null_mut(),
                0,
                0,
            )
        };

        if rc != 0 {
            Err(Error::Property("zfs_prop_get failed"))
        } else {
            Ok(unsafe { CStr::from_ptr(buf.as_ptr()) }
                .to_string_lossy()
                .into_owned()
                .into())
        }
    }

    /// Get a ZFS user property
    ///
    /// ## Errors
    ///
    /// If the property in not valid, or could not be retrieved.
    pub fn get_user(&self, prop: &str) -> Result<BString, Error> {
        let prop_c = CString::new(prop)?;

        if unsafe { zfs_prop_user(prop_c.as_ptr()) } == 0 {
            return Err(Error::InvalidUserProperty);
        }

        let props = unsafe { zfs_get_user_props(self.zhp.0.as_ptr()) };

        if props.is_null() {
            return Err(Error::Property("failed to get user properties"));
        }

        let mut entry: *mut NvList = null_mut();

        let rc = unsafe { nvlist_lookup_nvlist(props, prop_c.as_ptr(), &raw mut entry) };

        if rc != 0 || entry.is_null() {
            return Err(Error::Property("user property not found"));
        }

        let mut value: *const c_char = null();

        let rc = unsafe { nvlist_lookup_string(entry, c"value".as_ptr(), &raw mut value) };

        if rc != 0 || value.is_null() {
            Err(Error::Property("user property has no value"))
        } else {
            Ok(unsafe { CStr::from_ptr(value) }
                .to_string_lossy()
                .into_owned()
                .into())
        }
    }

    /// Set a standard ZFS property.
    /// ## Errors
    ///
    /// If the property in not valid, or could not be set.
    pub fn set(&self, prop: &str, value: &BStr) -> Result<(), Error> {
        let prop_c = CString::new(prop)?;
        let value_c = CString::new(value.iter().as_slice())?;

        let prop_id = unsafe { zfs_name_to_prop(prop_c.as_ptr()) };

        if prop_id < 0 {
            return Err(Error::Property("unknown standard property"));
        }

        let rc = unsafe { zfs_prop_set(self.zhp.0.as_ptr(), prop_c.as_ptr(), value_c.as_ptr()) };

        if rc != 0 {
            Err(Error::SetProperty("zfs_prop_set failed"))
        } else {
            Ok(())
        }
    }

    /// Set a ZFS user property
    ///
    /// ## Errors
    ///
    /// If the property in not valid, or could not be set.
    pub fn set_user(&self, prop: &str, value: &BStr) -> Result<(), Error> {
        let prop_c = CString::new(prop)?;
        let value_c = CString::new(value.iter().as_slice())?;

        if unsafe { zfs_prop_user(prop_c.as_ptr()) } == 0 {
            return Err(Error::InvalidUserProperty);
        }

        let rc = unsafe { zfs_prop_set(self.zhp.0.as_ptr(), prop_c.as_ptr(), value_c.as_ptr()) };

        if rc != 0 {
            Err(Error::SetProperty("zfs_prop_set failed"))
        } else {
            Ok(())
        }
    }

    /// Load the key for the dataset.
    ///
    /// This function does not check if the key is needed.
    /// This function calls the `zfs` executable to avoid all the implementation details needed to call it from libzfs.
    ///
    /// ## Errors
    ///
    /// If either `systemd-ask-password` or `zfs` fail.
    pub fn load_key(&self) -> Result<(), Error> {
        for x in 1..5 {
            let (r, w) = pipe()?;

            let mut ask = Spawner::abs("/usr/bin/systemd-ask-password")
                .args(["-n", &format!("Enter encryption key for {}", self.dataset)])
                .output(StreamMode::Fd(w))
                .error(StreamMode::Pipe)
                .spawn()?;

            let mut load = Spawner::abs("/usr/bin/zfs")
                .args(["load-key", &self.dataset])
                .input(StreamMode::Fd(r))
                .error(StreamMode::Pipe)
                .spawn()?;

            if ask.wait_and()? != 0 {
                return Err(Error::Process(ask.error_all()?));
            }

            if load.wait_and()? != 0 {
                let out = load.error_all()?;

                if out.contains("Incorrect key") {
                    eprint!("{out}");
                    sleep(Duration::from_secs(x));
                } else {
                    return Err(Error::Process(out));
                }
            } else {
                return Ok(());
            }
        }

        Err(Error::TooMany())
    }

    /// Load the key for the dataset with the provided value.
    ///
    /// ## Errors
    ///
    /// If `zfs` fails
    pub fn with_key(&self, key: &SensitiveData) -> Result<(), Error> {
        let mut load = Spawner::abs("/usr/bin/zfs")
            .args(["load-key", &self.dataset])
            .input(StreamMode::Pipe)
            .error(StreamMode::Pipe)
            .spawn()?;
        load.write_all(key.value())?;
        load.close()?;
        if load.wait_and()? != 0 {
            Err(Error::Process(load.error_all()?))
        } else {
            Ok(())
        }
    }

    /// Return the root dataset and all descendant filesystems.
    ///
    /// Each result has an independently opened handle. The root
    /// is included as well.
    ///
    /// ## Errors
    ///
    /// If we cannot iterate filesystems
    pub fn datasets(&self) -> Result<Vec<Self>, Error> {
        let mut names = Vec::<String>::new();

        names.push(self.dataset.clone());

        let rc = unsafe {
            zfs_iter_filesystems(
                self.zhp.0.as_ptr(),
                collect_filesystems,
                (&raw mut names).cast::<c_void>(),
            )
        };

        if rc != 0 {
            Err(Error::DatasetIteration)
        } else {
            names
                .into_iter()
                .map(|name| Self::new_with(&name, Rc::clone(&self.hdl)))
                .collect()
        }
    }

    /// Mount a dataset at the supplied path.
    ///
    /// This is intended for datasets with mountpoint=legacy.
    /// The caller is responsible for choosing the mountpoint.
    ///
    /// ## Errors
    ///
    /// If the `mount_at` call fails
    pub fn mount(&self, mountpoint: &str) -> Result<(), Error> {
        let mountpoint_c = CString::new(mountpoint)?;

        let rc = unsafe { zfs_mount_at(self.zhp.0.as_ptr(), null(), 0, mountpoint_c.as_ptr()) };

        if rc != 0 {
            Err(Error::LibZfs("zfs_mount_at failed"))
        } else {
            Ok(())
        }
    }

    /// Check whether the dataset is currently mounted.
    ///
    /// Works with both ordinary ZFS mountpoints and `mountpoint=legacy`.
    #[must_use]
    pub fn is_mounted(&self) -> bool {
        unsafe { zfs_is_mounted(self.zhp.0.as_ptr(), null_mut()) != 0 }
    }

    /// Unmount the dataset
    ///
    /// ## Errors
    ///
    /// If the unmount call fails.
    pub fn unmount(&self, recursive: bool) -> Result<(), Error> {
        let rc = if recursive {
            unsafe { zfs_unmountall(self.zhp.0.as_ptr(), 0) }
        } else {
            unsafe { zfs_unmount(self.zhp.0.as_ptr(), null(), 0) }
        };

        if rc != 0 {
            Err(Error::LibZfs("zfs_mount_at failed"))
        } else {
            Ok(())
        }
    }

    /// Remove the local value of a ZFS user property.
    ///
    /// If a parent dataset defines the property, its value will
    /// become visible through inheritance. Otherwise, the property
    /// is removed entirely.
    ///
    /// ## Errors
    ///
    /// If the property name is invalid or the operation fails.
    pub fn inherit_user(&self, prop: &str) -> Result<(), Error> {
        let prop_c = CString::new(prop)?;

        if unsafe { zfs_prop_user(prop_c.as_ptr()) } == 0 {
            return Err(Error::InvalidUserProperty);
        }

        let rc = unsafe { zfs_prop_inherit(self.zhp.0.as_ptr(), prop_c.as_ptr(), 0) };

        if rc != 0 {
            Err(Error::SetProperty("zfs_prop_inherit failed"))
        } else {
            Ok(())
        }
    }
}
