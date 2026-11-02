# Zirconium

Zirconium is a `mkinitcpio` hook that facilitates the importing and decryption of ZFS volumes during system boot. It has first-class support for using the system TPM to seal dataset keys against the system configuration (i.e Firmware and SecureBoot via PCRs) to perform automatic or PIN unlocking similar to `systemd-cryptenroll` for LUKS.

## Installation

Zirconium is written in Rust, and requires `cargo` or `rustup` to compile. Additionally, it needs:

1. `libzfs` *and* `zfs-utils`
2. A kernel with the ZFS Kernel Module.
3. `tpm2-libtss`

Build dependencies:
  1. `pkg-config`

Next, add `zirconium` to the `HOOKS` of your `mkinitcpio.conf` file. Also ensure you are using the `systemd` and the `keyboard` hook (And that `keyboard` is *before* `zirconium`). For example:

```
HOOKS=(systemd autodetect microcode modconf kms keyboard block zirconium)
```

## Configuration

By default, Zirconium will install itself into your boot image; its Service depends on `initrd-root-device.target`, and runs before the sysroot mount (`systemd` mounts your root filesystem on `/sysroot` in the boot image, then pivots the root into it). If want Zirconium to *do anything*, you’ll need to specify which pools need to be imported (Unless you have another means of having the pools imported before this point).

The `/etc/zirconium.toml` file specifies a `[pools]` field  that takes pool names as keys, and a list of devices the pool is composed of. For example:

```toml
[pools]
"zroot" = ["/dev/disk/by-id/XXX", "/dev/disk/by-id/YYY"]
```

Zirconium’s boot image hook will compose drop-in files for its service to depend on the availability of the specified devices.

> [!note]
> Zirconium is a monolithic service, waiting on all necessary devices for all pool before being executed; this is to avoid race-conditions on acquiring the TPM.


Zirconium only imports pools with `keyformat=passphrase`, and `keylocation=prompt`. This is because regardless of the mode Zirconium uses to unlock the volume, it will always have a fallback to manually entering the original password. Even under automatic TPM enrollment, you must use a known passphrase for the dataset. This is an explicit design choice to ensure that even in cases of catastrophic TPM loss (Such as unlocking the pool on another system, or clearing the TPM is the BIOS), the dataset can still be recovered (Even if that requires typing an extraordinarily complex passphrase that would not be memorized and used under normal circumstances.

### TPM Sealing

By default, Zirconium operates as a simpl:qe means of entering passphrases for ZFS datasets. It’s chief design, however, is utilizing the TPM of a system to ease/remove the need for entering a passphrase on boot. This is done via two methods:

1. Zirconium uses the TPM as a means of secure storage; on first use, Zirconium enrolls a private encryption key within the TPM that is sealed against the currently defined PCR registers in the configuration file (Defaulting to 0 (The Firmware state), and 7 (The SecureBoot state)). This key is then used for the various TPM features.
2. Zirconium uses the TPM to attest a known, good system state, before utilizing the secure key. This means that the simplified boot flow is only permitted if the system configuration is deemed secure (i.e booted into SecureBoot with the same BIOS version as when enrolled). It’s important to note that this attestation is performed *by* the TPM—it is impossible to overrule the refusal within the RAM or Boot image itself.

> [!warning]
> Zirconium defaults to using PCR registers 0+7. You can explicitly configure the PCRs that are used, but with two caveats:
> 
> 1. *Removing* either 0 or 7 should only be done with serious consideration, as it can allow for untrusted environments to unseal secret keys.
> 2. *Adding* more PCRs should only be done with even *more* consideration than above. Some PCRs can change on each boot, invalidating the key and denying any utility of the program.

You should also define a threat model and understand where Zirconium sits in it. Specifically:

1. Zirconium distrusts both external actors (i.e Dirty Maid Attacks), and the root filesystem itself (i.e Malware). For the latter reason, Zirconium deterministically modified the PCRs used to seal its encrypting key such that the values will remain consistent for downstream usage (e.g using `systemd-creds`), but unable to reconstruct the keys after the pivot into the real root.
2. Because the TPM and BIOS reconstruct the PCR values deterministically, any program that runs before Zirconium in that trusted state can derive the encryption keys. You should seriously consider enabling SecureBoot, as well as using a secure boot image like UKIs that sign the kernel image, command line, and splash image under a single file. If using a traditional bootloader, ensure it verifies and maintains the chain of trust; you may want to consider using PCR 8 (Hashing the command line), if the command line can be edited (Such as with GRUB), to prevent trivially dropping into a root shell with `init=sh` when using automatic decryption.

***

Zirconium performs enrollment automatically when first run; if you want to reconfigure an existing installation you can call `zr --purge` or wipe the TPM from the BIOS (Though note this may remove secrets and applications by other utilities).

You must then specify the mode of operation (As the default mode bypasses the TPM entirely and simply prompts for the password). This can be specified by setting the user property `zirconium:strategy` for each dataset (Though note that only encryption roots are considered, so you can allow inherited values so long as they have the same root). Options include:

1. `none` bypasses decryption entirely during the boot phase. This is useful if decryption should be performed later (Such a home dataset using the user’s psasword as key)
2. `pass` is the default behavior mentioned above.
3. `tpm` will encrypt the dataset using the TPM-sealed encryption key in the `zirconium:key` user property. Assuming an identical system configuration as during enrollment, Zirconium will automatically unlock the dataset on boot. If the decryption fails (Such as if the key changed, or system state was modified), the dataset is left locked.
4. `both` combines `tpm` and `pass`. If the dataset can be unlocked automatically, it is, otherwise Zirconium prompts for the password.
5. `enchanced` adds an additional—typically simpler—PIN that must be provided on top of a sound system state to unlock the volume. If either the PIN or system state is incorrect, it falls back to the original password. This avoids cold-boot attacks in `tpm` mode, but by electing for as easier to remember/type PIN, can be more convenient while allowing the real password to be far more complex than would be realistic to type otherwise on each boot.

## Home Unlocking

As mentioned in the previous section, using the `none` strategy is useful for datasets that should not be unlocked at boot time; chief of these is a home dataset that feeds the user password via PAM to unlock the dataset on login. This function can be provided by adding the follow line to the `auth` block in `/etc/pam.d/system-auth`:

```
auth       required                    pam_exec.so          expose_authtok  /usr/bin/zrh
```

This requires that the home dataset:
1. Is located directly in either `$ROOT/home/$USER`, where `$ROOT` is the `root` dataset in the configuration, or `$HOME/$USER` where `$HOME` is the `home_prefix` dataset in the configuration.
2. The dataset mentioned above is its own encryption root.


