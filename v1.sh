#!/usr/bin/env bash
# ------------------------------------------------------------
# Arch Linux automated installer (LUKS + systemd-boot + AppArmor)
# Dual-boot desktop (w/NVIDIA GPU) - FIXED VERSION
# ------------------------------------------------------------
set -euo pipefail
IFS=$'\n\t'

# Force BOOTSTRAPPED to be set to skip the GitHub download loop
export BOOTSTRAPPED=1

# ------------------- Helper functions -----------------------
info() { echo -e "\e[34m[+] $*\e[0m"; }
warn() { echo -e "\e[33m[!] $*\e[0m"; }
die()  { echo -e "\e[31m[!] $*\e[0m" >&2; exit 1; }

require() {
    command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

# ---- commands we will use later ----
for cmd in lsblk sgdisk cryptsetup mkfs.ext4 mkfs.fat mount \
    pacstrap genfstab arch-chroot blkid sed awk \
    reflector bootctl; do
    require "$cmd"
done

# ---------- Cleanup trap ----------
cleanup() {
  warn "Cleaning up after error..."
  mountpoint -q /mnt && umount -R /mnt || true
  cryptsetup status cryptroot >/dev/null 2>&1 && cryptsetup close cryptroot || true
}
trap cleanup ERR

# ---------- 1. Network check ----------
info "Checking network connectivity..."
if ! ping -c 1 -W 2 archlinux.org >/dev/null 2>&1; then
    die "No network connection. Connect via Ethernet or run 'iwctl' first."
fi

# ---------- UEFI mode check ----------
# systemd-boot requires UEFI; fail early if not booted in UEFI mode.
if [[ ! -d /sys/firmware/efi/efivars ]]; then
    die "System is not booted in UEFI mode. Reboot the installer in UEFI."
fi
info "UEFI mode confirmed."

# ---------- 3. Disk selection ----------
info "Available disks:"
# More robust disk detection - try multiple approaches
mapfile -t DISKS < <(
    lsblk -dpno NAME,SIZE,MODEL,TYPE | awk '
        /disk$/ || $4=="disk" { 
            print NR")", $1, $2, ($3 ? $3 : "Unknown") 
        }
    '
)

# If that didn't work, try a simpler approach
if (( ${#DISKS[@]} == 0 )); then
    info "First method failed, trying alternative disk detection..."
    mapfile -t DISKS < <(
        lsblk -dno NAME,SIZE,TYPE | awk '
            $3=="disk" { 
                print NR")", "/dev/"$1, $2, "disk"
            }
        '
    )
fi

if (( ${#DISKS[@]} == 0 )); then
    info "Debug information:"
    echo "Raw lsblk output:"
    lsblk -dpno NAME,SIZE,MODEL,TYPE || lsblk -dno NAME,SIZE,TYPE
    echo "Available block devices:"
    ls -la /dev/sd* /dev/nvme* /dev/vd* 2>/dev/null || echo "No common block devices found"
    die "No disks detected. Check the debug output above."
fi
printf "%s\n" "${DISKS[@]}"
read -rp "Enter the number of the disk to WIPE and install to: " IDX
if ! [[ "$IDX" =~ ^[0-9]+$ ]] || (( IDX < 1 || IDX > ${#DISKS[@]} )); then
    die "Invalid selection."
fi
DISK=$(printf "%s\n" "${DISKS[$((IDX-1))]}" | awk '{print $2}')
info "You selected: $DISK"

# ---------- 4. Destructive confirmation ----------
read -rp "Type EXACTLY: WIPE $DISK to confirm wiping this disk: " CONFIRM
if [[ "$CONFIRM" != "WIPE $DISK" ]]; then
    die "Confirmation failed - aborting."
fi

# ---------- 5. Basic system info ----------
read -rp "Hostname (e.g., pataphysics): " HOSTNAME
if ! [[ "$HOSTNAME" =~ ^[a-zA-Z0-9.-]+$ ]]; then
    die "Invalid hostname."
fi
read -rp "Non-root username to create: " NEWUSER
if ! [[ "$NEWUSER" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
    die "Invalid username."
fi

# ---------- 6. Password prompts ----------
info "Enter passwords (input will be hidden)."
read -srp "LUKS passphrase: " LUKS_PASS; echo
read -srp "Confirm LUKS passphrase: " LUKS_PASS2; echo
[[ "$LUKS_PASS" == "$LUKS_PASS2" ]] || die "LUKS passphrases differ."

read -srp "Root password: " ROOT_PASS; echo
read -srp "Confirm root password: " ROOT_PASS2; echo
[[ "$ROOT_PASS" == "$ROOT_PASS2" ]] || die "Root passwords differ."

read -srp "Password for user $NEWUSER: " USER_PASS; echo
read -srp "Confirm password for $NEWUSER: " USER_PASS2; echo
[[ "$USER_PASS" == "$USER_PASS2" ]] || die "User passwords differ."

# ---------- 7. Timezone & locale ----------
TZ_REGION="America/Chicago"   # change if you live elsewhere
LOCALE="en_US.UTF-8"

# ---------- 8. Partitioning ----------
info "Creating GPT, EFI partition and LUKS container on $DISK ..."
sgdisk --zap-all "$DISK"
sgdisk -o "$DISK"
sgdisk -n 1:0:+512M -t 1:EF00 "$DISK"   # EFI System Partition (512 MiB)
sgdisk -n 2:0:0    -t 2:8300 "$DISK"   # LUKS container (rest of the disk)

if [[ "$DISK" =~ [0-9]$ ]]; then
  P1="${DISK}p1"; P2="${DISK}p2"
else
  P1="${DISK}1";  P2="${DISK}2"
fi
EFI_PART="$P1"
LUKS_PART="$P2"
[[ -b "$EFI_PART" && -b "$LUKS_PART" ]] || die "Partition creation failed."

# ---------- 9. LUKS setup ----------
info "Formatting LUKS container..."
printf "%s" "$LUKS_PASS" | cryptsetup luksFormat --type luks2 "$LUKS_PART" -
info "Opening LUKS container..."
printf "%s" "$LUKS_PASS" | cryptsetup open --key-file - "$LUKS_PART" cryptroot

# ---------- 10. LUKS header backup (deferred) ----------
info "LUKS header will be backed up after the root filesystem is mounted (see step 18)."

# ---------- 11. Filesystems ----------
info "Creating filesystems..."
mkfs.ext4 -L ROOT /dev/mapper/cryptroot
mkfs.fat -F32 -L ESP "$EFI_PART"

# ---------- 12. Mount points ----------
info "Mounting filesystems..."
mount /dev/mapper/cryptroot /mnt
mkdir -p /mnt/boot
mount "$EFI_PART" /mnt/boot

# ---------- 13. Encrypted swapfile (4 GiB) ----------
info "Creating encrypted swapfile (4 GiB) inside LUKS container..."
fallocate -l 4G /mnt/swapfile
chmod 600 /mnt/swapfile
mkswap /mnt/swapfile
info "Activating swap on the installer environment..."
swapon /mnt/swapfile || warn "swapon failed; swap will still be enabled at first boot via fstab"

# ---------- 14. Optimise mirrors (speeds up pacstrap) ----------
info "Optimising pacman mirrors with reflector..."
reflector --country US --latest 10 --sort rate --save /etc/pacman.d/mirrorlist

# ---------- 15. Pacstrap - base system + essential packages ----------
info "Installing base system (this may take a few minutes)..."
# Detect CPU microcode (Intel vs AMD) for appropriate package
CPU_UCODE="intel-ucode"
if grep -qi "AuthenticAMD" /proc/cpuinfo; then
  CPU_UCODE="amd-ucode"
fi

pacstrap -K /mnt \
  base base-devel linux linux-firmware "${CPU_UCODE}" \
    nvidia nvidia-utils nvidia-settings \
    networkmanager vim sudo \
    dosfstools efibootmgr \
    systemd-resolved systemd-timesyncd \
    apparmor

# ---------- 16. fstab ----------
info "Generating fstab..."
genfstab -U /mnt >> /mnt/etc/fstab

# ensure the swapfile created earlier is enabled on first boot
echo '/swapfile none swap defaults 0 0' >> /mnt/etc/fstab
info "Added /swapfile entry to /mnt/etc/fstab"

# ---------- 17. Capture LUKS UUID (used in boot entry) ----------
LUKS_UUID=$(blkid -s UUID -o value "$LUKS_PART")
[[ -n "$LUKS_UUID" ]] || die "Unable to obtain LUKS UUID."

# ---------- 18. Backup LUKS header (now that /mnt is mounted) ----------
info "Saving LUKS header to /mnt/root/Documents/luks-header-backup.bin"
mkdir -p /mnt/root/Documents
cryptsetup luksHeaderBackup "$LUKS_PART" --header-backup-file /mnt/root/Documents/luks-header-backup.bin

# ---------- 19. Chroot configuration ----------
info "Configuring the new system inside chroot..."
arch-chroot /mnt /bin/bash - <<CHROOT_EOF
set -euo pipefail
IFS=\$'\\n\\t'

# ---- Timezone & clock ----
ln -sf /usr/share/zoneinfo/${TZ_REGION} /etc/localtime
hwclock --systohc

# ---- Locale ----
sed -i "s/^#${LOCALE}/${LOCALE}/" /etc/locale.gen
locale-gen
echo "LANG=${LOCALE}" > /etc/locale.conf

# ---- Hostname & hosts ----
echo "${HOSTNAME}" > /etc/hostname
cat > /etc/hosts <<EOFHOSTS
127.0.0.1   localhost
::1         localhost
127.0.1.1   ${HOSTNAME}.localdomain ${HOSTNAME}
EOFHOSTS

# ---- Root password ----
echo "root:${ROOT_PASS}" | chpasswd

# ---- Regular user ----
useradd -m -G wheel -s /bin/bash ${NEWUSER}
echo "${NEWUSER}:${USER_PASS}" | chpasswd

# ---- sudoers (wheel group, no NOPASSWD) ----
sed -i 's/^# %wheel ALL=(ALL:ALL) ALL/%wheel ALL=(ALL:ALL) ALL/' /etc/sudoers

# ---- mkinitcpio (encrypt + apparmor) ----
sed -i 's/^HOOKS=.*/HOOKS=(base udev autodetect modconf block keyboard encrypt filesystems apparmor fsck)/' /etc/mkinitcpio.conf
mkinitcpio -P

# ---- Enable essential services ----
systemctl enable NetworkManager
systemctl enable systemd-resolved
systemctl enable systemd-timesyncd
systemctl enable fstrim.timer

# ---- systemd-resolved stub (ensure /etc/resolv.conf points to it) ----
ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

# ---- systemd-boot installation ----
bootctl install

# ---- boot entry with full LSM chain + kernel lockdown ----
cat > /boot/loader/entries/arch.conf <<EOFBOOT
title   Arch Linux (encrypted)
linux   /vmlinuz-linux
initrd  /${CPU_UCODE}.img
initrd  /initramfs-linux.img
options cryptdevice=UUID=${LUKS_UUID}:cryptroot root=/dev/mapper/cryptroot rw quiet loglevel=3 lsm=landlock,yama,integrity,apparmor,bpf systemd.kernel_lockdown=confidentiality
EOFBOOT

# ---- loader.conf (default entry, timeout, no editor) ----
cat > /boot/loader/loader.conf <<EOFLOADER
default arch.conf
timeout 5
editor 0
EOFLOADER

# ---- Post-boot hardening script (runs as root) ----
cat > /root/post_boot_hardening.sh <<'EOSPOST'
#!/usr/bin/env bash
set -euo pipefail
IFS=\$'\\n\\t'

info(){ echo -e "\\e[34m[+] \$*\\e[0m"; }
warn(){ echo -e "\\e[33m[!] \$*\\e[0m"; }
die(){ echo -e "\\e[31m[!] \$*\\e[0m" >&2; exit 1; }

# ---- System update & mirror refresh ----
info "Updating system..."
pacman -Syu --noconfirm

info "Refreshing mirrors with reflector..."
pacman -S --noconfirm reflector
reflector --country US --latest 10 --sort rate --save /etc/pacman.d/mirrorlist

# ---- AppArmor ----
info "Installing & enabling AppArmor..."
pacman -S --noconfirm apparmor
systemctl enable --now apparmor
# Load default profiles (optional, safe to ignore failures)
apparmor_parser -r /etc/apparmor.d/* || true
cat /sys/module/apparmor/parameters/enabled || true

# ---- UFW (firewall) ----
info "Installing & configuring UFW..."
pacman -S --noconfirm ufw
systemctl enable --now ufw
ufw default deny incoming
ufw default allow outgoing
ufw --force enable
ufw status verbose

# ---- systemd-oomd (out-of-memory protection) ----
info "Installing & enabling systemd-oomd..."
pacman -S --noconfirm systemd-oomd
systemctl enable --now systemd-oomd

# ---- Secure Boot (sbctl) ----
info "Setting up Secure Boot keys (sbctl)..."
pacman -S --noconfirm sbctl
sbctl status || true
sbctl create-keys || true
sbctl enroll-keys --microsoft || true
# Re-sign kernel & bootloader (in case they changed)
sbctl sign -s /boot/vmlinuz-linux || true
sbctl sign -s /boot/EFI/systemd/systemd-bootx64.efi || true
sbctl verify || true
warn "Now reboot into BIOS and set Secure Boot -> ON (Windows UEFI mode), Mode -> Custom."

# ---- Optional: disable/remove SSH (privacy) ----
info "Disabling SSH (if installed)..."
systemctl disable --now sshd 2>/dev/null || true
pacman -Rns --noconfirm openssh 2>/dev/null || true

# ---- Privacy-focused applications ----
info "Installing privacy apps (official repo packages only)..."
pacman -S --noconfirm firefox dolphin timeshift

# AUR-only packages: install only if an AUR helper is available
AUR_PKGS=(proton-vpn-gtk-app torbrowser-launcher)
if command -v yay >/dev/null 2>&1; then
  info "Installing AUR packages with yay..."
  yay -S --noconfirm "\${AUR_PKGS[@]}" || warn "AUR installs failed; install manually after first boot."
else
  warn "Skipped AUR packages: \${AUR_PKGS[*]}. Install manually after first boot with an AUR helper (yay, paru, etc.)."
fi

# ---- Suggested next steps ----
info "All done! Suggested next steps:"
echo " * Run: torbrowser-launcher   (downloads & verifies the bundle)"
echo " * In Firefox -> Settings -> Privacy & Security -> Enable DoH -> Custom -> https://dns.nextdns.io/6598a4"
echo " * Run: timeshift-gtk   (create your first snapshot)"
echo " * Verify DNS / IP leaks at https://dnsleaktest.com/, https://ipleak.net/, https://check.torproject.org/"
echo " * Reboot into BIOS (F2), and turn on Secure Boot (Boot -> Secure Boot -> OS Type -> Windows UEFI mode -> Secure Boot Mode -> Custom) "
EOSPOST

chmod +x /root/post_boot_hardening.sh

CHROOT_EOF

# ---------- 20. Finish up ----------
info "Unmounting filesystems..."
umount -R /mnt

# close the LUKS mapper so the device is cleanly released
cryptsetup status cryptroot >/dev/null 2>&1 && cryptsetup close cryptroot || true

info "Installation complete! Remove the USB stick and reboot."
echo "When the system boots, log in as '${NEWUSER}' and run:"
echo "    sudo /root/post_boot_hardening.sh"
echo "to finish hardening, install your apps, and enable Secure Boot."

# Remove the automatic reboot to give user control
warn "Script completed successfully. Reboot manually when ready with: reboot"